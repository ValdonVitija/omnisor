//! Bounded, timestamp-ordered series. Counter deltas never bridge resets or gaps.
use std::collections::{BTreeMap, VecDeque};
use telemetry::{Observation, Value};

pub const MAX_SERIES: usize = 4096;
pub const MAX_POINTS: usize = 450;
pub const RETENTION_NANOS: u64 = 15 * 60 * 1_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Point {
    pub at: u64,
    pub value: f64,
}

#[derive(Clone, Debug)]
pub struct Series {
    pub latest: Observation,
    pub points: VecDeque<Point>,
}

#[derive(Clone, Debug, Default)]
pub struct MetricsSnapshot {
    pub sequence: u64,
    pub series: BTreeMap<(String, String), Series>,
    pub accepted: u64,
    pub rejected: u64,
    pub ignored: u64,
    pub dropped: u64,
    pub last_received: Option<u64>,
    rate_totals: BTreeMap<String, BTreeMap<u64, f64>>,
}

impl MetricsSnapshot {
    pub fn observations(&self) -> Vec<Observation> {
        self.series.values().map(|s| s.latest.clone()).collect()
    }
    pub fn scrape_state(&self, now: u64, interval: u64) -> &'static str {
        let Some(series) = self
            .series
            .get(&("collection.scrape.up".into(), "system".into()))
        else {
            return "Waiting for first scrape";
        };
        let at = series
            .latest
            .observed_at_unix_nano
            .parse::<u64>()
            .unwrap_or(0);
        if now.saturating_sub(at) > interval * 3 * 1_000_000_000 {
            return "Stale · no recent scrape";
        }
        match numeric(&series.latest) {
            Some(0.) => "Device scrape failed",
            Some(1.) => "Receiving metrics",
            _ => "Invalid scrape state",
        }
    }
    pub fn is_fresh(&self, now: u64, interval: u64) -> bool {
        self.scrape_state(now, interval) == "Receiving metrics"
    }
    pub fn latest_series(&self, name: &str) -> Option<&Series> {
        self.series
            .values()
            .filter(|series| series.latest.name == name)
            .max_by(|a, b| {
                numeric(&a.latest)
                    .unwrap_or(0.)
                    .total_cmp(&numeric(&b.latest).unwrap_or(0.))
            })
    }
    pub fn traffic(&self, name: &str, since: u64) -> Vec<Point> {
        self.rate_totals
            .get(name)
            .into_iter()
            .flat_map(|points| points.range(since..))
            .map(|(&at, &value)| Point { at, value })
            .collect()
    }
}

pub struct Store {
    pub data: MetricsSnapshot,
    device: String,
    interval: u64,
}

impl Store {
    pub fn new(device: String, interval: u64) -> Self {
        Self {
            data: MetricsSnapshot::default(),
            device,
            interval,
        }
    }
    pub fn ingest(
        &mut self,
        observations: Vec<Observation>,
        received: u64,
        rejected: usize,
        ignored: usize,
    ) {
        self.data.sequence += 1;
        self.data.rejected += rejected as u64;
        self.data.ignored += ignored as u64;
        self.data.last_received = Some(received);
        let mut derived = Vec::new();
        for observation in observations {
            let Ok(at) = observation.observed_at_unix_nano.parse::<u64>() else {
                self.data.rejected += 1;
                continue;
            };
            if observation.device_id != self.device
                || at > received.saturating_add(30_000_000_000)
                || received.saturating_sub(at) > RETENTION_NANOS
            {
                self.data.rejected += 1;
                continue;
            }
            let key = (observation.name.clone(), observation.entity_id.clone());
            if let Some(previous) = self.data.series.get(&key) {
                let previous_at = previous
                    .latest
                    .observed_at_unix_nano
                    .parse::<u64>()
                    .unwrap_or(0);
                if at <= previous_at {
                    self.data.dropped += 1;
                    continue;
                }
                if observation.kind == "cumulative_counter" {
                    let same_epoch =
                        observation.start_time_unix_nano == previous.latest.start_time_unix_nano;
                    if let Some(delta) = counter_delta(&observation, &previous.latest)
                        && same_epoch
                        && at - previous_at <= self.interval * 1_500_000_000
                        && let Some(name) = match observation.name.as_str() {
                            "interface.receive.bytes" => Some("interface.receive.bits_per_second"),
                            "interface.transmit.bytes" => {
                                Some("interface.transmit.bits_per_second")
                            }
                            _ => None,
                        }
                    {
                        let rate = delta * 8. / ((at - previous_at) as f64 / 1e9);
                        if rate.is_finite() {
                            let mut rate_observation = observation.clone();
                            rate_observation.name = name.into();
                            rate_observation.unit = "bit/s".into();
                            rate_observation.kind = "gauge".into();
                            rate_observation.value = Value::Number(rate);
                            rate_observation.source_metric =
                                format!("rate({})", observation.source_metric);
                            derived.push(rate_observation);
                        }
                    }
                }
            }
            self.insert(observation, at);
        }
        // Profiles may provide used/free or total/free for the same memory
        // entity. Never combine pools, observation times, units or metric kinds.
        for series in self
            .data
            .series
            .values()
            .filter(|s| s.latest.name == "device.memory.total")
        {
            let total = &series.latest;
            let Some(free) = self
                .data
                .series
                .get(&("device.memory.free".into(), total.entity_id.clone()))
                .map(|s| &s.latest)
            else {
                continue;
            };
            let has_direct_used = self
                .data
                .series
                .get(&("device.memory.used".into(), total.entity_id.clone()))
                .is_some_and(|s| {
                    s.latest.observed_at_unix_nano == total.observed_at_unix_nano
                        && !s.latest.source_metric.starts_with("derived:")
                });
            if has_direct_used || !matching_memory(total, free) {
                continue;
            }
            if let (Some(total_value), Some(free_value)) = (numeric(total), numeric(free))
                && total_value.is_finite()
                && total_value > 0.
                && free_value >= 0.
                && free_value <= total_value
            {
                let mut used = total.clone();
                used.name = "device.memory.used".into();
                used.value = Value::Number(total_value - free_value);
                used.source_metric =
                    format!("derived: {} - {}", total.source_metric, free.source_metric);
                used.attributes
                    .insert("calculation".into(), "total_minus_free".into());
                if let Some(ratio) = memory_ratio(&used, free) {
                    derived.push(ratio);
                }
                derived.push(used);
            }
        }
        for series in self
            .data
            .series
            .values()
            .filter(|s| s.latest.name == "device.memory.used")
        {
            let used = &series.latest;
            if let Some(free) = self
                .data
                .series
                .get(&("device.memory.free".into(), used.entity_id.clone()))
                && let Some(ratio) = memory_ratio(used, &free.latest)
            {
                derived.push(ratio);
            }
        }
        for observation in derived {
            let at = observation.observed_at_unix_nano.parse().unwrap_or(0);
            let key = (observation.name.clone(), observation.entity_id.clone());
            if self
                .data
                .series
                .get(&key)
                .is_none_or(|s| s.latest.observed_at_unix_nano.parse::<u64>().unwrap_or(0) < at)
            {
                self.insert(observation, at);
            }
        }
        for series in self.data.series.values_mut() {
            while series
                .points
                .front()
                .is_some_and(|p| received.saturating_sub(p.at) > RETENTION_NANOS)
            {
                series.points.pop_front();
            }
        }
    }
    fn insert(&mut self, observation: Observation, at: u64) {
        let key = (observation.name.clone(), observation.entity_id.clone());
        if !self.data.series.contains_key(&key) && self.data.series.len() >= MAX_SERIES {
            self.data.dropped += 1;
            return;
        }
        let value = numeric(&observation);
        let series = self.data.series.entry(key).or_insert_with(|| Series {
            latest: observation.clone(),
            points: VecDeque::new(),
        });
        series.latest = observation;
        if let Some(value) = value.filter(|v| v.is_finite()) {
            series.points.push_back(Point { at, value });
            let history = series.latest.name == "device.cpu.utilization"
                || series.latest.name == "device.memory.utilization"
                || series.latest.name.ends_with("bits_per_second");
            let max = if history { MAX_POINTS } else { 2 };
            while series.points.len() > max {
                series.points.pop_front();
            }
        }
        if series.latest.name.ends_with("bits_per_second")
            && let Some(value) = value.filter(|v| v.is_finite())
        {
            let totals = self
                .data
                .rate_totals
                .entry(series.latest.name.clone())
                .or_default();
            *totals.entry(at).or_default() += value;
            while totals.len() > MAX_POINTS
                || totals
                    .first_key_value()
                    .is_some_and(|(time, _)| at.saturating_sub(*time) > RETENTION_NANOS)
            {
                totals.pop_first();
            }
        }
        self.data.accepted += 1;
    }
}

fn matching_memory(left: &Observation, right: &Observation) -> bool {
    left.entity_id == right.entity_id
        && left.observed_at_unix_nano == right.observed_at_unix_nano
        && left.unit == "By"
        && right.unit == "By"
        && left.kind == "gauge"
        && right.kind == "gauge"
}
fn memory_ratio(used: &Observation, free: &Observation) -> Option<Observation> {
    if !matching_memory(used, free) {
        return None;
    }
    let (used_value, free_value) = (numeric(used)?, numeric(free)?);
    let total = used_value + free_value;
    if used_value < 0. || free_value < 0. || !total.is_finite() || total <= 0. {
        return None;
    }
    let mut ratio = used.clone();
    ratio.name = "device.memory.utilization".into();
    ratio.unit = "1".into();
    ratio.value = Value::Number(used_value / total);
    ratio.source_metric = format!(
        "derived: ({}) / (({}) + {})",
        used.source_metric, used.source_metric, free.source_metric
    );
    Some(ratio)
}

pub fn numeric(observation: &Observation) -> Option<f64> {
    match observation.value {
        Value::Number(value) => Some(value),
        Value::Integer(value) => Some(value as f64),
        Value::State(_) => None,
    }
}

fn counter_delta(current: &Observation, previous: &Observation) -> Option<f64> {
    match (&current.value, &previous.value) {
        (Value::Integer(current), Value::Integer(previous)) if current >= previous => {
            Some((*current as i128 - *previous as i128) as f64)
        }
        _ => {
            let (current, previous) = (numeric(current)?, numeric(previous)?);
            (current >= previous).then_some(current - previous)
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Statistics {
    pub min: f64,
    pub max: f64,
    pub sample_mean: f64,
    pub count: usize,
}
pub fn statistics(points: &[Point]) -> Option<Statistics> {
    if points.is_empty() {
        return None;
    }
    Some(Statistics {
        min: points.iter().map(|p| p.value).fold(f64::INFINITY, f64::min),
        max: points
            .iter()
            .map(|p| p.value)
            .fold(f64::NEG_INFINITY, f64::max),
        sample_mean: points.iter().map(|p| p.value).sum::<f64>() / points.len() as f64,
        count: points.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observation(
        name: &str,
        entity: &str,
        value: f64,
        at: u64,
        kind: &str,
        unit: &str,
    ) -> Observation {
        Observation {
            tenant_id: "local".into(),
            device_id: "d1".into(),
            entity_id: entity.into(),
            name: name.into(),
            value: Value::Number(value),
            unit: unit.into(),
            kind: kind.into(),
            observed_at_unix_nano: at.to_string(),
            start_time_unix_nano: "0".into(),
            received_at_unix_nano: at.to_string(),
            window_seconds: None,
            source_metric: name.into(),
            profile_id: "test".into(),
            profile_revision: "1".into(),
            attributes: BTreeMap::new(),
        }
    }
    #[test]
    fn counter_rate_needs_two_samples_and_rejects_resets_epoch_changes_and_gaps() {
        let mut store = Store::new("d1".into(), 5);
        let push = |store: &mut Store, value, at| {
            store.ingest(
                vec![observation(
                    "interface.receive.bytes",
                    "1",
                    value,
                    at,
                    "cumulative_counter",
                    "By",
                )],
                at,
                0,
                0,
            )
        };
        push(&mut store, 100., 10_000_000_000);
        assert!(
            store
                .data
                .latest_series("interface.receive.bits_per_second")
                .is_none()
        );
        push(&mut store, 200., 15_000_000_000);
        let rate = || ("interface.receive.bits_per_second".into(), "1".into());
        assert_eq!(
            store.data.series[&rate()].points.back().unwrap().value,
            160.
        );
        push(&mut store, 2., 20_000_000_000); // reset: no negative/fictional rate
        assert_eq!(store.data.series[&rate()].points.len(), 1);
        push(&mut store, 102., 40_000_000_000); // gap: new baseline
        assert_eq!(store.data.series[&rate()].points.len(), 1);
        let mut next = observation(
            "interface.receive.bytes",
            "1",
            202.,
            45_000_000_000,
            "cumulative_counter",
            "By",
        );
        next.start_time_unix_nano = "123".into();
        store.ingest(vec![next], 45_000_000_000, 0, 0);
        assert_eq!(store.data.series[&rate()].points.len(), 1);
        push(&mut store, 1000., 10_000_000_000); // old delivery must not rewind state
        assert_eq!(
            numeric(&store.data.series[&("interface.receive.bytes".into(), "1".into())].latest),
            Some(202.)
        );
    }
    #[test]
    fn integer_counter_precision_and_aggregate_rates_survive_large_totals() {
        let mut store = Store::new("d1".into(), 5);
        for (at, base) in [
            (10_000_000_000, 9_007_199_254_740_992_i64),
            (15_000_000_000, 9_007_199_254_740_993_i64),
        ] {
            let mut observations = Vec::new();
            for entity in ["1", "2"] {
                let mut observation = observation(
                    "interface.receive.bytes",
                    entity,
                    0.,
                    at,
                    "cumulative_counter",
                    "By",
                );
                observation.value = Value::Integer(base);
                observations.push(observation);
            }
            store.ingest(observations, at, 0, 0);
        }
        assert_eq!(
            store.data.traffic("interface.receive.bits_per_second", 0),
            vec![Point {
                at: 15_000_000_000,
                value: 3.2
            }]
        );
    }

    #[test]
    fn memory_joins_only_matching_pool_and_timestamp_and_retries_do_not_duplicate() {
        let mut store = Store::new("d1".into(), 5);
        let used = observation("device.memory.used", "pool-a", 60., 10, "gauge", "By");
        let free = observation("device.memory.free", "pool-b", 40., 10, "gauge", "By");
        store.ingest(vec![used.clone(), free], 10, 0, 0);
        assert!(
            store
                .data
                .latest_series("device.memory.utilization")
                .is_none()
        );
        let free = observation("device.memory.free", "pool-a", 40., 11, "gauge", "By");
        store.ingest(vec![free], 11, 0, 0);
        assert!(
            store
                .data
                .latest_series("device.memory.utilization")
                .is_none()
        );
        let mut used = used;
        used.observed_at_unix_nano = "11".into();
        store.ingest(vec![used.clone()], 11, 0, 0);
        assert_eq!(
            numeric(
                &store
                    .data
                    .latest_series("device.memory.utilization")
                    .unwrap()
                    .latest
            ),
            Some(0.6)
        );
        store.ingest(vec![used], 12, 0, 0);
        assert_eq!(
            store
                .data
                .latest_series("device.memory.utilization")
                .unwrap()
                .points
                .len(),
            1
        );
    }
    #[test]
    fn freshness_is_separate_from_data_and_unknown_or_failed_scrapes_cannot_be_healthy() {
        let mut store = Store::new("d1".into(), 5);
        assert!(!store.data.is_fresh(10, 5));
        store.ingest(
            vec![observation(
                "collection.scrape.up",
                "system",
                1.,
                10,
                "gauge",
                "1",
            )],
            10,
            0,
            0,
        );
        assert!(store.data.is_fresh(10, 5));
        assert!(!store.data.is_fresh(20_000_000_000, 5));
        store.ingest(
            vec![observation(
                "collection.scrape.up",
                "system",
                0.,
                20,
                "gauge",
                "1",
            )],
            20,
            0,
            0,
        );
        assert_eq!(store.data.scrape_state(20, 5), "Device scrape failed");
        assert!(!store.data.is_fresh(20, 5));
        store.ingest(
            vec![observation(
                "collection.scrape.up",
                "system",
                0.5,
                21,
                "gauge",
                "1",
            )],
            21,
            0,
            0,
        );
        assert!(!store.data.is_fresh(21, 5));
    }
    #[test]
    fn histories_are_bounded_and_cross_device_or_future_data_is_rejected() {
        let mut store = Store::new("d1".into(), 2);
        for n in 1..=(MAX_POINTS + 25) as u64 {
            store.ingest(
                vec![observation(
                    "device.cpu.utilization",
                    "0",
                    0.2,
                    n,
                    "gauge",
                    "1",
                )],
                n,
                0,
                0,
            );
        }
        assert_eq!(
            store
                .data
                .latest_series("device.cpu.utilization")
                .unwrap()
                .points
                .len(),
            MAX_POINTS
        );
        let mut other = observation("device.cpu.utilization", "0", 0.9, 999, "gauge", "1");
        other.device_id = "other".into();
        store.ingest(
            vec![
                other,
                observation(
                    "device.cpu.utilization",
                    "0",
                    0.9,
                    100_000_000_000,
                    "gauge",
                    "1",
                ),
            ],
            1000,
            0,
            0,
        );
        assert_eq!(store.data.rejected, 2);
        assert_eq!(
            numeric(
                &store
                    .data
                    .latest_series("device.cpu.utilization")
                    .unwrap()
                    .latest
            ),
            Some(0.2)
        );
        assert_eq!(
            statistics(&[Point { at: 1, value: 0.2 }, Point { at: 2, value: 0.8 }])
                .unwrap()
                .sample_mean,
            0.5
        );
    }
    #[test]
    fn total_and_free_derive_used_and_ratio_only_for_coherent_memory_readings() {
        let total = observation("device.memory.total", "processor", 100., 10, "gauge", "By");
        let free = observation("device.memory.free", "processor", 40., 10, "gauge", "By");
        let mut store = Store::new("d1".into(), 2);
        store.ingest(vec![total.clone(), free.clone()], 10_000_000_000, 0, 0);
        let used = store.data.latest_series("device.memory.used").unwrap();
        assert_eq!(numeric(&used.latest), Some(60.));
        assert_eq!(
            used.latest
                .attributes
                .get("calculation")
                .map(String::as_str),
            Some("total_minus_free")
        );
        assert_eq!(
            numeric(
                &store
                    .data
                    .latest_series("device.memory.utilization")
                    .unwrap()
                    .latest
            ),
            Some(0.6)
        );
        store.ingest(vec![total.clone(), free.clone()], 10_000_000_000, 0, 0);
        assert_eq!(
            store
                .data
                .latest_series("device.memory.utilization")
                .unwrap()
                .points
                .len(),
            1
        );
        let mut excessive = free.clone();
        excessive.value = Value::Number(101.);
        let mut invalid_store = Store::new("d1".into(), 2);
        invalid_store.ingest(vec![total.clone(), excessive], 10_000_000_000, 0, 0);
        assert!(
            invalid_store
                .data
                .latest_series("device.memory.used")
                .is_none()
        );
        let mut wrong_pool = free.clone();
        wrong_pool.entity_id = "io".into();
        let mut wrong_time = free.clone();
        wrong_time.observed_at_unix_nano = "11000000000".into();
        let mut wrong_unit = free.clone();
        wrong_unit.unit = "KiB".into();
        let mut wrong_kind = free.clone();
        wrong_kind.kind = "cumulative_counter".into();
        let mut negative = free.clone();
        negative.value = Value::Number(-1.);
        for invalid in [wrong_pool, wrong_time, wrong_unit, wrong_kind, negative] {
            let mut store = Store::new("d1".into(), 2);
            store.ingest(vec![total.clone(), invalid], 11_000_000_000, 0, 0);
            assert!(store.data.latest_series("device.memory.used").is_none());
            assert!(
                store
                    .data
                    .latest_series("device.memory.utilization")
                    .is_none()
            );
        }
        let mut direct = Store::new("d1".into(), 2);
        direct.ingest(
            vec![
                total,
                free,
                observation("device.memory.used", "processor", 10., 10, "gauge", "By"),
            ],
            10_000_000_000,
            0,
            0,
        );
        assert_eq!(
            numeric(
                &direct
                    .data
                    .latest_series("device.memory.used")
                    .unwrap()
                    .latest
            ),
            Some(10.)
        );
        assert_eq!(
            numeric(
                &direct
                    .data
                    .latest_series("device.memory.utilization")
                    .unwrap()
                    .latest
            ),
            Some(0.2)
        );
    }
}
