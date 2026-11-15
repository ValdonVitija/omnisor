//! A device-scoped snapshot derived from evidence, independently of GPUI.
//! Use the latest reading per series; never join memory or interface states
//! from different timestamps. Missing data is not a zero or a healthy state.

use std::collections::{BTreeMap, BTreeSet};

use omnisor_telemetry::{Observation, Value};

#[derive(Debug, PartialEq)]
pub struct Utilization {
    pub ratio: f64,
    pub entity: String,
    pub window_seconds: Option<u64>,
}

#[derive(Debug, Default, PartialEq)]
pub struct InterfaceSummary {
    pub total: usize,
    pub up: usize,
    pub down: usize,
    pub admin_down: usize,
    pub unknown: usize,
}

#[derive(Debug, Default, PartialEq)]
pub struct HealthSummary {
    pub cpu: Option<Utilization>,
    pub memory: Option<Utilization>,
    pub interfaces: InterfaceSummary,
    pub observation_count: usize,
}

impl HealthSummary {
    pub fn for_device(observations: &[Observation], device: &str) -> Self {
        let mut result = Self::default();
        let mut latest: BTreeMap<(&str, &str), (&Observation, u64)> = BTreeMap::new();
        let mut interfaces = BTreeSet::new();
        for observation in observations.iter().filter(|o| o.device_id == device) {
            result.observation_count += 1;
            let Ok(timestamp) = observation.observed_at_unix_nano.parse::<u64>() else {
                continue;
            };
            if observation.name.starts_with("interface.") {
                interfaces.insert(observation.entity_id.as_str());
            }
            let entry = latest
                .entry((observation.entity_id.as_str(), observation.name.as_str()))
                .or_insert((observation, timestamp));
            if timestamp > entry.1 {
                *entry = (observation, timestamp);
            }
        }
        for (&(entity, name), &(observation, timestamp)) in &latest {
            if name == "device.cpu.utilization"
                && observation.unit == "1"
                && observation.kind == "gauge"
            {
                if let Some(ratio) = number(observation).filter(|v| (0.0..=1.0).contains(v)) {
                    keep_highest(&mut result.cpu, ratio, entity, observation.window_seconds);
                }
            } else if name == "device.memory.used"
                && observation.unit == "By"
                && observation.kind == "gauge"
            {
                let Some(&(free, free_timestamp)) = latest.get(&(entity, "device.memory.free"))
                else {
                    continue;
                };
                if timestamp != free_timestamp || free.unit != "By" || free.kind != "gauge" {
                    continue;
                }
                if let (Some(used), Some(free)) = (number(observation), number(free)) {
                    let total = used + free;
                    if used >= 0.0 && free >= 0.0 && total.is_finite() && total > 0.0 {
                        keep_highest(&mut result.memory, used / total, entity, None);
                    }
                }
            }
        }
        result.interfaces.total = interfaces.len();
        for entity in interfaces {
            let admin = latest.get(&(entity, "interface.admin_status"));
            let oper = latest.get(&(entity, "interface.oper_status"));
            match (admin, oper) {
                (Some((admin, at)), Some((oper, ot))) if at == ot => {
                    match (state(admin), state(oper)) {
                        (Some("down"), _) => result.interfaces.admin_down += 1,
                        (Some("up"), Some("up")) => result.interfaces.up += 1,
                        (Some("up"), Some("down" | "lower_layer_down")) => {
                            result.interfaces.down += 1;
                        }
                        _ => result.interfaces.unknown += 1,
                    }
                }
                _ => result.interfaces.unknown += 1,
            }
        }
        result
    }
}

fn number(observation: &Observation) -> Option<f64> {
    let value = match observation.value {
        Value::Integer(value) => value as f64,
        Value::Number(value) => value,
        Value::State(_) => return None,
    };
    value.is_finite().then_some(value)
}

fn state(observation: &Observation) -> Option<&str> {
    match &observation.value {
        Value::State(value) => Some(value),
        _ => None,
    }
}

fn keep_highest(target: &mut Option<Utilization>, ratio: f64, entity: &str, window: Option<u64>) {
    if target.as_ref().is_none_or(|current| ratio > current.ratio) {
        *target = Some(Utilization {
            ratio,
            entity: entity.into(),
            window_seconds: window,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BUNDLED_CAPTURE, Capture};

    #[test]
    fn recorded_snapshot_separates_disabled_interfaces_from_faults() {
        let capture = Capture::from_json(BUNDLED_CAPTURE).unwrap();
        let summary = HealthSummary::for_device(&capture.observations, "lab-ios-01");
        assert_eq!(summary.cpu.unwrap().ratio, 0.96);
        assert_eq!(summary.memory.unwrap().ratio, 0.96);
        assert_eq!(
            summary.interfaces,
            InterfaceSummary {
                total: 2,
                up: 0,
                down: 1,
                admin_down: 1,
                unknown: 0,
            }
        );
        assert_eq!(summary.observation_count, 8);
        assert_eq!(
            HealthSummary::for_device(&capture.observations, "absent"),
            HealthSummary::default()
        );
    }

    #[test]
    fn memory_requires_matching_pool_and_timestamp_and_missing_cpu_stays_unknown() {
        let mut capture = Capture::from_json(BUNDLED_CAPTURE).unwrap();
        capture
            .observations
            .retain(|o| o.name != "device.cpu.utilization");
        let timestamp = capture
            .observations
            .iter()
            .find(|o| o.name == "device.memory.used")
            .unwrap()
            .observed_at_unix_nano
            .clone();
        let free = capture
            .observations
            .iter_mut()
            .find(|o| o.name == "device.memory.free")
            .unwrap();
        free.observed_at_unix_nano = "1".into();
        let summary = HealthSummary::for_device(&capture.observations, "lab-ios-01");
        assert!(summary.cpu.is_none());
        assert!(summary.memory.is_none());
        let free = capture
            .observations
            .iter_mut()
            .find(|o| o.name == "device.memory.free")
            .unwrap();
        free.observed_at_unix_nano = timestamp;
        free.entity_id = "another-pool".into();
        assert!(
            HealthSummary::for_device(&capture.observations, "lab-ios-01")
                .memory
                .is_none()
        );
    }

    #[test]
    fn latest_reading_wins_and_unmatched_interface_timestamps_stay_unknown() {
        let mut capture = Capture::from_json(BUNDLED_CAPTURE).unwrap();
        let mut cpu = capture
            .observations
            .iter()
            .find(|o| o.name == "device.cpu.utilization")
            .unwrap()
            .clone();
        cpu.value = Value::Number(0.2);
        cpu.observed_at_unix_nano =
            (cpu.observed_at_unix_nano.parse::<u64>().unwrap() + 1).to_string();
        capture.observations.push(cpu);
        let oper = capture
            .observations
            .iter_mut()
            .find(|o| o.name == "interface.oper_status")
            .unwrap();
        oper.observed_at_unix_nano = "1".into();
        let summary = HealthSummary::for_device(&capture.observations, "lab-ios-01");
        assert_eq!(summary.cpu.unwrap().ratio, 0.2);
        assert_eq!(summary.interfaces.unknown, 1);
        assert_eq!(summary.interfaces.down, 0);
    }
}
