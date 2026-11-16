//! Transport-independent normalization of OTLP measurements using device profiles.
//! Tenant identity and device/profile assignments come from trusted configuration.

use std::collections::BTreeMap;

pub use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::{
    common::v1::{AnyValue, KeyValue, any_value},
    metrics::v1::{AggregationTemporality, metric, number_data_point},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub devices: BTreeMap<String, Device>,
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub profile: String,
    pub vendor: String,
    pub os: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub revision: String,
    pub enabled: bool,
    pub mappings: BTreeMap<String, Mapping>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    pub name: String,
    pub unit: String,
    pub conversion: Conversion,
    pub kind: MetricKind,
    pub entity_label: Option<String>,
    pub window_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    Gauge,
    CumulativeCounter,
}

impl MetricKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Gauge => "gauge",
            Self::CumulativeCounter => "cumulative_counter",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Conversion {
    Identity,
    Ratio,
    PercentToRatio,
    AdminState,
    OperState,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid telemetry configuration: {0}")]
pub struct ConfigurationError(String);

impl Configuration {
    pub fn validate(&self) -> Result<(), ConfigurationError> {
        for (id, device) in &self.devices {
            if id.is_empty() || !self.profiles.contains_key(&device.profile) {
                return Err(ConfigurationError(format!(
                    "device {id:?} has no matching profile"
                )));
            }
        }
        for (id, profile) in &self.profiles {
            if id.is_empty() || profile.revision.is_empty() || profile.mappings.is_empty() {
                return Err(ConfigurationError(format!("profile {id:?} is incomplete")));
            }
            for mapping in profile.mappings.values() {
                if mapping.name.is_empty() || mapping.unit.is_empty() {
                    return Err(ConfigurationError(format!(
                        "profile {id:?} has an empty name/unit"
                    )));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Value {
    Integer(i64),
    Number(f64),
    State(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub tenant_id: String,
    pub device_id: String,
    pub entity_id: String,
    pub name: String,
    pub value: Value,
    pub unit: String,
    pub kind: String,
    // Strings preserve nanosecond precision when inspected in JavaScript.
    pub observed_at_unix_nano: String,
    pub start_time_unix_nano: String,
    pub received_at_unix_nano: String,
    pub window_seconds: Option<u64>,
    pub source_metric: String,
    pub profile_id: String,
    pub profile_revision: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Rejection {
    pub source_metric: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct NormalizedBatch {
    pub observations: Vec<Observation>,
    pub rejected: Vec<Rejection>,
    pub ignored_points: usize,
}

fn attributes(values: &[KeyValue]) -> BTreeMap<String, String> {
    values
        .iter()
        .filter_map(|entry| {
            let value = match entry.value.as_ref()?.value.as_ref()? {
                any_value::Value::StringValue(value) => value.clone(),
                any_value::Value::IntValue(value) => value.to_string(),
                any_value::Value::BoolValue(value) => value.to_string(),
                _ => return None,
            };
            Some((entry.key.clone(), value))
        })
        .collect()
}

/// Normalize a batch without network calls or persistence. The caller supplies
/// authenticated tenant context; payload tenant attributes never select it.
pub fn normalize(
    request: &ExportMetricsServiceRequest,
    config: &Configuration,
    tenant_id: &str,
    received_at: u64,
) -> NormalizedBatch {
    let mut batch = NormalizedBatch::default();
    for resource in &request.resource_metrics {
        let resource_attrs = resource
            .resource
            .as_ref()
            .map(|resource| attributes(&resource.attributes))
            .unwrap_or_default();
        for scope in &resource.scope_metrics {
            for metric in &scope.metrics {
                let (points, kind) = match &metric.data {
                    Some(metric::Data::Gauge(gauge)) => (&gauge.data_points, "gauge"),
                    Some(metric::Data::Sum(sum))
                        if sum.is_monotonic
                            && sum.aggregation_temporality
                                == AggregationTemporality::Cumulative as i32 =>
                    {
                        (&sum.data_points, "cumulative_counter")
                    }
                    unsupported => {
                        let count = match unsupported {
                            Some(metric::Data::Sum(value)) => value.data_points.len(),
                            Some(metric::Data::Histogram(value)) => value.data_points.len(),
                            Some(metric::Data::ExponentialHistogram(value)) => {
                                value.data_points.len()
                            }
                            Some(metric::Data::Summary(value)) => value.data_points.len(),
                            _ => 0,
                        };
                        for _ in 0..count {
                            batch.rejected.push(Rejection { source_metric: metric.name.clone(), reason: "only gauges and cumulative monotonic sums are supported in this slice".into() });
                        }
                        continue;
                    }
                };
                for point in points {
                    let mut attrs = resource_attrs.clone();
                    attrs.extend(attributes(&point.attributes));
                    let result = (|| {
                        let device_id = attrs.get("device_id").ok_or("missing device_id")?;
                        let device = config
                            .devices
                            .get(device_id)
                            .ok_or("device is not enrolled")?;
                        let profile = config
                            .profiles
                            .get(&device.profile)
                            .ok_or("missing profile")?;
                        if !profile.enabled {
                            return Err("profile is disabled");
                        }
                        let Some(mapping) = profile.mappings.get(&metric.name) else {
                            return Ok(None);
                        };
                        if mapping.kind.as_str() != kind {
                            return Err("metric kind does not match profile");
                        }
                        if point.flags & 1 != 0 {
                            return Err("source marked value unavailable");
                        }
                        if point.time_unix_nano == 0 {
                            return Err("missing observation timestamp");
                        }
                        let number = match point.value {
                            Some(number_data_point::Value::AsDouble(value)) => value,
                            Some(number_data_point::Value::AsInt(value)) => value as f64,
                            None => return Err("missing numeric value"),
                        };
                        if !number.is_finite() || number < 0.0 {
                            return Err("invalid negative or non-finite value");
                        }
                        let value = match mapping.conversion {
                            Conversion::Ratio if number <= 1.0 => Value::Number(number),
                            Conversion::Ratio => return Err("ratio outside 0..1"),
                            Conversion::Identity => match point.value {
                                Some(number_data_point::Value::AsInt(value)) => {
                                    Value::Integer(value)
                                }
                                _ => Value::Number(number),
                            },
                            Conversion::PercentToRatio if number <= 100.0 => {
                                Value::Number(number / 100.0)
                            }
                            Conversion::PercentToRatio => return Err("percentage outside 0..100"),
                            Conversion::AdminState | Conversion::OperState => {
                                let states: &[&str] = match mapping.conversion {
                                    Conversion::AdminState => &["up", "down", "testing"],
                                    _ => &[
                                        "up",
                                        "down",
                                        "testing",
                                        "unknown",
                                        "dormant",
                                        "not_present",
                                        "lower_layer_down",
                                    ],
                                };
                                if number.fract() != 0.0
                                    || number < 1.0
                                    || number > states.len() as f64
                                {
                                    return Err("unrecognized interface state");
                                }
                                Value::State(states[number as usize - 1].into())
                            }
                        };
                        let entity_id = match &mapping.entity_label {
                            Some(label) => attrs
                                .get(label)
                                .filter(|value| !value.is_empty())
                                .ok_or("missing entity label")?
                                .clone(),
                            None => "system".into(),
                        };
                        Ok(Some(Observation {
                            tenant_id: tenant_id.into(),
                            device_id: device_id.clone(),
                            entity_id,
                            name: mapping.name.clone(),
                            value,
                            unit: mapping.unit.clone(),
                            kind: kind.into(),
                            observed_at_unix_nano: point.time_unix_nano.to_string(),
                            start_time_unix_nano: point.start_time_unix_nano.to_string(),
                            received_at_unix_nano: received_at.to_string(),
                            window_seconds: mapping.window_seconds,
                            source_metric: metric.name.clone(),
                            profile_id: device.profile.clone(),
                            profile_revision: profile.revision.clone(),
                            attributes: attrs,
                        }))
                    })();
                    match result {
                        Ok(Some(observation)) => batch.observations.push(observation),
                        Ok(None) => batch.ignored_points += 1,
                        Err(reason) => batch.rejected.push(Rejection {
                            source_metric: metric.name.clone(),
                            reason: reason.into(),
                        }),
                    }
                }
            }
        }
    }
    batch
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub device_id: String,
    pub entity_id: String,
    pub severity: &'static str,
    pub message: String,
}

/// Evaluate only this collection's readings. Missing/stale data cannot resolve a
/// finding; the workspace state engine will own that lifecycle.
pub fn findings(observations: &[Observation]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let index: BTreeMap<_, _> = observations
        .iter()
        .map(|observation| {
            (
                (
                    observation.device_id.as_str(),
                    observation.entity_id.as_str(),
                    observation.name.as_str(),
                    observation.observed_at_unix_nano.as_str(),
                ),
                observation,
            )
        })
        .collect();
    for observation in observations {
        if observation.name == "device.memory.used"
            && let Some(free) = index.get(&(
                observation.device_id.as_str(),
                observation.entity_id.as_str(),
                "device.memory.free",
                observation.observed_at_unix_nano.as_str(),
            ))
        {
            let numeric = |value: &Value| match value {
                Value::Number(value) => Some(*value),
                Value::Integer(value) => Some(*value as f64),
                _ => None,
            };
            if let (Some(used), Some(free)) = (numeric(&observation.value), numeric(&free.value)) {
                let ratio = used / (used + free);
                if ratio.is_finite() && ratio >= 0.85 {
                    findings.push(Finding {
                        device_id: observation.device_id.clone(),
                        entity_id: observation.entity_id.clone(),
                        severity: if ratio >= 0.95 { "critical" } else { "warning" },
                        message: format!(
                            "Memory pool utilization is {:.1}% (used / (used + free))",
                            ratio * 100.0
                        ),
                    });
                }
            }
        }
        if observation.name == "device.cpu.utilization"
            && let Value::Number(value) = observation.value
            && value >= 0.8
        {
            findings.push(Finding {
                device_id: observation.device_id.clone(),
                entity_id: observation.entity_id.clone(),
                severity: if value >= 0.9 { "critical" } else { "warning" },
                message: format!(
                    "CPU utilization is {:.1}% (averaging window: {})",
                    value * 100.0,
                    observation
                        .window_seconds
                        .map(|seconds| format!("{seconds}s"))
                        .unwrap_or_else(|| "unspecified by source".into())
                ),
            });
        }
        if observation.name == "interface.oper_status"
            && observation.value == Value::State("down".into())
        {
            let admin_up = index
                .get(&(
                    observation.device_id.as_str(),
                    observation.entity_id.as_str(),
                    "interface.admin_status",
                    observation.observed_at_unix_nano.as_str(),
                ))
                .is_some_and(|other| other.value == Value::State("up".into()));
            if admin_up {
                findings.push(Finding {
                    device_id: observation.device_id.clone(),
                    entity_id: observation.entity_id.clone(),
                    severity: "warning",
                    message: "Interface is administratively up but operationally down".into(),
                });
            }
        }
    }
    findings
}

/// Convenience for tests and adapters building OTLP messages.
pub fn string_attribute(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.into())),
        }),
    }
}
