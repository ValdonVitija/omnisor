use opentelemetry_proto::tonic::{
    metrics::v1::{
        AggregationTemporality, Gauge, Histogram, HistogramDataPoint, Metric, NumberDataPoint,
        ResourceMetrics, ScopeMetrics, Sum, metric, number_data_point,
    },
    resource::v1::Resource,
};
use telemetry::{
    Configuration, ExportMetricsServiceRequest, Value, findings, normalize, string_attribute,
};

fn config() -> Configuration {
    let config: Configuration =
        serde_json::from_str(include_str!("../../../examples/telemetry/profiles.json")).unwrap();
    config.validate().unwrap();
    config
}

fn gauge(name: &str, value: f64, labels: &[(&str, &str)]) -> Metric {
    Metric {
        name: name.into(),
        data: Some(metric::Data::Gauge(Gauge {
            data_points: vec![NumberDataPoint {
                attributes: labels.iter().map(|(k, v)| string_attribute(k, v)).collect(),
                time_unix_nano: 1_800_000_000_000_000_000,
                value: Some(number_data_point::Value::AsDouble(value)),
                ..Default::default()
            }],
        })),
        ..Default::default()
    }
}

fn request(device: &str, metrics: Vec<Metric>) -> ExportMetricsServiceRequest {
    ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: vec![
                    string_attribute("device_id", device),
                    string_attribute("tenant_id", "spoofed"),
                ],
                ..Default::default()
            }),
            scope_metrics: vec![ScopeMetrics {
                metrics,
                ..Default::default()
            }],
            ..Default::default()
        }],
    }
}

#[test]
fn different_exporter_schemas_produce_the_same_semantics_with_trusted_tenant() {
    for (device, source, label, window) in [
        (
            "lab-ios-01",
            "cpmCPUTotal1minRev",
            "cpmCPUTotalIndex",
            Some(60),
        ),
        ("lab-router-02", "oc_cpu_utilization_percent", "cpu", None),
    ] {
        let result = normalize(
            &request(device, vec![gauge(source, 96.0, &[(label, "1")])]),
            &config(),
            "authenticated-tenant",
            123,
        );
        assert!(result.rejected.is_empty());
        let observation = &result.observations[0];
        assert_eq!(observation.tenant_id, "authenticated-tenant");
        assert_eq!(observation.name, "device.cpu.utilization");
        assert_eq!(observation.value, Value::Number(0.96));
        assert_eq!(observation.window_seconds, window);
        assert_eq!(observation.source_metric, source);
        assert_eq!(observation.profile_revision, "1");
        assert_eq!(findings(&result.observations)[0].severity, "critical");
    }
}

#[test]
fn rejects_unenrolled_devices_disabled_profiles_and_missing_entities() {
    let req = request(
        "unknown",
        vec![gauge("ifOperStatus", 1.0, &[("ifName", "eth0")])],
    );
    assert_eq!(
        normalize(&req, &config(), "tenant", 123).rejected[0].reason,
        "device is not enrolled"
    );
    let mut disabled = config();
    disabled.profiles.get_mut("ios-snmp").unwrap().enabled = false;
    let req = request(
        "lab-ios-01",
        vec![gauge("ifOperStatus", 1.0, &[("ifName", "eth0")])],
    );
    assert_eq!(
        normalize(&req, &disabled, "tenant", 123).rejected[0].reason,
        "profile is disabled"
    );
    let req = request("lab-ios-01", vec![gauge("ifOperStatus", 1.0, &[])]);
    assert_eq!(
        normalize(&req, &config(), "tenant", 123).rejected[0].reason,
        "missing entity label"
    );
}

#[test]
fn invalid_and_unavailable_values_never_become_healthy_zeroes() {
    for value in [f64::NAN, f64::INFINITY, -1.0, 101.0] {
        let result = normalize(
            &request(
                "lab-ios-01",
                vec![gauge(
                    "cpmCPUTotal1minRev",
                    value,
                    &[("cpmCPUTotalIndex", "1")],
                )],
            ),
            &config(),
            "tenant",
            123,
        );
        assert!(result.observations.is_empty());
        assert_eq!(result.rejected.len(), 1);
    }
    let mut metric = gauge("ifOperStatus", 0.0, &[("ifName", "eth0")]);
    if let Some(metric::Data::Gauge(gauge)) = &mut metric.data {
        gauge.data_points[0].flags = 1;
    }
    let result = normalize(
        &request("lab-ios-01", vec![metric]),
        &config(),
        "tenant",
        123,
    );
    assert_eq!(result.rejected[0].reason, "source marked value unavailable");
    for value in [0.0, 1.5, 8.0] {
        assert_eq!(
            normalize(
                &request(
                    "lab-ios-01",
                    vec![gauge("ifOperStatus", value, &[("ifName", "eth0")])]
                ),
                &config(),
                "tenant",
                123
            )
            .rejected
            .len(),
            1
        );
    }
}

#[test]
fn distinguishes_admin_down_from_fault_and_preserves_extended_states() {
    for (admin, oper, state, count) in [
        (1.0, 2.0, "down", 1),
        (2.0, 2.0, "down", 0),
        (1.0, 7.0, "lower_layer_down", 0),
    ] {
        let result = normalize(
            &request(
                "lab-ios-01",
                vec![
                    gauge("ifAdminStatus", admin, &[("ifName", "eth0")]),
                    gauge("ifOperStatus", oper, &[("ifName", "eth0")]),
                ],
            ),
            &config(),
            "tenant",
            123,
        );
        assert_eq!(result.observations[1].value, Value::State(state.into()));
        assert_eq!(findings(&result.observations).len(), count);
    }
}

#[test]
fn preserves_counter_temporality_start_time_and_integer_precision() {
    let integer = 9_007_199_254_740_993;
    let metric = Metric {
        name: "ifHCInOctets".into(),
        data: Some(metric::Data::Sum(Sum {
            is_monotonic: true,
            aggregation_temporality: AggregationTemporality::Cumulative as i32,
            data_points: vec![NumberDataPoint {
                attributes: vec![string_attribute("ifName", "eth0")],
                start_time_unix_nano: 100,
                time_unix_nano: 200,
                value: Some(number_data_point::Value::AsInt(integer)),
                ..Default::default()
            }],
        })),
        ..Default::default()
    };
    let result = normalize(
        &request("lab-ios-01", vec![metric.clone()]),
        &config(),
        "tenant",
        123,
    );
    let observation = &result.observations[0];
    assert_eq!(observation.value, Value::Integer(integer));
    assert_eq!(observation.kind, "cumulative_counter");
    assert_eq!(observation.start_time_unix_nano, "100");
    let mut delta = metric;
    if let Some(metric::Data::Sum(sum)) = &mut delta.data {
        sum.aggregation_temporality = AggregationTemporality::Delta as i32;
    }
    assert_eq!(
        normalize(
            &request("lab-ios-01", vec![delta]),
            &config(),
            "tenant",
            123
        )
        .rejected
        .len(),
        1
    );
    let wrong_kind = gauge("ifHCInOctets", 100.0, &[("ifName", "eth0")]);
    assert_eq!(
        normalize(
            &request("lab-ios-01", vec![wrong_kind]),
            &config(),
            "tenant",
            123
        )
        .rejected[0]
            .reason,
        "metric kind does not match profile"
    );
}

#[test]
fn rejects_unsupported_histogram_points_and_ignores_unmapped_gauges() {
    let histogram = Metric {
        name: "histogram".into(),
        data: Some(metric::Data::Histogram(Histogram {
            data_points: vec![HistogramDataPoint::default(), HistogramDataPoint::default()],
            ..Default::default()
        })),
        ..Default::default()
    };
    let result = normalize(
        &request("lab-ios-01", vec![histogram, gauge("up", 1.0, &[])]),
        &config(),
        "tenant",
        123,
    );
    assert_eq!(result.rejected.len(), 2);
    assert_eq!(result.ignored_points, 1);
}

#[test]
fn memory_rules_require_matching_pool_and_collection_timestamp() {
    let used = gauge(
        "ciscoMemoryPoolUsed",
        96.0,
        &[("ciscoMemoryPoolName", "Processor")],
    );
    let free = gauge(
        "ciscoMemoryPoolFree",
        4.0,
        &[("ciscoMemoryPoolName", "Processor")],
    );
    let result = normalize(
        &request("lab-ios-01", vec![used.clone(), free.clone()]),
        &config(),
        "tenant",
        123,
    );
    assert_eq!(findings(&result.observations)[0].severity, "critical");
    let result = normalize(
        &request("lab-ios-01", vec![used.clone()]),
        &config(),
        "tenant",
        123,
    );
    assert!(findings(&result.observations).is_empty());
    let mut result = normalize(
        &request("lab-ios-01", vec![used, free]),
        &config(),
        "tenant",
        123,
    );
    result.observations[1].observed_at_unix_nano = "different".into();
    assert!(findings(&result.observations).is_empty());
}
