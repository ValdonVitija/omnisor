use omnisor_collection::{Catalog, CollectionPlan, DeviceIdentity, Phase, Session, Source};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

fn plan(collector: PathBuf) -> CollectionPlan {
    CollectionPlan {
        device: DeviceIdentity {
            id: "test-device".into(),
            name: "Pipeline test".into(),
            vendor: "Omnisor lab".into(),
            ..Default::default()
        },
        profile_id: "synthetic".into(),
        interval_seconds: 2,
        collector,
        source: Source::Synthetic,
    }
}

#[test]
fn yaml_is_structured_and_source_tokens_are_environment_references() {
    let catalog = Catalog::bundled().unwrap();
    let mut plan = plan(std::env::current_exe().unwrap());
    plan.profile_id = "native-prometheus".into();
    plan.source = Source::Prometheus {
        endpoint: "https://router.example/metrics/$literal?target=device%3A161&module=system&module=if_mib&filter=%24literal".into(),
        bearer_token: "do-not-write-this".into(),
    };
    plan.validate(&catalog).unwrap();
    let yaml = plan
        .collector_yaml(&catalog, "127.0.0.1:4455", None)
        .unwrap();
    assert!(!yaml.contains("do-not-write-this"));
    assert!(yaml.contains("OMNISOR_SOURCE_TOKEN"));
    assert!(yaml.contains("$$literal"));
    let value: serde_json::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    let job = &value["receivers"]["prometheus/device"]["config"]["scrape_configs"][0];
    assert_eq!(job["honor_labels"], false);
    assert_eq!(job["scheme"], "https");
    assert_eq!(job["metrics_path"], "/metrics/$$literal");
    assert_eq!(job["params"]["target"], serde_json::json!(["device:161"]));
    assert_eq!(
        job["params"]["module"],
        serde_json::json!(["system", "if_mib"])
    );
    assert_eq!(job["params"]["filter"], serde_json::json!(["$$literal"]));
    plan.source = Source::Prometheus {
        endpoint: "http://localhost/metrics?community=secret".into(),
        bearer_token: String::new(),
    };
    assert!(plan.validate(&catalog).is_err());
    plan.source = Source::Prometheus {
        endpoint: "https://user:password@router/metrics".into(),
        bearer_token: String::new(),
    };
    assert!(plan.validate(&catalog).is_err());
    plan.profile_id = "nonexistent".into();
    assert!(plan.validate(&catalog).is_err());
}

#[test]
#[ignore = "requires OMNISOR_TEST_COLLECTOR pointing to otelcol-contrib 0.140.0 and loopback networking"]
fn real_collector_pipeline_and_stop_reap_processes() {
    let session = Session::start(plan(
        std::env::var_os("OMNISOR_TEST_COLLECTOR")
            .expect("set OMNISOR_TEST_COLLECTOR")
            .into(),
    ))
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let initial_address;
    loop {
        let snapshot = session.snapshot();
        assert_ne!(snapshot.phase, Phase::Failed, "{:?}", snapshot.error);
        if snapshot.metrics.sequence >= 3
            && snapshot
                .metrics
                .latest_series("interface.receive.bits_per_second")
                .is_some()
        {
            assert!(
                snapshot
                    .metrics
                    .is_fresh(omnisor_collection::unix_nanos(), 2)
            );
            assert!(
                snapshot
                    .metrics
                    .latest_series("device.memory.utilization")
                    .is_some()
            );
            assert!(
                snapshot
                    .metrics
                    .latest_series("device.cpu.utilization")
                    .unwrap()
                    .points
                    .len()
                    >= 2
            );
            assert!(!snapshot.process_ids.is_empty());
            initial_address = snapshot.receiver_address.unwrap();
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Timed out: phase={:?}, metrics={:?}",
            snapshot.phase,
            snapshot.metrics
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    session.shutdown_blocking();
    let snapshot = session.snapshot();
    assert_eq!(snapshot.phase, Phase::Stopped);
    assert!(snapshot.process_ids.is_empty());
    assert!(
        std::net::TcpStream::connect_timeout(&initial_address, Duration::from_millis(250)).is_err()
    );
}

#[test]
#[ignore = "requires OMNISOR_TEST_COLLECTOR and OMNISOR_TEST_SNMP_EXPORTER binaries and loopback networking"]
fn managed_snmp_unreachable_device_reports_failure_without_fabricated_readings() {
    use omnisor_collection::SnmpCredentials;
    let mut plan = plan(std::env::var_os("OMNISOR_TEST_COLLECTOR").unwrap().into());
    plan.profile_id = "cisco-ios-snmp".into();
    plan.source = Source::Snmp {
        target: "127.0.0.1:1".into(),
        credentials: SnmpCredentials::V2c {
            community: "test-read-only".into(),
        },
        exporter: std::env::var_os("OMNISOR_TEST_SNMP_EXPORTER")
            .unwrap()
            .into(),
    };
    let session = Session::start(plan).unwrap();
    let deadline = Instant::now() + Duration::from_secs(25);
    let directory;
    loop {
        let snapshot = session.snapshot();
        assert_ne!(
            snapshot.phase,
            Phase::Failed,
            "{:?}\n{:?}",
            snapshot.error,
            snapshot.diagnostics
        );
        if snapshot.metrics.sequence > 0 {
            assert_eq!(
                snapshot
                    .metrics
                    .scrape_state(omnisor_collection::unix_nanos(), 2),
                "Device scrape failed"
            );
            assert!(
                snapshot
                    .metrics
                    .latest_series("device.cpu.utilization")
                    .is_none()
            );
            assert!(
                snapshot
                    .metrics
                    .latest_series("device.memory.utilization")
                    .is_none()
            );
            assert_eq!(snapshot.process_ids.len(), 2);
            directory = snapshot.config_directory.clone().unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(directory.join("snmp.yaml"))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
                assert_eq!(
                    std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
            break;
        }
        assert!(Instant::now() < deadline, "No scrape outcome received");
        std::thread::sleep(Duration::from_millis(200));
    }
    session.shutdown_blocking();
    assert!(!directory.exists());
    assert_eq!(session.snapshot().phase, Phase::Stopped);
    assert!(session.snapshot().process_ids.is_empty());
}

#[test]
fn generated_snmp_modules_preserve_integer_enum_keys_and_quote_credentials() {
    use omnisor_collection::SnmpCredentials;
    let mut plan = plan(std::env::current_exe().unwrap());
    plan.profile_id = "cisco-ios-snmp".into();
    plan.source = Source::Snmp {
        target: "192.0.2.1:161".into(),
        credentials: SnmpCredentials::V2c {
            community: r#"example: "quoted" $literal"#.into(),
        },
        exporter: std::env::current_exe().unwrap(),
    };
    let yaml = plan.snmp_yaml(&Catalog::bundled().unwrap()).unwrap();
    let yaml: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    assert_eq!(
        yaml["auths"]["session"]["community"].as_str(),
        Some(r#"example: "quoted" $literal"#)
    );
    assert!(
        yaml["modules"]["if_mib"]["metrics"]
            .as_sequence()
            .unwrap()
            .iter()
            .filter_map(|m| m["enum_values"].as_mapping())
            .any(|values| values.keys().any(|key| key.as_i64().is_some()))
    );
}

#[tokio::test]
#[ignore = "requires OMNISOR_TEST_COLLECTOR and loopback networking"]
async fn direct_prometheus_endpoint_authentication_and_trusted_device_labels() {
    use axum::{
        Router,
        http::{HeaderMap, StatusCode},
        routing::get,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener,Router::new().route("/metrics",get(|headers: HeaderMap, axum::extract::RawQuery(query): axum::extract::RawQuery| async move {
            if headers.get("authorization").and_then(|h|h.to_str().ok()) != Some("Bearer external-test-token") {
                return (StatusCode::UNAUTHORIZED,[("content-type","text/plain")],String::new());
            }
            let query: Vec<_> = url::form_urlencoded::parse(query.as_deref().unwrap_or_default().as_bytes()).into_owned().collect();
            if !query.contains(&("target".into(),"device:161".into())) || !query.contains(&("filter".into(),"$literal".into())) || query.iter().filter(|(key,_)|key=="module").count()!=2 { return (StatusCode::BAD_REQUEST,[("content-type","text/plain")],String::new()); }
            (StatusCode::OK,[("content-type","text/plain; version=0.0.4")],"# TYPE omnisor_cpu_utilization_ratio gauge\nomnisor_cpu_utilization_ratio{cpu=\"0\",device_id=\"untrusted-exporter-label\"} 0.33\n".into())
        }))).await.unwrap();
    });
    let mut plan = plan(std::env::var_os("OMNISOR_TEST_COLLECTOR").unwrap().into());
    plan.profile_id = "native-prometheus".into();
    plan.source = Source::Prometheus {
        endpoint: format!(
            "http://{address}/metrics?target=device%3A161&module=system&module=if_mib&filter=%24literal"
        ),
        bearer_token: "external-test-token".into(),
    };
    let session = Session::start(plan).unwrap();
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let snapshot = session.snapshot();
        assert_ne!(
            snapshot.phase,
            Phase::Failed,
            "{:?} {:?}",
            snapshot.error,
            snapshot.diagnostics
        );
        if let Some(cpu) = snapshot.metrics.latest_series("device.cpu.utilization") {
            assert_eq!(cpu.latest.device_id, "test-device");
            assert_eq!(omnisor_collection::store::numeric(&cpu.latest), Some(0.33));
            assert!(
                snapshot
                    .metrics
                    .is_fresh(omnisor_collection::unix_nanos(), 2)
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "No authenticated endpoint readings: {:?}",
            snapshot.metrics
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    session.shutdown_blocking();
    server.abort();
    let _ = server.await;
    assert_eq!(session.snapshot().phase, Phase::Stopped);
}
