use health::{
    HealthConnectionConfig, HealthTarget, SectionStatus, builtin_health_provider,
    collect_device_health, collect_health_with_executor,
};
use lab::{DeviceOptions, LabDevice, PASSWORD, Profile, Scenario, USERNAME};
use omnisor::{CiscoVariant, DeviceSession, ServerCheckMethod};

#[tokio::test]
#[ignore = "opens loopback SSH sockets; run ./tests/lab.sh test"]
async fn health_collection_over_ssh_covers_supported_platforms_and_scenarios() {
    for (profile, variant) in [
        (Profile::Ios, CiscoVariant::Ios),
        (Profile::IosXe, CiscoVariant::IosXe),
        (Profile::IosLegacy, CiscoVariant::IosLegacy),
    ] {
        for scenario in [Scenario::Healthy, Scenario::Degraded, Scenario::Unsupported] {
            let mut options = DeviceOptions::new(profile);
            options.scenario = scenario;
            let device = LabDevice::start(0, options).await.unwrap();
            let config = HealthConnectionConfig {
                address: "127.0.0.1".into(),
                port: device.address().port(),
                username: USERNAME.into(),
                password: PASSWORD.into(),
                vendor: variant.into(),
            };
            let snapshot = collect_device_health(&config).await.unwrap();
            assert_eq!(snapshot.device.hostname, format!("lab-{}", profile.name()));
            assert_eq!(snapshot.interfaces.total, 3);
            match scenario {
                Scenario::Healthy => {
                    assert_eq!(snapshot.system.status, SectionStatus::Ok);
                    assert_eq!(snapshot.interfaces.status, SectionStatus::Ok);
                    assert_eq!(snapshot.neighbor_summary().reachable, 3);
                }
                Scenario::Degraded => {
                    assert_eq!(snapshot.system.status, SectionStatus::Critical);
                    assert_eq!(snapshot.interfaces.down, 1);
                    assert_eq!(snapshot.neighbor_summary().unreachable, 3);
                    assert!(snapshot.finding_summary().critical > 0);
                }
                Scenario::Unsupported => {
                    assert_eq!(snapshot.system.status, SectionStatus::Ok);
                    assert_eq!(snapshot.neighbors.status, SectionStatus::Unknown);
                    assert!(
                        snapshot
                            .metadata
                            .iter()
                            .any(|m| m.name == "LLDP Neighbors"
                                && m.status == SectionStatus::Unknown)
                    );
                }
            }
            device.stop().await.unwrap();
        }
    }
}

#[tokio::test]
#[ignore = "opens loopback SSH sockets; run ./tests/lab.sh test"]
async fn refresh_reuses_a_live_ssh_session() {
    let device = LabDevice::start(0, DeviceOptions::new(Profile::Ios))
        .await
        .unwrap();
    let vendor = CiscoVariant::Ios.into();
    let provider = builtin_health_provider(&vendor).unwrap();
    let target = HealthTarget {
        address: "127.0.0.1".into(),
        port: device.address().port(),
    };
    let mut session = DeviceSession::connect(device.address(), USERNAME, PASSWORD, vendor)
        .await
        .unwrap();
    let first = collect_health_with_executor(&target, provider.as_ref(), &mut session)
        .await
        .unwrap();
    let second = collect_health_with_executor(&target, provider.as_ref(), &mut session)
        .await
        .unwrap();
    assert_eq!(first.neighbor_summary().reachable, 3);
    assert_eq!(second.neighbor_summary().reachable, 3);
    assert!(second.collected_at >= first.collected_at);
    session.close().await.unwrap();
    device.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "opens loopback SSH sockets; run ./tests/lab.sh test"]
async fn live_snapshots_follow_failures_and_recovery_without_reconnecting() {
    for (profile, variant) in [
        (Profile::Ios, CiscoVariant::Ios),
        (Profile::IosXe, CiscoVariant::IosXe),
        (Profile::IosLegacy, CiscoVariant::IosLegacy),
    ] {
        let device = LabDevice::start(0, DeviceOptions::new(profile))
            .await
            .unwrap();
        let provider = builtin_health_provider(&variant.into()).unwrap();
        let target = HealthTarget {
            address: device.address().ip().to_string(),
            port: device.address().port(),
        };
        let mut session = DeviceSession::builder()
            .address(&target.address)
            .port(target.port)
            .username(USERNAME)
            .password(PASSWORD)
            .vendor(variant)
            .server_check(ServerCheckMethod::with_public_key(device.public_key()))
            .connect()
            .await
            .unwrap();
        let mut previous_collection = None;

        for scenario in [
            Scenario::Healthy,
            Scenario::Degraded,
            Scenario::Unsupported,
            Scenario::Healthy,
        ] {
            device.set_scenario(scenario);
            let snapshot = collect_health_with_executor(&target, provider.as_ref(), &mut session)
                .await
                .unwrap();
            if let Some(previous) = previous_collection {
                assert!(snapshot.collected_at >= previous);
            }
            previous_collection = Some(snapshot.collected_at);
            assert_eq!(snapshot.device.hostname, format!("lab-{}", profile.name()));
            assert_eq!(snapshot.interfaces.total, 3);
            match scenario {
                Scenario::Healthy => {
                    assert_eq!(snapshot.system.cpu_percent, Some(19.0));
                    assert_eq!(snapshot.system.status, SectionStatus::Ok);
                    assert_eq!(snapshot.interfaces.status, SectionStatus::Ok);
                    assert_eq!(snapshot.neighbor_summary().reachable, 3);
                    assert_eq!(snapshot.finding_summary().critical, 0);
                }
                Scenario::Degraded => {
                    assert_eq!(snapshot.system.cpu_percent, Some(96.0));
                    assert_eq!(snapshot.system.status, SectionStatus::Critical);
                    assert_eq!(snapshot.interfaces.down, 1);
                    assert_eq!(snapshot.neighbor_summary().unreachable, 3);
                    assert!(snapshot.finding_summary().critical > 0);
                }
                Scenario::Unsupported => {
                    assert_eq!(snapshot.system.status, SectionStatus::Ok);
                    assert_eq!(snapshot.neighbors.status, SectionStatus::Unknown);
                    assert!(snapshot.metadata.iter().any(|check| {
                        check.name == "LLDP Neighbors" && check.status == SectionStatus::Unknown
                    }));
                }
            }
            let state = session.send_command("show lab").await.unwrap();
            assert!(state.output.contains(&format!("scenario={scenario:?}")));
        }
        session.close().await.unwrap();
        device.stop().await.unwrap();
    }
}
