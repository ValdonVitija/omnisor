//! Live session lifecycle checks. Run with `cargo test -p health --test live_monitor -- --ignored`.

use health::{
    CiscoIosHealthProvider, CommandExecutor, HealthConnectionConfig, HealthError, HealthFuture,
    HealthProvider, HealthSessionOptions, HealthTarget, LiveHealthSession, SectionStatus,
};
use lab::{DeviceOptions, LabDevice, PASSWORD, Profile, Scenario, USERNAME};
use omnisor::{CiscoVariant, Error, ServerCheckMethod};
use std::{
    io::Write,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, SystemTime},
};

fn config(device: &LabDevice) -> HealthConnectionConfig {
    HealthConnectionConfig {
        address: device.address().ip().to_string(),
        port: device.address().port(),
        username: USERNAME.into(),
        password: PASSWORD.into(),
        vendor: CiscoVariant::Ios.into(),
    }
}

fn lab_options(device: &LabDevice) -> HealthSessionOptions {
    HealthSessionOptions {
        server_check: ServerCheckMethod::PublicKey(device.public_key().into()),
        connect_timeout: Duration::from_secs(3),
        command_timeout: Duration::from_millis(300),
        collection_timeout: Duration::from_secs(3),
    }
}

#[tokio::test]
#[ignore = "opens loopback SSH sockets; run the live_monitor integration suite"]
async fn changing_health_snapshots_reuse_one_verified_connection() {
    let device = LabDevice::start(0, DeviceOptions::new(Profile::Ios))
        .await
        .unwrap();
    let mut monitor =
        LiveHealthSession::with_options(config(&device), lab_options(&device)).unwrap();

    assert_eq!(
        monitor.collect_once().await.unwrap().system.status,
        SectionStatus::Ok
    );
    device.set_scenario(Scenario::Degraded);
    let degraded = monitor.collect_once().await.unwrap();
    assert_eq!(degraded.system.status, SectionStatus::Critical);
    assert_eq!(degraded.interfaces.down, 1);
    device.set_scenario(Scenario::Unsupported);
    let partial = monitor.collect_once().await.unwrap();
    assert_eq!(partial.system.status, SectionStatus::Ok);
    assert_eq!(partial.neighbors.status, SectionStatus::Unknown);
    device.set_scenario(Scenario::Healthy);
    assert_eq!(
        monitor.collect_once().await.unwrap().system.status,
        SectionStatus::Ok
    );
    assert_eq!(monitor.connection_generation(), 1);
    assert!(monitor.is_connected());

    monitor.close().await;
    assert!(!monitor.is_connected());
    monitor.collect_once().await.unwrap();
    assert_eq!(monitor.connection_generation(), 2);
    monitor.close().await;
    device.stop().await.unwrap();
}

enum Fault {
    Command(&'static str),
    Pending,
}

struct FaultOnSecondCollection {
    calls: AtomicUsize,
    fault: Fault,
    delegate: CiscoIosHealthProvider,
}

impl FaultOnSecondCollection {
    fn new(fault: Fault) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            fault,
            delegate: CiscoIosHealthProvider::new(CiscoVariant::Ios).unwrap(),
        }
    }
}

impl HealthProvider for FaultOnSecondCollection {
    fn collect<'a>(
        &'a self,
        executor: &'a mut dyn CommandExecutor,
        target: &'a HealthTarget,
    ) -> HealthFuture<'a> {
        Box::pin(async move {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
                match self.fault {
                    Fault::Command(command) => {
                        let source = executor.execute(command).await.unwrap_err();
                        return Err(HealthError::Command {
                            command: command.into(),
                            source,
                        });
                    }
                    Fault::Pending => return std::future::pending().await,
                }
            }
            self.delegate.collect(executor, target).await
        })
    }
}

#[tokio::test]
#[ignore = "opens loopback SSH sockets; run the live_monitor integration suite"]
async fn command_timeout_and_disconnect_discard_the_session_before_recovery() {
    for command in ["lab timeout", "lab disconnect"] {
        let device = LabDevice::start(0, DeviceOptions::new(Profile::Ios))
            .await
            .unwrap();
        let mut monitor = LiveHealthSession::with_provider(
            config(&device),
            lab_options(&device),
            Box::new(FaultOnSecondCollection::new(Fault::Command(command))),
        )
        .unwrap();
        monitor.collect_once().await.unwrap();
        let error = monitor.collect_once().await.unwrap_err();
        assert!(matches!(
            (&error, command),
            (
                HealthError::Command {
                    source: Error::DeviceTimeout,
                    ..
                },
                "lab timeout"
            ) | (
                HealthError::Command {
                    source: Error::DeviceSessionClosed,
                    ..
                },
                "lab disconnect"
            )
        ));
        assert!(!monitor.is_connected());
        let recovered = monitor.collect_once().await.unwrap();
        assert_eq!(recovered.system.status, SectionStatus::Ok);
        assert_eq!(monitor.connection_generation(), 2);
        monitor.close().await;
        device.stop().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "opens loopback SSH sockets; run the live_monitor integration suite"]
async fn collection_deadline_discards_a_session_even_if_the_provider_never_finishes() {
    let device = LabDevice::start(0, DeviceOptions::new(Profile::Ios))
        .await
        .unwrap();
    let options = HealthSessionOptions {
        collection_timeout: Duration::from_secs(2),
        ..lab_options(&device)
    };
    let mut monitor = LiveHealthSession::with_provider(
        config(&device),
        options,
        Box::new(FaultOnSecondCollection::new(Fault::Pending)),
    )
    .unwrap();
    monitor.collect_once().await.unwrap();
    assert!(matches!(
        monitor.collect_once().await,
        Err(HealthError::Timeout {
            operation: "health collection",
            ..
        })
    ));
    assert!(!monitor.is_connected());
    monitor.collect_once().await.unwrap();
    assert_eq!(monitor.connection_generation(), 2);
    monitor.close().await;
    device.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "opens loopback SSH sockets; run the live_monitor integration suite"]
async fn cancelled_collection_does_not_reuse_its_connection() {
    let device = LabDevice::start(0, DeviceOptions::new(Profile::Ios))
        .await
        .unwrap();
    let mut monitor = LiveHealthSession::with_provider(
        config(&device),
        lab_options(&device),
        Box::new(FaultOnSecondCollection::new(Fault::Pending)),
    )
    .unwrap();
    monitor.collect_once().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), monitor.collect_once())
            .await
            .is_err()
    );
    assert!(!monitor.is_connected());
    monitor.collect_once().await.unwrap();
    assert_eq!(monitor.connection_generation(), 2);
    monitor.close().await;
    device.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "opens loopback SSH sockets; run the live_monitor integration suite"]
async fn incorrect_host_key_fails_before_collection() {
    let device = LabDevice::start(0, DeviceOptions::new(Profile::Ios))
        .await
        .unwrap();
    let another = LabDevice::start(0, DeviceOptions::new(Profile::Ios))
        .await
        .unwrap();
    let options = HealthSessionOptions {
        server_check: ServerCheckMethod::PublicKey(another.public_key().into()),
        ..lab_options(&device)
    };
    let mut monitor = LiveHealthSession::with_options(config(&device), options).unwrap();
    assert!(matches!(
        monitor.collect_once().await,
        Err(HealthError::Connection(_))
    ));
    assert!(!monitor.is_connected());
    assert_eq!(monitor.connection_generation(), 0);
    device.stop().await.unwrap();
    another.stop().await.unwrap();
}

struct TemporaryKnownHosts(PathBuf);

impl TemporaryKnownHosts {
    fn new(contents: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "omnisor-health-known-hosts-{}-{nonce}",
            std::process::id()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        Self(path)
    }
}

impl Drop for TemporaryKnownHosts {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::test]
#[ignore = "opens loopback SSH sockets; run the live_monitor integration suite"]
async fn known_hosts_files_match_standard_host_and_port_entries() {
    let device = LabDevice::start(0, DeviceOptions::new(Profile::Ios))
        .await
        .unwrap();
    let another = LabDevice::start(0, DeviceOptions::new(Profile::Ios))
        .await
        .unwrap();
    let entry = |key: &str| {
        format!(
            "[127.0.0.1]:{} ssh-ed25519 {key}\n",
            device.address().port()
        )
    };
    let known_hosts = TemporaryKnownHosts::new(&entry(device.public_key()));
    let options = HealthSessionOptions {
        server_check: ServerCheckMethod::KnownHostsFile(
            known_hosts.0.to_string_lossy().into_owned(),
        ),
        ..lab_options(&device)
    };
    let mut monitor = LiveHealthSession::with_options(config(&device), options).unwrap();
    monitor.collect_once().await.unwrap();
    monitor.close().await;
    std::fs::write(&known_hosts.0, entry(another.public_key())).unwrap();
    assert!(matches!(
        monitor.collect_once().await,
        Err(HealthError::Connection(_))
    ));
    assert!(!monitor.is_connected());
    assert_eq!(monitor.connection_generation(), 1);
    device.stop().await.unwrap();
    another.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "opens loopback TCP sockets; run the live_monitor integration suite"]
async fn ssh_handshake_has_an_outer_connection_deadline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stalled_server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let options = HealthSessionOptions {
        server_check: ServerCheckMethod::NoCheck,
        connect_timeout: Duration::from_millis(100),
        ..HealthSessionOptions::default()
    };
    let config = HealthConnectionConfig {
        address: address.ip().to_string(),
        port: address.port(),
        username: USERNAME.into(),
        password: PASSWORD.into(),
        vendor: CiscoVariant::Ios.into(),
    };
    let mut monitor = LiveHealthSession::with_options(config, options).unwrap();
    assert!(matches!(
        monitor.collect_once().await,
        Err(HealthError::Timeout {
            operation: "SSH connection",
            ..
        })
    ));
    assert!(!monitor.is_connected());
    stalled_server.abort();
    let _ = stalled_server.await;
}
