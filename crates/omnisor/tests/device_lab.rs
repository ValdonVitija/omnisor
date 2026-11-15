//! Real loopback SSH tests. Run with `./tests/lab.sh test`.
use omnisor::{CiscoVariant, DeviceConfig, DeviceSession, DeviceVendor, Error, JuniperVariant};
use omnisor_lab::{DeviceOptions, ENABLE_SECRET, LabDevice, PASSWORD, Profile, USERNAME};
use std::time::Duration;

fn vendor(profile: Profile) -> DeviceVendor {
    match profile {
        Profile::Ios => CiscoVariant::Ios.into(),
        Profile::IosXe => CiscoVariant::IosXe.into(),
        Profile::IosLegacy => CiscoVariant::IosLegacy.into(),
        Profile::IosXr => CiscoVariant::IosXr.into(),
        Profile::NxOs => CiscoVariant::NxOs.into(),
        Profile::Asa => CiscoVariant::Asa.into(),
        Profile::Wlc => CiscoVariant::Wlc.into(),
        Profile::Junos => JuniperVariant::Junos.into(),
        Profile::ScreenOs => JuniperVariant::ScreenOs.into(),
    }
}

async fn connect(device: &LabDevice, config: DeviceConfig) -> DeviceSession {
    DeviceSession::connect(
        device.address(),
        USERNAME,
        PASSWORD,
        config.timeout(Duration::from_secs(3)),
    )
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "opens loopback SSH sockets; run ./tests/lab.sh test"]
async fn all_vendor_profiles_initialize_execute_and_detect_errors() {
    for profile in Profile::ALL {
        let device = LabDevice::start(0, DeviceOptions::new(profile))
            .await
            .unwrap();
        let config = vendor(profile).into_config();
        let expected_paging = config.disable_paging_commands.len();
        let mut session = connect(&device, config).await;
        let result = session.send_command("show lab").await.unwrap();
        assert!(!result.has_error, "{profile:?}: {result:?}");
        assert!(
            result
                .output
                .contains(&format!("paging_commands={expected_paging}")),
            "{profile:?}: {result:?}"
        );
        let command = if profile == Profile::ScreenOs {
            "get system"
        } else {
            "show version"
        };
        let result = session.send_command(command).await.unwrap();
        assert!(
            result.output.contains("synthetic"),
            "{profile:?}: {result:?}"
        );
        assert!(!result.output.contains(&format!("lab-{}>", profile.name())));
        assert!(
            session
                .send_command("invalid-command")
                .await
                .unwrap()
                .has_error,
            "{profile:?}"
        );
        session.close().await.unwrap();
        device.stop().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "opens loopback SSH sockets; run ./tests/lab.sh test"]
async fn scenario_changes_are_shared_by_existing_and_new_clients() {
    let device = LabDevice::start(0, DeviceOptions::new(Profile::Ios))
        .await
        .unwrap();
    let mut first = connect(&device, CiscoVariant::Ios.into_config()).await;
    let mut second = connect(&device, CiscoVariant::Ios.into_config()).await;
    device.set_scenario(omnisor_lab::Scenario::Degraded);
    for session in [&mut first, &mut second] {
        assert!(
            session
                .send_command("show lab")
                .await
                .unwrap()
                .output
                .contains("scenario=Degraded")
        );
    }
    let mut third = connect(&device, CiscoVariant::Ios.into_config()).await;
    assert!(
        third
            .send_command("show lab")
            .await
            .unwrap()
            .output
            .contains("scenario=Degraded")
    );
    device.set_scenario(omnisor_lab::Scenario::Healthy);
    for session in [&mut first, &mut second, &mut third] {
        assert!(
            session
                .send_command("show lab")
                .await
                .unwrap()
                .output
                .contains("scenario=Healthy")
        );
        session.close().await.unwrap();
    }
    device.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "opens loopback SSH sockets; run ./tests/lab.sh test"]
async fn cisco_modes_are_isolated_between_clients_and_secrets_are_checked() {
    let device = LabDevice::start(0, DeviceOptions::new(Profile::Ios))
        .await
        .unwrap();
    let mut first = connect(&device, CiscoVariant::Ios.into_config()).await;
    let mut second = connect(&device, CiscoVariant::Ios.into_config()).await;
    assert!(
        first
            .enter_enable_mode("enable", Some("wrong-secret"))
            .await
            .is_err()
    );
    first
        .enter_enable_mode("enable", Some(ENABLE_SECRET))
        .await
        .unwrap();
    first.enter_config_mode("config t").await.unwrap();
    let output = first.send_command("show lab").await.unwrap();
    assert!(output.raw_output.ends_with("(config)#"));
    let output = second.send_command("show lab").await.unwrap();
    assert!(output.raw_output.ends_with("lab-ios>"));
    first.exit_config_mode("exit").await.unwrap();
    first.exit_from_enable_mode("disable").await.unwrap();
    first.close().await.unwrap();
    second.close().await.unwrap();
    device.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "opens loopback SSH sockets; run ./tests/lab.sh test"]
async fn fragmented_commands_and_delayed_chunked_replies_stay_in_sync() {
    let mut options = DeviceOptions::new(Profile::Ios);
    options.chunk_size = 7;
    options.response_delay = Duration::from_millis(30);
    let device = LabDevice::start(0, options).await.unwrap();
    let mut session = connect(&device, CiscoVariant::Ios.into_config()).await;
    session.send_raw("show ver").await.unwrap();
    let result = session.send_command("sion").await.unwrap();
    assert!(result.output.contains("synthetic ios device"));
    assert!(!result.has_error);
    assert!(!session.send_command("show lab").await.unwrap().has_error);
    session.close().await.unwrap();
    device.stop().await.unwrap();
}

#[tokio::test]
#[ignore = "opens loopback SSH sockets; run ./tests/lab.sh test"]
async fn closed_transport_is_reported_before_the_command_deadline() {
    let device = LabDevice::start(0, DeviceOptions::new(Profile::Ios))
        .await
        .unwrap();
    let mut session = connect(&device, CiscoVariant::Ios.into_config()).await;
    device.stop().await.unwrap();

    // Closing the complete SSH transport can close the channel without an
    // explicit channel EOF/Close message. Do not spin on ready None until the
    // session's three-second command deadline expires.
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        session.wait_for_pattern("this-prompt-will-never-arrive"),
    )
    .await
    .expect("a closed transport should be reported before the command timeout");
    assert!(matches!(result, Err(Error::DeviceSessionClosed)));
    let _ = session.close().await;
}

#[tokio::test]
#[ignore = "opens loopback SSH sockets; run ./tests/lab.sh test"]
async fn authentication_timeout_and_disconnect_are_reported() {
    let device = LabDevice::start(0, DeviceOptions::new(Profile::Ios))
        .await
        .unwrap();
    assert!(
        DeviceSession::connect(
            device.address(),
            USERNAME,
            "wrong-password",
            CiscoVariant::Ios
        )
        .await
        .is_err()
    );
    let mut session = connect(&device, CiscoVariant::Ios.into_config()).await;
    assert!(matches!(
        session.send_command("lab disconnect").await,
        Err(Error::DeviceSessionClosed)
    ));
    let _ = session.close().await;
    let mut session = DeviceSession::connect(
        device.address(),
        USERNAME,
        PASSWORD,
        CiscoVariant::Ios
            .into_config()
            .timeout(Duration::from_millis(200)),
    )
    .await
    .unwrap();
    assert!(matches!(
        session.send_command("lab timeout").await,
        Err(Error::DeviceTimeout)
    ));
    session.close().await.unwrap();
    device.stop().await.unwrap();
}
