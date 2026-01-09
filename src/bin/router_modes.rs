use omnisor::{CiscoVariant, DeviceSession};

#[tokio::main]
async fn main() -> Result<(), omnisor::Error> {
    let mut session = DeviceSession::connect(
        ("192.168.142.130", 22),
        "cisco",
        "StrongPassword123",
        CiscoVariant::IosLegacy,
    )
    .await?;

    //Be careful with the chronology of steps for now.
    //In the future I plan to offer the possibility
    //of going into any mode from every other mode
    //without having to follow the normal chronology of steps.
    let _ = session.enter_enable_mode("enable", Some("cisco")).await?;
    let _ = session.enter_config_mode("config t").await?;
    let _ = session.exit_config_mode("exit").await?;
    let _ = session.exit_from_enable_mode("disable").await?;

    session.close().await?;
    Ok(())
}
