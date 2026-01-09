use omnisor::device::{CiscoVariant, DeviceSession};

// use scopeguard::defer;
#[tokio::main]
async fn main() -> Result<(), omnisor::Error> {
    let mut session = DeviceSession::connect(
        ("192.168.142.130", 22),
        "cisco",
        "StrongPassword123",
        CiscoVariant::IosLegacy,
    )
    .await?;

    let _result: omnisor::DeviceCommandResult = session.send_command("show version").await?;
    dbg!(_result.output);

    let _running_conf = session.send_command("show running-config").await?;
    dbg!(_running_conf.output);

    let _ = session.enter_config_mode("config t").await?;

    let do_show = session.send_command("do show ip int br").await?;
    dbg!(do_show.output);

    let _exit_config = session.exit_config_mode("exit").await?;

    let _running_conf_2 = session.send_command("show running-config").await?;
    dbg!(_running_conf_2.output);

    session.close().await?;

    Ok(())
}
