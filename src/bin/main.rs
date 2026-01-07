use omnisor::device::{CiscoVariant, DeviceSession};

#[tokio::main]
async fn main() -> Result<(), omnisor::Error> {
    let mut session = DeviceSession::connect(
        ("192.168.142.130", 22),
        "cisco",
        "StrongPassword123",
        CiscoVariant::IosLegacy,
    )
    .await?;

    for _ in 0..10 {
        println!("================================\n");
        let result = session.send_command("show version").await?;
        println!("{}", result.output);
    }
    session.close().await?;
    Ok(())
}
