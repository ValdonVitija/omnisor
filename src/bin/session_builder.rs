use omnisor::{CiscoVariant, DeviceSession};

#[tokio::main]
async fn main() -> Result<(), omnisor::Error> {
    let mut session = DeviceSession::builder()
        .address("192.168.142.130")
        .port(22)
        .username("cisco")
        .password("StrongPassword123")
        .vendor(CiscoVariant::IosLegacy)
        .connect()
        .await?;

    let result = session.send_command("show version").await?;
    println!("{}", result.output);

    session.close().await?;
    Ok(())
}
