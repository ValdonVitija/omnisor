use omnisor::device::{CiscoVariant, DeviceSession};
use std::env;

#[tokio::main]
async fn main() -> Result<(), omnisor::Error> {
    let address = env::var("OMNISOR_EXAMPLE_ADDR").expect("set OMNISOR_EXAMPLE_ADDR");
    let username = env::var("OMNISOR_EXAMPLE_USER").expect("set OMNISOR_EXAMPLE_USER");
    let password = env::var("OMNISOR_EXAMPLE_PASSWORD").expect("set OMNISOR_EXAMPLE_PASSWORD");

    let mut session = DeviceSession::connect(
        (address.as_str(), 22),
        &username,
        &password,
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
