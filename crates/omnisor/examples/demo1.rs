// THIS SHOULD CONNECT TO THE CISCO LAB DEVICE, EXECUTE 'show ip int br',
// THEN PRINT THE OUTPUT AND DISCONNECT FROM THE DEVICE

use omnisor::{CiscoVariant, DeviceSession};
use std::env;

#[tokio::main]
async fn main() -> Result<(), omnisor::Error> {
    let address = env::var("OMNISOR_EXAMPLE_ADDR").expect("set OMNISOR_EXAMPLE_ADDR");
    let username = env::var("OMNISOR_EXAMPLE_USER").expect("set OMNISOR_EXAMPLE_USER");
    let password = env::var("OMNISOR_EXAMPLE_PASSWORD").expect("set OMNISOR_EXAMPLE_PASSWORD");

    let mut session = DeviceSession::builder()
        .address(address)
        .port(22)
        .username(username)
        .password(password)
        .vendor(CiscoVariant::IosLegacy)
        .connect()
        .await?;

    let result = session.send_command("show ip int br").await?;
    println!("{}", result.output);

    session.close().await?;
    Ok(())
}
