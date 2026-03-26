// 1. CONNECT TO CISCO LAB DEVICE
// 2. ENTER ENABLE MODE
// 3. EXECUTE 'show ip int br fastEthernet 0/0',
// 4. PRINT THE OUTPUT TO SHOW NO IP ADDRESS IS CONFIGURED
// 5. ENTER CONFIG MODE
// 6. EXECUTE 'int fa0/0'
// 7. EXECUTE 'ip address 10.10.10.10 255.255.255.0'
// 8. EXIT CONFIG MODE
// 9. EXECUTE 'show ip int br fastEthernet 0/0'
// 10. PRINT THE OUTPUT
// 11. EXIT ENABLE MODE

use omnisor::{CiscoVariant, DeviceSession};
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

    let _ = session.enter_enable_mode("enable", Some(&password)).await?;
    let out_fa_0_0 = session
        .send_command("show ip int br fastEthernet 0/0")
        .await?;
    println!(
        "{}\n\n--------------------------------------------",
        out_fa_0_0.output
    );

    let _ = session.enter_config_mode("config t").await?;
    let int_fa_0_0 = session.send_command("int fa0/0").await?;
    println!("{}", int_fa_0_0.output);
    let _ = session
        .send_command("ip address 10.10.10.10 255.255.255.0")
        .await?;
    // first exit goes from config-if# to config#
    let _ = session.exit_config_mode("exit").await?;
    // second exit goes from config# to enable#
    let _ = session.exit_config_mode("exit").await?;
    let fa_0_0_configured = session
        .send_command("show ip int br fastEthernet 0/0")
        .await?;
    println!("{}", fa_0_0_configured.output);

    let _ = session.exit_from_enable_mode("disable").await?;
    session.close().await?;
    Ok(())
}
