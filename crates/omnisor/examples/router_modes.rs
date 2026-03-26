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

    //Be careful with the chronology of steps for now.
    //In the future I plan to offer the possibility
    //of going into any mode from every other mode
    //without having to follow the normal chronology of steps.
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
// OUTPUT:

// Interface                  IP-Address      OK? Method Status                Protocol
// FastEthernet0/0            unassigned      YES manual administratively down down

// --------------------------------------------

// Interface                  IP-Address      OK? Method Status                Protocol
// FastEthernet0/0            10.10.10.10     YES manual administratively down down
