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
// OUTPUT:
// cargo r --release --bin example1
//    Compiling omnisor v0.1.2 (/Users/vvitija/oss/omnisor)
//     Finished `release` profile [optimized] target(s) in 2.57s
//      Running `/Users/vvitija/oss/omnisor/target/release/example1`

// Interface                  IP-Address      OK? Method Status                Protocol
// FastEthernet0/0            unassigned      YES NVRAM  administratively down down
// GigabitEthernet2/0         192.168.142.130 YES DHCP   up                    up
