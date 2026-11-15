//! Connect to a simulator or real lab device without editing an example's source.
use omnisor::{CiscoVariant, DeviceConfig, DeviceSession, DeviceVendor, JuniperVariant};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 4 {
        return Err("usage: lab_probe PROFILE HOST PORT 'COMMAND'; credentials via OMNISOR_LAB_USER / OMNISOR_LAB_PASSWORD (defaults admin / omnisor)".into());
    }
    let vendor: DeviceVendor = match args[0].as_str() {
        "ios" => CiscoVariant::Ios.into(),
        "ios-xe" => CiscoVariant::IosXe.into(),
        "ios-legacy" => CiscoVariant::IosLegacy.into(),
        "ios-xr" => CiscoVariant::IosXr.into(),
        "nxos" => CiscoVariant::NxOs.into(),
        "asa" => CiscoVariant::Asa.into(),
        "wlc" => CiscoVariant::Wlc.into(),
        "junos" => JuniperVariant::Junos.into(),
        "screenos" => JuniperVariant::ScreenOs.into(),
        // Demonstrates a custom SSH profile; this does not add a health provider.
        "srlinux" => DeviceConfig::with_prompt(r"(?:^|[\r\n])[AB]:[\w.\-]+@[\w.\-]+[#>]\s*$")
            .term_type("dumb")
            .add_error_pattern(r"(?i)error:")
            .into(),
        profile => return Err(format!("unknown lab profile: {profile}").into()),
    };
    let port: u16 = args[2].parse()?;
    let user = std::env::var("OMNISOR_LAB_USER").unwrap_or_else(|_| "admin".into());
    let password = std::env::var("OMNISOR_LAB_PASSWORD").unwrap_or_else(|_| "omnisor".into());
    let mut session =
        DeviceSession::connect((args[1].as_str(), port), &user, &password, vendor).await?;
    let result = session.send_command(&args[3]).await;
    session.close().await?;
    let result = result?;
    println!("{}", result.output);
    if result.has_error {
        return Err(format!("device rejected command: {:?}", result.error_match).into());
    }
    Ok(())
}
