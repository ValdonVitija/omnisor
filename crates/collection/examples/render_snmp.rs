//! Render a private exporter file using the same catalog as the desktop.
use collection::{Catalog, CollectionPlan, DeviceIdentity, SnmpCredentials, Source};
use std::{fs::OpenOptions, io::Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if !(2..=3).contains(&args.len()) {
        return Err("Usage: render_snmp OUTPUT AUTH_JSON [PROFILE_ID]".into());
    }
    let auth: serde_json::Value = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    let community = auth["community"]
        .as_str()
        .ok_or("AUTH_JSON requires a community field")?
        .to_owned();
    let plan = CollectionPlan {
        device: DeviceIdentity::default(),
        profile_id: args
            .get(2)
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "cisco-ios-snmp".into()),
        interval_seconds: 10,
        collector: Default::default(),
        source: Source::Snmp {
            target: String::new(),
            credentials: SnmpCredentials::V2c { community },
            exporter: Default::default(),
        },
    };
    let yaml = plan
        .snmp_yaml(&Catalog::bundled()?)
        .map_err(std::io::Error::other)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&args[0])?.write_all(yaml.as_bytes())?;
    Ok(())
}
