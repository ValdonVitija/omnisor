//! Device selection -> internal collection plan. Users provide device/access
//! information; profile policy selects protocols, components and cadence.
use crate::{
    Catalog, CollectionPlan, DeviceIdentity, SnmpCredentials, Source, catalog::DeviceProfile,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceDetails {
    pub label: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub device_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConnectionPolicy {
    SnmpV3 {
        port: u16,
        interval_seconds: u64,
    },
    SnmpCommunity {
        port: u16,
        interval_seconds: u64,
    },
    Prometheus {
        scheme: String,
        port: u16,
        path: String,
        bearer_required: bool,
        interval_seconds: u64,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequiredCredentials {
    None,
    MonitoringAccount,
    ReadOnlyCommunity,
    BearerToken,
}
impl ConnectionPolicy {
    pub fn credentials(&self) -> RequiredCredentials {
        match self {
            Self::SnmpV3 { .. } => RequiredCredentials::MonitoringAccount,
            Self::SnmpCommunity { .. } => RequiredCredentials::ReadOnlyCommunity,
            Self::Prometheus {
                bearer_required: true,
                ..
            } => RequiredCredentials::BearerToken,
            Self::Prometheus { .. } => RequiredCredentials::None,
        }
    }
    pub fn validate(&self, profile: &DeviceProfile) -> Result<(), String> {
        let (port, interval, adapter) = match self {
            Self::SnmpV3 {
                port,
                interval_seconds,
            }
            | Self::SnmpCommunity {
                port,
                interval_seconds,
            } => (*port, *interval_seconds, "snmp"),
            Self::Prometheus {
                port,
                interval_seconds,
                scheme,
                path,
                ..
            } => {
                if !["http", "https"].contains(&scheme.as_str())
                    || !path.starts_with('/')
                    || path.contains(['?', '#'])
                {
                    return Err(format!("Invalid HTTP connection policy for {}", profile.id));
                }
                (*port, *interval_seconds, "prometheus")
            }
        };
        if port == 0
            || !(2..=300).contains(&interval)
            || !profile.adapters.iter().any(|a| a == adapter)
        {
            return Err(format!("Invalid connection policy for {}", profile.id));
        }
        Ok(())
    }
}

/// No Debug/Serialize: these values must not enter diagnostics or saved metadata.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub privacy_password: String,
    #[serde(alias = "community")]
    pub access_key: String,
}

impl Credentials {
    fn from_private_file(path: &Path) -> Result<Self, String> {
        let file = std::fs::File::open(path).map_err(|_| "Cannot open this device's monitoring credentials. Rerun lab setup or check its credential file.")?;
        let metadata = file
            .metadata()
            .map_err(|_| "Cannot inspect monitoring credential file")?;
        if !metadata.is_file() || metadata.len() > 16 * 1024 {
            return Err("Monitoring credentials must be a regular file up to 16 KiB".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("Monitoring credential file must be private (0600)".into());
            }
        }
        let mut bytes = Vec::new();
        file.take(16 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "Cannot read monitoring credential file")?;
        if bytes.len() > 16 * 1024 {
            return Err("Monitoring credential file exceeds 16 KiB".into());
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            "Invalid monitoring credential file; expected a credentials JSON object".into()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavedDevice {
    pub id: String,
    pub name: String,
    pub address: String,
    pub profile_id: String,
    /// Site connectivity, separate from vendor/model defaults. No credentials.
    #[serde(default)]
    pub gateway: Option<ExporterGateway>,
    /// Deployment-specific access; the model still controls metric mappings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<ConnectionPolicy>,
    /// Reference only. Secrets are loaded after Connect, never while rendering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_file: Option<PathBuf>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExporterGateway {
    pub metrics_url: String,
    #[serde(default)]
    pub bearer_required: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavedDevices {
    pub schema_version: u32,
    pub devices: Vec<SavedDevice>,
}
impl Default for SavedDevices {
    fn default() -> Self {
        Self {
            schema_version: 1,
            devices: Vec::new(),
        }
    }
}
impl SavedDevices {
    pub fn from_json(json: &str, catalog: &Catalog) -> Result<Self, String> {
        if json.len() > 64 * 1024 {
            return Err("Saved device list exceeds 64 KiB".into());
        }
        let devices: Self =
            serde_json::from_str(json).map_err(|e| format!("Cannot read saved devices: {e}"))?;
        if devices.schema_version != 1 {
            return Err("Unsupported saved device format".into());
        }
        let mut ids = BTreeSet::new();
        for device in &devices.devices {
            if device.id.is_empty() || device.name.trim().is_empty() || !ids.insert(&device.id) {
                return Err("Saved devices require unique IDs and names".into());
            }
            let profile = catalog.resolve(&device.profile_id)?;
            if profile.device.is_none() || profile.connection.is_none() {
                return Err("Saved device has no device connection policy".into());
            }
            address(&device.address, 161)?;
            if let Some(policy) = &device.connection {
                if device.gateway.is_some() {
                    return Err(
                        "Saved device cannot combine direct access and an exporter gateway".into(),
                    );
                }
                policy.validate(&profile)?;
            }
            if device
                .credentials_file
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            {
                return Err("Monitoring credential file reference must be an absolute path".into());
            }
            if let Some(gateway) = &device.gateway {
                crate::config::validate_endpoint(&gateway.metrics_url)?;
                if !profile.adapters.iter().any(|a| a == "prometheus") {
                    return Err("Saved gateway is incompatible with the device profile".into());
                }
            }
        }
        Ok(devices)
    }
    pub fn discover(catalog: &Catalog) -> Result<Self, String> {
        let path = std::env::var_os("OMNISOR_DEVICES_FILE")
            .map(PathBuf::from)
            .or_else(|| {
                companion_files("devices.json")
                    .into_iter()
                    .find(|p| p.is_file())
            });
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let mut text = String::new();
        std::fs::File::open(&path)
            .map_err(|e| format!("Cannot open saved devices: {e}"))?
            .take(64 * 1024 + 1)
            .read_to_string(&mut text)
            .map_err(|e| e.to_string())?;
        Self::from_json(&text, catalog)
    }
    pub fn get(&self, id: &str) -> Result<&SavedDevice, String> {
        self.devices
            .iter()
            .find(|d| d.id == id)
            .ok_or_else(|| "Saved device no longer exists".into())
    }
}

#[derive(Clone)]
pub enum DeviceTarget {
    Saved(String),
    New { profile_id: String, address: String },
}
#[derive(Default)]
pub struct RuntimeTools {
    pub collector: PathBuf,
    pub snmp_exporter: PathBuf,
}
impl RuntimeTools {
    pub fn discover() -> Self {
        Self {
            collector: find_binary("OMNISOR_OTELCOL", "otelcol-contrib"),
            snmp_exporter: find_binary("OMNISOR_SNMP_EXPORTER", "snmp_exporter"),
        }
    }
}

impl Catalog {
    pub fn credentials_for(
        &self,
        target: &DeviceTarget,
        saved: &SavedDevices,
    ) -> Result<RequiredCredentials, String> {
        let profile_id = match target {
            DeviceTarget::Saved(id) => {
                let device = saved.get(id)?;
                if device.credentials_file.is_some() {
                    return Ok(RequiredCredentials::None);
                }
                if let Some(gateway) = &device.gateway {
                    return Ok(if gateway.bearer_required {
                        RequiredCredentials::BearerToken
                    } else {
                        RequiredCredentials::None
                    });
                }
                if let Some(policy) = &device.connection {
                    return Ok(policy.credentials());
                }
                &device.profile_id
            }
            DeviceTarget::New { profile_id, .. } => profile_id,
        };
        self.resolve(profile_id)?
            .connection
            .map(|c| c.credentials())
            .ok_or_else(|| "Choose a supported device family".into())
    }
    pub fn plan_device(
        &self,
        target: &DeviceTarget,
        saved: &SavedDevices,
        credentials: Credentials,
        tools: &RuntimeTools,
    ) -> Result<CollectionPlan, String> {
        let (profile_id, host, name, id, gateway, site_policy, credentials_file) = match target {
            DeviceTarget::Saved(id) => {
                let device = saved.get(id)?;
                (
                    device.profile_id.as_str(),
                    device.address.as_str(),
                    device.name.clone(),
                    device.id.clone(),
                    device.gateway.as_ref(),
                    device.connection.as_ref(),
                    device.credentials_file.as_deref(),
                )
            }
            DeviceTarget::New {
                profile_id,
                address: host,
            } => (
                profile_id.as_str(),
                host.as_str(),
                host.trim().to_owned(),
                format!("device-{}", crate::unix_nanos()),
                None,
                None,
                None,
            ),
        };
        let profile = self.resolve(profile_id)?;
        let details = profile
            .device
            .as_ref()
            .ok_or("Choose a supported device family")?;
        let policy = site_policy
            .or(profile.connection.as_ref())
            .ok_or("Device has no connection policy")?;
        policy.validate(&profile)?;
        let credentials = match credentials_file {
            Some(path) => Credentials::from_private_file(path)?,
            None => credentials,
        };
        // Identity input is always an address, even when a site gateway handles it.
        address(host, 161)?;
        let (source, interval_seconds) = if let Some(gateway) = gateway {
            if gateway.bearer_required && credentials.access_key.is_empty() {
                return Err("Enter the monitoring access token".into());
            }
            (
                Source::Prometheus {
                    endpoint: gateway.metrics_url.clone(),
                    bearer_token: credentials.access_key,
                },
                interval(policy),
            )
        } else {
            match policy {
                ConnectionPolicy::SnmpV3 {
                    port,
                    interval_seconds,
                } => {
                    if credentials.username.trim().is_empty()
                        || credentials.password.len() < 8
                        || credentials.privacy_password.len() < 8
                    {
                        return Err("Enter the monitoring username, authentication password, and privacy password (at least 8 bytes each)".into());
                    }
                    (
                        Source::Snmp {
                            target: address(host, *port)?,
                            credentials: SnmpCredentials::V3 {
                                username: credentials.username,
                                auth_password: credentials.password,
                                priv_password: credentials.privacy_password,
                            },
                            exporter: tools.snmp_exporter.clone(),
                        },
                        *interval_seconds,
                    )
                }
                ConnectionPolicy::SnmpCommunity {
                    port,
                    interval_seconds,
                } => {
                    if credentials.access_key.is_empty() {
                        return Err("Enter the read-only monitoring community".into());
                    }
                    (
                        Source::Snmp {
                            target: address(host, *port)?,
                            credentials: SnmpCredentials::V2c {
                                community: credentials.access_key,
                            },
                            exporter: tools.snmp_exporter.clone(),
                        },
                        *interval_seconds,
                    )
                }
                ConnectionPolicy::Prometheus {
                    scheme,
                    port,
                    path,
                    bearer_required,
                    interval_seconds,
                } => {
                    if *bearer_required && credentials.access_key.is_empty() {
                        return Err("Enter the monitoring access token".into());
                    }
                    (
                        Source::Prometheus {
                            endpoint: format!("{scheme}://{}{path}", address(host, *port)?),
                            bearer_token: credentials.access_key,
                        },
                        *interval_seconds,
                    )
                }
            }
        };
        let plan = CollectionPlan {
            device: DeviceIdentity {
                id,
                name,
                vendor: profile.vendor.clone(),
                model: details.model.clone(),
                device_type: details.device_type.clone(),
                os: profile.os.clone(),
                os_version: String::new(),
            },
            profile_id: profile.id,
            interval_seconds,
            collector: tools.collector.clone(),
            source,
        };
        if !plan.collector.is_file()
            || matches!(&plan.source,Source::Snmp {exporter,..} if !exporter.is_file())
        {
            return Err(
                "Omnisor's monitoring components are missing. Check the application installation."
                    .into(),
            );
        }
        plan.validate(self)?;
        Ok(plan)
    }
}
fn interval(policy: &ConnectionPolicy) -> u64 {
    match policy {
        ConnectionPolicy::SnmpV3 {
            interval_seconds, ..
        }
        | ConnectionPolicy::SnmpCommunity {
            interval_seconds, ..
        }
        | ConnectionPolicy::Prometheus {
            interval_seconds, ..
        } => *interval_seconds,
    }
}

fn address(input: &str, default_port: u16) -> Result<String, String> {
    let input = input.trim();
    if input.is_empty()
        || input.len() > 253
        || input.contains(['/', '?', '#', '@', '$'])
        || input.chars().any(char::is_whitespace)
    {
        return Err("Enter a device IP address or hostname, optionally with a port".into());
    }
    if let Ok(ip) = input.parse::<std::net::IpAddr>() {
        return Ok(match ip {
            std::net::IpAddr::V4(_) => format!("{ip}:{default_port}"),
            std::net::IpAddr::V6(_) => format!("[{ip}]:{default_port}"),
        });
    }
    let parsed = url::Url::parse(&format!("omnisor://{input}"))
        .map_err(|_| "Enter a valid device IP address or hostname")?;
    if parsed.host_str().is_none() || parsed.port() == Some(0) {
        return Err("Enter a valid device address and port".into());
    }
    let port = parsed.port().unwrap_or(default_port);
    Ok(format!(
        "{}:{port}",
        &parsed[url::Position::BeforeHost..url::Position::AfterHost]
    ))
}
fn companion_files(name: &str) -> Vec<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .map(|parent| {
            vec![
                parent.join("collection-tools").join(name),
                parent.join("../collection-tools").join(name),
            ]
        })
        .unwrap_or_default()
}
fn find_binary(variable: &str, name: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("PATH").and_then(|paths| {
                std::env::split_paths(&paths)
                    .map(|p| p.join(name))
                    .find(|p| p.is_file())
            })
        })
        .or_else(|| companion_files(name).into_iter().find(|p| p.is_file()))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tools() -> RuntimeTools {
        RuntimeTools {
            collector: std::env::current_exe().unwrap(),
            snmp_exporter: std::env::current_exe().unwrap(),
        }
    }
    fn account() -> Credentials {
        Credentials {
            username: "monitor".into(),
            password: "auth-secret".into(),
            privacy_password: "priv-secret".into(),
            ..Default::default()
        }
    }
    fn device_target(profile_id: &str) -> DeviceTarget {
        DeviceTarget::New {
            profile_id: profile_id.into(),
            address: "192.0.2.10".into(),
        }
    }
    fn saved_json() -> serde_json::Value {
        serde_json::json!({"schema_version":1,"devices":[{"id":"lab-ios","name":"Lab IOS","address":"10.0.2.15","profile_id":"cisco-iosvl2","gateway":{"metrics_url":"http://127.0.0.1:2245/snmp?target=127.0.0.1%3A1161&auth=session&module=system,if_mib,cisco_device"}}]})
    }
    #[test]
    fn model_selects_access_policy_and_never_downgrades_for_missing_credentials() {
        let catalog = Catalog::bundled().unwrap();
        let saved = SavedDevices::default();
        let target = device_target("cisco-iosvl2");
        assert_eq!(
            catalog.credentials_for(&target, &saved).unwrap(),
            RequiredCredentials::MonitoringAccount
        );
        assert!(
            catalog
                .plan_device(
                    &target,
                    &saved,
                    Credentials {
                        access_key: "community-is-not-a-v3-account".into(),
                        ..Default::default()
                    },
                    &tools()
                )
                .is_err()
        );
        let plan = catalog
            .plan_device(&target, &saved, account(), &tools())
            .unwrap();
        assert_eq!(plan.device.model, "IOSvL2");
        assert_eq!(plan.device.vendor, "Cisco");
        assert_eq!(plan.interval_seconds, 10);
        assert!(
            matches!(plan.source,Source::Snmp {target,credentials:SnmpCredentials::V3 {..},..} if target=="192.0.2.10:161")
        );
        assert_eq!(
            catalog.resolve(&plan.profile_id).unwrap().snmp_modules,
            ["system", "if_mib", "cisco_ios_legacy"]
        );
        assert!(
            catalog
                .plan_device(&device_target("unknown-model"), &saved, account(), &tools())
                .is_err()
        );
        assert!(
            catalog
                .plan_device(
                    &device_target("native-prometheus"),
                    &saved,
                    Credentials::default(),
                    &tools()
                )
                .is_err()
        );
    }
    #[test]
    fn site_gateway_changes_the_route_and_credentials_only_for_its_saved_device() {
        let catalog = Catalog::bundled().unwrap();
        let mut json = saved_json();
        let saved = SavedDevices::from_json(&json.to_string(), &catalog).unwrap();
        let selected = DeviceTarget::Saved("lab-ios".into());
        assert_eq!(
            catalog.credentials_for(&selected, &saved).unwrap(),
            RequiredCredentials::None
        );
        // Exporter is not installed: this route must still work through the gateway.
        let tools = RuntimeTools {
            snmp_exporter: PathBuf::new(),
            ..tools()
        };
        let plan = catalog
            .plan_device(&selected, &saved, Credentials::default(), &tools)
            .unwrap();
        assert_eq!(plan.device.id, "lab-ios");
        assert!(
            matches!(plan.source,Source::Prometheus {endpoint,..} if endpoint.contains("2245/snmp?"))
        );
        assert!(
            catalog
                .plan_device(
                    &device_target("cisco-iosvl2"),
                    &saved,
                    Credentials::default(),
                    &tools
                )
                .is_err()
        );
        json["devices"][0]["gateway"]["bearer_required"] = true.into();
        let saved = SavedDevices::from_json(&json.to_string(), &catalog).unwrap();
        assert_eq!(
            catalog.credentials_for(&selected, &saved).unwrap(),
            RequiredCredentials::BearerToken
        );
        assert!(
            catalog
                .plan_device(&selected, &saved, Credentials::default(), &tools)
                .is_err()
        );
        assert!(
            catalog
                .plan_device(
                    &selected,
                    &saved,
                    Credentials {
                        access_key: "token".into(),
                        ..Default::default()
                    },
                    &tools
                )
                .is_ok()
        );
    }
    #[test]
    fn model_policy_overrides_parent_and_requests_only_its_access_credential() {
        let mut catalog = Catalog::bundled().unwrap();
        catalog.profiles.get_mut("cisco-iosvl2").unwrap().connection =
            Some(ConnectionPolicy::SnmpCommunity {
                port: 1161,
                interval_seconds: 20,
            });
        let target = device_target("cisco-iosvl2");
        let saved = SavedDevices::default();
        assert_eq!(
            catalog.credentials_for(&target, &saved).unwrap(),
            RequiredCredentials::ReadOnlyCommunity
        );
        let plan = catalog
            .plan_device(
                &target,
                &saved,
                Credentials {
                    access_key: "read-only".into(),
                    ..Default::default()
                },
                &tools(),
            )
            .unwrap();
        assert_eq!(plan.interval_seconds, 20);
        assert!(
            matches!(plan.source,Source::Snmp {target,credentials:SnmpCredentials::V2c {..},..} if target=="192.0.2.10:1161")
        );
        catalog.profiles.get_mut("cisco-iosvl2").unwrap().connection =
            Some(ConnectionPolicy::Prometheus {
                scheme: "https".into(),
                port: 9443,
                path: "/device/metrics".into(),
                bearer_required: true,
                interval_seconds: 15,
            });
        assert_eq!(
            catalog.credentials_for(&target, &saved).unwrap(),
            RequiredCredentials::BearerToken
        );
        let plan = catalog
            .plan_device(
                &target,
                &saved,
                Credentials {
                    access_key: "token".into(),
                    ..Default::default()
                },
                &tools(),
            )
            .unwrap();
        assert!(
            matches!(plan.source,Source::Prometheus {endpoint,bearer_token} if endpoint=="https://192.0.2.10:9443/device/metrics" && bearer_token=="token")
        );
    }
    #[test]
    fn saved_devices_reject_ambiguous_invalid_and_secret_bearing_records() {
        let catalog = Catalog::bundled().unwrap();
        let json = saved_json();
        let mut duplicate = json.clone();
        duplicate["devices"]
            .as_array_mut()
            .unwrap()
            .push(json["devices"][0].clone());
        assert!(SavedDevices::from_json(&duplicate.to_string(), &catalog).is_err());
        for (field, value) in [
            ("profile_id", "unknown"),
            ("address", "http://router"),
            ("password", "must-not-persist"),
        ] {
            let mut invalid = json.clone();
            invalid["devices"][0][field] = value.into();
            assert!(SavedDevices::from_json(&invalid.to_string(), &catalog).is_err());
        }
        for endpoint in [
            "http://user:password@localhost/metrics",
            "http://localhost/snmp?community=secret",
        ] {
            let mut invalid = json.clone();
            invalid["devices"][0]["gateway"]["metrics_url"] = endpoint.into();
            assert!(SavedDevices::from_json(&invalid.to_string(), &catalog).is_err());
        }
        assert!(SavedDevices::from_json(&" ".repeat(65537), &catalog).is_err());
    }
    #[test]
    fn device_addresses_preserve_custom_ports_and_ipv6_and_reject_urls() {
        for (input, expected) in [
            ("192.0.2.1", "192.0.2.1:161"),
            ("router.example:80", "router.example:80"),
            ("::1", "[::1]:161"),
            ("[2001:db8::1]:1161", "[2001:db8::1]:1161"),
        ] {
            assert_eq!(address(input, 161).unwrap(), expected);
        }
        for input in [
            "",
            "http://router",
            "router/metrics",
            "user@router",
            "router:0",
            "router:invalid",
            "router?token=secret",
            "bad host",
        ] {
            assert!(address(input, 161).is_err(), "{input}");
        }
    }
    #[test]
    fn saved_direct_access_loads_private_credentials_and_starts_a_local_snmp_plan() {
        use std::io::Write;
        let catalog = Catalog::bundled().unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "{{\"community\":\"test-read-only\"}}").unwrap();
        let mut json = saved_json();
        let record = &mut json["devices"][0];
        record.as_object_mut().unwrap().remove("gateway");
        record["address"] = "127.0.0.1:1161".into();
        record["connection"] =
            serde_json::json!({"kind":"snmp_community","port":161,"interval_seconds":30});
        record["credentials_file"] = file.path().to_string_lossy().to_string().into();
        let saved = SavedDevices::from_json(&json.to_string(), &catalog).unwrap();
        let selected = DeviceTarget::Saved("lab-ios".into());
        assert_eq!(
            catalog.credentials_for(&selected, &saved).unwrap(),
            RequiredCredentials::None
        );
        let plan = catalog
            .plan_device(&selected, &saved, Credentials::default(), &tools())
            .unwrap();
        assert!(
            matches!(plan.source,Source::Snmp {target,credentials:SnmpCredentials::V2c {community},..} if target=="127.0.0.1:1161" && community=="test-read-only")
        );
        assert!(
            !serde_json::to_string(&saved)
                .unwrap()
                .contains("test-read-only")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(
                catalog
                    .plan_device(&selected, &saved, Credentials::default(), &tools())
                    .err()
                    .unwrap()
                    .contains("0600")
            );
        }
        file.close().unwrap();
        assert!(
            catalog
                .plan_device(&selected, &saved, Credentials::default(), &tools())
                .is_err()
        );
        json["devices"][0]["credentials_file"] = "relative-private.json".into();
        assert!(SavedDevices::from_json(&json.to_string(), &catalog).is_err());
    }
}
