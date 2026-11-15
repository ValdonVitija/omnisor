use crate::catalog::{Catalog, DeviceIdentity, asset};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf};
use url::Url;

/// Secrets deliberately have no Debug/Serialize implementation.
pub enum SnmpCredentials {
    V2c {
        community: String,
    },
    V3 {
        username: String,
        auth_password: String,
        priv_password: String,
    },
}

pub enum Source {
    Synthetic,
    Prometheus {
        endpoint: String,
        bearer_token: String,
    },
    Snmp {
        target: String,
        credentials: SnmpCredentials,
        exporter: PathBuf,
    },
}

impl Source {
    pub fn adapter(&self) -> &'static str {
        match self {
            Self::Synthetic => "synthetic",
            Self::Prometheus { .. } => "prometheus",
            Self::Snmp { .. } => "snmp",
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::Synthetic => "Synthetic exporter",
            Self::Prometheus { .. } => "Prometheus endpoint",
            Self::Snmp { .. } => "SNMP exporter",
        }
    }
    pub(crate) fn secrets(&self) -> Vec<String> {
        match self {
            Self::Synthetic => vec![],
            Self::Prometheus { bearer_token, .. } => vec![bearer_token.clone()],
            Self::Snmp {
                credentials: SnmpCredentials::V2c { community },
                ..
            } => vec![community.clone()],
            Self::Snmp {
                credentials:
                    SnmpCredentials::V3 {
                        username,
                        auth_password,
                        priv_password,
                    },
                ..
            } => vec![
                username.clone(),
                auth_password.clone(),
                priv_password.clone(),
            ],
        }
    }
}

pub struct CollectionPlan {
    pub device: DeviceIdentity,
    pub profile_id: String,
    pub interval_seconds: u64,
    pub collector: PathBuf,
    pub source: Source,
}

impl CollectionPlan {
    pub fn validate(&self, catalog: &Catalog) -> Result<(), String> {
        if self.device.id.is_empty()
            || self.device.id.len() > 80
            || !self
                .device
                .id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
        {
            return Err(
                "Device ID must contain 1–80 letters, numbers, hyphens or underscores".into(),
            );
        }
        if self.device.name.trim().is_empty() {
            return Err("Enter a device name".into());
        }
        for field in [
            &self.device.name,
            &self.device.vendor,
            &self.device.model,
            &self.device.os,
            &self.device.os_version,
            &self.device.device_type,
        ] {
            if field.len() > 256 || field.chars().any(char::is_control) {
                return Err("Device details must be single-line text up to 256 bytes".into());
            }
        }
        if !(2..=300).contains(&self.interval_seconds) {
            return Err("Collection interval must be 2–300 seconds".into());
        }
        if !self.collector.is_file() {
            return Err("Select an installed otelcol-contrib executable".into());
        }
        let profile = catalog.resolve(&self.profile_id)?;
        if !profile
            .adapters
            .iter()
            .any(|adapter| adapter == self.source.adapter())
        {
            return Err("The selected profile does not support this collection method".into());
        }
        match &self.source {
            Source::Synthetic => {}
            Source::Prometheus {
                endpoint,
                bearer_token,
            } => {
                validate_endpoint(endpoint)?;
                if bearer_token.chars().any(char::is_control) {
                    return Err("Bearer token cannot contain control characters".into());
                }
            }
            Source::Snmp {
                target,
                credentials,
                exporter,
            } => {
                if !exporter.is_file() {
                    return Err("Select an installed snmp_exporter executable".into());
                }
                let address = if target.contains("://") {
                    target.clone()
                } else {
                    format!("udp://{target}")
                };
                let address =
                    Url::parse(&address).map_err(|_| "Enter an SNMP host or host:port")?;
                if !["udp", "tcp"].contains(&address.scheme())
                    || address.host_str().is_none()
                    || !address.username().is_empty()
                    || address.password().is_some()
                    || !address.path().is_empty()
                    || address.query().is_some()
                    || address.fragment().is_some()
                {
                    return Err("SNMP target must be a hostname/IP with optional port and udp:// or tcp:// transport".into());
                }
                match credentials {
                    SnmpCredentials::V2c { community } if community.is_empty() => return Err("Enter the read-only SNMP community".into()),
                    SnmpCredentials::V3 { username, auth_password, priv_password } if username.is_empty() || auth_password.len() < 8 || priv_password.len() < 8 => return Err("SNMPv3 requires a username and authentication/privacy passwords of at least 8 bytes (SHA/AES)".into()),
                    _ => {},
                }
                if profile.snmp_modules.is_empty() {
                    return Err("Profile declares no SNMP modules".into());
                }
            }
        }
        Ok(())
    }

    pub fn collector_yaml(
        &self,
        catalog: &Catalog,
        ingest: &str,
        exporter: Option<&str>,
    ) -> Result<String, String> {
        let profile = catalog.resolve(&self.profile_id)?;
        let timeout = self.interval_seconds.saturating_sub(1).clamp(1, 25);
        let (endpoint, mut params) = match &self.source {
            Source::Synthetic => (format!("http://{ingest}/synthetic/metrics"), json!({})),
            Source::Prometheus { endpoint, .. } => (endpoint.clone(), json!({})),
            Source::Snmp { target, .. } => (
                format!(
                    "http://{}/snmp",
                    exporter.ok_or("Missing managed exporter address")?
                ),
                json!({"target":[literal(target)], "auth":["session"], "module":[profile.snmp_modules.join(",")]}),
            ),
        };
        let endpoint = Url::parse(&endpoint).map_err(|e| e.to_string())?;
        // Exporters such as SNMP and blackbox receive target/module parameters
        // in the query. Preserve repeated values and escape Collector expansion.
        for (key, value) in endpoint.query_pairs() {
            let entry = params
                .as_object_mut()
                .expect("parameter map")
                .entry(literal(&key))
                .or_insert_with(|| json!([]));
            entry
                .as_array_mut()
                .expect("parameter values")
                .push(json!(literal(&value)));
        }
        let mut job = json!({
            "job_name": "device-health",
            "scheme": endpoint.scheme(),
            "metrics_path": literal(endpoint.path()),
            "honor_labels": false,
            "honor_timestamps": false,
            "scrape_interval": format!("{}s", self.interval_seconds),
            "scrape_timeout": format!("{timeout}s"),
            "sample_limit": 10000,
            "label_limit": 40,
            "label_value_length_limit": 1024,
            "params": params,
            "static_configs": [{"targets":[literal(&endpoint[url::Position::BeforeHost..url::Position::AfterPort])],
                "labels":{"device_id":literal(&self.device.id), "adapter_id":self.source.adapter()}}]
        });
        // Only retain explicitly mapped series and Prometheus's scrape health.
        // This bounds downstream cardinality and avoids storing unrelated metrics.
        let names = profile
            .mappings
            .keys()
            .map(|name| regex_literal(name))
            .collect::<Vec<_>>()
            .join("|");
        job["metric_relabel_configs"] =
            json!([{"source_labels":["__name__"],"regex":format!("({names})"),"action":"keep"}]);
        if let Source::Prometheus { bearer_token, .. } = &self.source
            && !bearer_token.is_empty()
        {
            job["authorization"] =
                json!({"type":"Bearer", "credentials":"${env:OMNISOR_SOURCE_TOKEN}"});
        }
        let mut config: Value =
            serde_yaml_ng::from_str(asset(&catalog.components.collector.base_config)?)
                .map_err(|e| e.to_string())?;
        config["receivers"]["prometheus/device"]["config"]["scrape_configs"] = json!([job]);
        config["exporters"]["otlphttp/desktop"]["endpoint"] = json!(format!("http://{ingest}"));
        serde_yaml_ng::to_string(&config).map_err(|e| e.to_string())
    }

    pub fn snmp_yaml(&self, catalog: &Catalog) -> Result<String, String> {
        let Source::Snmp { credentials, .. } = &self.source else {
            return Err("Not an SNMP plan".into());
        };
        let auth = match credentials {
            SnmpCredentials::V2c { community } => json!({"version":2,"community":community}),
            SnmpCredentials::V3 {
                username,
                auth_password,
                priv_password,
            } => {
                json!({"version":3,"security_level":"authPriv","username":username,"auth_protocol":"SHA","password":auth_password,"priv_protocol":"AES","priv_password":priv_password})
            }
        };
        let mut modules = BTreeMap::new();
        for module in catalog.resolve(&self.profile_id)?.snmp_modules {
            let yaml: serde_yaml_ng::Value = serde_yaml_ng::from_str(asset(&format!(
                "{}/{module}.yaml",
                catalog.components.snmp_exporter.modules_directory
            ))?)
            .map_err(|e| e.to_string())?;
            modules.insert(module.clone(), yaml["modules"][&module].clone());
        }
        #[derive(serde::Serialize)]
        struct ExporterConfig {
            auths: BTreeMap<String, Value>,
            modules: BTreeMap<String, serde_yaml_ng::Value>,
        }
        // Keep YAML integer enum keys as integers; a JSON round-trip would
        // silently stringify them and fail the exporter's strict Go decoder.
        serde_yaml_ng::to_string(&ExporterConfig {
            auths: BTreeMap::from([("session".into(), auth)]),
            modules,
        })
        .map_err(|e| e.to_string())
    }
}

pub(crate) fn validate_endpoint(endpoint: &str) -> Result<(), String> {
    let url = Url::parse(endpoint).map_err(|_| "Enter a complete HTTP(S) metrics URL")?;
    if !["http", "https"].contains(&url.scheme())
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "Metrics URL must be HTTP(S), without embedded credentials or a fragment".into(),
        );
    }
    if url.query_pairs().any(|(key, _)| {
        [
            "password",
            "community",
            "token",
            "access_token",
            "api_key",
            "secret",
        ]
        .contains(&key.to_ascii_lowercase().as_str())
    }) {
        return Err("Use the bearer-token field or the exporter's named authentication; credentials must not be placed in URL query parameters".into());
    }
    Ok(())
}
fn literal(text: &str) -> String {
    text.replace('$', "$$")
}
fn regex_literal(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if ".+*?()|[]{}^$\\".contains(c) {
                vec!['\\', c]
            } else {
                vec![c]
            }
        })
        .collect()
}
