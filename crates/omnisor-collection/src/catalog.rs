use omnisor_telemetry::{Configuration, Conversion, Device, Mapping, MetricKind, Profile};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

include!(concat!(env!("OUT_DIR"), "/assets.rs"));

pub fn asset(path: &str) -> Result<&'static str, String> {
    ASSETS
        .iter()
        .find(|(key, _)| *key == path)
        .map(|(_, value)| *value)
        .ok_or_else(|| format!("Missing bundled collection asset: {path}"))
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceIdentity {
    pub id: String,
    pub name: String,
    pub vendor: String,
    pub model: String,
    pub device_type: String,
    pub os: String,
    pub os_version: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceProfile {
    pub id: String,
    pub revision: String,
    pub title: String,
    pub vendor: String,
    pub os: String,
    pub support: String,
    pub adapters: Vec<String>,
    #[serde(default)]
    pub extends: Vec<String>,
    #[serde(default)]
    pub snmp_modules: Vec<String>,
    #[serde(default)]
    pub mappings: BTreeMap<String, Mapping>,
    #[serde(default)]
    pub device: Option<crate::access::DeviceDetails>,
    #[serde(default)]
    pub connection: Option<crate::access::ConnectionPolicy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    schema_version: u32,
    profiles: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorComponent {
    pub version: String,
    pub base_config: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnmpComponent {
    pub version: String,
    pub modules_directory: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Components {
    pub collector: CollectorComponent,
    pub snmp_exporter: SnmpComponent,
}

#[derive(Clone)]
pub struct Catalog {
    pub profiles: BTreeMap<String, DeviceProfile>,
    pub components: Components,
}

impl Catalog {
    pub fn bundled() -> Result<Self, String> {
        let index: Index =
            serde_yaml_ng::from_str(asset("catalog.yaml")?).map_err(|e| e.to_string())?;
        if index.schema_version != 1 {
            return Err("Unsupported collection catalog version".into());
        }
        let mut profiles = BTreeMap::new();
        for path in index.profiles {
            let profile: DeviceProfile =
                serde_yaml_ng::from_str(asset(&path)?).map_err(|e| format!("{path}: {e}"))?;
            if profiles.insert(profile.id.clone(), profile).is_some() {
                return Err("Duplicate collection profile ID".into());
            }
        }
        let components =
            serde_yaml_ng::from_str(asset("components.yaml")?).map_err(|e| e.to_string())?;
        let catalog = Self {
            profiles,
            components,
        };
        asset(&catalog.components.collector.base_config)?;
        for id in catalog.profiles.keys() {
            let profile = catalog.resolve(id)?;
            if profile.device.is_some() && profile.connection.is_none() {
                return Err(format!("Device profile {id} has no connection policy"));
            }
            if let Some(policy) = &profile.connection {
                policy.validate(&profile)?;
            }
            for module in profile.snmp_modules {
                asset(&format!(
                    "{}/{module}.yaml",
                    catalog.components.snmp_exporter.modules_directory
                ))?;
            }
        }
        Ok(catalog)
    }

    pub fn resolve(&self, id: &str) -> Result<DeviceProfile, String> {
        self.resolve_inner(id, &mut Vec::new())
    }

    fn resolve_inner(&self, id: &str, stack: &mut Vec<String>) -> Result<DeviceProfile, String> {
        if stack.iter().any(|ancestor| ancestor == id) || stack.len() >= 12 {
            return Err(format!("Profile inheritance cycle/depth at {id}"));
        }
        let mut profile = self
            .profiles
            .get(id)
            .cloned()
            .ok_or_else(|| format!("Unknown profile: {id}"))?;
        stack.push(id.into());
        let mut mappings = BTreeMap::new();
        let mut modules = Vec::new();
        let mut inherited_connection = None;
        for parent in &profile.extends {
            let inherited = self.resolve_inner(parent, stack)?;
            if let Some(connection) = inherited.connection {
                if profile.connection.is_none()
                    && inherited_connection
                        .as_ref()
                        .is_some_and(|prior| prior != &connection)
                {
                    return Err(format!("Conflicting connection policies for profile {id}"));
                }
                inherited_connection = Some(connection);
            }
            mappings.extend(inherited.mappings);
            for module in inherited.snmp_modules {
                if !modules.contains(&module) {
                    modules.push(module);
                }
            }
        }
        stack.pop();
        mappings.extend(profile.mappings);
        for module in profile.snmp_modules {
            if !modules.contains(&module) {
                modules.push(module);
            }
        }
        mappings.insert(
            "up".into(),
            Mapping {
                name: "collection.scrape.up".into(),
                unit: "1".into(),
                conversion: Conversion::Identity,
                kind: MetricKind::Gauge,
                entity_label: None,
                window_seconds: None,
            },
        );
        profile.mappings = mappings;
        profile.snmp_modules = modules;
        profile.connection = profile.connection.or(inherited_connection);
        if profile.revision.is_empty() || profile.adapters.is_empty() {
            return Err(format!("Incomplete profile {id}"));
        }
        Ok(profile)
    }

    pub fn normalization(
        &self,
        profile_id: &str,
        device: &DeviceIdentity,
    ) -> Result<Configuration, String> {
        let profile = self.resolve(profile_id)?;
        let config = Configuration {
            devices: BTreeMap::from([(
                device.id.clone(),
                Device {
                    profile: profile.id.clone(),
                    vendor: device.vendor.clone(),
                    os: device.os.clone(),
                },
            )]),
            profiles: BTreeMap::from([(
                profile.id,
                Profile {
                    revision: profile.revision,
                    enabled: true,
                    mappings: profile.mappings,
                },
            )]),
        };
        config.validate().map_err(|e| e.to_string())?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cisco_inherits_interfaces_and_overrides_cpu_memory_without_duplication() {
        let catalog = Catalog::bundled().unwrap();
        let profile = catalog.resolve("cisco-ios-snmp").unwrap();
        assert_eq!(profile.snmp_modules, ["system", "if_mib", "cisco_device"]);
        assert_eq!(
            profile.mappings["ciscoMemoryPoolUsed"]
                .entity_label
                .as_deref(),
            Some("ciscoMemoryPoolType")
        );
        assert!(profile.mappings.contains_key("ifHCInOctets"));
        assert_eq!(
            profile.mappings["cpmCPUTotal1minRev"].window_seconds,
            Some(60)
        );
        let mut cyclic = catalog.clone();
        cyclic
            .profiles
            .get_mut("generic-if-mib")
            .unwrap()
            .extends
            .push("cisco-ios-snmp".into());
        assert!(cyclic.resolve("cisco-ios-snmp").is_err());
    }
}
