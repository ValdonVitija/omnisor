mod cisco;

use omnisor::device::DeviceVendor;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct HealthConnectionConfig {
    pub address: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub vendor: DeviceVendor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SectionStatus {
    Ok,
    Warning,
    Critical,
    Unknown,
}

impl SectionStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warning => "WARNING",
            Self::Critical => "CRITICAL",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityStatus {
    Reachable,
    Unreachable,
    Unknown,
}

impl ReachabilityStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Reachable => "Reachable",
            Self::Unreachable => "Unreachable",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    pub hostname: String,
    pub management_address: String,
    pub vendor: String,
}

#[derive(Debug, Clone)]
pub struct SystemHealth {
    pub status: SectionStatus,
    pub cpu_percent: Option<f32>,
    pub memory_percent: Option<f32>,
    pub uptime: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InterfaceIssue {
    pub name: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct InterfaceHealth {
    pub status: SectionStatus,
    pub total: usize,
    pub up: usize,
    pub down: usize,
    pub admin_down: usize,
    pub notable_issues: Vec<InterfaceIssue>,
}

#[derive(Debug, Clone)]
pub struct NeighborHealth {
    pub protocol: &'static str,
    pub local_interface: String,
    pub neighbor_id: String,
    pub remote_interface: Option<String>,
    pub management_ip: Option<String>,
    pub reachability: ReachabilityStatus,
}

#[derive(Debug, Clone)]
pub struct NeighborsSection {
    pub status: SectionStatus,
    pub protocols_seen: Vec<&'static str>,
    pub entries: Vec<NeighborHealth>,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub status: SectionStatus,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct CheckMetadata {
    pub name: &'static str,
    pub status: SectionStatus,
    pub details: String,
}

#[derive(Debug, Clone)]
pub struct DeviceHealthSnapshot {
    pub device: DeviceIdentity,
    pub system: SystemHealth,
    pub interfaces: InterfaceHealth,
    pub neighbors: NeighborsSection,
    pub findings: Vec<Finding>,
    pub metadata: Vec<CheckMetadata>,
    pub collected_at: Instant,
}

impl DeviceHealthSnapshot {
    pub fn refresh_age_secs(&self) -> u64 {
        self.collected_at.elapsed().as_secs()
    }

    pub fn neighbor_summary(&self) -> NeighborReachabilitySummary {
        let mut summary = NeighborReachabilitySummary {
            total: self.neighbors.entries.len(),
            reachable: 0,
            unreachable: 0,
            unknown: 0,
        };

        for neighbor in &self.neighbors.entries {
            match neighbor.reachability {
                ReachabilityStatus::Reachable => summary.reachable += 1,
                ReachabilityStatus::Unreachable => summary.unreachable += 1,
                ReachabilityStatus::Unknown => summary.unknown += 1,
            }
        }

        summary
    }

    pub fn finding_summary(&self) -> SeveritySummary {
        let mut summary = SeveritySummary::default();

        for finding in &self.findings {
            match finding.status {
                SectionStatus::Ok => summary.ok += 1,
                SectionStatus::Warning => summary.warning += 1,
                SectionStatus::Critical => summary.critical += 1,
                SectionStatus::Unknown => summary.unknown += 1,
            }
        }

        summary
    }

    pub fn interface_distribution(&self) -> InterfaceDistribution {
        let total = self.interfaces.total.max(1);
        InterfaceDistribution {
            up_ratio: self.interfaces.up as f32 / total as f32,
            down_ratio: self.interfaces.down as f32 / total as f32,
            admin_down_ratio: self.interfaces.admin_down as f32 / total as f32,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NeighborReachabilitySummary {
    pub total: usize,
    pub reachable: usize,
    pub unreachable: usize,
    pub unknown: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeveritySummary {
    pub ok: usize,
    pub warning: usize,
    pub critical: usize,
    pub unknown: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InterfaceDistribution {
    pub up_ratio: f32,
    pub down_ratio: f32,
    pub admin_down_ratio: f32,
}

pub async fn collect_device_health(
    config: &HealthConnectionConfig,
) -> Result<DeviceHealthSnapshot, String> {
    match &config.vendor {
        DeviceVendor::Cisco(variant) => cisco::collect_cisco_device_health(config, *variant).await,
        DeviceVendor::Juniper(variant) => Err(format!(
            "device health is not implemented yet for {}",
            juniper_label(*variant)
        )),
        DeviceVendor::Custom(_) => {
            Err("device health is not implemented yet for custom device profiles".to_string())
        }
        _ => Err("device health is not implemented yet for this device vendor".to_string()),
    }
}

pub async fn collect_cisco_device_health(
    config: &HealthConnectionConfig,
) -> Result<DeviceHealthSnapshot, String> {
    match &config.vendor {
        DeviceVendor::Cisco(variant) => cisco::collect_cisco_device_health(config, *variant).await,
        _ => Err("collect_cisco_device_health requires a Cisco device vendor".to_string()),
    }
}

pub fn findings_status(findings: &[Finding]) -> SectionStatus {
    if findings.is_empty() {
        return SectionStatus::Ok;
    }
    combine_statuses(&findings.iter().map(|finding| finding.status).collect::<Vec<_>>())
}

pub fn combine_statuses(statuses: &[SectionStatus]) -> SectionStatus {
    if statuses.is_empty() {
        return SectionStatus::Unknown;
    }

    let mut has_unknown = false;
    let mut best = SectionStatus::Ok;

    for status in statuses {
        match status {
            SectionStatus::Critical => return SectionStatus::Critical,
            SectionStatus::Warning => best = SectionStatus::Warning,
            SectionStatus::Unknown => has_unknown = true,
            SectionStatus::Ok => {}
        }
    }

    if best == SectionStatus::Warning {
        SectionStatus::Warning
    } else if has_unknown {
        SectionStatus::Unknown
    } else {
        SectionStatus::Ok
    }
}

pub fn status_from_percent(value: f32, warning: f32, critical: f32) -> SectionStatus {
    if value >= critical {
        SectionStatus::Critical
    } else if value >= warning {
        SectionStatus::Warning
    } else {
        SectionStatus::Ok
    }
}

pub(crate) fn derive_neighbors_status(
    neighbors: &[NeighborHealth],
    no_protocols: bool,
) -> SectionStatus {
    if no_protocols {
        return SectionStatus::Unknown;
    }
    if neighbors
        .iter()
        .any(|neighbor| neighbor.reachability == ReachabilityStatus::Unreachable)
    {
        return SectionStatus::Warning;
    }
    if neighbors
        .iter()
        .any(|neighbor| neighbor.reachability == ReachabilityStatus::Unknown)
    {
        return SectionStatus::Unknown;
    }
    SectionStatus::Ok
}

fn juniper_label(variant: omnisor::JuniperVariant) -> &'static str {
    match variant {
        omnisor::JuniperVariant::Junos => "Juniper Junos",
        omnisor::JuniperVariant::ScreenOs => "Juniper ScreenOS",
        _ => "Juniper Device",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnisor::{DeviceVendor, JuniperVariant};
    use std::time::Duration;

    fn sample_snapshot() -> DeviceHealthSnapshot {
        DeviceHealthSnapshot {
            device: DeviceIdentity {
                hostname: "router-1".to_string(),
                management_address: "192.0.2.10:22".to_string(),
                vendor: "Cisco IOS (Legacy)".to_string(),
            },
            system: SystemHealth {
                status: SectionStatus::Warning,
                cpu_percent: Some(82.0),
                memory_percent: None,
                uptime: Some("1 week".to_string()),
            },
            interfaces: InterfaceHealth {
                status: SectionStatus::Warning,
                total: 4,
                up: 2,
                down: 1,
                admin_down: 1,
                notable_issues: vec![InterfaceIssue {
                    name: "Fa0/1".to_string(),
                    detail: "status: down, protocol: down".to_string(),
                }],
            },
            neighbors: NeighborsSection {
                status: SectionStatus::Unknown,
                protocols_seen: vec!["CDP", "LLDP"],
                entries: vec![
                    NeighborHealth {
                        protocol: "CDP",
                        local_interface: "Fa0/0".to_string(),
                        neighbor_id: "sw1".to_string(),
                        remote_interface: Some("Gi0/24".to_string()),
                        management_ip: Some("10.0.0.2".to_string()),
                        reachability: ReachabilityStatus::Reachable,
                    },
                    NeighborHealth {
                        protocol: "LLDP",
                        local_interface: "Fa0/1".to_string(),
                        neighbor_id: "sw2".to_string(),
                        remote_interface: Some("Gi0/23".to_string()),
                        management_ip: None,
                        reachability: ReachabilityStatus::Unknown,
                    },
                    NeighborHealth {
                        protocol: "CDP",
                        local_interface: "Fa0/2".to_string(),
                        neighbor_id: "sw3".to_string(),
                        remote_interface: Some("Gi0/22".to_string()),
                        management_ip: Some("10.0.0.3".to_string()),
                        reachability: ReachabilityStatus::Unreachable,
                    },
                ],
            },
            findings: vec![
                Finding {
                    status: SectionStatus::Warning,
                    message: "A neighbor did not answer ping.".to_string(),
                },
                Finding {
                    status: SectionStatus::Unknown,
                    message: "Memory usage could not be parsed.".to_string(),
                },
            ],
            metadata: vec![CheckMetadata {
                name: "System CPU",
                status: SectionStatus::Warning,
                details: "CPU one-minute usage 82.0%".to_string(),
            }],
            collected_at: Instant::now() - Duration::from_secs(5),
        }
    }

    #[test]
    fn unsupported_vendor_returns_clear_error() {
        let config = HealthConnectionConfig {
            address: "192.0.2.10".to_string(),
            port: 22,
            username: "admin".to_string(),
            password: "pass".to_string(),
            vendor: DeviceVendor::Juniper(JuniperVariant::Junos),
        };

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let err = runtime.block_on(collect_device_health(&config)).unwrap_err();
        assert!(err.contains("Juniper Junos"));
    }

    #[test]
    fn cisco_only_entrypoint_rejects_non_cisco_vendor() {
        let config = HealthConnectionConfig {
            address: "192.0.2.10".to_string(),
            port: 22,
            username: "admin".to_string(),
            password: "pass".to_string(),
            vendor: DeviceVendor::Juniper(JuniperVariant::Junos),
        };

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let err = runtime.block_on(collect_cisco_device_health(&config)).unwrap_err();
        assert!(err.contains("requires a Cisco device vendor"));
    }

    #[test]
    fn neighbor_summary_counts_all_states() {
        let snapshot = sample_snapshot();
        let summary = snapshot.neighbor_summary();
        assert_eq!(
            summary,
            NeighborReachabilitySummary {
                total: 3,
                reachable: 1,
                unreachable: 1,
                unknown: 1,
            }
        );
    }

    #[test]
    fn finding_summary_counts_severities() {
        let snapshot = sample_snapshot();
        let summary = snapshot.finding_summary();
        assert_eq!(
            summary,
            SeveritySummary {
                ok: 0,
                warning: 1,
                critical: 0,
                unknown: 1,
            }
        );
    }

    #[test]
    fn interface_distribution_matches_counts() {
        let snapshot = sample_snapshot();
        let distribution = snapshot.interface_distribution();
        assert!((distribution.up_ratio - 0.5).abs() < f32::EPSILON);
        assert!((distribution.down_ratio - 0.25).abs() < f32::EPSILON);
        assert!((distribution.admin_down_ratio - 0.25).abs() < f32::EPSILON);
    }
}
