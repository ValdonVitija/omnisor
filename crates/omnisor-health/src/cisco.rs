use crate::{
    CheckMetadata, CommandExecutor, DeviceHealthSnapshot, DeviceIdentity, Finding, HealthError,
    HealthFuture, HealthProvider, HealthTarget, InterfaceHealth, NeighborsSection,
    ReachabilityStatus, SectionStatus, SystemHealth, derive_neighbors_status, status_from_percent,
};
use omnisor::CiscoVariant;
use std::{collections::HashMap, net::IpAddr, time::Instant};

mod parsers;
use parsers::*;

/// IOS-family health commands and parsers, independent of the SSH transport.
#[derive(Debug, Clone, Copy)]
pub struct CiscoIosHealthProvider {
    variant: CiscoVariant,
}

impl CiscoIosHealthProvider {
    pub fn new(variant: CiscoVariant) -> Result<Self, HealthError> {
        if crate::provider::SUPPORTED_CISCO_IOS_VARIANTS.contains(&variant) {
            Ok(Self { variant })
        } else {
            Err(HealthError::UnsupportedVendor(variant.to_string()))
        }
    }
}

impl HealthProvider for CiscoIosHealthProvider {
    fn collect<'a>(
        &'a self,
        executor: &'a mut dyn CommandExecutor,
        target: &'a HealthTarget,
    ) -> HealthFuture<'a> {
        Box::pin(collect_cisco_ios_health(executor, target, self.variant))
    }
}

async fn collect_cisco_ios_health(
    session: &mut dyn CommandExecutor,
    target: &HealthTarget,
    variant: CiscoVariant,
) -> Result<DeviceHealthSnapshot, HealthError> {
    let mut findings = Vec::new();
    let mut metadata = Vec::new();

    let hostname_result = run_command(
        session,
        "Device Identity",
        "show running-config | include ^hostname",
    )
    .await?;
    let version_result = run_command(session, "Version", "show version | include uptime").await?;
    let cpu_result = run_command(
        session,
        "System CPU",
        "show processes cpu | include one minute:",
    )
    .await?;
    let memory_result = run_command(
        session,
        "System Memory",
        "show processes memory | include Processor Pool Total:",
    )
    .await?;
    let interfaces_result = run_command(session, "Interfaces", "show ip interface brief").await?;
    let cdp_result = run_command(session, "CDP Neighbors", "show cdp neighbors detail").await?;
    let lldp_result = run_command(session, "LLDP Neighbors", "show lldp neighbors detail").await?;

    let hostname = match hostname_result {
        Ok(output) => {
            let hostname = parse_hostname(&output);
            metadata.push(CheckMetadata {
                name: "Device Identity",
                status: if hostname.is_some() {
                    SectionStatus::Ok
                } else {
                    SectionStatus::Unknown
                },
                details: if hostname.is_some() {
                    "hostname command completed"
                } else {
                    "hostname output could not be parsed"
                }
                .to_string(),
            });
            match hostname {
                Some(hostname) => hostname,
                None => {
                    findings.push(Finding {
                        status: SectionStatus::Unknown,
                        message: "Could not parse hostname; using the management address."
                            .to_string(),
                    });
                    target.address.clone()
                }
            }
        }
        Err(err) => {
            metadata.push(CheckMetadata {
                name: "Device Identity",
                status: SectionStatus::Unknown,
                details: err.clone(),
            });
            findings.push(Finding {
                status: SectionStatus::Unknown,
                message: format!("Could not read hostname: {err}"),
            });
            target.address.clone()
        }
    };

    let uptime = match version_result {
        Ok(output) => {
            let uptime = parse_uptime(&output);
            metadata.push(CheckMetadata {
                name: "Version",
                status: if uptime.is_some() {
                    SectionStatus::Ok
                } else {
                    SectionStatus::Unknown
                },
                details: if uptime.is_some() {
                    "version uptime line parsed"
                } else {
                    "uptime output could not be parsed"
                }
                .to_string(),
            });
            if uptime.is_none() {
                findings.push(Finding {
                    status: SectionStatus::Unknown,
                    message: "Uptime could not be parsed from the device output.".to_string(),
                });
            }
            uptime
        }
        Err(err) => {
            metadata.push(CheckMetadata {
                name: "Version",
                status: SectionStatus::Unknown,
                details: err.clone(),
            });
            findings.push(Finding {
                status: SectionStatus::Unknown,
                message: format!("Could not read uptime: {err}"),
            });
            None
        }
    };

    let cpu_five_minute_percent = cpu_result
        .as_ref()
        .ok()
        .and_then(|output| parse_cpu_five_minute_percent(output));
    metadata.push(CheckMetadata {
        name: "System CPU (5m)",
        status: cpu_five_minute_percent
            .map(|value| status_from_percent(value, 80.0, 90.0))
            .unwrap_or(SectionStatus::Unknown),
        details: cpu_five_minute_percent
            .map(|value| format!("CPU five-minute usage {value:.1}%"))
            .unwrap_or_else(|| "five-minute CPU usage is unavailable".to_string()),
    });
    if cpu_five_minute_percent.is_none() {
        findings.push(Finding {
            status: SectionStatus::Unknown,
            message: "Five-minute CPU usage is unavailable.".to_string(),
        });
    }
    let cpu_percent = match cpu_result {
        Ok(output) => match parse_cpu_percent(&output) {
            Some(value) => {
                metadata.push(CheckMetadata {
                    name: "System CPU",
                    status: status_from_percent(value, 80.0, 90.0),
                    details: format!("CPU one-minute usage {:.1}%", value),
                });
                Some(value)
            }
            None => {
                metadata.push(CheckMetadata {
                    name: "System CPU",
                    status: SectionStatus::Unknown,
                    details: "CPU output did not match expected Cisco format".to_string(),
                });
                findings.push(Finding {
                    status: SectionStatus::Unknown,
                    message: "CPU usage could not be parsed from the device output.".to_string(),
                });
                None
            }
        },
        Err(err) => {
            metadata.push(CheckMetadata {
                name: "System CPU",
                status: SectionStatus::Unknown,
                details: err.clone(),
            });
            findings.push(Finding {
                status: SectionStatus::Unknown,
                message: format!("CPU check failed: {err}"),
            });
            None
        }
    };

    let memory_percent = match memory_result {
        Ok(output) => match parse_memory_percent(&output) {
            Some(value) => {
                metadata.push(CheckMetadata {
                    name: "System Memory",
                    status: status_from_percent(value, 85.0, 95.0),
                    details: format!("Memory usage {:.1}%", value),
                });
                Some(value)
            }
            None => {
                metadata.push(CheckMetadata {
                    name: "System Memory",
                    status: SectionStatus::Unknown,
                    details: "memory output did not match expected Cisco format".to_string(),
                });
                findings.push(Finding {
                    status: SectionStatus::Unknown,
                    message: "Memory usage could not be parsed from the device output.".to_string(),
                });
                None
            }
        },
        Err(err) => {
            metadata.push(CheckMetadata {
                name: "System Memory",
                status: SectionStatus::Unknown,
                details: err.clone(),
            });
            findings.push(Finding {
                status: SectionStatus::Unknown,
                message: format!("Memory check failed: {err}"),
            });
            None
        }
    };

    for (name, value, warning, critical) in [
        ("CPU one-minute usage", cpu_percent, 80.0, 90.0),
        ("CPU five-minute usage", cpu_five_minute_percent, 80.0, 90.0),
        ("Memory usage", memory_percent, 85.0, 95.0),
    ] {
        if let Some(value) = value {
            let status = status_from_percent(value, warning, critical);
            if matches!(status, SectionStatus::Warning | SectionStatus::Critical) {
                findings.push(Finding {
                    status,
                    message: format!("{name} is {value:.1}%."),
                });
            }
        }
    }

    let system = SystemHealth {
        status: crate::combine_statuses(&[
            cpu_percent
                .map(|value| status_from_percent(value, 80.0, 90.0))
                .unwrap_or(SectionStatus::Unknown),
            cpu_five_minute_percent
                .map(|value| status_from_percent(value, 80.0, 90.0))
                .unwrap_or(SectionStatus::Unknown),
            memory_percent
                .map(|value| status_from_percent(value, 85.0, 95.0))
                .unwrap_or(SectionStatus::Unknown),
        ]),
        cpu_percent,
        cpu_five_minute_percent,
        memory_percent,
        uptime,
    };

    let interfaces = match interfaces_result {
        Ok(output) => match parse_interface_summary(&output) {
            Some(summary) => {
                metadata.push(CheckMetadata {
                    name: "Interfaces",
                    status: summary.status,
                    details: format!(
                        "{} up / {} down / {} admin down",
                        summary.up, summary.down, summary.admin_down
                    ),
                });
                if !summary.notable_issues.is_empty() {
                    findings.push(Finding {
                        status: summary.status,
                        message: format!("{} interfaces need attention.", summary.down),
                    });
                }
                summary
            }
            None => {
                metadata.push(CheckMetadata {
                    name: "Interfaces",
                    status: SectionStatus::Unknown,
                    details: "interface summary parser returned no data".to_string(),
                });
                findings.push(Finding {
                    status: SectionStatus::Unknown,
                    message: "Interface summary could not be parsed.".to_string(),
                });
                InterfaceHealth {
                    status: SectionStatus::Unknown,
                    total: 0,
                    up: 0,
                    down: 0,
                    admin_down: 0,
                    notable_issues: Vec::new(),
                }
            }
        },
        Err(err) => {
            metadata.push(CheckMetadata {
                name: "Interfaces",
                status: SectionStatus::Unknown,
                details: err.clone(),
            });
            findings.push(Finding {
                status: SectionStatus::Unknown,
                message: format!("Interface summary check failed: {err}"),
            });
            InterfaceHealth {
                status: SectionStatus::Unknown,
                total: 0,
                up: 0,
                down: 0,
                admin_down: 0,
                notable_issues: Vec::new(),
            }
        }
    };

    let mut neighbors = Vec::new();
    let mut protocols_seen = Vec::new();

    match cdp_result {
        Ok(output) => {
            let mut parsed = parse_cdp_neighbors(&output);
            if parsed.is_empty() {
                findings.push(Finding {
                    status: SectionStatus::Unknown,
                    message: "CDP returned no usable neighbors or may be disabled.".to_string(),
                });
                metadata.push(CheckMetadata {
                    name: "CDP Neighbors",
                    status: SectionStatus::Unknown,
                    details: "no CDP neighbors parsed".to_string(),
                });
            } else {
                protocols_seen.push("CDP");
                metadata.push(CheckMetadata {
                    name: "CDP Neighbors",
                    status: SectionStatus::Ok,
                    details: format!("parsed {} CDP neighbors", parsed.len()),
                });
                neighbors.append(&mut parsed);
            }
        }
        Err(err) => {
            metadata.push(CheckMetadata {
                name: "CDP Neighbors",
                status: SectionStatus::Unknown,
                details: err.clone(),
            });
            findings.push(Finding {
                status: SectionStatus::Unknown,
                message: format!("CDP check unavailable: {err}"),
            });
        }
    }

    match lldp_result {
        Ok(output) => {
            let mut parsed = parse_lldp_neighbors(&output);
            if parsed.is_empty() {
                findings.push(Finding {
                    status: SectionStatus::Unknown,
                    message: "LLDP returned no usable neighbors or may be disabled.".to_string(),
                });
                metadata.push(CheckMetadata {
                    name: "LLDP Neighbors",
                    status: SectionStatus::Unknown,
                    details: "no LLDP neighbors parsed".to_string(),
                });
            } else {
                protocols_seen.push("LLDP");
                metadata.push(CheckMetadata {
                    name: "LLDP Neighbors",
                    status: SectionStatus::Ok,
                    details: format!("parsed {} LLDP neighbors", parsed.len()),
                });
                neighbors.append(&mut parsed);
            }
        }
        Err(err) => {
            metadata.push(CheckMetadata {
                name: "LLDP Neighbors",
                status: SectionStatus::Unknown,
                details: err.clone(),
            });
            findings.push(Finding {
                status: SectionStatus::Unknown,
                message: format!("LLDP check unavailable: {err}"),
            });
        }
    }

    let mut reachability_by_ip: HashMap<IpAddr, Result<ReachabilityStatus, String>> =
        HashMap::new();
    for neighbor in &mut neighbors {
        let Some(ip) = neighbor.management_ip.clone() else {
            neighbor.reachability = ReachabilityStatus::Unknown;
            findings.push(Finding {
                status: SectionStatus::Unknown,
                message: format!(
                    "{} on {} has no management IP, so reachability is unknown.",
                    neighbor.neighbor_id, neighbor.local_interface
                ),
            });
            continue;
        };

        let Ok(address) = ip.parse::<IpAddr>() else {
            findings.push(Finding {
                status: SectionStatus::Unknown,
                message: format!(
                    "Neighbor {} has an invalid management IP ({ip}).",
                    neighbor.neighbor_id
                ),
            });
            continue;
        };
        let result = if let Some(result) = reachability_by_ip.get(&address) {
            result.clone()
        } else {
            let result = run_command(
                session,
                "Neighbor Reachability",
                &format!("ping {address} repeat 1 timeout 1"),
            )
            .await?
            .map(|output| parse_ping_reachability(&output));
            reachability_by_ip.insert(address, result.clone());
            result
        };
        match result {
            Ok(reachability) => {
                neighbor.reachability = reachability;
                if reachability == ReachabilityStatus::Unreachable {
                    findings.push(Finding {
                        status: SectionStatus::Warning,
                        message: format!(
                            "Neighbor {} ({ip}) did not answer ping.",
                            neighbor.neighbor_id
                        ),
                    });
                } else if reachability == ReachabilityStatus::Unknown {
                    findings.push(Finding {
                        status: SectionStatus::Unknown,
                        message: format!(
                            "Could not interpret reachability to neighbor {} ({ip}).",
                            neighbor.neighbor_id
                        ),
                    });
                }
            }
            Err(err) => {
                neighbor.reachability = ReachabilityStatus::Unknown;
                findings.push(Finding {
                    status: SectionStatus::Unknown,
                    message: format!(
                        "Could not verify reachability to neighbor {} ({ip}): {err}",
                        neighbor.neighbor_id
                    ),
                });
            }
        }
    }

    let mut neighbor_check_statuses: Vec<_> = metadata
        .iter()
        .filter(|check| matches!(check.name, "CDP Neighbors" | "LLDP Neighbors"))
        .map(|check| check.status)
        .collect();
    neighbor_check_statuses.push(derive_neighbors_status(
        &neighbors,
        protocols_seen.is_empty(),
    ));

    let snapshot = DeviceHealthSnapshot {
        device: DeviceIdentity {
            hostname,
            management_address: target.management_address(),
            vendor: variant.to_string(),
        },
        system,
        interfaces,
        neighbors: NeighborsSection {
            status: crate::combine_statuses(&neighbor_check_statuses),
            protocols_seen,
            entries: neighbors,
        },
        findings,
        metadata,
        collected_at: Instant::now(),
    };

    Ok(snapshot)
}

async fn run_command(
    session: &mut dyn CommandExecutor,
    name: &'static str,
    command: &str,
) -> Result<Result<String, String>, HealthError> {
    // Transport errors can leave the prompt stream out of sync and abort the
    // collection. CLI rejections are recoverable, unavailable individual checks.
    let result = session
        .execute(command)
        .await
        .map_err(|source| HealthError::Command {
            command: command.to_string(),
            source,
        })?;

    if result.has_error {
        return Ok(Err(format!(
            "{name} command returned device error {}",
            result.error_match.unwrap_or_else(|| "unknown".to_string())
        )));
    }

    Ok(Ok(result.output))
}
