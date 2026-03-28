use crate::{
    CheckMetadata, DeviceHealthSnapshot, DeviceIdentity, Finding, HealthConnectionConfig,
    InterfaceHealth, InterfaceIssue, NeighborHealth, NeighborsSection, ReachabilityStatus,
    SectionStatus, SystemHealth, derive_neighbors_status, status_from_percent,
};
use omnisor::{CiscoVariant, DeviceSession};
use regex::Regex;
use std::time::Instant;

pub(crate) async fn collect_cisco_device_health(
    config: &HealthConnectionConfig,
    variant: CiscoVariant,
) -> Result<DeviceHealthSnapshot, String> {
    let mut session = DeviceSession::connect(
        (config.address.as_str(), config.port),
        &config.username,
        &config.password,
        variant,
    )
    .await
    .map_err(|err| format!("unable to connect to device: {err}"))?;

    let mut findings = Vec::new();
    let mut metadata = Vec::new();

    let hostname_result =
        run_command(&mut session, "Device Identity", "show running-config | include ^hostname")
            .await;
    let version_result = run_command(&mut session, "Version", "show version | include uptime").await;
    let cpu_result = run_command(
        &mut session,
        "System CPU",
        "show processes cpu | include one minute:",
    )
    .await;
    let memory_result = run_command(
        &mut session,
        "System Memory",
        "show processes memory | include Processor Pool Total:",
    )
    .await;
    let interfaces_result = run_command(&mut session, "Interfaces", "show ip interface brief").await;
    let cdp_result = run_command(&mut session, "CDP Neighbors", "show cdp neighbors detail").await;
    let lldp_result = run_command(&mut session, "LLDP Neighbors", "show lldp neighbors detail").await;

    let hostname = match hostname_result {
        Ok(output) => {
            metadata.push(CheckMetadata {
                name: "Device Identity",
                status: SectionStatus::Ok,
                details: "hostname command completed".to_string(),
            });
            parse_hostname(&output).unwrap_or_else(|| config.address.clone())
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
            config.address.clone()
        }
    };

    let uptime = match version_result {
        Ok(output) => {
            metadata.push(CheckMetadata {
                name: "Version",
                status: SectionStatus::Ok,
                details: "version uptime line parsed".to_string(),
            });
            parse_uptime(&output)
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

    let system = SystemHealth {
        status: crate::combine_statuses(&[
            cpu_percent
                .map(|value| status_from_percent(value, 80.0, 90.0))
                .unwrap_or(SectionStatus::Unknown),
            memory_percent
                .map(|value| status_from_percent(value, 85.0, 95.0))
                .unwrap_or(SectionStatus::Unknown),
        ]),
        cpu_percent,
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
                        message: format!("{} interfaces need attention.", summary.notable_issues.len()),
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

        match run_command(
            &mut session,
            "Neighbor Reachability",
            &format!("ping {ip} repeat 1 timeout 1"),
        )
        .await
        {
            Ok(output) => {
                let reachability = parse_ping_reachability(&output);
                neighbor.reachability = reachability;
                if reachability == ReachabilityStatus::Unreachable {
                    findings.push(Finding {
                        status: SectionStatus::Warning,
                        message: format!("Neighbor {} ({ip}) did not answer ping.", neighbor.neighbor_id),
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

    let snapshot = DeviceHealthSnapshot {
        device: DeviceIdentity {
            hostname,
            management_address: format!("{}:{}", config.address, config.port),
            vendor: variant.to_string(),
        },
        system,
        interfaces,
        neighbors: NeighborsSection {
            status: derive_neighbors_status(&neighbors, protocols_seen.is_empty()),
            protocols_seen,
            entries: neighbors,
        },
        findings,
        metadata,
        collected_at: Instant::now(),
    };

    let _ = session.close().await;
    Ok(snapshot)
}

async fn run_command(
    session: &mut DeviceSession,
    name: &'static str,
    command: &str,
) -> Result<String, String> {
    let result = session
        .send_command(command)
        .await
        .map_err(|err| format!("{name} command failed: {err}"))?;

    if result.has_error {
        return Err(format!(
            "{name} command returned device error {}",
            result.error_match.unwrap_or_else(|| "unknown".to_string())
        ));
    }

    Ok(result.output)
}

fn parse_hostname(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix("hostname ")
            .map(|hostname| hostname.trim().to_string())
    })
}

fn parse_uptime(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.find(" uptime is ")
            .map(|idx| line[idx + " uptime is ".len()..].trim().to_string())
    })
}

fn parse_cpu_percent(output: &str) -> Option<f32> {
    let regex = Regex::new(r"one minute:\s*([0-9]+(?:\.[0-9]+)?)%").ok()?;
    regex
        .captures(output)
        .and_then(|captures| captures.get(1))
        .and_then(|value| value.as_str().parse::<f32>().ok())
}

fn parse_memory_percent(output: &str) -> Option<f32> {
    let regex =
        Regex::new(r"Processor Pool Total:\s*([0-9]+)\s*Used:\s*([0-9]+)\s*Free:\s*([0-9]+)")
            .ok()?;
    let captures = regex.captures(output)?;
    let total = captures.get(1)?.as_str().parse::<f32>().ok()?;
    let used = captures.get(2)?.as_str().parse::<f32>().ok()?;
    if total == 0.0 {
        return None;
    }
    Some((used / total) * 100.0)
}

fn parse_interface_summary(output: &str) -> Option<InterfaceHealth> {
    let mut total = 0usize;
    let mut up = 0usize;
    let mut down = 0usize;
    let mut admin_down = 0usize;
    let mut notable_issues = Vec::new();

    for line in output.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }

        total += 1;
        let name = cols[0].to_string();
        let status = cols[4..cols.len() - 1].join(" ");
        let protocol = cols[cols.len() - 1];

        if status.eq_ignore_ascii_case("up") && protocol.eq_ignore_ascii_case("up") {
            up += 1;
            continue;
        }

        if status.eq_ignore_ascii_case("administratively down") {
            admin_down += 1;
        } else {
            down += 1;
        }

        if notable_issues.len() < 6 {
            notable_issues.push(InterfaceIssue {
                name,
                detail: format!("status: {status}, protocol: {protocol}"),
            });
        }
    }

    if total == 0 {
        return None;
    }

    let status = if down > 0 {
        SectionStatus::Warning
    } else if up > 0 || admin_down > 0 {
        SectionStatus::Ok
    } else {
        SectionStatus::Unknown
    };

    Some(InterfaceHealth {
        status,
        total,
        up,
        down,
        admin_down,
        notable_issues,
    })
}

fn parse_cdp_neighbors(output: &str) -> Vec<NeighborHealth> {
    let mut neighbors = Vec::new();

    for block in output.split("-------------------------") {
        let block = block.trim();
        if block.is_empty() {
            continue;
        }

        let neighbor_id = extract_value(block, "Device ID:");
        let management_ip = extract_value(block, "IP address:");
        let interface_line = extract_value(block, "Interface:");
        let Some(interface_line) = interface_line else {
            continue;
        };

        let (local_interface, remote_interface) = split_cdp_interface_line(&interface_line);
        let Some(neighbor_id) = neighbor_id else {
            continue;
        };

        neighbors.push(NeighborHealth {
            protocol: "CDP",
            local_interface,
            neighbor_id,
            remote_interface,
            management_ip,
            reachability: ReachabilityStatus::Unknown,
        });
    }

    neighbors
}

fn split_cdp_interface_line(line: &str) -> (String, Option<String>) {
    if let Some((local, remote)) = line.split_once(", Port ID (outgoing port):") {
        (local.trim().to_string(), Some(remote.trim().to_string()))
    } else {
        (line.trim().to_string(), None)
    }
}

fn parse_lldp_neighbors(output: &str) -> Vec<NeighborHealth> {
    let mut neighbors = Vec::new();

    for block in output.split("------------------------------------------------") {
        let block = block.trim();
        if block.is_empty() {
            continue;
        }

        let local_interface = extract_value(block, "Local Intf:");
        let neighbor_id =
            extract_value(block, "System Name:").or_else(|| extract_value(block, "Chassis id:"));
        let remote_interface = extract_value(block, "Port id:");
        let management_ip = extract_value(block, "Management Address:");

        let (Some(local_interface), Some(neighbor_id)) = (local_interface, neighbor_id) else {
            continue;
        };

        neighbors.push(NeighborHealth {
            protocol: "LLDP",
            local_interface,
            neighbor_id,
            remote_interface,
            management_ip,
            reachability: ReachabilityStatus::Unknown,
        });
    }

    neighbors
}

fn extract_value(block: &str, prefix: &str) -> Option<String> {
    block.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix(prefix)
            .map(|value| value.trim().to_string())
    })
}

fn parse_ping_reachability(output: &str) -> ReachabilityStatus {
    let regex = match Regex::new(r"Success rate is ([0-9]+) percent") {
        Ok(regex) => regex,
        Err(_) => return ReachabilityStatus::Unknown,
    };

    match regex
        .captures(output)
        .and_then(|captures| captures.get(1))
        .and_then(|value| value.as_str().parse::<u8>().ok())
    {
        Some(100) => ReachabilityStatus::Reachable,
        Some(0) => ReachabilityStatus::Unreachable,
        Some(_) => ReachabilityStatus::Unknown,
        None => ReachabilityStatus::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpu_percent() {
        let output =
            "CPU utilization for five seconds: 2%/0%; one minute: 19%; five minutes: 12%";
        assert_eq!(parse_cpu_percent(output), Some(19.0));
    }

    #[test]
    fn parses_memory_percent() {
        let output = "Processor Pool Total: 99327584 Used: 41837772 Free: 57489812";
        let percent = parse_memory_percent(output).unwrap();
        assert!((percent - 42.12).abs() < 0.1);
    }

    #[test]
    fn parses_interface_summary() {
        let output = "\
Interface                  IP-Address      OK? Method Status                Protocol\n\
GigabitEthernet0/0         10.0.0.1        YES manual up                    up\n\
GigabitEthernet0/1         unassigned      YES unset  administratively down down\n\
GigabitEthernet0/2         unassigned      YES unset  down                  down\n";

        let summary = parse_interface_summary(output).unwrap();
        assert_eq!(summary.total, 3);
        assert_eq!(summary.up, 1);
        assert_eq!(summary.admin_down, 1);
        assert_eq!(summary.down, 1);
        assert_eq!(summary.status, SectionStatus::Warning);
    }

    #[test]
    fn parses_cdp_neighbors() {
        let output = "\
-------------------------\n\
Device ID: core-sw1\n\
Entry address(es):\n\
  IP address: 10.0.0.2\n\
Platform: cisco WS-C2960, Capabilities: Switch IGMP\n\
Interface: GigabitEthernet0/0, Port ID (outgoing port): GigabitEthernet0/48\n";

        let neighbors = parse_cdp_neighbors(output);
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].neighbor_id, "core-sw1");
        assert_eq!(neighbors[0].management_ip.as_deref(), Some("10.0.0.2"));
        assert_eq!(neighbors[0].remote_interface.as_deref(), Some("GigabitEthernet0/48"));
    }

    #[test]
    fn neighbor_without_ip_stays_unknown() {
        let output = "\
------------------------------------------------\n\
Local Intf: Gi0/1\n\
Chassis id: 0011.2233.4455\n\
Port id: Gi1/0/48\n\
System Name: core-sw1\n";
        let neighbors = parse_lldp_neighbors(output);
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].management_ip, None);
        assert_eq!(neighbors[0].reachability, ReachabilityStatus::Unknown);
    }
}
