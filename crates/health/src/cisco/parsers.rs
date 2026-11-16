use crate::{InterfaceHealth, InterfaceIssue, NeighborHealth, ReachabilityStatus, SectionStatus};
use regex::Regex;
use std::{net::IpAddr, sync::LazyLock};

static CPU_ONE_MINUTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"one minute:\s*([0-9]+(?:\.[0-9]+)?)%").expect("valid CPU regex"));
static CPU_FIVE_MINUTES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"five minutes:\s*([0-9]+(?:\.[0-9]+)?)%").expect("valid CPU regex")
});
static MEMORY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Processor Pool Total:\s*([0-9]+)\s*Used:\s*([0-9]+)\s*Free:\s*([0-9]+)")
        .expect("valid memory regex")
});
static PING_SUCCESS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Success rate is ([0-9]+) percent").expect("valid ping regex"));

pub(super) fn parse_hostname(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix("hostname ")
            .map(|hostname| hostname.trim().to_string())
            .filter(|hostname| !hostname.is_empty())
    })
}

pub(super) fn parse_uptime(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.find(" uptime is ")
            .map(|idx| line[idx + " uptime is ".len()..].trim().to_string())
            .filter(|uptime| !uptime.is_empty())
    })
}

pub(super) fn parse_cpu_percent(output: &str) -> Option<f32> {
    parse_cpu_window(output, &CPU_ONE_MINUTE)
}

pub(super) fn parse_cpu_five_minute_percent(output: &str) -> Option<f32> {
    parse_cpu_window(output, &CPU_FIVE_MINUTES)
}

fn parse_cpu_window(output: &str, regex: &Regex) -> Option<f32> {
    regex
        .captures(output)
        .and_then(|captures| captures.get(1))
        .and_then(|value| value.as_str().parse::<f32>().ok())
        .filter(|value| value.is_finite() && (0.0..=100.0).contains(value))
}

pub(super) fn parse_memory_percent(output: &str) -> Option<f32> {
    let captures = MEMORY.captures(output)?;
    let total = captures.get(1)?.as_str().parse::<u64>().ok()?;
    let used = captures.get(2)?.as_str().parse::<u64>().ok()?;
    let free = captures.get(3)?.as_str().parse::<u64>().ok()?;
    if total == 0 || used.checked_add(free)? != total {
        return None;
    }
    Some((used as f64 / total as f64 * 100.0) as f32)
}

pub(super) fn parse_interface_summary(output: &str) -> Option<InterfaceHealth> {
    let mut total = 0usize;
    let mut up = 0usize;
    let mut down = 0usize;
    let mut admin_down = 0usize;
    let mut notable_issues = Vec::new();

    let rows = output
        .lines()
        .skip_while(|line| {
            !(line.contains("Interface")
                && line.contains("IP-Address")
                && line.contains("Protocol"))
        })
        .skip(1);
    for line in rows {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        // A partial table must not become a healthy summary of only the rows we
        // happened to understand. Keep malformed/truncated output unknown.
        if cols.len() < 6
            || !matches!(cols[2], "YES" | "NO")
            || !(cols[1].eq_ignore_ascii_case("unassigned") || cols[1].parse::<IpAddr>().is_ok())
        {
            return None;
        }

        let name = cols[0].to_string();
        let status = cols[4..cols.len() - 1].join(" ");
        let protocol = cols[cols.len() - 1];
        if !["up", "down", "administratively down", "reset", "deleted"]
            .iter()
            .any(|known| status.eq_ignore_ascii_case(known))
            || !["up", "down", "deleted"]
                .iter()
                .any(|known| protocol.eq_ignore_ascii_case(known))
        {
            return None;
        }
        total += 1;

        if status.eq_ignore_ascii_case("up") && protocol.eq_ignore_ascii_case("up") {
            up += 1;
            continue;
        }

        if status.eq_ignore_ascii_case("administratively down") {
            admin_down += 1;
            continue;
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

pub(super) fn parse_cdp_neighbors(output: &str) -> Vec<NeighborHealth> {
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

pub(super) fn parse_lldp_neighbors(output: &str) -> Vec<NeighborHealth> {
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
            .filter(|value| !value.is_empty())
    })
}

pub(super) fn parse_ping_reachability(output: &str) -> ReachabilityStatus {
    match PING_SUCCESS
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
        let output = "CPU utilization for five seconds: 2%/0%; one minute: 19%; five minutes: 12%";
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
    fn malformed_interface_rows_do_not_leave_a_healthy_partial_summary() {
        let valid =
            "Interface IP-Address OK? Method Status Protocol\nGi0/0 10.0.0.1 YES manual up up\n";
        for malformed in [
            "Gi0/1 unassigned YES unset down",
            "Gi0/1 unassigned YES unset unexpected down",
            "Gi0/1 unassigned YES unset up unavailable",
            "Gi0/1 invalid-address YES manual up up",
            "Gi0/1 unassigned maybe unset up up",
        ] {
            assert!(
                parse_interface_summary(&format!("{valid}{malformed}\n")).is_none(),
                "malformed row must make collection unknown: {malformed}"
            );
        }
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
        assert_eq!(
            neighbors[0].remote_interface.as_deref(),
            Some("GigabitEthernet0/48")
        );
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
