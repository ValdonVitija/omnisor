use health::{
    CiscoIosHealthProvider, CommandExecutor, CommandFuture, DeviceHealthSnapshot, DeviceIdentity,
    HealthConnectionConfig, HealthError, HealthFuture, HealthProvider, HealthTarget,
    InterfaceHealth, NeighborsSection, ReachabilityStatus, SectionStatus, SystemHealth,
    collect_device_health, collect_health_with_executor, supported_health_vendors,
};
use omnisor::{CiscoVariant, DeviceCommandResult, DeviceVendor, Error};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

const HOSTNAME: &str = "show running-config | include ^hostname";
const UPTIME: &str = "show version | include uptime";
const CPU: &str = "show processes cpu | include one minute:";
const MEMORY: &str = "show processes memory | include Processor Pool Total:";
const INTERFACES: &str = "show ip interface brief";
const CDP: &str = "show cdp neighbors detail";
const LLDP: &str = "show lldp neighbors detail";
const PING_OK: &str = "Success rate is 100 percent (1/1), round-trip min/avg/max = 1/1/1 ms";

struct ExpectedCommand {
    command: &'static str,
    result: Result<DeviceCommandResult, Error>,
}

impl ExpectedCommand {
    fn output(command: &'static str, output: &str) -> Self {
        Self {
            command,
            result: Ok(DeviceCommandResult {
                raw_output: format!("branch-router#{command}\r\n{output}\r\nbranch-router#"),
                output: output.to_string(),
                has_error: false,
                error_match: None,
            }),
        }
    }

    fn cli_error(command: &'static str) -> Self {
        let mut response = Self::output(command, "% Invalid input detected at '^' marker.");
        let result = response.result.as_mut().unwrap();
        result.has_error = true;
        result.error_match = Some("% Invalid".to_string());
        response
    }

    fn transport_error(command: &'static str, error: Error) -> Self {
        Self {
            command,
            result: Err(error),
        }
    }
}

/// Enforces the command sequence, including the absence of extra pings.
struct TranscriptExecutor {
    expected: VecDeque<ExpectedCommand>,
    executed: Vec<String>,
}

impl TranscriptExecutor {
    fn new(expected: impl IntoIterator<Item = ExpectedCommand>) -> Self {
        Self {
            expected: expected.into_iter().collect(),
            executed: Vec::new(),
        }
    }

    fn assert_complete(&self) {
        assert!(
            self.expected.is_empty(),
            "{} expected commands were not executed",
            self.expected.len()
        );
    }
}

impl CommandExecutor for TranscriptExecutor {
    fn execute<'a>(&'a mut self, command: &'a str) -> CommandFuture<'a> {
        Box::pin(async move {
            let expected = self
                .expected
                .pop_front()
                .unwrap_or_else(|| panic!("unexpected command: {command}"));
            assert_eq!(command, expected.command, "transcript command mismatch");
            self.executed.push(command.to_string());
            expected.result
        })
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn target() -> HealthTarget {
    HealthTarget {
        address: "192.0.2.10".to_string(),
        port: 2222,
    }
}

fn metrics_commands() -> Vec<ExpectedCommand> {
    vec![
        ExpectedCommand::output(HOSTNAME, include_str!("fixtures/ios_hostname.txt")),
        ExpectedCommand::output(UPTIME, include_str!("fixtures/ios_uptime.txt")),
        ExpectedCommand::output(CPU, include_str!("fixtures/ios_cpu.txt")),
        ExpectedCommand::output(MEMORY, include_str!("fixtures/ios_memory.txt")),
        ExpectedCommand::output(INTERFACES, include_str!("fixtures/ios_interfaces.txt")),
    ]
}

fn healthy_transcript() -> Vec<ExpectedCommand> {
    let mut commands = metrics_commands();
    commands.extend([
        ExpectedCommand::output(CDP, include_str!("fixtures/ios_cdp.txt")),
        ExpectedCommand::output(LLDP, include_str!("fixtures/ios_lldp.txt")),
        ExpectedCommand::output("ping 10.0.0.2 repeat 1 timeout 1", PING_OK),
        ExpectedCommand::output("ping 10.0.0.3 repeat 1 timeout 1", PING_OK),
    ]);
    commands
}

#[test]
fn ios_family_health_replays_metrics_and_probes_each_management_ip_once() {
    let runtime = runtime();
    for variant in [
        CiscoVariant::Ios,
        CiscoVariant::IosXe,
        CiscoVariant::IosLegacy,
    ] {
        let provider = CiscoIosHealthProvider::new(variant).unwrap();
        let mut transcript = TranscriptExecutor::new(healthy_transcript());
        let snapshot = runtime
            .block_on(collect_health_with_executor(
                &target(),
                &provider,
                &mut transcript,
            ))
            .unwrap();

        transcript.assert_complete();
        assert_eq!(snapshot.device.hostname, "branch-router");
        assert_eq!(snapshot.device.management_address, "192.0.2.10:2222");
        assert_eq!(snapshot.device.vendor, variant.to_string());
        assert_eq!(snapshot.system.cpu_percent, Some(19.0));
        assert_eq!(snapshot.system.cpu_five_minute_percent, Some(12.0));
        assert_eq!(snapshot.system.memory_percent, Some(42.0));
        assert_eq!(
            snapshot.system.uptime.as_deref(),
            Some("2 weeks, 3 days, 4 hours, 12 minutes")
        );
        assert_eq!(snapshot.system.status, SectionStatus::Ok);
        assert_eq!(snapshot.interfaces.total, 4);
        assert_eq!(snapshot.interfaces.up, 2);
        assert_eq!(snapshot.interfaces.down, 1);
        assert_eq!(snapshot.interfaces.admin_down, 1);
        assert_eq!(snapshot.interfaces.status, SectionStatus::Warning);
        assert!(
            snapshot
                .interfaces
                .notable_issues
                .iter()
                .any(|issue| issue.name == "GigabitEthernet0/3")
        );
        assert_eq!(snapshot.neighbors.protocols_seen, ["CDP", "LLDP"]);
        assert_eq!(snapshot.neighbors.entries.len(), 3);
        assert_eq!(snapshot.neighbors.status, SectionStatus::Ok);
        assert_eq!(snapshot.neighbor_summary().reachable, 3);
        assert_eq!(snapshot.neighbors.entries[0].protocol, "CDP");
        assert_eq!(
            snapshot.neighbors.entries[0].remote_interface.as_deref(),
            Some("GigabitEthernet0/48")
        );
        assert_eq!(snapshot.neighbors.entries[1].protocol, "LLDP");
        assert_eq!(snapshot.neighbors.entries[1].neighbor_id, "core-sw1");
        assert_eq!(
            transcript
                .executed
                .iter()
                .filter(|command| command.starts_with("ping "))
                .count(),
            2
        );
    }
}

#[test]
fn truncated_interface_tables_are_unknown_instead_of_healthy_partial_counts() {
    let provider = CiscoIosHealthProvider::new(CiscoVariant::Ios).unwrap();
    let mut commands = healthy_transcript();
    commands[4] = ExpectedCommand::output(
        INTERFACES,
        "Interface IP-Address OK? Method Status Protocol\nGi0/0 10.0.0.1 YES manual up up\nGi0/1 unassigned YES unset down",
    );
    let mut transcript = TranscriptExecutor::new(commands);
    let snapshot = runtime()
        .block_on(collect_health_with_executor(
            &target(),
            &provider,
            &mut transcript,
        ))
        .unwrap();

    transcript.assert_complete();
    assert_eq!(snapshot.interfaces.status, SectionStatus::Unknown);
    assert_eq!(snapshot.interfaces.total, 0);
    assert_eq!(snapshot.system.status, SectionStatus::Ok);
    assert!(snapshot.findings.iter().any(|finding| {
        finding.status == SectionStatus::Unknown && finding.message.contains("Interface summary")
    }));
}

#[test]
fn interface_finding_counts_all_problems_while_examples_stay_bounded() {
    let provider = CiscoIosHealthProvider::new(CiscoVariant::Ios).unwrap();
    let mut interfaces = "Interface IP-Address OK? Method Status Protocol\n".to_string();
    for index in 0..8 {
        interfaces.push_str(&format!("Gi0/{index} unassigned YES unset down down\n"));
    }
    let mut commands = healthy_transcript();
    commands[4] = ExpectedCommand::output(INTERFACES, &interfaces);
    let mut transcript = TranscriptExecutor::new(commands);
    let snapshot = runtime()
        .block_on(collect_health_with_executor(
            &target(),
            &provider,
            &mut transcript,
        ))
        .unwrap();

    transcript.assert_complete();
    assert_eq!(snapshot.interfaces.down, 8);
    assert_eq!(snapshot.interfaces.notable_issues.len(), 6);
    assert!(snapshot.findings.iter().any(|finding| {
        finding.status == SectionStatus::Warning
            && finding.message == "8 interfaces need attention."
    }));
}

#[test]
fn partial_failures_stay_unknown_and_invalid_neighbor_addresses_are_never_executed() {
    let provider = CiscoIosHealthProvider::new(CiscoVariant::Ios).unwrap();
    let mut transcript = TranscriptExecutor::new([
        ExpectedCommand::cli_error(HOSTNAME),
        ExpectedCommand::output(UPTIME, include_str!("fixtures/ios_uptime.txt")),
        ExpectedCommand::output(CPU, "CPU statistics are unavailable"),
        ExpectedCommand::cli_error(MEMORY),
        ExpectedCommand::output(INTERFACES, "Interface summary unavailable"),
        ExpectedCommand::output(
            CDP,
            "\
-------------------------\n\
Device ID: no-management-address\n\
Interface: GigabitEthernet0/0, Port ID (outgoing port): GigabitEthernet0/48\n\
-------------------------\n\
Device ID: invalid-management-address\n\
  IP address: 10.0.0.2 repeat 500\n\
Interface: GigabitEthernet0/1, Port ID (outgoing port): GigabitEthernet0/47\n",
        ),
        ExpectedCommand::cli_error(LLDP),
    ]);
    let snapshot = runtime()
        .block_on(collect_health_with_executor(
            &target(),
            &provider,
            &mut transcript,
        ))
        .unwrap();

    transcript.assert_complete();
    assert_eq!(snapshot.device.hostname, "192.0.2.10");
    assert_eq!(snapshot.system.cpu_percent, None);
    assert_eq!(snapshot.system.cpu_five_minute_percent, None);
    assert_eq!(snapshot.system.memory_percent, None);
    assert_eq!(snapshot.system.status, SectionStatus::Unknown);
    assert_eq!(snapshot.interfaces.status, SectionStatus::Unknown);
    assert_eq!(snapshot.interfaces.total, 0);
    assert_eq!(snapshot.neighbors.entries.len(), 2);
    assert_eq!(snapshot.neighbors.status, SectionStatus::Unknown);
    assert!(
        snapshot
            .neighbors
            .entries
            .iter()
            .all(|neighbor| neighbor.reachability == ReachabilityStatus::Unknown)
    );
    assert!(
        snapshot
            .findings
            .iter()
            .any(|finding| finding.status == SectionStatus::Unknown)
    );
    for name in [
        "Device Identity",
        "System CPU",
        "System Memory",
        "Interfaces",
        "LLDP Neighbors",
    ] {
        assert_eq!(
            snapshot
                .metadata
                .iter()
                .find(|metadata| metadata.name == name)
                .unwrap()
                .status,
            SectionStatus::Unknown,
            "{name} should preserve the unavailable check"
        );
    }
    assert!(
        !transcript
            .executed
            .iter()
            .any(|command| command.starts_with("ping "))
    );
}

#[test]
fn neighbor_probe_failure_is_shared_without_duplicating_commands() {
    let provider = CiscoIosHealthProvider::new(CiscoVariant::Ios).unwrap();
    let mut commands = metrics_commands();
    commands.extend([
        ExpectedCommand::output(CDP, include_str!("fixtures/ios_cdp.txt")),
        ExpectedCommand::output(LLDP, include_str!("fixtures/ios_lldp.txt")),
        ExpectedCommand::cli_error("ping 10.0.0.2 repeat 1 timeout 1"),
        ExpectedCommand::output(
            "ping 10.0.0.3 repeat 1 timeout 1",
            "Success rate is 0 percent (0/1)",
        ),
    ]);
    let mut transcript = TranscriptExecutor::new(commands);
    let snapshot = runtime()
        .block_on(collect_health_with_executor(
            &target(),
            &provider,
            &mut transcript,
        ))
        .unwrap();

    transcript.assert_complete();
    assert_eq!(snapshot.neighbor_summary().unknown, 2);
    assert_eq!(snapshot.neighbor_summary().unreachable, 1);
    assert_eq!(snapshot.neighbors.status, SectionStatus::Warning);
    assert!(snapshot.findings.iter().any(|finding| {
        finding.status == SectionStatus::Warning && finding.message.contains("core-sw2")
    }));
}

#[test]
fn invalid_numeric_metrics_are_unknown_instead_of_healthy_values() {
    let runtime = runtime();
    let provider = CiscoIosHealthProvider::new(CiscoVariant::Ios).unwrap();
    for memory in [
        "Processor Pool Total: 100 Used: 110 Free: 0",
        "Processor Pool Total: 0 Used: 0 Free: 0",
        "Processor Pool Total: 100 Used: 42 Free: 90",
    ] {
        let mut transcript = TranscriptExecutor::new([
            ExpectedCommand::output(HOSTNAME, "hostname "),
            ExpectedCommand::output(UPTIME, "branch-router uptime is "),
            ExpectedCommand::output(
                CPU,
                "CPU utilization for five seconds: 2%/0%; one minute: 101%; five minutes: 1000%",
            ),
            ExpectedCommand::output(MEMORY, memory),
            ExpectedCommand::output(INTERFACES, include_str!("fixtures/ios_interfaces.txt")),
            ExpectedCommand::output(CDP, "Total cdp entries displayed : 0"),
            ExpectedCommand::output(LLDP, "Total entries displayed: 0"),
        ]);
        let snapshot = runtime
            .block_on(collect_health_with_executor(
                &target(),
                &provider,
                &mut transcript,
            ))
            .unwrap();

        transcript.assert_complete();
        assert_eq!(snapshot.device.hostname, "192.0.2.10");
        assert_eq!(snapshot.system.uptime, None);
        assert_eq!(snapshot.system.cpu_percent, None);
        assert_eq!(snapshot.system.cpu_five_minute_percent, None);
        assert_eq!(snapshot.system.memory_percent, None, "{memory}");
        assert_eq!(snapshot.system.status, SectionStatus::Unknown);
        assert_eq!(snapshot.neighbors.status, SectionStatus::Unknown);
        for name in [
            "Device Identity",
            "Version",
            "System CPU",
            "System CPU (5m)",
            "System Memory",
        ] {
            assert_eq!(
                snapshot
                    .metadata
                    .iter()
                    .find(|metadata| metadata.name == name)
                    .unwrap()
                    .status,
                SectionStatus::Unknown,
                "{name} should preserve invalid device output"
            );
        }
    }
}

#[test]
fn unparsed_ping_output_produces_an_unknown_finding() {
    let provider = CiscoIosHealthProvider::new(CiscoVariant::Ios).unwrap();
    let mut commands = healthy_transcript();
    commands[4] = ExpectedCommand::output(
        INTERFACES,
        "Interface IP-Address OK? Method Status Protocol\nGi0/0 10.0.0.1 YES manual up up",
    );
    let first_ping = commands.len() - 2;
    commands[first_ping] = ExpectedCommand::output(
        "ping 10.0.0.2 repeat 1 timeout 1",
        "unrecognized ping output",
    );
    let mut transcript = TranscriptExecutor::new(commands);
    let snapshot = runtime()
        .block_on(collect_health_with_executor(
            &target(),
            &provider,
            &mut transcript,
        ))
        .unwrap();

    transcript.assert_complete();
    assert_eq!(snapshot.interfaces.status, SectionStatus::Ok);
    assert_eq!(snapshot.system.status, SectionStatus::Ok);
    assert_eq!(snapshot.neighbors.status, SectionStatus::Unknown);
    assert!(!snapshot.findings.is_empty());
    assert!(snapshot.findings.iter().all(|finding| {
        finding.status == SectionStatus::Unknown && finding.message.contains("reachability")
    }));
}

#[test]
fn transport_timeout_stops_collection_and_preserves_the_command_error() {
    let runtime = runtime();
    let provider = CiscoIosHealthProvider::new(CiscoVariant::Ios).unwrap();
    for failed_command in [CPU, MEMORY] {
        let mut commands = healthy_transcript();
        let response = commands
            .iter_mut()
            .find(|expected| expected.command == failed_command)
            .unwrap();
        *response = ExpectedCommand::transport_error(failed_command, Error::DeviceTimeout);
        let mut transcript = TranscriptExecutor::new(commands);
        let error = runtime
            .block_on(collect_health_with_executor(
                &target(),
                &provider,
                &mut transcript,
            ))
            .unwrap_err();

        match error {
            HealthError::Command { command, source } => {
                assert_eq!(command, failed_command);
                assert!(matches!(source, Error::DeviceTimeout));
            }
            other => panic!("expected the original command error, got {other:?}"),
        }
        let (executed, next_command) = if failed_command == CPU {
            (vec![HOSTNAME, UPTIME, CPU], MEMORY)
        } else {
            (vec![HOSTNAME, UPTIME, CPU, MEMORY], INTERFACES)
        };
        assert_eq!(transcript.executed, executed);
        assert_eq!(transcript.expected.front().unwrap().command, next_command);
        // The caller retains this executor and can close or replace its session.
        // No queued command may run after a lost prompt or transport failure.
        assert!(!transcript.expected.is_empty());
    }
}

#[test]
fn five_minute_cpu_severity_and_missing_metrics_are_reported_as_findings() {
    let runtime = runtime();
    let provider = CiscoIosHealthProvider::new(CiscoVariant::Ios).unwrap();
    for (output, expected_percent, expected_status) in [
        (
            "CPU utilization for five seconds: 2%/0%; one minute: 19%; five minutes: 95%",
            Some(95.0),
            SectionStatus::Critical,
        ),
        (
            "CPU utilization for five seconds: 2%/0%; one minute: 19%; five minutes: unavailable",
            None,
            SectionStatus::Unknown,
        ),
        (
            "CPU utilization for five seconds: 2%/0%; one minute: 19%",
            None,
            SectionStatus::Unknown,
        ),
    ] {
        let mut commands = healthy_transcript();
        let response = commands
            .iter_mut()
            .find(|expected| expected.command == CPU)
            .unwrap();
        *response = ExpectedCommand::output(CPU, output);
        let mut transcript = TranscriptExecutor::new(commands);
        let snapshot = runtime
            .block_on(collect_health_with_executor(
                &target(),
                &provider,
                &mut transcript,
            ))
            .unwrap();

        transcript.assert_complete();
        assert_eq!(snapshot.system.cpu_percent, Some(19.0));
        assert_eq!(snapshot.system.cpu_five_minute_percent, expected_percent);
        assert_eq!(snapshot.system.status, expected_status);
        assert!(
            snapshot.findings.iter().any(|finding| {
                finding.status == expected_status && finding.message.contains("CPU")
            }),
            "five-minute CPU {expected_status:?} must appear in the device findings"
        );
        assert_eq!(
            snapshot
                .metadata
                .iter()
                .find(|metadata| metadata.name == "System CPU (5m)")
                .unwrap()
                .status,
            expected_status
        );
    }
}

#[test]
fn failed_discovery_protocol_keeps_neighbor_health_unknown_when_other_probes_succeed() {
    let runtime = runtime();
    let provider = CiscoIosHealthProvider::new(CiscoVariant::Ios).unwrap();
    for failed_protocol in [CDP, LLDP] {
        let mut commands = metrics_commands();
        commands.push(if failed_protocol == CDP {
            ExpectedCommand::cli_error(CDP)
        } else {
            ExpectedCommand::output(CDP, include_str!("fixtures/ios_cdp.txt"))
        });
        commands.push(if failed_protocol == LLDP {
            ExpectedCommand::cli_error(LLDP)
        } else {
            ExpectedCommand::output(LLDP, include_str!("fixtures/ios_lldp.txt"))
        });
        commands.push(ExpectedCommand::output(
            "ping 10.0.0.2 repeat 1 timeout 1",
            PING_OK,
        ));
        if failed_protocol == CDP {
            commands.push(ExpectedCommand::output(
                "ping 10.0.0.3 repeat 1 timeout 1",
                PING_OK,
            ));
        }
        let mut transcript = TranscriptExecutor::new(commands);
        let snapshot = runtime
            .block_on(collect_health_with_executor(
                &target(),
                &provider,
                &mut transcript,
            ))
            .unwrap();

        transcript.assert_complete();
        assert!(!snapshot.neighbors.entries.is_empty());
        assert!(
            snapshot
                .neighbors
                .entries
                .iter()
                .all(|neighbor| { neighbor.reachability == ReachabilityStatus::Reachable })
        );
        assert_eq!(snapshot.neighbors.status, SectionStatus::Unknown);
        assert!(snapshot.findings.iter().any(|finding| {
            finding.status == SectionStatus::Unknown
                && finding.message.contains(if failed_protocol == CDP {
                    "CDP"
                } else {
                    "LLDP"
                })
        }));
    }
}

#[test]
fn repeated_snapshots_reuse_the_executor_and_refresh_neighbor_probes() {
    let provider = CiscoIosHealthProvider::new(CiscoVariant::Ios).unwrap();
    let mut commands = healthy_transcript();
    commands.extend(healthy_transcript());
    let mut transcript = TranscriptExecutor::new(commands);
    runtime().block_on(async {
        let target = target();
        let first = collect_health_with_executor(&target, &provider, &mut transcript)
            .await
            .unwrap();
        let second = collect_health_with_executor(&target, &provider, &mut transcript)
            .await
            .unwrap();
        assert!(second.collected_at >= first.collected_at);
        assert_eq!(second.neighbor_summary().reachable, 3);
    });
    transcript.assert_complete();
    assert_eq!(
        transcript
            .executed
            .iter()
            .filter(|command| command.starts_with("ping "))
            .count(),
        4,
        "a new snapshot must probe again rather than reuse a stale result"
    );
}

#[test]
fn only_implemented_ios_variants_are_advertised_and_accepted() {
    let runtime = runtime();
    let supported = supported_health_vendors();
    assert_eq!(supported.len(), 3);
    for variant in [
        CiscoVariant::Ios,
        CiscoVariant::IosXe,
        CiscoVariant::IosLegacy,
    ] {
        assert!(supported.contains(&DeviceVendor::Cisco(variant)));
        assert!(CiscoIosHealthProvider::new(variant).is_ok());
    }
    for variant in [
        CiscoVariant::IosXr,
        CiscoVariant::NxOs,
        CiscoVariant::Asa,
        CiscoVariant::Wlc,
    ] {
        let error = match CiscoIosHealthProvider::new(variant) {
            Ok(_) => panic!("{variant} has no implemented health command profile"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(&variant.to_string()));
        assert!(!supported.contains(&DeviceVendor::Cisco(variant)));
        let config = HealthConnectionConfig {
            address: "not a valid network address".to_string(),
            port: 0,
            username: String::new(),
            password: String::new(),
            vendor: DeviceVendor::Cisco(variant),
        };
        assert_eq!(
            runtime
                .block_on(collect_device_health(&config))
                .unwrap_err(),
            error.to_string(),
            "unsupported health profiles must be rejected before address resolution or SSH"
        );
    }
}

/// Integration tests compile this implementation as an external crate consumer.
/// A new provider can define its own command without changing core vendor matches.
struct CustomHealthProvider {
    collected: AtomicUsize,
}

impl HealthProvider for CustomHealthProvider {
    fn collect<'a>(
        &'a self,
        executor: &'a mut dyn CommandExecutor,
        target: &'a HealthTarget,
    ) -> HealthFuture<'a> {
        Box::pin(async move {
            let result = executor.execute("custom health snapshot").await.unwrap();
            self.collected.fetch_add(1, Ordering::SeqCst);
            Ok(DeviceHealthSnapshot {
                device: DeviceIdentity {
                    hostname: result.output,
                    management_address: format!("{}:{}", target.address, target.port),
                    vendor: "External custom provider".to_string(),
                },
                system: SystemHealth {
                    status: SectionStatus::Ok,
                    cpu_percent: Some(1.0),
                    cpu_five_minute_percent: None,
                    memory_percent: Some(2.0),
                    uptime: None,
                },
                interfaces: InterfaceHealth {
                    status: SectionStatus::Unknown,
                    total: 0,
                    up: 0,
                    down: 0,
                    admin_down: 0,
                    notable_issues: Vec::new(),
                },
                neighbors: NeighborsSection {
                    status: SectionStatus::Unknown,
                    protocols_seen: Vec::new(),
                    entries: Vec::new(),
                },
                findings: Vec::new(),
                metadata: Vec::new(),
                collected_at: Instant::now(),
            })
        })
    }
}

#[test]
fn external_provider_accepts_trait_objects_and_reuses_the_callers_executor() {
    let provider = CustomHealthProvider {
        collected: AtomicUsize::new(0),
    };
    let mut transcript = TranscriptExecutor::new([
        ExpectedCommand::output("custom health snapshot", "custom-device-first"),
        ExpectedCommand::output("custom health snapshot", "custom-device-second"),
    ]);
    runtime().block_on(async {
        let provider_object: &dyn HealthProvider = &provider;
        let executor_object: &mut dyn CommandExecutor = &mut transcript;
        let target = target();
        let first = collect_health_with_executor(&target, provider_object, executor_object)
            .await
            .unwrap();
        let second = collect_health_with_executor(&target, provider_object, executor_object)
            .await
            .unwrap();
        assert_eq!(first.device.hostname, "custom-device-first");
        assert_eq!(second.device.hostname, "custom-device-second");
        assert_eq!(second.device.vendor, "External custom provider");
    });
    transcript.assert_complete();
    assert_eq!(provider.collected.load(Ordering::SeqCst), 2);
}
