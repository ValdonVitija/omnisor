# Compatibility and validation register

Inventory updated 2026-11-14 against the current code and
[lab guide](../../tests/lab/README.md). The IOSvL2 entry below includes live
host-side SSH and health collection evidence.
Use this register for [M1](../../ROADMAP.md#m1--make-local-collection-trustworthy).

## Current evidence

| Device family/profile | Synthetic SSH coverage | Built-in health collector | Real-device evidence recorded in the lab guide |
| --- | --- | --- | --- |
| Cisco IOS | Yes | Yes | No model/software health validation recorded |
| Cisco IOS-XE | Yes | Yes | No model/software health validation recorded |
| Cisco IOS Legacy | Yes, including legacy SSH negotiation | Yes | IOSvL2 20190423 virtual guest verified below; physical hardware remains unvalidated |
| Cisco IOS-XR, NX-OS, ASA, WLC | Yes | No | No real-image validation recorded |
| Juniper Junos, ScreenOS | Yes | No | No real-image validation recorded |
| Nokia SR Linux | Custom profile outside the synthetic catalog | No | 26.7.2 native ARM64 startup and Omnisor SSH response documented; no health validation |
| MikroTik RouterOS CHR | No | No | 7.23.8 reaches its login console under QEMU TCG; no Omnisor SSH/health validation recorded |

The health replay fixtures are synthetic IOS-style output. Synthetic SSH
endpoints validate session/collector behavior against the implemented fixture
responses. Neither establishes compatibility with a vendor's full CLI or a
particular real-device firmware release.

## Structured telemetry evidence (2026-11-14)

- Real `otelcol-contrib` 0.140.0-release binary scrapes the local synthetic exporter,
  sends authenticated OTLP protobuf, and produces CPU/memory history and traffic
  rates in the GPUI desktop. This is protocol/runtime evidence, not hardware evidence.
- Real `snmp_exporter` 0.29.0 loads the composed system/IF-MIB/Cisco modules; an
  unreachable target produces `up=0` without fabricated resource readings.
- Binary tests verify child/listener cleanup, Unix file/directory permissions,
  and temporary credential removal. YAML tests preserve numeric enum keys.
- GNS3 IOSvL2 20190423 was additionally tested on 2026-11-13 through the real
  v0.29.0 exporter and Collector: two scrapes produced 61 normalized series,
  zero rejected points, system identity/agent uptime, six logical interface
  states (including Null0), counters and derived traffic rates. A private capture
  is at `tests/lab/images/iosvl2-snmp-capture-20261113.json` (ignored).
- On 2026-11-14, direct Mac SNMP walks confirmed that this image returns
  noSuchObject for the newer process/memory-pool trees, but implements legacy
  `avgBusy1` (CPU), `freeMem` (free processor bytes), and `processorRam` (CPU RAM bytes).
  The generated `cisco_ios_legacy` module and `cisco-iosvl2` revision 2 map these OIDs.
- Both exporter and Collector now run natively on macOS under the same Omnisor
  Session used by the desktop. The container exporter was stopped; a loopback UDP
  lab transport exposes the agent. Two real scrapes yielded **66 normalized series,
  zero rejected points**, CPU, processor total/free RAM, derived used/utilization,
  and traffic rates. The captured CPU was 5%; memory total 726901760 bytes, free
  541329336 bytes, derived used 185572424 bytes and utilization 25.5292%.
- Private evidence: `tests/lab/images/iosvl2-native-snmp-capture-20261114.json`
  and `iosvl2-native-snmp-metrics.prom` (ignored). This validates the specified
  virtual image/profile and native pipeline, not all Cisco hardware/software.
  SSH evidence below remains separate.

## Real-device health validation

### Cisco IOSvL2 — verified virtual NOS

- Validated on 2026-11-07: real Cisco IOSvL2 software under GNS3 3.0.6/QEMU TCG
  on the local ARM64 backend; this does not establish physical-switch compatibility.
- Image: `vios_l2-adventerprisek9-m.ssa.high_iron_20190423.qcow2`,
  MD5 `71cacb678f98a106f99e889b97b34686`, SHA256
  `1afd5a51544d399ec67170b245977a857b52c1fdd0843ac8c720a55a4e8f7ca8`.
- Reported release: `15.2(CML_NIGHTLY_20190423)FLO_DSGS7`, synced to
  `V152_6_0_81_E`; use the Cisco IOS Legacy SSH/health profile.
- Verified: authenticated host-side SSH, console-pinned host key, and two complete
  snapshots through the web API. CPU averages, memory, uptime, hostname, and five
  interface states were parsed; the management interface was up/up.
- Limits: one virtual software build, isolated management endpoint, no connected
  topology peer. CDP/LLDP correctly remain Unknown under the current collector's
  empty-neighbor policy; neighbor discovery/probing is not validated by this run.
- Local artifacts (ignored by Git): image provenance, trusted public host key, and
  exported health JSON under `tests/lab/images/`. Setup and connection details are
  in the [Cisco lab guide](../../tests/lab/README.md#verified-cisco-iosvl2-device).

Additional Cisco IOS/IOS-XE combinations remain targets; record IOS Legacy
separately. A new
vendor/provider needs its own evidence before being included in the health catalog.

For each tested combination, record:

```text
Validation reference / date / tester:
Omnisor revision:
Vendor, device model, exact software version, and image checksum if applicable:
Physical/virtual device, host architecture, and relevant lab configuration:
Device profile, authentication method, and host verification policy:
Commands/checks exercised and required device privileges:
Expected versus observed values/status for each check:
Unsupported commands, malformed/unavailable values, and partial failure behavior:
Collection duration, device impact, and known limitations:
Sanitized transcript/replay fixture and test references:
Conclusion: SSH-only verified, specified health checks verified, or failed:
```

Keep credentials and identifying customer output out of committed fixtures. Record
software provenance before sanitizing transcripts. A successful boot, an SSH
response, and verified health checks are distinct levels of evidence.

## Capacity evidence

The 10–100-device range is a pilot target. No fleet benchmark is recorded in this
register. Follow the [engineering acceptance scenarios](PILOT_PLAYBOOK.md#engineering-acceptance)
and retain environment, run definition, device count, concurrency, latency/fault
settings, completion/error counts, resource usage, and storage growth with each
benchmark. Validate device impact on real equipment separately.
