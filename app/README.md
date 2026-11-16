# Omnisor desktop

Standalone GPUI device-health workspace. Startup is idle. Selecting Device Health
opens connection setup; only **Connect** launches components and contacts
a target. Other mini-apps remain independent entries in the compact sidebar.

## Run a live session

Install the tested component binaries (`otelcol-contrib` 0.140.0 and, for SNMP,
`snmp_exporter` 0.29.0). Put them on PATH, supply developer environment
overrides, or place them in a companion
`collection-tools` directory next to the executable (or its debug/release parent).

```sh
OMNISOR_OTELCOL=/path/to/otelcol-contrib \
OMNISOR_SNMP_EXPORTER=/path/to/snmp_exporter \
cargo run -p app --features gui
```

1. Open **Device health** or **Connect device**.
2. Select a saved device, or enter the address and device family for a new device.
   The catalog selects protocol, exporter, modules, cadence and credential needs.
   Setup does not expose protocol, YAML profile, interval or executable selectors.
3. Enter only the requested monitoring credentials. The current Cisco family
   policy requires a monitoring username plus authentication and privacy passwords
   (SNMPv3 SHA/AES authPriv). A model policy can instead request a read-only
   community or an access token. A configured gateway can require no new credentials.
   There is no automatic downgrade or protocol guessing from the supplied passwords.
4. Select **Connect** (Cmd-Enter). Omnisor binds local OTLP ingestion, starts an
   exporter if the plan needs one, then starts the Collector. No command-output
   parsing supplies these measurements.
5. Inspect Overview, Interfaces, Observations, Findings, and Collection. Stop,
   leaving Device Health, or closing/quitting the app releases owned processes.

A new device currently requires an explicit device family; automatic model/OS
identification is not implemented. Catalog-derived identity is connection context,
not verified hardware discovery. Missing measurements remain unavailable.

For the running GNS3 IOSvL2 lab, `./tests/lab.sh real telemetry` configures the
read-only SNMP path to Mac UDP `127.0.0.1:1161` and registers **lab-cisco-iosvl2**
in `target/collection-tools/devices.json`. Restart the desktop to load the record,
then select it and **Connect**. No metrics URL, port mapping or community is entered
in setup. Omnisor reads the private lab credential reference at Connect and owns
both native macOS `snmp_exporter` and Collector processes. The lab containers
provide only IOS and UDP transport; they run no metrics exporter.
See the [lab guide](../tests/lab/README.md#prometheus-telemetry-from-the-running-iosvl2-lab).

Saved devices are optional, non-secret device/site connection records, loaded
from `OMNISOR_DEVICES_FILE` or a companion `collection-tools/devices.json`. They
can override deployment access policy, reference a private credential file, or
associate a device with an existing exporter gateway. This is not a complete
inventory UI or an OS credential store; see [the schema](../collection/README.md#device-access-resolution).

**Try a simulated device** on the start view checks the complete pipeline without
hardware. Its changing exporter readings travel through a real Collector and OTLP
receiver. The dashboard labels them simulated. This requires the Collector binary,
but no SNMP exporter or credentials. It is separate from real device setup.

The **Collection** tab shows pipeline status, process IDs, receiver address,
generated Collector YAML (environment references, not token values), and bounded,
redacted component diagnostics. Errors and stale sources remain visible.

## Device health presentation

- Vendor, model, device type, OS/version, and identity provenance.
- Latest fresh CPU/memory/interface/finding summaries.
- CPU and memory history plus observed receive/transmit traffic graphs, real UTC
  axes and units, selectable maximum 1/5/15-minute windows, min/max/sample mean,
  and sample counts. A new session shows only the available history.
- CPU labels retain the source averaging window. Memory joins the same entity and
  timestamp; a total/free source derives used = total − free. Counter rates require two valid points and exclude resets/gaps.
- A paged interface table separates admin/oper state, traffic rates, cumulative
  errors/discards, missing values, and historical states.
- Freshness and `up` are distinct from process liveness. Failed, stale, or stopped
  collection cannot be presented as healthy zero usage. Previous graphs remain
  available for inspection while the session is open.

History is in RAM: 15 minutes, up to 450 history points per series and 4096 series.
Current desktop scope is one active device session. Process pooling, persistent
inventory/history, binary packaging, and broader device validation remain future
work. See [collection configuration](../collection/README.md) for profiles,
YAML layout, bounds, credential lifetime, and exact statistical semantics.

Device Health currently supports collection sessions only. Capture-file import,
recorded previews, and the capture startup argument are unavailable. The simulated
device runs through a real Collector session. Live history remains in memory and
is not persisted or exported.

## Native build and controls

GPUI is pinned to `0.2.2`. The `gui` feature enables native dependencies;
`runtime_shaders` avoids the separate build-time Metal compiler on macOS. Rust
and Apple command-line development tools, a graphical session, and Metal-capable
hardware are required. Linux/Windows native packaging and behavior need separate
validation. Framework support does not imply Omnisor release compatibility.

Cmd-1 opens Device Health, Tab/Shift-Tab move through form inputs, Cmd-Enter starts
collection, Escape/Omnisor wordmark return to the start view, and Cmd-Q quits.
The form supports native text selection, clipboard input, IME, and masked secret
fields. Packaging, accessibility audits, application menus and updates remain work.

## Code boundaries and checks

- `crates/collection`: typed profiles/plans, YAML assembly, Tokio runtime,
  process ownership, OTLP receiving, bounded series/rates and immutable snapshots.
- `crates/telemetry`: transport-independent normalization and finding rules.
- Desktop model: session observations, mini-app demand and health summaries.
- `src/ui/connection.rs`, `engine.rs`: connection form and GPUI/runtime bridge.
- `src/ui/live_health.rs`, `charts.rs`, `records.rs`: live presentation and evidence.
- `src/ui/input.rs`: native text input adapted from the Apache-2.0 GPUI example.
- `src/main.rs`, `src/ui.rs`, `navigation.rs`: window, shell, tab and app routing.

```sh
cargo test --workspace
cargo clippy -p app -p collection \
  --features app/gui --all-targets -- -D warnings
OMNISOR_TEST_COLLECTOR=/path/to/otelcol-contrib \
OMNISOR_TEST_SNMP_EXPORTER=/path/to/snmp_exporter \
cargo test -p collection --test pipeline -- --ignored --nocapture
```

Native checks additionally exercise connection setup, a live synthetic session,
chart/table rendering, return navigation, and clean shutdown. Real-device SNMP
validation requires the selected device to be reachable and configured.
