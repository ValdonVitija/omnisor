# Prometheus and OpenTelemetry collection example

This runnable slice demonstrates device measurements passing through a Prometheus
exporter, the real OpenTelemetry Collector, and Rust OTLP ingestion into canonical
Omnisor observations. Open the inspection page to compare each representation and
switch between healthy and degraded readings.

The included exporters are **synthetic fixtures**. One follows selected metric
names and labels from the Prometheus SNMP exporter; the other demonstrates a
different exporter schema. The latter's `oc_*` names are illustrative, not an
OpenConfig standard or a gNMI implementation. No physical device or OS compatibility
is established by these fixtures. A real SNMP exporter configuration is included
below for connecting an accessible device.

## Run the example

Install a native `otelcol-contrib` binary from the
[Collector releases](https://github.com/open-telemetry/opentelemetry-collector-releases/releases/tag/v0.140.0).
The configuration and integration smoke test were exercised with the `v0.140.0`
release archive (whose binary reports `0.140.1`). Run commands from the repository
root. A Prometheus server, Docker, device credentials, and a broker are not needed
for the synthetic example.

Terminal 1:

```sh
cargo run -p omnisor-telemetry-demo
```

Terminal 2:

```sh
export OMNISOR_DEMO_TOKEN=local-telemetry-demo
export OMNISOR_OTEL_STORAGE="$(mktemp -d)"
otelcol-contrib --config examples/telemetry/otelcol.yaml
```

Open <http://127.0.0.1:9464>. The Collector scrapes both exporters every five
seconds, batches the readings, and sends OTLP/HTTP protobuf to `/v1/metrics`.
The debug exporter also prints decoded telemetry in Terminal 2.

The page shows:

1. Exporter text, independently selectable for each source schema.
2. The latest actual OTLP request decoded as JSON for inspection.
3. Canonical observations from that request.
4. CPU, memory, and interface findings plus rejected values.

The source selector changes the exporter text; the other panels show the latest
incoming batch, which may contain either or both devices. Use the JSON endpoint
to inspect the ten retained batches. Click **High CPU and interface failure** to
produce 96% CPU, 96% memory utilization, and an interface fault on both devices.
The IOS fixture also has an intentionally disabled interface, which does not
produce a fault. **Healthy readings** restores the source readings on the next
scrape; this demo does not implement incident resolution.

Stop both processes with Ctrl-C. Collector queue files remain in
`OMNISOR_OTEL_STORAGE`; reuse that directory for queue recovery or remove it after
the example. The optional `OMNISOR_DEMO_ADDR` sets a different loopback address in
both processes. `OMNISOR_OTEL_METRICS_PORT` overrides the Collector's own monitoring
port, which defaults to 8889. This example is bound to loopback and is not a SaaS
deployment.

## Follow one measurement

A real Cisco SNMP device can expose CPU through this MIB object:

```text
CISCO-PROCESS-MIB::cpmCPUTotal1minRev.1
OID: 1.3.6.1.4.1.9.9.109.1.1.1.1.7.1
Value: 96 (one-minute CPU busy percentage)
```

The SNMP exporter produces Prometheus text. Our synthetic IOS endpoint emits the
same selected measurement shape:

```prometheus
# TYPE cpmCPUTotal1minRev gauge
cpmCPUTotal1minRev{cpmCPUTotalIndex="1"} 96
```

The Collector adds configured target labels, assigns a scrape timestamp, and
converts the measurement into an OTLP gauge. A shortened decoded representation:

```json
{
  "name": "cpmCPUTotal1minRev",
  "gauge": {
    "dataPoints": [{
      "attributes": [
        {"key": "device_id", "value": {"stringValue": "lab-ios-01"}},
        {"key": "cpmCPUTotalIndex", "value": {"stringValue": "1"}}
      ],
      "timeUnixNano": "1794525797439000000",
      "asDouble": 96
    }]
  }
}
```

The receiver authenticates its local Collector token, binds it to `demo-tenant`,
and selects the device's enrolled profile from `profiles.json`. It never obtains
tenant identity or profile assignments from exporter-controlled labels.
The corresponding normalized observation includes:

```json
{
  "tenant_id": "demo-tenant",
  "device_id": "lab-ios-01",
  "entity_id": "1",
  "name": "device.cpu.utilization",
  "value": 0.96,
  "unit": "1",
  "kind": "gauge",
  "window_seconds": 60,
  "source_metric": "cpmCPUTotal1minRev",
  "profile_id": "ios-snmp",
  "profile_revision": "1"
}
```

The complete observation also preserves timestamps and attributes. Rules evaluate
the canonical name and value, producing a critical CPU finding at 90% and above.
The five-second scrape cadence does not change this device's one-minute CPU window.
The second exporter profile leaves the averaging window unspecified.

| Source reading | Canonical result | Processing |
| --- | --- | --- |
| CPU percentage | `device.cpu.utilization`, ratio | Divide by 100; reject values outside 0–100 |
| Used/free memory bytes | `device.memory.used` / `device.memory.free` | Preserve pool identity; evaluate used / (used + free) only for matching timestamps |
| `ifAdminStatus=1` | `interface.admin_status="up"` | Decode the administrative state enum |
| `ifOperStatus=2` | `interface.oper_status="down"` | Flag down only when matching administrative state is up |
| `ifHCInOctets` | `interface.receive.bytes` | Preserve cumulative counter semantics and start timestamp; do not call it bandwidth |

Interface state conversion retains all seven IF-MIB operational enum values. The
initial interface rule evaluates the explicit `down` state. It does not yet cover
all operational states, flapping, counter resets, or protocol correlation.

CPU warning/critical thresholds are 80%/90%; memory thresholds are 85%/95%.
Rules operate on each received batch. Joining measurements across batches and
managing persistent finding lifecycles belong in the future state service.

## Change a device profile

`profiles.json` maps enrolled device IDs to profiles. Each source metric mapping
defines its canonical name, expected gauge/counter kind, conversion, unit,
entity label, and optional averaging window. Set a profile's `enabled` to `false`
to reject its observations explicitly. Remove a scrape job from `otelcol.yaml`
to stop collection. Editing mappings does not require changing transport or rule
code; restart the demo to load configuration.

```sh
OMNISOR_TELEMETRY_CONFIG=/path/to/profiles.json cargo run -p omnisor-telemetry-demo
```

Unmapped gauge/counter points, including Collector scrape metadata, are counted
as ignored. Unknown devices, disabled profiles, missing entities, invalid values,
missing timestamps, unavailable flags, and incorrect metric kinds are rejected.
OTLP partial-success responses report rejected point counts. Histograms, summaries,
and delta sums are outside this first slice and are rejected explicitly.

Raw OTLP remains available in the inspection capture. Normalized attributes retain
scalar string/integer/boolean labels; nested, byte, and floating-point attributes
are not normalized in this example. OTLP integer values remain integers in Rust;
Prometheus floating-point counter precision cannot be recovered by normalization.
Timestamp strings preserve nanosecond precision in JavaScript. A counter start time
of zero means the source did not supply one.

## Connect a real SNMP exporter

The device → exporter hop uses SNMP, not OpenTelemetry. The exporter → Collector →
Omnisor path is unchanged. Use an accessible device and an upstream
[`snmp_exporter`](https://github.com/prometheus/snmp_exporter/tree/v0.29.0)
configured with `if_mib`, `cisco_device`, and an appropriate authentication entry.
Keep credentials in the exporter's local configuration. The bundled profile uses
the v0.29.0 names/labels; available MIB objects vary by device and OS.

With the demo receiver running and the exporter listening on `127.0.0.1:9116`:

```sh
export OMNISOR_DEVICE_ADDRESS=192.0.2.10  # replace with your device
export OMNISOR_SNMP_AUTH=customer_v3     # named auth in your exporter config
export OMNISOR_DEMO_TOKEN=local-telemetry-demo
export OMNISOR_OTEL_STORAGE="$(mktemp -d)"
otelcol-contrib \
  --config examples/telemetry/otelcol.yaml \
  --config examples/telemetry/otelcol-snmp.yaml
```

The overlay replaces the pipeline receiver with the real SNMP scrape job. The
synthetic receivers are no longer active. It deliberately uses the enrolled ID
`lab-ios-01`; replace that label and add your actual device to the profile inventory.
The synthetic scenario buttons affect only the synthetic endpoints, not the real
device. Collection errors remain visible in Collector logs and the raw `up` metric.
The page reports stale ingestion after 15 seconds without a batch; this is a
batch-level indication, not per-device freshness or reachability.

For another vendor, use that exporter's modules and a matching profile. Prefer
standard IF-MIB mappings where supported. Native Prometheus endpoints can be
scraped directly. A later gNMI adapter can feed OTLP through the same ingestion
boundary; this example does not implement that adapter.

## Verify the complete pipeline

Offline Rust checks:

```sh
cargo test -p omnisor-telemetry -p omnisor-telemetry-demo
cargo clippy -p omnisor-telemetry -p omnisor-telemetry-demo --all-targets -- -D warnings
```

Real Collector smoke test:

```sh
OTELCOL_BIN=/path/to/otelcol-contrib bash tests/telemetry.sh \
  --output /tmp/omnisor-telemetry-capture
```

The test starts isolated processes, verifies both source schemas, checks healthy
readings, changes the fixtures, and verifies CPU/memory/interface findings. It also
checks that stopping the Collector produces no new batches, then stops its
processes. Captures include exporter text, complete decoded OTLP, observations,
findings, and process logs. The checked-in `sample-output.json` contains excerpts
from an actual successful run for reading without starting the processes.

## Boundary with the desktop application

`crates/omnisor-telemetry` owns reusable profile normalization and initial rules;
it has no HTTP, SSH, broker, or database dependency. The demo tool owns loopback
HTTP ingestion, synthetic exporter endpoints, bounded inspection captures, and
the page. The existing SSH dashboards continue to use their current collector.

The receiver accepts only uncompressed OTLP/HTTP protobuf with a 1 MiB request
limit and keeps the last ten requests in memory. Its single demo credential binds
to one configured inventory; it is not a production enrollment service. Successful
acknowledgement means in-memory acceptance, not durable delivery. The Collector's
disk-backed queue protects pending exports; it cannot make this receiver durable.

The primary application is now the standalone GPUI workbench in
`apps/omnisor-desktop`. Its `omnisor-collection` runtime now supervises the
Collector and optional SNMP exporter after connection setup, receives authenticated
local OTLP, and presents bounded live history. The runtime configuration catalog
is under [`collection/`](../../collection/README.md); these files remain a standalone
wire-format walkthrough and synthetic fixture for inspection and replay. The two
flows share normalization types/rules. Neither proves device compatibility without
a test against the exact device/OS.
