# Omnisor Health

Reusable health and troubleshooting domain logic for Omnisor.

This crate sits above the core `omnisor` SSH/device APIs and owns:

- health snapshot types
- findings and status modeling
- reusable collectors/checks
- vendor-specific health parsers and adapters

This crate has no GUI dependencies and remains available to applications and other Rust libraries.

## Collection and extension

`LiveHealthSession` manages repeated collection over a reusable SSH connection.
Use it from an application or another Rust library. The original `collect_device_health` and
`collect_cisco_device_health` one-shot entry points are retained and return string
errors for compatibility.

For connection reuse or custom behavior, use the separate interfaces:

- `HealthProvider` owns a vendor/model's commands, parsing, and health assessment.
- `CommandExecutor` executes one command on an existing connection. `DeviceSession`
  implements it; recorded output or other transports can implement it too.
- `HealthTarget` passes the management address and port to providers without credentials.
- `collect_health_with_executor` borrows both interfaces and leaves connection ownership
  with the caller. It supports trait objects, including externally implemented providers.
- `collect_health_with_provider` opens/closes SSH using a supplied provider and the
  configured device profile. These new entry points return typed `HealthError` values.

Implement a provider in your own crate and pass it directly to either collection entry
point. A custom CLI can use `DeviceConfig` in the core library for its prompt, paging,
and error patterns. Neither requires changes to the core SSH implementation or the
built-in health vendor match. Applications can discover built-in providers through
`supported_health_vendors` or supply their own provider directly.

### Managed live collection

```no_run
use omnisor::CiscoVariant;
use health::{HealthConnectionConfig, LiveHealthSession};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = HealthConnectionConfig {
        address: "192.0.2.10".into(),
        port: 22,
        username: "admin".into(),
        password: "password".into(),
        vendor: CiscoVariant::Ios.into(),
    };
    // Register and verify the device in the operator's known_hosts file first.
    let mut health = LiveHealthSession::new(config)?;
    let first = health.collect_once().await?;
    println!("{}: {:?}", first.device.hostname, first.system.status);

    tokio::time::sleep(Duration::from_secs(10)).await;
    let second = health.collect_once().await?;
    println!("{}: {:?}", second.device.hostname, second.system.status);
    health.close().await;
    Ok(())
}
```

The first `collect_once` connects, and later successful calls reuse that connection.
Calls take `&mut self`, keeping commands on one session sequential. Scheduling is
owned by the caller: start the next refresh after the current one finishes to avoid
overlap. `is_connected` reports whether a connection is cached; it is not a remote
liveness probe. `connection_generation` counts successfully opened connections.

`LiveHealthSession::with_options` accepts `HealthSessionOptions`:

| Option | Default | Behavior |
| --- | --- | --- |
| `server_check` | `ServerCheckMethod::DefaultKnownHostsFile` | Verify the device against the operator's SSH known-hosts file |
| `connect_timeout` | 10 seconds | Bound asynchronous connection, authentication, and CLI initialization |
| `command_timeout` | 10 seconds | Limit the wait for an individual command's prompt |
| `collection_timeout` | 60 seconds | Bound the complete command/probe sequence, excluding connection setup |

Timeouts must be greater than zero. Hostname resolution currently follows the core
client's synchronous system lookup and cannot be preempted by the connection
deadline. Use an explicitly trusted pinned public key or known-hosts file when
appropriate. `ServerCheckMethod::NoCheck` is an explicit opt-in for disposable lab
devices whose synthetic host keys change on restart.

Any collection error, deadline, or cancellation invalidates the current connection.
A later `collect_once` reconnects instead of consuming late output from an earlier
command. Call `close().await` when monitoring stops; cleanup is bounded to two
seconds. Dropping a connected session schedules bounded cleanup when a Tokio
runtime is available. `with_provider` applies the same lifecycle to an external
`HealthProvider`. These APIs return typed `HealthError` values. Configuration debug
output redacts the password.

The original one-shot helpers use the convenience connection path, which disables
host verification. That behavior is retained for compatibility. Use
`LiveHealthSession`, or configure a verified `DeviceSession` explicitly, for live
device access.

### Reuse an SSH connection

```no_run
use omnisor::{CiscoVariant, DeviceSession, ServerCheckMethod};
use health::{CiscoIosHealthProvider, HealthTarget, collect_health_with_executor};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = HealthTarget {
        address: "192.0.2.10".to_string(),
        port: 22,
    };
    let provider = CiscoIosHealthProvider::new(CiscoVariant::Ios)?;
    let mut session = DeviceSession::builder()
        .address(&target.address)
        .port(target.port)
        .username("admin")
        .password("password")
        .vendor(CiscoVariant::Ios)
        .server_check(ServerCheckMethod::DefaultKnownHostsFile)
        .connect()
        .await?;

    let first = collect_health_with_executor(&target, &provider, &mut session).await?;
    let second = collect_health_with_executor(&target, &provider, &mut session).await?;
    println!("{}: {:?}", first.device.hostname, second.system.status);
    session.close().await?;
    Ok(())
}
```

## Health coverage and time windows

Built-in health commands currently cover Cisco IOS, IOS-XE, and IOS Legacy. SSH support
for other Cisco platforms and Juniper does not imply health command/parser coverage.
`supported_health_vendors` exposes the built-in provider catalog to library consumers.
Unsupported built-in health profiles fail before opening a connection; use an external
provider to extend them.

CPU readings include the device's one-minute and five-minute averages. The existing
`SystemHealth::cpu_percent` remains the one-minute value; the added
`cpu_five_minute_percent` is optional. Downstream struct literals must supply this new
field. Memory and interface state are readings collected during the command sequence,
and `collected_at` records when the sequence completed. A snapshot is not a stored
five-minute history or an atomic measurement across all checks.

Live health is a sequence of polled snapshots. A ten-second refresh cadence does
not turn device-reported one-minute or five-minute CPU averages into instantaneous
readings. The caller should display snapshot age and collection state, retain the
previous successful snapshot on failure, and mark that retained data stale until a
fresh collection succeeds. Pausing automatic refresh does not refresh old data.

Unavailable or malformed metrics remain `Unknown`. Neighbor pings run once per unique
management IP per snapshot, with results shared across CDP/LLDP entries. Invalid IP
strings are not sent as commands. Administratively disabled interfaces are counted
separately from operational problems. Parsers compile their fixed regexes once.

CLI command rejection leaves that check `Unknown` while the other checks continue.
Transport failures abort collection with `HealthError::Command`, preserving the
underlying error and failed command. Callers that own an SSH executor should close
and reconnect before retrying, because a timeout can leave late output in the prompt
stream. The one-shot managed entry points close their session after collection;
`LiveHealthSession` keeps a successful connection open for the next refresh.

## Tests without a lab

```sh
cargo test -p health
```

The integration tests in `tests/health_replay.rs` feed synthetic IOS-style fixtures
through the public executor/provider API. They cover full and partial snapshots,
malformed metrics, neighbor probe reuse, supported profiles, and external providers.
They validate collector behavior without a network connection; they do not establish
compatibility with every firmware/model. Sanitized transcripts from real devices can
extend this coverage when a lab is available again.

The ignored `live_monitor` suite exercises real loopback SSH connections, host-key
verification, changing scenarios, session reuse, deadlines, cancellation, and
reconnection after failure. Run it with the synthetic device suite:

```sh
./tests/lab.sh test
# Or only the managed live-session cases:
cargo test -p health --test live_monitor -- --ignored
```
