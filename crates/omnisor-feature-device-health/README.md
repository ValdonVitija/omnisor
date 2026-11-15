# Omnisor Feature: Device Health

This crate contains the Device Health ratatui feature flow for `omnisor-app`.

It owns:

- device-health-specific setup flow
- feature-local state
- health screen rendering
- interaction over `omnisor-health`

It is mounted by the main `omnisor-app` shell through a static feature registry.

The connection picker uses the health profiles registered by `omnisor-health`.
SSH support in the core library does not imply a health collector for that platform.
The system dashboard shows device-reported one-minute and five-minute CPU averages
when available, plus current memory usage and snapshot age.

During connection setup, characters such as `q` are entered into text fields.
Use Escape to return to the launcher; `q` quits from the launcher or dashboard.
If a background worker stops unexpectedly, the feature reports a failure and allows
another connection attempt or refresh while retaining the previous snapshot.

## Live health snapshots

Connect starts the first health collection, then opens the dashboard when a
snapshot is available. One owned background worker keeps a reusable SSH session;
the UI remains responsive during connection and collection.

Automatic refresh defaults to 10 seconds after each completed attempt. Configure
an interval from 5 to 3600 seconds during connection setup. Collections run
sequentially, so a slow device cannot accumulate overlapping refreshes. These are
periodic snapshots, not streaming telemetry or atomic readings across checks.

- `p` or Space pauses/resumes automatic refresh. An already running attempt may finish.
- `r` refreshes immediately, including while automatic refresh is paused.
- Escape cancels the active worker and returns to the launcher; `q` quits from the dashboard.

A failed attempt retains the last successful snapshot, shows `STALE`, and retries
on the next automatic interval. A snapshot older than twice the configured
interval is also shown as stale. The freshness cards identify paused collection
and stale data independently of the health readings. Transport errors cause the
shared session engine to reconnect before another attempt.

Host trust defaults to verifying the user's `~/.ssh/known_hosts`. Establish trust
with a normal SSH client before connecting. The connection form also offers an
explicit `INSECURE (lab only)` option for isolated synthetic devices, whose host
keys change on each lab start. An insecure connection remains labeled on the
dashboard. Passwords are masked in the form and redacted from configuration debug output.
