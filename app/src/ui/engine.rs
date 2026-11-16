use super::*;
use app::{Capture, RecordedFinding};
use collection::{Phase, unix_nanos};
use std::time::Duration;

impl Workbench {
    pub(super) fn configure_device(&mut self, cx: &mut Context<Self>) {
        self.detach_session();
        let _ = self.launcher.open(MiniApp::DeviceHealth);
        self.setup = Some(connection::ConnectionForm::new(
            &self.catalog,
            &self.saved_devices,
            self.saved_devices_error.clone(),
            cx,
        ));
        cx.notify();
    }
    pub(super) fn attach_session(&mut self, session: Session, cx: &mut Context<Self>) {
        self.detach_session();
        let generation = self
            .launcher
            .open(MiniApp::DeviceHealth)
            .expect("available health tool");
        let _ = self.launcher.request_live_operation();
        self.setup = None;
        self.workspace = Workspace::empty();
        self.workspace.selected_device = Some(session.snapshot().device.id.clone());
        self.summary = HealthSummary::default();
        self.collection_fresh = false;
        self.live = Some(session.snapshot());
        self.session = Some(session.clone());
        self.poll_task = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_millis(500)).await;
                let snapshot = session.snapshot();
                let active = snapshot.phase.active();
                let result = this.update(cx, |this, cx| {
                    if !this.launcher.accepts_result(MiniApp::DeviceHealth, generation) { session.stop(); return false; }
                    let now = unix_nanos();
                    let fresh = snapshot.phase == Phase::Running && snapshot.metrics.is_fresh(now, snapshot.interval_seconds);
                    let changed = this.live.as_ref().is_none_or(|old| old.metrics.sequence != snapshot.metrics.sequence || old.phase != snapshot.phase) || this.collection_fresh != fresh;
                    if changed {
                        let observations = snapshot.metrics.observations();
                        let cutoff = now.saturating_sub(snapshot.interval_seconds*3*1_000_000_000);
                        let current: Vec<_> = observations.iter().filter(|o| fresh && o.observed_at_unix_nano.parse::<u64>().unwrap_or(0) >= cutoff).cloned().collect();
                        this.summary = HealthSummary::for_device(&current, &snapshot.device.id);
                        this.workspace.capture = Some(Capture {
                            description: if snapshot.source == "Synthetic exporter" { "Synthetic measurements collected through a real Collector; no physical device is connected.".into() } else { "Collection session observations. Device identity comes from the selected device profile and connection record.".into() },
                            observations,
                            findings: telemetry::findings(&current).into_iter().map(|f| RecordedFinding { device_id:f.device_id, entity_id:f.entity_id, severity:f.severity.into(), message:f.message }).collect(),
                        });
                        this.workspace.source = format!("{} → OpenTelemetry → local OTLP receiver", snapshot.source);
                        this.collection_fresh = fresh;
                    }
                    this.live = Some(snapshot);
                    this.retired_sessions.retain(|s| s.snapshot().phase.active());
                    cx.notify();
                    true
                });
                if !matches!(result, Ok(true)) || !active { break; }
            }
        }));
        cx.notify();
    }
    pub(super) fn stop_collection(&mut self, cx: &mut Context<Self>) {
        if let Some(session) = &self.session {
            session.stop();
        }
        self.launcher.stop_operation();
        cx.notify();
    }
    pub(super) fn detach_session(&mut self) {
        self.poll_task = None;
        if let Some(session) = self.session.take() {
            session.stop();
            self.retired_sessions.push(session);
        }
        self.launcher.stop_operation();
        self.live = None;
        self.collection_fresh = false;
    }
    pub(super) fn shutdown_sessions(&mut self) {
        if let Some(session) = &self.session {
            session.shutdown_blocking();
        }
        for session in &self.retired_sessions {
            session.shutdown_blocking();
        }
    }
    pub(super) fn collection_footer(&self) -> String {
        match &self.live {
            Some(snapshot) if self.session.is_some() => format!(
                "Local collection · {} · {} series",
                snapshot.phase.label(),
                snapshot.metrics.series.len()
            ),
            _ => "Local workspace · No collection requested".into(),
        }
    }
}
impl Drop for Workbench {
    fn drop(&mut self) {
        self.shutdown_sessions();
    }
}
