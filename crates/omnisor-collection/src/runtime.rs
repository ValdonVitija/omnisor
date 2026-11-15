use crate::{
    Catalog, CollectionPlan, DeviceIdentity, Source,
    ingest::{IngestState, router},
    store::{MetricsSnapshot, Store},
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::Path,
    process::Stdio,
    sync::{Arc, Mutex, RwLock},
    thread,
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    sync::watch,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}
impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Self::Starting => "Starting",
            Self::Running => "Running",
            Self::Stopping => "Stopping",
            Self::Stopped => "Stopped",
            Self::Failed => "Failed",
        }
    }
    pub fn active(self) -> bool {
        matches!(self, Self::Starting | Self::Running | Self::Stopping)
    }
}

#[derive(Clone, Debug)]
pub struct SessionSnapshot {
    pub phase: Phase,
    pub device: DeviceIdentity,
    pub profile_id: String,
    pub source: String,
    pub interval_seconds: u64,
    pub metrics: Arc<MetricsSnapshot>,
    pub error: Option<String>,
    pub receiver_address: Option<SocketAddr>,
    pub process_ids: Vec<u32>,
    pub config_directory: Option<std::path::PathBuf>,
    pub collector_yaml: Option<String>,
    pub diagnostics: Vec<String>,
}

struct Inner {
    snapshot: Arc<RwLock<Arc<SessionSnapshot>>>,
    stop: watch::Sender<bool>,
    done: watch::Receiver<bool>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

#[derive(Clone)]
pub struct Session {
    inner: Arc<Inner>,
}
impl Session {
    pub fn start(plan: CollectionPlan) -> Result<Self, String> {
        let catalog = Catalog::bundled()?;
        plan.validate(&catalog)?;
        let initial = SessionSnapshot {
            phase: Phase::Starting,
            device: plan.device.clone(),
            profile_id: plan.profile_id.clone(),
            source: plan.source.label().into(),
            interval_seconds: plan.interval_seconds,
            metrics: Arc::new(MetricsSnapshot::default()),
            error: None,
            receiver_address: None,
            process_ids: vec![],
            config_directory: None,
            collector_yaml: None,
            diagnostics: vec![],
        };
        let snapshot = Arc::new(RwLock::new(Arc::new(initial)));
        let (stop, stop_rx) = watch::channel(false);
        let (done_tx, done) = watch::channel(false);
        let shared = snapshot.clone();
        let worker = thread::Builder::new()
            .name("omnisor-collection".into())
            .spawn(move || {
                let result = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build();
                match result {
                    Ok(runtime) => runtime.block_on(run(plan, catalog, shared.clone(), stop_rx)),
                    Err(error) => update(&shared, |s| {
                        s.phase = Phase::Failed;
                        s.error = Some(format!("Cannot create collection runtime: {error}"));
                    }),
                }
                let _ = done_tx.send(true);
            })
            .map_err(|e| format!("Cannot create collection worker: {e}"))?;
        Ok(Self {
            inner: Arc::new(Inner {
                snapshot,
                stop,
                done,
                worker: Mutex::new(Some(worker)),
            }),
        })
    }
    pub fn snapshot(&self) -> Arc<SessionSnapshot> {
        self.inner
            .snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn stop(&self) {
        let _ = self.inner.stop.send(true);
    }
    pub async fn stopped(&self) {
        let mut done = self.inner.done.clone();
        while !*done.borrow_and_update() {
            if done.changed().await.is_err() {
                break;
            }
        }
    }
    /// Only for application exit / headless clients. Normal UI Stop is asynchronous.
    pub fn shutdown_blocking(&self) {
        self.stop();
        if let Some(worker) = self
            .inner
            .worker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = worker.join();
        }
    }
}

type Shared = Arc<RwLock<Arc<SessionSnapshot>>>;
fn update(shared: &Shared, change: impl FnOnce(&mut SessionSnapshot)) {
    let mut lock = shared.write().unwrap_or_else(|e| e.into_inner());
    let mut snapshot = (**lock).clone();
    change(&mut snapshot);
    *lock = Arc::new(snapshot);
}

async fn run(
    plan: CollectionPlan,
    catalog: Catalog,
    shared: Shared,
    mut stop: watch::Receiver<bool>,
) {
    let mut children: Vec<Child> = Vec::new();
    let mut server = None;
    let mut directory = None;
    let log: crate::diagnostics::Log = Default::default();
    let mut log_tasks = Vec::new();
    let result = async {
        if *stop.borrow() { return Ok(()); }
        let config = catalog.normalization(&plan.profile_id, &plan.device)?;
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| format!("Cannot bind local OTLP receiver: {e}"))?;
        let address = listener.local_addr().map_err(|e| e.to_string())?;
        let token = rand::random::<[u8;32]>().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let mut secrets = plan.source.secrets(); secrets.push(token.clone());
        let secrets = Arc::new(secrets);
        let store = Arc::new(Mutex::new(Store::new(plan.device.id.clone(), plan.interval_seconds)));
        let state = IngestState { config: Arc::new(config), store: store.clone(), authorization: Arc::new(format!("Bearer {token}")), synthetic: matches!(plan.source, Source::Synthetic), started: Instant::now() };
        server = Some(tokio::spawn(async move { axum::serve(listener, router(state)).await }));
        update(&shared, |s| s.receiver_address = Some(address));
        let mut builder = tempfile::Builder::new(); builder.prefix("omnisor-session-");
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; builder.permissions(fs::Permissions::from_mode(0o700)); }
        let dir = builder.tempdir().map_err(|e| e.to_string())?;
        let root = dir.path().to_path_buf(); directory = Some(dir);
        update(&shared, |s| s.config_directory = Some(root.clone()));
        let mut exporter_address = None;
        if let Source::Snmp { exporter, .. } = &plan.source {
            let reservation = TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
            let endpoint = reservation.local_addr().map_err(|e| e.to_string())?;
            drop(reservation);
            let snmp_config = root.join("snmp.yaml");
            private_write(&snmp_config, &plan.snmp_yaml(&catalog)?)?;
            let mut command = Command::new(fs::canonicalize(exporter).map_err(|e| e.to_string())?);
            command.arg(format!("--config.file={}", snmp_config.display()))
                .arg(format!("--web.listen-address={endpoint}"));
            let mut child = spawn(command)?;
            if let Some(stderr) = child.stderr.take() { log_tasks.push(crate::diagnostics::start(stderr,"snmp_exporter",secrets.clone(),log.clone())); }
            children.push(child);
            let started = Instant::now();
            loop {
                if let Some(status) = children[0].try_wait().map_err(|e| e.to_string())? { return Err(format!("SNMP exporter exited during startup ({status}). Use the supported v0.29.0 binary and profile.")); }
                if TcpStream::connect(endpoint).await.is_ok() { break; }
                if started.elapsed() > Duration::from_secs(5) { return Err("SNMP exporter did not become ready within 5 seconds".into()); }
                tokio::select! { _ = stop.changed() => return Ok(()), _ = tokio::time::sleep(Duration::from_millis(50)) => {} }
            }
            exporter_address = Some(endpoint.to_string());
        }
        if *stop.borrow() { return Ok(()); }
        let collector_config = root.join("otelcol.yaml");
        let yaml = plan.collector_yaml(&catalog, &address.to_string(), exporter_address.as_deref())?;
        private_write(&collector_config, &yaml)?;
        update(&shared, |s| s.collector_yaml = Some(yaml));
        let mut command = Command::new(fs::canonicalize(&plan.collector).map_err(|e| e.to_string())?);
        command.arg("--config").arg(&collector_config).env("OMNISOR_INGEST_TOKEN", token);
        if let Source::Prometheus { bearer_token, .. } = &plan.source { command.env("OMNISOR_SOURCE_TOKEN", bearer_token); }
        let mut child = spawn(command)?;
        if let Some(stderr) = child.stderr.take() { log_tasks.push(crate::diagnostics::start(stderr,"otelcol",secrets.clone(),log.clone())); }
        children.push(child);
        update(&shared, |s| { s.phase = Phase::Running; s.process_ids = children.iter().filter_map(Child::id).collect(); });
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        let mut sequence = 0;
        loop {
            tokio::select! {
                _ = stop.changed() => break,
                _ = tick.tick() => {
                    if server.as_ref().is_some_and(|s| s.is_finished()) { return Err("Local OTLP receiver stopped unexpectedly".into()); }
                    for child in &mut children {
                        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                            return Err(format!("Collection component exited ({status}). Confirm binary versions and selected profile. Restart collection after correcting the setup."));
                        }
                    }
                    let snapshot = {
                        let store = store.lock().unwrap_or_else(|e| e.into_inner());
                        (store.data.sequence != sequence).then(|| Arc::new(store.data.clone()))
                    };
                    update(&shared, |s| s.diagnostics = log.lock().unwrap_or_else(|e|e.into_inner()).iter().cloned().collect());
                    if let Some(snapshot) = snapshot { sequence = snapshot.sequence; update(&shared, |s| s.metrics = snapshot); }
                }
            }
        }
        Ok::<_, String>(())
    }.await;
    update(&shared, |s| s.phase = Phase::Stopping);
    // Reverse dependency order. Await reaping before deleting credentials/config.
    for child in children.iter_mut().rev() {
        #[cfg(unix)]
        if let Some(pid) = child.id() {
            // Each child has its own process group. Stop descendants as well.
            unsafe {
                libc::kill(-(pid as i32), libc::SIGTERM);
            }
            if tokio::time::timeout(Duration::from_millis(500), child.wait())
                .await
                .is_err()
            {
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGKILL);
                }
            }
        }
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    if let Some(server) = server {
        server.abort();
        let _ = server.await;
    }
    for mut task in log_tasks {
        if tokio::time::timeout(Duration::from_millis(200), &mut task)
            .await
            .is_err()
        {
            task.abort();
        }
    }
    drop(directory);
    update(&shared, |s| {
        s.config_directory = None;
        s.diagnostics = log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect();
        s.process_ids.clear();
        s.receiver_address = None;
        match result {
            Ok(()) => s.phase = Phase::Stopped,
            Err(error) => {
                s.phase = Phase::Failed;
                s.error = Some(error);
            }
        }
    });
}
fn spawn(mut command: Command) -> Result<Child, String> {
    #[cfg(unix)]
    command.process_group(0);
    command
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
        .spawn()
        .map_err(|e| format!("Cannot start collection component: {e}"))
}
fn private_write(path: &Path, contents: &str) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    file.write_all(contents.as_bytes())
        .map_err(|e| e.to_string())
}
