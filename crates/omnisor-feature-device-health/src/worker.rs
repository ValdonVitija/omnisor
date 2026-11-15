//! One owned runtime and reusable health session per active TUI device.

use omnisor::ServerCheckMethod;
use omnisor_health::{
    DeviceHealthSnapshot, HealthConnectionConfig, HealthSessionOptions, LiveHealthSession,
};
use std::{
    future::Future,
    sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError},
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::sync::{mpsc as async_mpsc, oneshot};

const CLOSE_TIMEOUT: Duration = Duration::from_millis(150);
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(100);
const STOP_WAIT: Duration = Duration::from_millis(350);

#[derive(Debug)]
pub(super) struct RefreshResult {
    pub snapshot: Option<DeviceHealthSnapshot>,
    pub status: String,
    pub error: Option<String>,
}

impl RefreshResult {
    pub fn failed(error: String) -> Self {
        Self {
            snapshot: None,
            status: "Device health collection failed.".to_string(),
            error: Some(error),
        }
    }

    fn from_collection(result: Result<DeviceHealthSnapshot, String>) -> Self {
        match result {
            Ok(snapshot) => Self {
                snapshot: Some(snapshot),
                status: "Device health snapshot collected.".to_string(),
                error: None,
            },
            Err(error) => Self::failed(error),
        }
    }
}

pub(super) struct HealthWorker {
    commands: async_mpsc::Sender<()>,
    results: Receiver<RefreshResult>,
    stop: Option<oneshot::Sender<()>>,
    done: Receiver<()>,
    thread: Option<JoinHandle<()>>,
}

impl HealthWorker {
    pub fn spawn(
        config: HealthConnectionConfig,
        server_check: ServerCheckMethod,
    ) -> Result<Self, String> {
        let session = LiveHealthSession::with_options(
            config,
            HealthSessionOptions {
                server_check,
                ..HealthSessionOptions::default()
            },
        )
        .map_err(|error| error.to_string())?;
        let (commands, command_rx) = async_mpsc::channel(1);
        let (result_tx, results) = mpsc::channel();
        let (stop, stop_rx) = oneshot::channel();
        let (done_tx, done) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("omnisor-health".to_string())
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => {
                        runtime.block_on(run_worker(session, command_rx, stop_rx, result_tx));
                        // DNS or other runtime blocking tasks must not delay leaving the UI.
                        runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
                    }
                    Err(error) => {
                        let _ = result_tx.send(RefreshResult::failed(format!(
                            "Unable to initialize the health runtime: {error}"
                        )));
                    }
                }
                let _ = done_tx.send(());
            })
            .map_err(|error| format!("Unable to start the health worker: {error}"))?;
        Ok(Self {
            commands,
            results,
            stop: Some(stop),
            done,
            thread: Some(thread),
        })
    }

    pub fn refresh(&self) -> Result<(), ()> {
        self.commands.try_send(()).map_err(|_| ())
    }

    pub fn try_recv(&self) -> Result<RefreshResult, TryRecvError> {
        self.results.try_recv()
    }

    #[cfg(test)]
    pub fn test_channel() -> (
        Self,
        mpsc::Sender<RefreshResult>,
        async_mpsc::Receiver<()>,
        oneshot::Receiver<()>,
    ) {
        let (commands, command_rx) = async_mpsc::channel(1);
        let (result_tx, results) = mpsc::channel();
        let (stop, stop_rx) = oneshot::channel();
        let (done_tx, done) = mpsc::channel();
        drop(done_tx);
        (
            Self {
                commands,
                results,
                stop: Some(stop),
                done,
                thread: None,
            },
            result_tx,
            command_rx,
            stop_rx,
        )
    }
}

impl Drop for HealthWorker {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            match self.done.recv_timeout(STOP_WAIT) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                    let _ = thread.join();
                }
                // The cancellation token is already delivered. Avoid blocking the UI
                // indefinitely if an external/runtime operation does not yield.
                Err(RecvTimeoutError::Timeout) => drop(thread),
            }
        }
    }
}

trait WorkerCollector {
    fn collect(&mut self) -> impl Future<Output = Result<DeviceHealthSnapshot, String>> + Send;
    fn close(&mut self) -> impl Future<Output = ()> + Send;
}

impl WorkerCollector for LiveHealthSession {
    async fn collect(&mut self) -> Result<DeviceHealthSnapshot, String> {
        self.collect_once().await.map_err(|error| error.to_string())
    }

    async fn close(&mut self) {
        LiveHealthSession::close(self).await;
    }
}

async fn run_worker<C: WorkerCollector>(
    mut collector: C,
    mut commands: async_mpsc::Receiver<()>,
    mut stop: oneshot::Receiver<()>,
    results: mpsc::Sender<RefreshResult>,
) {
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => break,
            command = commands.recv() => {
                if command.is_none() {
                    break;
                }
                let result = tokio::select! {
                    biased;
                    _ = &mut stop => break,
                    result = collector.collect() => result,
                };
                if results.send(RefreshResult::from_collection(result)).is_err() {
                    break;
                }
            }
        }
    }
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, collector.close()).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct PendingCollector {
        started: Option<oneshot::Sender<()>>,
        closed: Arc<AtomicBool>,
    }

    impl WorkerCollector for PendingCollector {
        async fn collect(&mut self) -> Result<DeviceHealthSnapshot, String> {
            if let Some(started) = self.started.take() {
                let _ = started.send(());
            }
            std::future::pending().await
        }

        async fn close(&mut self) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn stop_cancels_an_inflight_collection_without_publishing_a_late_result() {
        let (commands, command_rx) = async_mpsc::channel(1);
        let (stop, stop_rx) = oneshot::channel();
        let (results, result_rx) = mpsc::channel();
        let (started, started_rx) = oneshot::channel();
        let closed = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(run_worker(
            PendingCollector {
                started: Some(started),
                closed: closed.clone(),
            },
            command_rx,
            stop_rx,
            results,
        ));

        commands.send(()).await.unwrap();
        started_rx.await.unwrap();
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();

        assert!(closed.load(Ordering::SeqCst));
        assert!(matches!(
            result_rx.try_recv(),
            Err(TryRecvError::Disconnected)
        ));
    }

    #[tokio::test]
    async fn closing_the_command_channel_stops_an_idle_worker() {
        let (commands, command_rx) = async_mpsc::channel(1);
        let (_stop, stop_rx) = oneshot::channel();
        let (results, _result_rx) = mpsc::channel();
        let closed = Arc::new(AtomicBool::new(false));
        drop(commands);

        tokio::time::timeout(
            Duration::from_secs(1),
            run_worker(
                PendingCollector {
                    started: None,
                    closed: closed.clone(),
                },
                command_rx,
                stop_rx,
                results,
            ),
        )
        .await
        .unwrap();
        assert!(closed.load(Ordering::SeqCst));
    }
}
