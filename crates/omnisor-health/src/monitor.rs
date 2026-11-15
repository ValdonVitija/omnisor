//! Reusable, bounded SSH collection for a live single-device health view.

use crate::{
    DeviceHealthSnapshot, HealthConnectionConfig, HealthError, HealthProvider, HealthTarget,
    builtin_health_provider,
};
use omnisor::{DeviceSession, ServerCheckMethod};
use std::{fmt, time::Duration};

const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Connection policy and deadlines for [`LiveHealthSession`].
///
/// The default verifies the device against the operator's SSH known-hosts file.
/// Use an explicit pinned key or known-hosts file for unattended deployments.
/// Disabling verification with `ServerCheckMethod::NoCheck` is intended only for
/// explicitly trusted development labs.
#[derive(Debug, Clone)]
pub struct HealthSessionOptions {
    pub server_check: ServerCheckMethod,
    /// Includes TCP/SSH negotiation, authentication, and CLI initialization.
    pub connect_timeout: Duration,
    /// Maximum time for one command to finish at its prompt.
    pub command_timeout: Duration,
    /// Maximum time for the complete command/probe sequence, excluding connection.
    pub collection_timeout: Duration,
}

impl Default for HealthSessionOptions {
    fn default() -> Self {
        Self {
            server_check: ServerCheckMethod::DefaultKnownHostsFile,
            connect_timeout: Duration::from_secs(10),
            command_timeout: Duration::from_secs(10),
            collection_timeout: Duration::from_secs(60),
        }
    }
}

impl HealthSessionOptions {
    fn validate(&self) -> Result<(), HealthError> {
        for (name, duration) in [
            ("connect_timeout", self.connect_timeout),
            ("command_timeout", self.command_timeout),
            ("collection_timeout", self.collection_timeout),
        ] {
            if duration.is_zero() {
                return Err(HealthError::InvalidConfig(format!(
                    "{name} must be greater than zero"
                )));
            }
        }
        Ok(())
    }
}

/// Collect successive snapshots over one healthy SSH session.
///
/// Collection takes `&mut self`, so a caller cannot overlap refreshes on this
/// connection. Each call reuses the current connection or opens a new one. Any
/// collection error, deadline, or cancellation discards that connection; the
/// next call reconnects instead of consuming late output from a previous command.
///
/// Call [`Self::close`] when monitoring stops. Dropping a connected session also
/// schedules bounded cleanup when a Tokio runtime is available. Scheduling the
/// next refresh, retaining an older snapshot, and marking stale UI data remain
/// the caller's responsibility.
pub struct LiveHealthSession {
    config: HealthConnectionConfig,
    options: HealthSessionOptions,
    provider: Box<dyn HealthProvider>,
    session: SessionSlot,
    connection_generation: u64,
}

impl fmt::Debug for LiveHealthSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LiveHealthSession")
            .field("config", &self.config)
            .field("options", &self.options)
            .field("connected", &self.is_connected())
            .field("connection_generation", &self.connection_generation)
            .finish_non_exhaustive()
    }
}

impl LiveHealthSession {
    /// Select a built-in health provider and use verified SSH host keys.
    /// No network connection is made until [`Self::collect_once`].
    pub fn new(config: HealthConnectionConfig) -> Result<Self, HealthError> {
        Self::with_options(config, HealthSessionOptions::default())
    }

    /// Select a built-in health provider with an explicit connection policy.
    pub fn with_options(
        config: HealthConnectionConfig,
        options: HealthSessionOptions,
    ) -> Result<Self, HealthError> {
        let provider = builtin_health_provider(&config.vendor)?;
        Self::with_provider(config, options, provider)
    }

    /// Use an externally implemented provider with the same managed lifecycle.
    pub fn with_provider(
        config: HealthConnectionConfig,
        options: HealthSessionOptions,
        provider: Box<dyn HealthProvider>,
    ) -> Result<Self, HealthError> {
        options.validate()?;
        if config.address.trim().is_empty() {
            return Err(HealthError::InvalidConfig(
                "device address must not be empty".into(),
            ));
        }
        if config.port == 0 {
            return Err(HealthError::InvalidConfig(
                "device port must be greater than zero".into(),
            ));
        }
        Ok(Self {
            config,
            options,
            provider,
            session: SessionSlot::default(),
            connection_generation: 0,
        })
    }

    /// Whether a connection is cached for reuse, not a remote liveness probe.
    pub fn is_connected(&self) -> bool {
        self.session.0.is_some()
    }

    /// Number of connections successfully opened by this monitor.
    pub fn connection_generation(&self) -> u64 {
        self.connection_generation
    }

    pub async fn collect_once(&mut self) -> Result<DeviceHealthSnapshot, HealthError> {
        // Keep the active session outside `self` across every await. Cancellation
        // drops this slot and schedules cleanup rather than caching a dirty stream.
        let mut active = std::mem::take(&mut self.session);
        let target = HealthTarget::from(&self.config);
        if active.0.is_none() {
            let profile = self
                .config
                .vendor
                .to_config()
                .timeout(self.options.command_timeout);
            let connection = DeviceSession::builder()
                .address(target.management_address())
                .username(&self.config.username)
                .password(&self.config.password)
                .vendor(profile)
                .server_check(self.options.server_check.clone())
                .connect();
            active.0 = Some(
                tokio::time::timeout(self.options.connect_timeout, connection)
                    .await
                    .map_err(|_| HealthError::Timeout {
                        operation: "SSH connection",
                        timeout: self.options.connect_timeout,
                    })?
                    .map_err(HealthError::Connection)?,
            );
            self.connection_generation += 1;
        }

        let session = active.0.as_mut().expect("connected before collection");
        let result = tokio::time::timeout(
            self.options.collection_timeout,
            self.provider.collect(session, &target),
        )
        .await
        .map_err(|_| HealthError::Timeout {
            operation: "health collection",
            timeout: self.options.collection_timeout,
        })
        .and_then(|result| result);

        match result {
            Ok(snapshot) => {
                self.session = active;
                Ok(snapshot)
            }
            Err(error) => {
                active.close().await;
                Err(error)
            }
        }
    }

    /// Close the current connection within a bounded cleanup deadline.
    /// A later collection may open a fresh connection.
    pub async fn close(&mut self) {
        self.session.close().await;
    }
}

#[derive(Default)]
struct SessionSlot(Option<DeviceSession>);

impl SessionSlot {
    async fn close(&mut self) {
        if let Some(session) = self.0.as_mut() {
            let _ = tokio::time::timeout(CLOSE_TIMEOUT, session.close()).await;
        }
        self.0 = None;
    }
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        if let Some(mut session) = self.0.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            runtime.spawn(async move {
                let _ = tokio::time::timeout(CLOSE_TIMEOUT, session.close()).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnisor::{CiscoVariant, JuniperVariant};

    fn config() -> HealthConnectionConfig {
        HealthConnectionConfig {
            address: "192.0.2.10".into(),
            port: 22,
            username: "operator".into(),
            password: "never-print-this-password".into(),
            vendor: CiscoVariant::Ios.into(),
        }
    }

    #[test]
    fn new_sessions_verify_hosts_and_redact_credentials_without_connecting() {
        let options = HealthSessionOptions::default();
        assert!(matches!(
            options.server_check,
            ServerCheckMethod::DefaultKnownHostsFile
        ));
        let config = config();
        assert!(!format!("{config:?}").contains(&config.password));
        let monitor = LiveHealthSession::new(config).unwrap();
        assert!(!monitor.is_connected());
        assert_eq!(monitor.connection_generation(), 0);
        let debug = format!("{monitor:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("never-print-this-password"));
    }

    #[test]
    fn invalid_connection_settings_are_rejected_before_io() {
        for field in 0..3 {
            let mut options = HealthSessionOptions::default();
            match field {
                0 => options.connect_timeout = Duration::ZERO,
                1 => options.command_timeout = Duration::ZERO,
                _ => options.collection_timeout = Duration::ZERO,
            }
            assert!(matches!(
                LiveHealthSession::with_options(config(), options),
                Err(HealthError::InvalidConfig(_))
            ));
        }
        let mut empty = config();
        empty.address = "  ".into();
        assert!(matches!(
            LiveHealthSession::new(empty),
            Err(HealthError::InvalidConfig(_))
        ));
        let mut invalid_port = config();
        invalid_port.port = 0;
        assert!(matches!(
            LiveHealthSession::new(invalid_port),
            Err(HealthError::InvalidConfig(_))
        ));
    }

    #[test]
    fn unsupported_builtin_provider_fails_before_io() {
        let mut config = config();
        config.vendor = JuniperVariant::Junos.into();
        assert!(matches!(
            LiveHealthSession::new(config),
            Err(HealthError::UnsupportedVendor(_))
        ));
    }
}
