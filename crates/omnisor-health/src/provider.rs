//! Health providers and command execution are separate from SSH connection setup.

use crate::{DeviceHealthSnapshot, HealthConnectionConfig};
use omnisor::{CiscoVariant, DeviceCommandResult, DeviceSession, DeviceVendor};
use std::{future::Future, net::Ipv6Addr, pin::Pin, time::Duration};

/// Result of executing a command on an existing device session.
pub type CommandFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DeviceCommandResult, omnisor::Error>> + Send + 'a>>;

/// A command source that can be an SSH session, a replay, or another transport.
///
/// Providers execute commands sequentially because interactive CLI sessions have
/// one prompt and cannot safely multiplex commands on the same channel.
pub trait CommandExecutor: Send {
    fn execute<'a>(&'a mut self, command: &'a str) -> CommandFuture<'a>;
}

impl CommandExecutor for DeviceSession {
    fn execute<'a>(&'a mut self, command: &'a str) -> CommandFuture<'a> {
        Box::pin(self.send_command(command))
    }
}

/// The identity of the device being assessed, without connection credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthTarget {
    pub address: String,
    pub port: u16,
}

impl HealthTarget {
    pub fn management_address(&self) -> String {
        if self.address.parse::<Ipv6Addr>().is_ok() {
            format!("[{}]:{}", self.address, self.port)
        } else {
            format!("{}:{}", self.address, self.port)
        }
    }
}

impl From<&HealthConnectionConfig> for HealthTarget {
    fn from(config: &HealthConnectionConfig) -> Self {
        Self {
            address: config.address.clone(),
            port: config.port,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HealthError {
    #[error("invalid health session configuration: {0}")]
    InvalidConfig(String),
    #[error("device health is not implemented yet for {0}")]
    UnsupportedVendor(String),
    #[error("unable to connect to device: {0}")]
    Connection(#[source] omnisor::Error),
    #[error("{operation} timed out after {timeout:?}; reconnect before retrying")]
    Timeout {
        operation: &'static str,
        timeout: Duration,
    },
    #[error("health command `{command}` failed: {source}; reconnect before retrying")]
    Command {
        command: String,
        #[source]
        source: omnisor::Error,
    },
    #[error("health collection failed: {0}")]
    Collection(String),
}

pub type HealthFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DeviceHealthSnapshot, HealthError>> + Send + 'a>>;

/// A vendor/model adapter that produces the common health snapshot.
///
/// Implement this trait in an external crate and pass it to
/// [`collect_health_with_provider`] or [`collect_health_with_executor`]. A new
/// provider does not require changes to Omnisor's connection or built-in vendor
/// matching. Registering it in the terminal app's picker is a separate step.
pub trait HealthProvider: Send + Sync {
    fn collect<'a>(
        &'a self,
        executor: &'a mut dyn CommandExecutor,
        target: &'a HealthTarget,
    ) -> HealthFuture<'a>;
}

pub(crate) const SUPPORTED_CISCO_IOS_VARIANTS: &[CiscoVariant] = &[
    CiscoVariant::Ios,
    CiscoVariant::IosXe,
    CiscoVariant::IosLegacy,
];

/// Built-in health coverage, which is narrower than core SSH device support.
pub fn supported_health_vendors() -> Vec<DeviceVendor> {
    SUPPORTED_CISCO_IOS_VARIANTS
        .iter()
        .copied()
        .map(DeviceVendor::Cisco)
        .collect()
}

/// Select a built-in provider before attempting a connection.
pub fn builtin_health_provider(
    vendor: &DeviceVendor,
) -> Result<Box<dyn HealthProvider>, HealthError> {
    match vendor {
        DeviceVendor::Cisco(variant) => Ok(Box::new(crate::CiscoIosHealthProvider::new(*variant)?)),
        DeviceVendor::Juniper(variant) => Err(HealthError::UnsupportedVendor(variant.to_string())),
        DeviceVendor::Custom(_) => Err(HealthError::UnsupportedVendor(
            "custom device profiles; supply a HealthProvider".to_string(),
        )),
        _ => Err(HealthError::UnsupportedVendor(
            "this device vendor".to_string(),
        )),
    }
}

/// Collect through an existing connection or a replay, without reconnecting.
/// The caller owns the executor's lifecycle, including closing an SSH session.
/// On a transport error, the built-in provider stops sending commands. Close and
/// reconnect before retrying: a timed-out interactive CLI may still send output.
pub async fn collect_health_with_executor(
    target: &HealthTarget,
    provider: &dyn HealthProvider,
    executor: &mut dyn CommandExecutor,
) -> Result<DeviceHealthSnapshot, HealthError> {
    provider.collect(executor, target).await
}

/// Connect using the configured SSH profile and collect with a supplied provider.
/// Use [`collect_health_with_executor`] for custom transports, authentication,
/// host-key verification, or reuse of an existing connection.
pub async fn collect_health_with_provider(
    config: &HealthConnectionConfig,
    provider: &dyn HealthProvider,
) -> Result<DeviceHealthSnapshot, HealthError> {
    let mut session = DeviceSession::connect(
        (config.address.as_str(), config.port),
        &config.username,
        &config.password,
        config.vendor.clone(),
    )
    .await
    .map_err(HealthError::Connection)?;

    let result = provider
        .collect(&mut session, &HealthTarget::from(config))
        .await;
    // Preserve the collection result even if the remote side already closed.
    let _ = session.close().await;
    result
}
