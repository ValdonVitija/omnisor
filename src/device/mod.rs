//! Interactive PTY session support for network devices.
//!
//! This module provides abstractions for interacting with network devices
//! (routers, switches, firewalls) that require persistent PTY sessions.
//! You can execute commands and receive the output in sequence within a single client session.

mod cisco;
mod juniper;

pub use cisco::CiscoVariant;
pub use juniper::JuniperVariant;

use regex::Regex;
use russh::Preferred;
use russh::client::Config;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::{AuthMethod, Client, ServerCheckMethod, ToSocketAddrsWithHostname};

// pub use russh::cipher::Name as CipherName;
// pub use russh::kex::Name as KexName;
// pub use russh::mac::Name as MacName;

/// Supported network device vendors and platforms.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceVendor {
    /// Cisco devices (IOS, IOS-XE, NX-OS, ...)
    Cisco(CiscoVariant),
    /// Juniper devices (Junos)
    Juniper(JuniperVariant),
    /// Arista EOS devices
    AristaEos,
    /// Generic Linux/Unix systems
    Linux,
    /// Custom configuration
    Custom(DeviceConfig),
}

impl DeviceVendor {
    pub fn into_config(self) -> DeviceConfig {
        match self {
            Self::Cisco(variant) => variant.into_config(),
            Self::Juniper(variant) => variant.into_config(),
            Self::AristaEos => Self::arista_eos_config(),
            Self::Linux => Self::linux_config(),
            Self::Custom(config) => config,
        }
    }

    pub fn to_config(&self) -> DeviceConfig {
        self.clone().into_config()
    }

    fn arista_eos_config() -> DeviceConfig {
        DeviceConfig::with_prompt(r"[\r\n][\w\-\.]+[#>]\s*$")
            .add_disable_paging_command("terminal length 0")
            .add_disable_paging_command("terminal width 32767")
            .add_error_pattern(r"% Invalid")
            .add_error_pattern(r"% Incomplete")
    }

    fn linux_config() -> DeviceConfig {
        DeviceConfig::with_prompt(r"[\r\n][\w\-\.\@\:~]+[\$#]\s*$")
            .add_error_pattern(r"command not found")
            .add_error_pattern(r"No such file or directory")
            .add_error_pattern(r"Permission denied")
    }
}

impl Default for DeviceVendor {
    fn default() -> Self {
        Self::Linux
    }
}

impl From<DeviceConfig> for DeviceVendor {
    fn from(config: DeviceConfig) -> Self {
        Self::Custom(config)
    }
}

impl From<CiscoVariant> for DeviceVendor {
    fn from(variant: CiscoVariant) -> Self {
        Self::Cisco(variant)
    }
}

impl From<JuniperVariant> for DeviceVendor {
    fn from(variant: JuniperVariant) -> Self {
        Self::Juniper(variant)
    }
}

/// SSH algorithm preferences for device connections.
///
/// Different network devices support different SSH algorithms.
/// Legacy devices may require older algorithms like DH_G1_SHA1 or AES_CBC ciphers.
///
/// This struct wraps russh's algorithm types directly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshAlgorithms {
    /// Preferred key exchange algorithms
    pub kex: Option<Vec<russh::kex::Name>>,
    /// Preferred cipher algorithms
    pub cipher: Option<Vec<russh::cipher::Name>>,
    /// Preferred MAC algorithms
    pub mac: Option<Vec<russh::mac::Name>>,
}

/// The following method can be used to set the preferred algorithms.
/// All fields are optional and if set, you have to use russh built in support types
impl SshAlgorithms {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set preferred key exchange algorithms.
    pub fn kex(mut self, algorithms: Vec<russh::kex::Name>) -> Self {
        self.kex = Some(algorithms);
        self
    }

    /// Set preferred cipher algorithms.
    pub fn cipher(mut self, algorithms: Vec<russh::cipher::Name>) -> Self {
        self.cipher = Some(algorithms);
        self
    }

    /// Set preferred MAC algorithms.
    pub fn mac(mut self, algorithms: Vec<russh::mac::Name>) -> Self {
        self.mac = Some(algorithms);
        self
    }

    /// Create algorithm preferences for legacy devices.
    ///
    /// Such algorithms are usually needed for devices with outdated SSH implementations.
    /// Noticed such issues when developing this library with older cisco emulated devices on gns3.
    pub fn legacy() -> Self {
        Self::new()
            .kex(vec![
                russh::kex::CURVE25519_PRE_RFC_8731,
                russh::kex::DH_G14_SHA256,
                russh::kex::DH_G14_SHA1,
                russh::kex::DH_G1_SHA1,
                russh::kex::DH_GEX_SHA256,
                russh::kex::DH_GEX_SHA1,
            ])
            .cipher(vec![
                russh::cipher::AES_256_CTR,
                russh::cipher::AES_128_CTR,
                russh::cipher::AES_256_CBC,
                russh::cipher::AES_192_CBC,
                russh::cipher::AES_128_CBC,
            ])
        // .mac(vec![russh::mac::HMAC_SHA1])
    }

    pub fn modern() -> Self {
        Self::new()
            .kex(vec![
                russh::kex::CURVE25519,
                russh::kex::ECDH_SHA2_NISTP256,
                russh::kex::DH_G14_SHA256,
            ])
            .cipher(vec![
                russh::cipher::CHACHA20_POLY1305,
                russh::cipher::AES_256_GCM,
                russh::cipher::AES_128_GCM,
                russh::cipher::AES_256_CTR,
            ])
    }

    /// Convert to russh Preferred configuration.
    pub(crate) fn to_preferred(&self) -> Preferred {
        let mut preferred = Preferred::default();

        if let Some(ref kex) = self.kex {
            preferred.kex = Cow::Owned(kex.clone());
        }

        if let Some(ref cipher) = self.cipher {
            preferred.cipher = Cow::Owned(cipher.clone());
        }

        if let Some(ref mac) = self.mac {
            preferred.mac = Cow::Owned(mac.clone());
        }

        preferred
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceConfig {
    /// Regex pattern to detect the command prompt
    pub prompt_pattern: String,
    /// Timeout for waiting for prompt after sending a command
    pub command_timeout: Duration,
    /// Optional patterns that indicate an error occurred
    pub error_patterns: Vec<String>,
    /// Terminal type for PTY request (default: "xterm")
    pub term_type: String,
    /// Terminal width
    pub term_width: u32,
    /// Terminal height
    pub term_height: u32,
    /// Commands to disable pagination. Example: "terminal length 0" for Cisco
    pub disable_paging_commands: Vec<String>,
    /// Read buffer size
    pub read_buffer_size: usize,
    /// Small delay between reads to allow output to accumulate
    pub read_delay: Duration,
    /// SSH algorithm preferences for this device type. When dealing with older devices,
    /// you will often need to explicitly set which algorithms the target device supports.
    pub ssh_algorithms: Option<SshAlgorithms>,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            prompt_pattern: r"[\r\n][\w\-\.]+[#>$]\s*$".to_string(),
            command_timeout: Duration::from_secs(30),
            error_patterns: vec![],
            term_type: "xterm".to_string(),
            term_width: 200,
            term_height: 24,
            disable_paging_commands: vec![],
            read_buffer_size: 65536,
            read_delay: Duration::from_millis(100),
            ssh_algorithms: None,
        }
    }
}

impl DeviceConfig {
    /// Create a new device configuration with a custom prompt pattern.
    pub fn with_prompt(prompt_pattern: impl Into<String>) -> Self {
        Self {
            prompt_pattern: prompt_pattern.into(),
            ..Default::default()
        }
    }

    /// Set the command timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.command_timeout = timeout;
        self
    }

    /// Add an error pattern to detect command failures.
    pub fn add_error_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.error_patterns.push(pattern.into());
        self
    }

    /// Add a command to disable pagination.
    pub fn add_disable_paging_command(mut self, command: impl Into<String>) -> Self {
        self.disable_paging_commands.push(command.into());
        self
    }

    /// Set terminal dimensions.
    pub fn terminal_size(mut self, width: u32, height: u32) -> Self {
        self.term_width = width;
        self.term_height = height;
        self
    }

    /// Set the terminal type.
    pub fn term_type(mut self, term_type: impl Into<String>) -> Self {
        self.term_type = term_type.into();
        self
    }

    /// Set the read delay between chunk reads.
    pub fn read_delay(mut self, delay: Duration) -> Self {
        self.read_delay = delay;
        self
    }

    /// Set SSH algorithm preferences.
    pub fn ssh_algorithms(mut self, algorithms: SshAlgorithms) -> Self {
        self.ssh_algorithms = Some(algorithms);
        self
    }

    /// Use legacy SSH algorithms (for older devices).
    pub fn with_legacy_algorithms(self) -> Self {
        self.ssh_algorithms(SshAlgorithms::legacy())
    }

    /// Use modern SSH algorithms.
    pub fn with_modern_algorithms(self) -> Self {
        self.ssh_algorithms(SshAlgorithms::modern())
    }

    /// Build a russh Config from this DeviceConfig.
    pub(crate) fn to_ssh_config(&self) -> Config {
        let mut config = Config::default();

        if let Some(ref algorithms) = self.ssh_algorithms {
            config.preferred = algorithms.to_preferred();
        }

        config
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCommandResult {
    /// The full output received (including the command echo and prompt)
    pub raw_output: String,
    /// The cleaned output (command echo and final prompt stripped)
    pub output: String,
    /// Whether an error pattern was detected in the output
    pub has_error: bool,
    /// The matched error pattern, if any
    pub error_match: Option<String>,
}

/// A high level abstraction to interact with network devices over SSH with an interactive pty session.
pub struct DeviceSession {
    client: Client,
    channel: russh::Channel<russh::client::Msg>,
    config: DeviceConfig,
    prompt_regex: Regex,
    error_regexes: Vec<Regex>,
    buffer: Arc<Mutex<String>>,
}

impl DeviceSession {
    pub async fn connect<A, V>(
        addr: A,
        username: &str,
        password: &str,
        vendor: V,
    ) -> Result<Self, crate::Error>
    where
        A: ToSocketAddrsWithHostname,
        V: Into<DeviceVendor>,
    {
        let config = vendor.into().into_config();
        let ssh_config = config.to_ssh_config();

        let client = Client::connect_with_config(
            addr,
            username,
            AuthMethod::with_password(password),
            ServerCheckMethod::NoCheck,
            ssh_config,
        )
        .await?;

        Self::from_client(client, config).await
    }

    /// Connect using a builder for more configuration options.
    pub fn builder() -> DeviceSessionBuilder {
        DeviceSessionBuilder::new()
    }

    /// Create a device session from an existing SSH client. The client you pass to this function is 'wrapped' into the DeviceSession.
    /// Recommended to use DeviceSession::connect or DeviceSessionBuilder instead.
    pub async fn from_client(client: Client, config: DeviceConfig) -> Result<Self, crate::Error> {
        let channel = client.get_channel().await?;

        channel
            .request_pty(
                true,
                &config.term_type,
                config.term_width,
                config.term_height,
                0,
                0,
                &[],
            )
            .await?;

        channel.request_shell(true).await?;

        let prompt_regex = Regex::new(&config.prompt_pattern)
            .map_err(|e| crate::Error::InvalidPromptPattern(e.to_string()))?;

        let error_regexes: Vec<Regex> = config
            .error_patterns
            .iter()
            .map(|p| Regex::new(p).map_err(|e| crate::Error::InvalidPromptPattern(e.to_string())))
            .collect::<Result<Vec<Regex>, _>>()?;

        let mut session = Self {
            client,
            channel,
            config: config.clone(),
            prompt_regex,
            error_regexes,
            buffer: Arc::new(Mutex::new(String::new())),
        };

        session.wait_for_prompt().await?;

        for cmd in &config.disable_paging_commands {
            session.send_command(cmd).await?;
        }

        Ok(session)
    }

    /// Send a command and wait for the prompt to return.
    pub async fn send_command(
        &mut self,
        command: &str,
    ) -> Result<DeviceCommandResult, crate::Error> {
        {
            let mut buf = self.buffer.lock().await;
            buf.clear();
        }

        let cmd_with_newline = format!("{}\n", command);
        self.channel.data(cmd_with_newline.as_bytes()).await?;

        let raw_output = self.wait_for_prompt().await?;

        let output = self.clean_output(&raw_output, command);
        let (has_error, error_match) = self.check_for_errors(&raw_output);

        Ok(DeviceCommandResult {
            raw_output,
            output,
            has_error,
            error_match,
        })
    }

    /// Send raw data without waiting for a prompt.
    pub async fn send_raw(&mut self, data: &str) -> Result<(), crate::Error> {
        self.channel.data(data.as_bytes()).await?;
        Ok(())
    }

    /// Send a line (with newline appended) without waiting for prompt.
    pub async fn send_line(&mut self, line: &str) -> Result<(), crate::Error> {
        self.send_raw(&format!("{}\n", line)).await
    }

    /// Read available data without waiting for prompt.
    pub async fn read_available(&mut self) -> Result<String, crate::Error> {
        self.read_with_timeout(Duration::from_millis(500)).await
    }

    /// Wait for a specific pattern to appear in the output.
    pub async fn wait_for_pattern(&mut self, pattern: &str) -> Result<String, crate::Error> {
        let regex =
            Regex::new(pattern).map_err(|e| crate::Error::InvalidPromptPattern(e.to_string()))?;

        let result = timeout(self.config.command_timeout, async {
            let mut accumulated = String::new();
            loop {
                let data = self.read_chunk().await?;
                accumulated.push_str(&data);

                if regex.is_match(&accumulated) {
                    return Ok(accumulated);
                }
            }
        })
        .await
        .map_err(|_| crate::Error::DeviceTimeout)?;

        result
    }

    pub fn config(&self) -> &DeviceConfig {
        &self.config
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    async fn wait_for_prompt(&mut self) -> Result<String, crate::Error> {
        let result = timeout(self.config.command_timeout, async {
            let mut accumulated = {
                let buf = self.buffer.lock().await;
                buf.clone()
            };

            loop {
                let data = self.read_chunk().await?;
                accumulated.push_str(&data);

                if self.prompt_regex.is_match(&accumulated) {
                    return Ok(accumulated);
                }
            }
        })
        .await
        .map_err(|_| crate::Error::DeviceTimeout)?;

        result
    }

    async fn read_chunk(&mut self) -> Result<String, crate::Error> {
        tokio::time::sleep(self.config.read_delay).await;

        let mut output = String::new();

        while let Ok(Some(msg)) =
            tokio::time::timeout(Duration::from_millis(50), self.channel.wait()).await
        {
            match msg {
                russh::ChannelMsg::Data { data } => {
                    output.push_str(&String::from_utf8_lossy(&data));
                }
                russh::ChannelMsg::Eof => {
                    return Err(crate::Error::DeviceSessionClosed);
                }
                russh::ChannelMsg::Close => {
                    return Err(crate::Error::DeviceSessionClosed);
                }
                _ => {}
            }
        }

        Ok(output)
    }

    async fn read_with_timeout(&mut self, read_timeout: Duration) -> Result<String, crate::Error> {
        let mut output = String::new();
        let deadline = tokio::time::Instant::now() + read_timeout;

        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(100), self.channel.wait()).await {
                Ok(Some(msg)) => match msg {
                    russh::ChannelMsg::Data { data } => {
                        output.push_str(&String::from_utf8_lossy(&data));
                    }
                    russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                    _ => {}
                },
                Ok(None) => break,
                Err(_) => continue,
            }
        }

        Ok(output)
    }

    fn clean_output(&self, raw: &str, command: &str) -> String {
        let mut output = raw.to_string();

        if let Some(pos) = output.find('\n') {
            let first_line = &output[..pos];
            if first_line.contains(command) || first_line.trim() == command.trim() {
                output = output[pos + 1..].to_string();
            }
        }

        if let Some(mat) = self.prompt_regex.find(&output) {
            output = output[..mat.start()].to_string();
        }

        output = output.replace('\r', "");
        output.trim().to_string()
    }

    fn check_for_errors(&self, output: &str) -> (bool, Option<String>) {
        for regex in &self.error_regexes {
            if let Some(mat) = regex.find(output) {
                return (true, Some(mat.as_str().to_string()));
            }
        }
        (false, None)
    }

    /// Close the session gracefully.
    pub async fn close(self) -> Result<(), crate::Error> {
        self.channel.eof().await?;
        self.channel.close().await.map_err(crate::Error::SshError)?;
        self.client.disconnect().await?;
        Ok(())
    }
}

impl std::fmt::Debug for DeviceSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceSession")
            .field("config", &self.config)
            .field("client", &self.client)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct DeviceSessionBuilder {
    address: Option<String>,
    port: u16,
    username: Option<String>,
    auth: Option<AuthMethod>,
    server_check: ServerCheckMethod,
    vendor: DeviceVendor,
    // config_overrides: DeviceConfigOverrides,
}

//NOTE: Will think about this again, because it feels a bit to unnecessary atm

// #[derive(Debug, Clone, Default)]
// struct DeviceConfigOverrides {
//     command_timeout: Option<Duration>,
//     term_width: Option<u32>,
//     term_height: Option<u32>,
//     read_delay: Option<Duration>,
//     additional_error_patterns: Vec<String>,
//     additional_disable_paging: Vec<String>,
//     ssh_algorithms: Option<SshAlgorithms>,
// }

impl DeviceSessionBuilder {
    pub fn new() -> Self {
        Self {
            address: None,
            port: 22,
            username: None,
            auth: None,
            server_check: ServerCheckMethod::NoCheck,
            vendor: DeviceVendor::default(),
            // config_overrides: DeviceConfigOverrides::default(),
        }
    }

    pub fn address<A: Into<String>>(mut self, addr: A) -> Self {
        self.address = Some(addr.into());
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn username<S: Into<String>>(mut self, username: S) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn password<S: Into<String>>(mut self, password: S) -> Self {
        self.auth = Some(AuthMethod::with_password(&password.into()));
        self
    }

    pub fn auth(mut self, auth: AuthMethod) -> Self {
        self.auth = Some(auth);
        self
    }

    pub fn server_check(mut self, check: ServerCheckMethod) -> Self {
        self.server_check = check;
        self
    }

    pub fn vendor<V: Into<DeviceVendor>>(mut self, vendor: V) -> Self {
        self.vendor = vendor.into();
        self
    }
    //NOTE: Will think about this again, because it feels a bit to unnecessary atm

    // pub fn command_timeout(mut self, timeout: Duration) -> Self {
    //     self.config_overrides.command_timeout = Some(timeout);
    //     self
    // }

    // pub fn terminal_size(mut self, width: u32, height: u32) -> Self {
    //     self.config_overrides.term_width = Some(width);
    //     self.config_overrides.term_height = Some(height);
    //     self
    // }

    // pub fn read_delay(mut self, delay: Duration) -> Self {
    //     self.config_overrides.read_delay = Some(delay);
    //     self
    // }

    // pub fn add_error_pattern<S: Into<String>>(mut self, pattern: S) -> Self {
    //     self.config_overrides
    //         .additional_error_patterns
    //         .push(pattern.into());
    //     self
    // }

    // pub fn add_disable_paging<S: Into<String>>(mut self, command: S) -> Self {
    //     self.config_overrides
    //         .additional_disable_paging
    //         .push(command.into());
    //     self
    // }

    // /// Set SSH algorithm preferences.
    // pub fn ssh_algorithms(mut self, algorithms: SshAlgorithms) -> Self {
    //     self.config_overrides.ssh_algorithms = Some(algorithms);
    //     self
    // }

    // pub fn with_legacy_algorithms(self) -> Self {
    //     self.ssh_algorithms(SshAlgorithms::legacy())
    // }

    pub async fn connect(self) -> Result<DeviceSession, crate::Error> {
        let address = self
            .address
            .ok_or_else(|| crate::Error::InvalidAddress("Address not specified".into()))?;
        let username = self
            .username
            .ok_or_else(|| crate::Error::InvalidAddress("Username not specified".into()))?;
        let auth = self.auth.ok_or_else(|| {
            crate::Error::InvalidAddress("Authentication method not specified".into())
        })?;

        let full_address = if address.contains(':') {
            address
        } else {
            format!("{}:{}", address, self.port)
        };

        let mut config = self.vendor.into_config();

        //NOTE: Will think about this again, because it feels a bit to unnecessary atm

        // if let Some(timeout) = self.config_overrides.command_timeout {
        //     config.command_timeout = timeout;
        // }
        // if let Some(width) = self.config_overrides.term_width {
        //     config.term_width = width;
        // }
        // if let Some(height) = self.config_overrides.term_height {
        //     config.term_height = height;
        // }
        // if let Some(delay) = self.config_overrides.read_delay {
        //     config.read_delay = delay;
        // }
        // if let Some(algorithms) = self.config_overrides.ssh_algorithms {
        //     config.ssh_algorithms = Some(algorithms);
        // }
        // config
        //     .error_patterns
        //     .extend(self.config_overrides.additional_error_patterns);
        // config
        //     .disable_paging_commands
        //     .extend(self.config_overrides.additional_disable_paging);

        let ssh_config = config.to_ssh_config();

        let client = Client::connect_with_config(
            full_address,
            &username,
            auth,
            self.server_check,
            ssh_config,
        )
        .await?;

        DeviceSession::from_client(client, config).await
    }
}

impl Default for DeviceSessionBuilder {
    fn default() -> Self {
        Self::new()
    }
}
