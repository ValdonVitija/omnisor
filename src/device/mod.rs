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
use tokio::time::timeout;

use crate::{AuthMethod, Client, ServerCheckMethod, ToSocketAddrsWithHostname};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceVendor {
    /// Cisco devices (IOS, IOS-XE, NX-OS, ...)
    Cisco(CiscoVariant),
    /// Juniper devices (Junos)
    Juniper(JuniperVariant),
    /// Arista EOS devices
    // AristaEos,
    /// Custom configuration
    Custom(DeviceConfig),
}

impl DeviceVendor {
    pub fn into_config(self) -> DeviceConfig {
        match self {
            Self::Cisco(variant) => variant.into_config(),
            Self::Juniper(variant) => variant.into_config(),
            // Self::AristaEos => Self::arista_eos_config(),
            Self::Custom(config) => config,
        }
    }

    pub fn to_config(&self) -> DeviceConfig {
        self.clone().into_config()
    }

    // NOTE: Not sure if this if correct, but tried to do it with what I found about EOS, because
    // I don't have a lab device to test against.
    // fn arista_eos_config() -> DeviceConfig {
    //     DeviceConfig::with_prompt(r"[\r\n][\w\-\.]+[#>]\s*$")
    //         .add_disable_paging_command("terminal length 0")
    //         .add_disable_paging_command("terminal width 32767")
    //         .add_error_pattern(r"% Invalid")
    //         .add_error_pattern(r"% Incomplete")
    // }
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

    pub fn kex(mut self, algorithms: Vec<russh::kex::Name>) -> Self {
        self.kex = Some(algorithms);
        self
    }

    pub fn cipher(mut self, algorithms: Vec<russh::cipher::Name>) -> Self {
        self.cipher = Some(algorithms);
        self
    }

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
    /// Optional regex pattern to detect the enable mode prompt
    pub enable_mode_prompt_pattern: Option<String>,
    /// Optional regex pattern to detect the enable mode password if prompted
    pub enable_mode_password_prompt_pattern: Option<String>,
    /// Optional regex pattern to detect configuration mode
    pub config_mode_prompt_pattern: Option<String>,
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
    pub read_delay: Option<Duration>,
    /// SSH algorithm preferences for this device type. When dealing with older devices,
    /// you will often need to explicitly set which algorithms the target device supports.
    pub ssh_algorithms: Option<SshAlgorithms>,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            prompt_pattern: r"(?:^|[\r\n])[\w\-\.]+[#>$]\s*$".to_string(),
            enable_mode_prompt_pattern: r"(?:^|[\r\n])[\w\-\.]+[#]\s*$".to_string().into(),
            enable_mode_password_prompt_pattern: r"(?i)password:".to_string().into(),
            config_mode_prompt_pattern: r"(?:^|[\r\n])[\w\-\.:\/]+\(config[^\)]*\)#\s*$"
                .to_string()
                .into(),
            command_timeout: Duration::from_secs(30),
            error_patterns: vec![],
            term_type: "xterm".to_string(),
            term_width: 200,
            term_height: 24,
            disable_paging_commands: vec![],
            read_buffer_size: 65536,
            read_delay: None,
            ssh_algorithms: None,
        }
    }
}
/// The following functions allow to set all deviceconfig paramters using the builder pattern
impl DeviceConfig {
    pub fn with_prompt(prompt_pattern: impl Into<String>) -> Self {
        Self {
            prompt_pattern: prompt_pattern.into(),
            ..Default::default()
        }
    }
    pub fn add_enable_mode_prompt_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.enable_mode_prompt_pattern = Some(pattern.into());
        self
    }
    pub fn add_enable_mode_password_prompt_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.enable_mode_password_prompt_pattern = Some(pattern.into());
        self
    }
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.command_timeout = timeout;
        self
    }

    pub fn add_error_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.error_patterns.push(pattern.into());
        self
    }

    pub fn add_disable_paging_command(mut self, command: impl Into<String>) -> Self {
        self.disable_paging_commands.push(command.into());
        self
    }

    pub fn terminal_size(mut self, width: u32, height: u32) -> Self {
        self.term_width = width;
        self.term_height = height;
        self
    }

    pub fn term_type(mut self, term_type: impl Into<String>) -> Self {
        self.term_type = term_type.into();
        self
    }

    pub fn read_delay(mut self, delay: Option<Duration>) -> Self {
        self.read_delay = delay;
        self
    }

    pub fn ssh_algorithms(mut self, algorithms: SshAlgorithms) -> Self {
        self.ssh_algorithms = Some(algorithms);
        self
    }

    pub fn with_legacy_algorithms(self) -> Self {
        self.ssh_algorithms(SshAlgorithms::legacy())
    }

    pub fn with_modern_algorithms(self) -> Self {
        self.ssh_algorithms(SshAlgorithms::modern())
    }

    /// Builds a russh Config from this DeviceConfig
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
    /// Whether an error pattern was detected in the output.
    pub has_error: bool,
    /// The matched error pattern, if any. The number of error messages
    /// is quite hard to be determined as of now by me, but I want something like this to be a valid
    /// parameter when getting the command result.
    pub error_match: Option<String>,
}

/// A high level abstraction to interact with network devices over SSH with an interactive pty session.
#[derive(Debug)]
pub struct DeviceSession {
    client: Client,
    channel: russh::Channel<russh::client::Msg>,
    config: Arc<DeviceConfig>,
    /// This stores the prompt we are currently interested in. That can change between user/enable/config modes
    prompt_regex: Regex,
    /// The initial/default prompt pattern. When we enter a device, this should be generic to match either user or enable mode.
    base_prompt_regex: Regex,
    error_regexes: Vec<Regex>,
    enable_regex: Option<Regex>,
    enable_password_regex: Option<Regex>,
    config_regex: Option<Regex>,
    buffer: String,
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
    /// Use this method if you want to create a new device session using the builder pattern by chaining method calls to set
    /// parameters in sequence
    pub fn builder() -> DeviceSessionBuilder {
        DeviceSessionBuilder::new()
    }

    /// Create a device session from an existing SSH client.
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

        let base_prompt_regex = Regex::new(&config.prompt_pattern)
            .map_err(|e| crate::Error::InvalidPromptPattern(e.to_string()))?;

        let prompt_regex = base_prompt_regex.clone();

        let error_regexes: Vec<Regex> = config
            .error_patterns
            .iter()
            .map(|p| Regex::new(p).map_err(|e| crate::Error::InvalidPromptPattern(e.to_string())))
            .collect::<Result<Vec<Regex>, _>>()?;

        let enable_regex = if let Some(ref p) = config.enable_mode_prompt_pattern {
            Some(Regex::new(p).map_err(|e| crate::Error::InvalidPromptPattern(e.to_string()))?)
        } else {
            None
        };

        let enable_password_regex = if let Some(ref p) = config.enable_mode_password_prompt_pattern
        {
            Some(Regex::new(p).map_err(|e| crate::Error::InvalidPromptPattern(e.to_string()))?)
        } else {
            None
        };

        let config_regex = if let Some(ref p) = config.config_mode_prompt_pattern {
            Some(Regex::new(p).map_err(|e| crate::Error::InvalidPromptPattern(e.to_string()))?)
        } else {
            None
        };

        let config_arc = Arc::new(config);

        let mut session = Self {
            client,
            channel,
            config: config_arc.clone(),
            prompt_regex,
            base_prompt_regex,
            error_regexes,
            enable_regex,
            enable_password_regex,
            config_regex,
            buffer: String::with_capacity(4096),
        };

        session.wait_for_prompt().await?;

        for cmd in &config_arc.disable_paging_commands {
            session.send_command(cmd).await?;
        }

        Ok(session)
    }

    pub async fn send_command(
        &mut self,
        command: &str,
    ) -> Result<DeviceCommandResult, crate::Error> {
        self.buffer.clear();

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

    /// Send raw data without waiting for a prompt. Might be useful for quick executions, to get on a new line or whatever.
    pub async fn send_raw(&mut self, data: &str) -> Result<(), crate::Error> {
        self.channel.data(data.as_bytes()).await?;
        Ok(())
    }

    /// Exacly as send_raw, but automatically adds a new line at the end of the given str
    pub async fn send_line(&mut self, line: &str) -> Result<(), crate::Error> {
        self.send_raw(&format!("{}\n", line)).await
    }

    /// It just consumes the available data left on the channel and it does not wait for any prompt or pattern to match
    pub async fn read_available(&mut self) -> Result<String, crate::Error> {
        let mut output = String::new();
        self.read_with_timeout(Duration::from_millis(500), &mut output)
            .await?;
        Ok(output)
    }

    /// Wait for a specific pattern to appear in the output.
    pub async fn wait_for_pattern(&mut self, pattern: &str) -> Result<String, crate::Error> {
        let regex =
            Regex::new(pattern).map_err(|e| crate::Error::InvalidPromptPattern(e.to_string()))?;

        self.wait_for_regex(&regex).await
    }

    pub fn config(&self) -> &DeviceConfig {
        &self.config
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    async fn wait_for_prompt(&mut self) -> Result<String, crate::Error> {
        let regex: Regex = self.prompt_regex.clone();
        self.wait_for_regex(&regex).await
    }
    /// Helper for basically any type of regex. I want to have a function that can be exposed and used by the potential crate user
    /// and not just by the rest of the functions here internally.
    async fn wait_for_regex(&mut self, regex: &Regex) -> Result<String, crate::Error> {
        let result = timeout(self.config.command_timeout, async {
            let mut accumulated = std::mem::take(&mut self.buffer);
            loop {
                self.read_chunk(&mut accumulated).await?;

                if regex.is_match(&accumulated) {
                    return Ok(accumulated);
                }
            }
        })
        .await
        .map_err(|_| crate::Error::DeviceTimeout)?;
        result
    }

    /// Reads incoming data and appends it to the provided buffer.
    async fn read_chunk(&mut self, output: &mut String) -> Result<usize, crate::Error> {
        let mut got_data = false;
        let start_len = output.len();

        while let Ok(Some(msg)) =
            tokio::time::timeout(Duration::from_millis(10), self.channel.wait()).await
        {
            match msg {
                russh::ChannelMsg::Data { data } => {
                    output.push_str(&String::from_utf8_lossy(&data));
                    got_data = true;
                }
                russh::ChannelMsg::ExtendedData { data, .. } => {
                    output.push_str(&String::from_utf8_lossy(&data));
                    got_data = true;
                }
                russh::ChannelMsg::Eof | russh::ChannelMsg::Close => {
                    return Err(crate::Error::DeviceSessionClosed);
                }
                // russh::ChannelMsg::Success
                // | russh::ChannelMsg::WindowAdjusted { .. }
                // | russh::ChannelMsg::Signal { .. } => {
                //     continue;
                // }
                russh::ChannelMsg::Failure => {
                    if !got_data {
                        return Err(crate::Error::DeviceSessionClosed);
                    }
                }
                // NOTE: I have to think about explicitly handling these cases, because with what I saw, not really needed here
                // russh::ChannelMsg::ExitStatus { .. } => {
                //     return Err(crate::Error::DeviceSessionClosed);
                // }
                // russh::ChannelMsg::ExitSignal { .. } => {
                //     return Err(crate::Error::DeviceSessionClosed);
                // }
                _ => {}
            }
        }
        Ok(output.len() - start_len)
    }

    async fn read_with_timeout(
        &mut self,
        read_timeout: Duration,
        output: &mut String,
    ) -> Result<usize, crate::Error> {
        let deadline = tokio::time::Instant::now() + read_timeout;
        let start_len = output.len();

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

        Ok(output.len() - start_len)
    }

    fn clean_output(&self, raw: &str, command: &str) -> String {
        let mut start_index = 0;
        let mut end_index = raw.len();

        if let Some(pos) = raw.find('\n') {
            let first_line = &raw[..pos];
            if first_line.contains(command) {
                start_index = pos + 1;
            }
        }

        let current_slice = &raw[start_index..];
        if let Some(mat) = self.prompt_regex.find(current_slice) {
            end_index = start_index + mat.start();
        }

        if start_index >= end_index {
            return String::new();
        }

        let content = &raw[start_index..end_index];
        content.replace('\r', "").trim().to_string()
    }

    fn check_for_errors(&self, output: &str) -> (bool, Option<String>) {
        for regex in &self.error_regexes {
            if let Some(mat) = regex.find(output) {
                return (true, Some(mat.as_str().to_string()));
            }
        }
        (false, None)
    }

    async fn check_enable_mode(&mut self) -> bool {
        if let Some(regex) = self.enable_regex.clone() {
            if let Ok(result) = self.send_command("").await {
                return regex.is_match(&result.raw_output);
            }
        }
        false
    }

    /// Try to enter enable mode. If your user is privileged enough, you will most likely get into this mode once the initial
    /// session is formed. Still useful/needed.
    pub async fn enter_enable_mode(
        &mut self,
        command: &str,
        enable_secret: Option<&str>,
    ) -> Result<(), crate::Error> {
        if self.check_enable_mode().await {
            if let Some(ref regex) = self.enable_regex {
                self.prompt_regex = regex.clone();
            }
            return Ok(());
        }

        self.send_line(command).await?;

        let output = self.wait_for_prompt_or_pattern().await?;

        if let Some(ref pwd_regex) = self.enable_password_regex {
            if pwd_regex.is_match(&output) {
                if let Some(secret) = enable_secret {
                    self.send_line(secret).await?;
                    let _ = self.wait_for_prompt().await?;

                    if self.check_enable_mode().await {
                        if let Some(ref regex) = self.enable_regex {
                            self.prompt_regex = regex.clone();
                        }
                        return Ok(());
                    } else {
                        return Err(crate::Error::EnableModePasswordFailed);
                    }
                } else {
                    return Err(crate::Error::EnableModePasswordFailed);
                }
            }
        }

        if self.check_enable_mode().await {
            if let Some(ref regex) = self.enable_regex {
                self.prompt_regex = regex.clone();
            }
            return Ok(());
        }

        Err(crate::Error::EnableModeCommandFailed)
    }

    pub async fn exit_from_enable_mode(&mut self, command: &str) -> Result<(), crate::Error> {
        if !self.check_enable_mode().await {
            self.prompt_regex = self.base_prompt_regex.clone();
            return Ok(());
        }

        self.send_line(command).await?;

        let base_regex = self.base_prompt_regex.clone();
        self.wait_for_regex(&base_regex).await?;

        self.prompt_regex = base_regex;

        if self.check_enable_mode().await {
            return Err(crate::Error::EnableCommandDidntExit);
        }

        Ok(())
    }

    /// Wait for either the standard prompt or a specific pattern (mostly for password prompt like on enable mode, but not restricted)
    /// We can do better here, because this function might feel a bit redundant, since we can combile some other functions
    /// to achieve the same thing in enter_enable_mode.
    /// NOTE: Needs refactoring, but not rn.
    async fn wait_for_prompt_or_pattern(&mut self) -> Result<String, crate::Error> {
        let result = timeout(self.config.command_timeout, async {
            let mut accumulated = std::mem::take(&mut self.buffer);

            loop {
                self.read_chunk(&mut accumulated).await?;

                if self.prompt_regex.is_match(&accumulated) {
                    return Ok(accumulated);
                }

                if let Some(ref pwd_regex) = self.enable_password_regex {
                    if pwd_regex.is_match(&accumulated) {
                        return Ok(accumulated);
                    }
                }
            }
        })
        .await
        .map_err(|_| crate::Error::DeviceTimeout)?;

        result
    }

    async fn check_config_mode(&mut self) -> bool {
        if let Some(regex) = self.config_regex.clone() {
            if let Ok(result) = self.send_command("").await {
                return regex.is_match(&result.raw_output);
            }
        }
        false
    }
    pub async fn enter_config_mode(&mut self, command: &str) -> Result<(), crate::Error> {
        if self.check_config_mode().await {
            if let Some(ref regex) = self.config_regex {
                self.prompt_regex = regex.clone();
            }
            return Ok(());
        }

        self.send_line(command).await?;

        if let Some(ref regex) = self.config_regex {
            // We cannot use wait_for_prompt() here because self.prompt_regex is currently enable/# and we expect (config)#
            let regex_clone = regex.clone();
            self.wait_for_regex(&regex_clone).await?;

            self.prompt_regex = regex_clone;
        } else {
            self.wait_for_prompt().await?;
        }

        Ok(())
    }

    pub async fn exit_config_mode(&mut self, command: &str) -> Result<(), crate::Error> {
        if !self.check_config_mode().await {
            if let Some(ref regex) = self.enable_regex {
                self.prompt_regex = regex.clone();
            } else {
                self.prompt_regex = self.base_prompt_regex.clone();
            }
            return Ok(());
        }

        self.send_line(command).await?;

        let target_regex = if let Some(ref regex) = self.enable_regex {
            regex.clone()
        } else {
            self.base_prompt_regex.clone()
        };

        self.wait_for_regex(&target_regex).await?;

        self.prompt_regex = target_regex;

        if self.check_config_mode().await {
            return Err(crate::Error::ConfigCommandDidntExit);
        }

        Ok(())
    }

    /// Close resources gracefully. This requires an explicit call. It would be ideal to handle it by implementing
    /// the drop trait but that is not quite hard considering that drop is not async. It possible but don't really
    /// want to spend that much time engineering a workaround solution that includes tokio
    pub async fn close(&mut self) -> Result<(), crate::Error> {
        let _ = self.channel.eof().await;
        let _ = self.channel.close().await;
        self.client.disconnect().await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DeviceSessionBuilder {
    address: Option<String>,
    port: u16,
    username: Option<String>,
    auth: Option<AuthMethod>,
    server_check: ServerCheckMethod,
    vendor: Option<DeviceVendor>,
}

impl DeviceSessionBuilder {
    pub fn new() -> Self {
        Self {
            address: None,
            port: 22,
            username: None,
            auth: None,
            server_check: ServerCheckMethod::NoCheck,
            vendor: None,
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
        self.vendor = Some(vendor.into());
        self
    }

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

        let config = if let Some(v) = self.vendor {
            v.into_config()
        } else {
            DeviceConfig::default()
        };

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
