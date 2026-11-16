#![doc = include_str!("../README.md")]
pub mod client;
pub mod device;
pub mod error;
mod to_socket_addrs_with_hostname;

pub use client::{AuthMethod, Client, CommandExecutedResult, ServerCheckMethod};
pub use error::Error;
pub use to_socket_addrs_with_hostname::ToSocketAddrsWithHostname;

// Re-export commonly used device types at crate root for convenience
pub use device::{
    CiscoVariant, DeviceCommandResult, DeviceConfig, DeviceSession, DeviceSessionBuilder,
    DeviceVendor, JuniperVariant, SshAlgorithms,
};

// Re-export russh algorithm modules for direct use
pub use russh::cipher;
pub use russh::kex;
pub use russh::mac;
