//! Local collection engine. No native GUI dependencies, SSH command parsing,
//! global ports, or repository-relative runtime configuration paths.

pub mod access;
pub mod catalog;
pub mod config;
mod diagnostics;
mod ingest;
pub mod runtime;
pub mod store;
mod synthetic;

pub use catalog::{Catalog, DeviceIdentity};
pub use config::{CollectionPlan, SnmpCredentials, Source};
pub use runtime::{Phase, Session, SessionSnapshot};

pub fn unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
