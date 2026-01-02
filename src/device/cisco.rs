//! Cisco device configurations.

use super::{DeviceConfig, SshAlgorithms};

/// Cisco device variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum CiscoVariant {
    #[default]
    Ios,
    IosXe,
    IosXr,
    NxOs,
    Asa,
    Wlc,
    IosLegacy,
}

impl CiscoVariant {
    pub fn into_config(self) -> DeviceConfig {
        match self {
            Self::Ios | Self::IosXe => Self::ios_config(),
            Self::IosXr => Self::ios_xr_config(),
            Self::NxOs => Self::nxos_config(),
            Self::Asa => Self::asa_config(),
            Self::Wlc => Self::wlc_config(),
            Self::IosLegacy => Self::ios_legacy_config(),
        }
    }

    fn ios_config() -> DeviceConfig {
        DeviceConfig::with_prompt(r"[\r\n][\w\-\.]+[#>]\s*$")
            .add_disable_paging_command("terminal length 0")
            .add_disable_paging_command("terminal width 512")
            .add_error_pattern(r"% Invalid")
            .add_error_pattern(r"% Incomplete")
            .add_error_pattern(r"% Ambiguous")
            .add_error_pattern(r"% Unknown")
    }

    fn ios_xr_config() -> DeviceConfig {
        DeviceConfig::with_prompt(r"[\r\n][\w\-\.:\/]+[#>]\s*$")
            .add_disable_paging_command("terminal length 0")
            .add_disable_paging_command("terminal width 512")
            .add_error_pattern(r"% Invalid")
            .add_error_pattern(r"% Incomplete")
            .add_error_pattern(r"% Ambiguous")
            .add_error_pattern(r"% Failed")
    }

    fn nxos_config() -> DeviceConfig {
        DeviceConfig::with_prompt(r"[\r\n][\w\-\.]+[#>]\s*$")
            .add_disable_paging_command("terminal length 0")
            .add_disable_paging_command("terminal width 511")
            .add_error_pattern(r"% Invalid")
            .add_error_pattern(r"% Incomplete")
            .add_error_pattern(r"% Ambiguous")
            .add_error_pattern(r"Syntax error")
    }

    fn asa_config() -> DeviceConfig {
        DeviceConfig::with_prompt(r"[\r\n][\w\-\.\/]+[#>]\s*$")
            .add_disable_paging_command("terminal pager 0")
            .add_error_pattern(r"ERROR:")
            .add_error_pattern(r"% Invalid")
            .add_error_pattern(r"% Incomplete")
    }

    fn wlc_config() -> DeviceConfig {
        // WLC has a different prompt style: (Cisco Controller) >
        DeviceConfig::with_prompt(r"[\r\n]\([^\)]+\)\s*[#>]\s*$")
            .add_disable_paging_command("config paging disable")
            .add_error_pattern(r"Incorrect usage")
            .add_error_pattern(r"Invalid")
    }

    fn ios_legacy_config() -> DeviceConfig {
        DeviceConfig::with_prompt(r"[\r\n][\w\-\.]+[#>]\s*$")
            .add_disable_paging_command("terminal length 0")
            .add_disable_paging_command("terminal width 512")
            .add_error_pattern(r"% Invalid")
            .add_error_pattern(r"% Incomplete")
            .add_error_pattern(r"% Ambiguous")
            .add_error_pattern(r"% Unknown")
            .ssh_algorithms(
                SshAlgorithms::new()
                    .kex(vec![
                        russh::kex::DH_G14_SHA1,
                        russh::kex::DH_G1_SHA1,
                        russh::kex::DH_GEX_SHA1,
                    ])
                    .cipher(vec![
                        russh::cipher::AES_256_CBC,
                        russh::cipher::AES_192_CBC,
                        russh::cipher::AES_128_CBC,
                        russh::cipher::AES_256_CTR,
                        russh::cipher::AES_128_CTR,
                    ])
                    .mac(vec![russh::mac::HMAC_SHA1]),
            )
    }
}

impl std::fmt::Display for CiscoVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ios => write!(f, "Cisco IOS"),
            Self::IosXe => write!(f, "Cisco IOS-XE"),
            Self::IosXr => write!(f, "Cisco IOS-XR"),
            Self::NxOs => write!(f, "Cisco NX-OS"),
            Self::Asa => write!(f, "Cisco ASA"),
            Self::Wlc => write!(f, "Cisco WLC"),
            Self::IosLegacy => write!(f, "Cisco IOS (Legacy)"),
        }
    }
}
