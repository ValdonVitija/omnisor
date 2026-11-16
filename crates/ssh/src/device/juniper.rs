//! Juniper device configurations.
//! NOT STABLE!!!!!!

use super::DeviceConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum JuniperVariant {
    #[default]
    Junos,
    ScreenOs,
}

impl JuniperVariant {
    pub fn into_config(self) -> DeviceConfig {
        match self {
            Self::Junos => Self::junos_config(),
            Self::ScreenOs => Self::screenos_config(),
        }
    }

    fn junos_config() -> DeviceConfig {
        // Junos prompt: user@hostname> or user@hostname#
        DeviceConfig::with_prompt(r"[\r\n][\w\-\.]+@[\w\-\.]+[>#%]\s*$")
            .add_disable_paging_command("set cli screen-length 0")
            .add_disable_paging_command("set cli screen-width 511")
            .add_error_pattern(r"error:")
            .add_error_pattern(r"syntax error")
            .add_error_pattern(r"unknown command")
            .add_error_pattern(r"missing argument")
    }

    fn screenos_config() -> DeviceConfig {
        // ScreenOS prompt: hostname->
        DeviceConfig::with_prompt(r"[\r\n][\w\-\.]+\->\s*$")
            .add_disable_paging_command("set console page 0")
            .add_error_pattern(r"unknown keyword")
            .add_error_pattern(r"invalid input")
    }
}

impl std::fmt::Display for JuniperVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Junos => write!(f, "Juniper Junos"),
            Self::ScreenOs => write!(f, "Juniper ScreenOS"),
        }
    }
}
