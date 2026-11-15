//! Desktop workspace state, independent of GPUI and native windowing.
//!
//! Captures are historical evidence. Loading one never opens a device connection
//! or starts a collector. Future live collection will use a separate runtime.

pub mod health;
pub mod launcher;

use std::{
    collections::BTreeSet,
    io::{self, Read},
    path::Path,
};

use omnisor_telemetry::{Observation, Value};
use serde::Deserialize;

pub const MAX_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
pub const BUNDLED_CAPTURE: &str = include_str!("../../../examples/telemetry/sample-output.json");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tool {
    DeviceHealth,
    Interfaces,
    Observations,
    Findings,
    Collection,
}

impl Tool {
    pub const ALL: [Self; 5] = [
        Self::DeviceHealth,
        Self::Interfaces,
        Self::Observations,
        Self::Findings,
        Self::Collection,
    ];
    pub fn title(self) -> &'static str {
        match self {
            Self::DeviceHealth => "Device health",
            Self::Interfaces => "Interfaces",
            Self::Observations => "Observations",
            Self::Findings => "Findings",
            Self::Collection => "Collection",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RecordedFinding {
    pub device_id: String,
    pub entity_id: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct Capture {
    pub description: String,
    #[serde(rename = "degraded_canonical_observations", alias = "observations")]
    pub observations: Vec<Observation>,
    #[serde(rename = "degraded_findings", alias = "findings", default)]
    pub findings: Vec<RecordedFinding>,
}

impl Capture {
    pub fn from_json(json: &str) -> Result<Self, String> {
        if json.len() > MAX_CAPTURE_BYTES {
            return Err("Capture exceeds the 4 MiB limit".into());
        }
        let capture: Self =
            serde_json::from_str(json).map_err(|error| format!("Cannot read capture: {error}"))?;
        for observation in &capture.observations {
            if observation.device_id.is_empty()
                || observation.entity_id.is_empty()
                || observation.name.is_empty()
            {
                return Err(
                    "Capture contains an observation without device, entity, or metric identity"
                        .into(),
                );
            }
            if observation.observed_at_unix_nano.parse::<u64>().is_err() {
                return Err("Capture contains an invalid observation timestamp".into());
            }
        }
        Ok(capture)
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        // Bound the read itself, including files that grow after opening.
        let file = std::fs::File::open(path)
            .map_err(|error| format!("Cannot open {}: {error}", path.display()))?;
        let mut json = String::new();
        file.take((MAX_CAPTURE_BYTES + 1) as u64)
            .read_to_string(&mut json)
            .map_err(|error| format!("Cannot read {}: {error}", path.display()))?;
        Self::from_json(&json)
    }

    pub fn device_ids(&self) -> Vec<String> {
        self.observations
            .iter()
            .map(|observation| observation.device_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

pub struct Workspace {
    pub tool: Tool,
    pub capture: Option<Capture>,
    pub selected_device: Option<String>,
    pub source: String,
    pub error: Option<String>,
}

impl Workspace {
    pub fn empty() -> Self {
        Self {
            tool: Tool::DeviceHealth,
            capture: None,
            selected_device: None,
            source: "No capture loaded".into(),
            error: None,
        }
    }

    pub fn open(path: Option<&Path>) -> Self {
        let source = path
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "Bundled synthetic telemetry capture".into());
        let result = match path {
            Some(path) => Capture::read(path),
            None => Capture::from_json(BUNDLED_CAPTURE),
        };
        let (capture, error) = match result {
            Ok(capture) => (Some(capture), None),
            Err(error) => (None, Some(error)),
        };
        let selected_device = capture
            .as_ref()
            .and_then(|capture| capture.device_ids().into_iter().next());
        Self {
            tool: Tool::DeviceHealth,
            capture,
            selected_device,
            source,
            error,
        }
    }

    pub fn select_device(&mut self, id: &str) {
        if self.capture.as_ref().is_some_and(|capture| {
            capture
                .observations
                .iter()
                .any(|observation| observation.device_id == id)
        }) {
            self.selected_device = Some(id.into());
        }
    }

    pub fn observations(&self) -> Vec<&Observation> {
        self.capture
            .iter()
            .flat_map(|capture| &capture.observations)
            .filter(|observation| {
                self.selected_device.as_deref() == Some(observation.device_id.as_str())
            })
            .collect()
    }

    pub fn findings(&self) -> Vec<&RecordedFinding> {
        self.capture
            .iter()
            .flat_map(|capture| &capture.findings)
            .filter(|finding| self.selected_device.as_deref() == Some(finding.device_id.as_str()))
            .collect()
    }
}

pub fn display_value(observation: &Observation) -> String {
    match &observation.value {
        Value::Number(value) if observation.name == "device.cpu.utilization" => {
            format!("{:.1}%", value * 100.0)
        }
        Value::Number(value) => format!("{value} {}", observation.unit),
        Value::Integer(value) => format!("{value} {}", observation.unit),
        Value::State(state) => state.clone(),
    }
}

pub fn capture_argument(
    args: impl IntoIterator<Item = String>,
) -> Result<Option<std::path::PathBuf>, io::Error> {
    let mut args = args.into_iter();
    match args.next().as_deref() {
        None => Ok(None),
        Some("--capture") => {
            let path = args
                .next()
                .ok_or_else(|| io::Error::other("--capture requires a file path"))?;
            if args.next().is_some() {
                return Err(io::Error::other("Usage: omnisor-desktop [--capture FILE]"));
            }
            Ok(Some(path.into()))
        }
        _ => Err(io::Error::other("Usage: omnisor-desktop [--capture FILE]")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_capture_preserves_source_semantics_and_filters_device_scope() {
        let mut json: serde_json::Value = serde_json::from_str(BUNDLED_CAPTURE).unwrap();
        let mut other = json["degraded_canonical_observations"][0].clone();
        other["device_id"] = "other-device".into();
        json["degraded_canonical_observations"]
            .as_array_mut()
            .unwrap()
            .push(other);
        let capture = Capture::from_json(&json.to_string()).unwrap();
        let mut workspace = Workspace::open(None);
        workspace.capture = Some(capture);
        workspace.select_device("lab-ios-01");
        assert_eq!(workspace.observations().len(), 8);
        assert_eq!(workspace.findings().len(), 3);
        let cpu = workspace
            .observations()
            .into_iter()
            .find(|observation| observation.name == "device.cpu.utilization")
            .unwrap();
        assert_eq!(cpu.window_seconds, Some(60));
        assert_eq!(display_value(cpu), "96.0%");
        workspace.select_device("other-device");
        assert_eq!(workspace.observations().len(), 1);
        assert!(workspace.findings().is_empty());
    }

    #[test]
    fn failed_capture_does_not_silently_show_sample_data() {
        let workspace = Workspace::open(Some(Path::new("/nonexistent/omnisor-capture.json")));
        assert!(workspace.capture.is_none());
        assert!(workspace.error.is_some());
        assert!(workspace.observations().is_empty());
        assert!(Capture::from_json("{}").is_err());
        assert!(Capture::from_json(&" ".repeat(MAX_CAPTURE_BYTES + 1)).is_err());
    }

    #[test]
    fn identity_and_timestamp_are_required_for_historical_observations() {
        let mut json: serde_json::Value = serde_json::from_str(BUNDLED_CAPTURE).unwrap();
        json["degraded_canonical_observations"][0]["observed_at_unix_nano"] = "invalid".into();
        assert!(Capture::from_json(&json.to_string()).is_err());
        json["degraded_canonical_observations"][0]["observed_at_unix_nano"] = "100".into();
        json["degraded_canonical_observations"][0]["device_id"] = "".into();
        assert!(Capture::from_json(&json.to_string()).is_err());
    }
}
