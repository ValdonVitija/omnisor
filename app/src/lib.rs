//! Desktop session state, independent of GPUI and native windowing.
//! Device Health presents observations and findings from collection sessions.

pub mod health;
pub mod launcher;

use serde::Deserialize;
use telemetry::{Observation, Value};

#[cfg(test)]
pub(crate) const BUNDLED_CAPTURE: &str =
    include_str!("../../examples/telemetry/sample-output.json");

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

pub struct Workspace {
    pub tool: Tool,
    pub capture: Option<Capture>,
    pub selected_device: Option<String>,
    pub source: String,
}

impl Workspace {
    pub fn empty() -> Self {
        Self {
            tool: Tool::DeviceHealth,
            capture: None,
            selected_device: None,
            source: "No collection session".into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_observations_preserve_source_semantics_and_filter_device_scope() {
        let mut json: serde_json::Value = serde_json::from_str(BUNDLED_CAPTURE).unwrap();
        let mut other = json["degraded_canonical_observations"][0].clone();
        other["device_id"] = "other-device".into();
        json["degraded_canonical_observations"]
            .as_array_mut()
            .unwrap()
            .push(other);
        let capture: Capture = serde_json::from_value(json).unwrap();
        let mut workspace = Workspace::empty();
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
}
