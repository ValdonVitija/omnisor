//! Mini-app registration and navigation. Selection is not a request to collect.
//! A future runtime reconciles explicit demand, never the entire tool catalogue.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MiniApp {
    DeviceHealth,
    ConfigurationCompare,
    IpTools,
    ProtocolInspector,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    Metrics,
    DeviceAccess,
}

#[derive(Clone, Copy, Debug)]
pub struct Registration {
    pub id: MiniApp,
    pub title: &'static str,
    pub description: &'static str,
    pub category: &'static str,
    pub available: bool,
    /// Potential requirements, acquired only after an explicit live operation.
    pub capabilities: &'static [Capability],
}

pub const MINI_APPS: &[Registration] = &[
    Registration {
        id: MiniApp::DeviceHealth,
        title: "Device health",
        description: "A clear view of CPU, memory, interfaces, and the signals that need attention.",
        category: "DIAGNOSTICS",
        available: true,
        capabilities: &[Capability::Metrics],
    },
    Registration {
        id: MiniApp::ConfigurationCompare,
        title: "Configuration compare",
        description: "Compare two configurations and make sense of what changed.",
        category: "CONFIGURATION",
        available: false,
        capabilities: &[],
    },
    Registration {
        id: MiniApp::IpTools,
        title: "IP tools",
        description: "Work through subnets, address ranges, and network boundaries.",
        category: "UTILITIES",
        available: false,
        capabilities: &[],
    },
    Registration {
        id: MiniApp::ProtocolInspector,
        title: "Protocol inspector",
        description: "Look closer at routing peers, sessions, and protocol state.",
        category: "PROTOCOLS",
        available: false,
        capabilities: &[Capability::DeviceAccess],
    },
];

impl MiniApp {
    pub fn registration(self) -> &'static Registration {
        MINI_APPS
            .iter()
            .find(|registration| registration.id == self)
            .expect("registered mini-app")
    }
}

#[derive(Default)]
pub struct LauncherState {
    active: Option<MiniApp>,
    generation: u64,
    demand: Vec<Capability>,
}

impl LauncherState {
    pub fn active(&self) -> Option<MiniApp> {
        self.active
    }

    /// Opening a mini-app never requests collection or inherits another app's work.
    pub fn open(&mut self, app: MiniApp) -> Result<u64, &'static str> {
        if !app.registration().available {
            return Err("This mini-app is not available yet");
        }
        if self.active == Some(app) {
            return Ok(self.generation);
        }
        self.generation += 1;
        self.active = Some(app);
        self.demand.clear();
        Ok(self.generation)
    }

    /// Desired capabilities, not running-process status. Only an explicit live
    /// operation may call this; recorded evidence uses no capabilities.
    pub fn request_live_operation(&mut self) -> Result<&[Capability], &'static str> {
        let app = self.active.ok_or("Choose a mini-app first")?;
        self.demand = app.registration().capabilities.to_vec();
        Ok(&self.demand)
    }

    pub fn demand(&self) -> &[Capability] {
        &self.demand
    }

    pub fn stop_operation(&mut self) {
        self.demand.clear();
    }

    pub fn return_to_launcher(&mut self) {
        self.generation += 1;
        self.active = None;
        self.demand.clear();
    }

    /// Guards asynchronous results when the user leaves or reopens an app.
    pub fn accepts_result(&self, app: MiniApp, generation: u64) -> bool {
        self.active == Some(app) && self.generation == generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_and_opening_health_do_not_request_collectors() {
        let mut launcher = LauncherState::default();
        assert_eq!(launcher.active(), None);
        assert!(launcher.demand().is_empty());
        assert!(launcher.request_live_operation().is_err());
        launcher.open(MiniApp::DeviceHealth).unwrap();
        assert!(launcher.demand().is_empty());
        assert_eq!(
            launcher.request_live_operation().unwrap(),
            &[Capability::Metrics]
        );
        launcher.return_to_launcher();
        assert!(launcher.demand().is_empty());
    }

    #[test]
    fn local_tools_have_no_metric_dependency_and_planned_tools_cannot_launch() {
        for app in [MiniApp::ConfigurationCompare, MiniApp::IpTools] {
            assert!(app.registration().capabilities.is_empty());
            let mut launcher = LauncherState::default();
            assert!(launcher.open(app).is_err());
            assert_eq!(launcher.active(), None);
            assert!(launcher.demand().is_empty());
        }
        assert_eq!(
            MiniApp::ProtocolInspector.registration().capabilities,
            &[Capability::DeviceAccess]
        );
    }

    #[test]
    fn late_results_cannot_reopen_a_closed_or_replaced_mini_app() {
        let mut launcher = LauncherState::default();
        let first = launcher.open(MiniApp::DeviceHealth).unwrap();
        assert!(launcher.accepts_result(MiniApp::DeviceHealth, first));
        launcher.return_to_launcher();
        assert!(!launcher.accepts_result(MiniApp::DeviceHealth, first));
        let second = launcher.open(MiniApp::DeviceHealth).unwrap();
        assert!(!launcher.accepts_result(MiniApp::DeviceHealth, first));
        assert!(launcher.accepts_result(MiniApp::DeviceHealth, second));
        assert!(launcher.demand().is_empty());
    }

    #[test]
    fn opening_the_current_app_preserves_its_operation_and_generation() {
        let mut launcher = LauncherState::default();
        let generation = launcher.open(MiniApp::DeviceHealth).unwrap();
        launcher.request_live_operation().unwrap();
        assert_eq!(launcher.open(MiniApp::DeviceHealth).unwrap(), generation);
        assert_eq!(launcher.demand(), &[Capability::Metrics]);
    }
}
