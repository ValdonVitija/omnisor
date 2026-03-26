use omnisor::{CiscoVariant, DeviceSession};
use omnisor_health::{
    DeviceHealthSnapshot, HealthConnectionConfig, InterfaceDistribution, InterfaceHealth,
    InterfaceIssue, ReachabilityStatus, SectionStatus, collect_cisco_device_health,
    findings_status, status_from_percent,
};
use ratatui::{
    Frame,
    crossterm::event::KeyCode,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table, Wrap},
};
use std::{
    sync::mpsc::{self, Receiver},
    thread,
};

const HEALTH_SECTIONS: &[HealthSection] = &[
    HealthSection::System,
    HealthSection::Interfaces,
    HealthSection::Neighbors,
    HealthSection::Findings,
];

const VENDOR_OPTIONS: &[CiscoVariant] = &[
    CiscoVariant::Ios,
    CiscoVariant::IosXe,
    CiscoVariant::IosXr,
    CiscoVariant::NxOs,
    CiscoVariant::Asa,
    CiscoVariant::Wlc,
    CiscoVariant::IosLegacy,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureSignal {
    None,
    BackToLauncher,
    ExitApp,
}

#[derive(Debug, Clone)]
struct CliConfig {
    address: String,
    port: u16,
    username: String,
    password: String,
    vendor: CiscoVariant,
}

impl From<&CliConfig> for HealthConnectionConfig {
    fn from(value: &CliConfig) -> Self {
        Self {
            address: value.address.clone(),
            port: value.port,
            username: value.username.clone(),
            password: value.password.clone(),
            vendor: value.vendor,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionField {
    Address,
    Port,
    Username,
    Password,
    Vendor,
    Connect,
}

impl ConnectionField {
    fn title(self) -> &'static str {
        match self {
            Self::Address => "Address",
            Self::Port => "Port",
            Self::Username => "Username",
            Self::Password => "Password",
            Self::Vendor => "Vendor",
            Self::Connect => "Connect",
        }
    }

    fn all() -> &'static [Self] {
        &[
            Self::Address,
            Self::Port,
            Self::Username,
            Self::Password,
            Self::Vendor,
            Self::Connect,
        ]
    }
}

#[derive(Debug, Clone)]
struct ConnectionForm {
    address: String,
    port: String,
    username: String,
    password: String,
    vendor_index: usize,
    selected_field: usize,
}

impl ConnectionForm {
    fn new() -> Self {
        Self {
            address: String::new(),
            port: "22".to_string(),
            username: String::new(),
            password: String::new(),
            vendor_index: default_vendor_index(),
            selected_field: 0,
        }
    }

    fn selected(&self) -> ConnectionField {
        ConnectionField::all()[self.selected_field]
    }

    fn move_up(&mut self) {
        if self.selected_field == 0 {
            self.selected_field = ConnectionField::all().len() - 1;
        } else {
            self.selected_field -= 1;
        }
    }

    fn move_down(&mut self) {
        self.selected_field = (self.selected_field + 1) % ConnectionField::all().len();
    }

    fn current_vendor(&self) -> CiscoVariant {
        VENDOR_OPTIONS[self.vendor_index]
    }

    fn cycle_vendor_prev(&mut self) {
        if self.vendor_index == 0 {
            self.vendor_index = VENDOR_OPTIONS.len() - 1;
        } else {
            self.vendor_index -= 1;
        }
    }

    fn cycle_vendor_next(&mut self) {
        self.vendor_index = (self.vendor_index + 1) % VENDOR_OPTIONS.len();
    }

    fn field_value(&self, field: ConnectionField) -> String {
        match field {
            ConnectionField::Address => self.address.clone(),
            ConnectionField::Port => self.port.clone(),
            ConnectionField::Username => self.username.clone(),
            ConnectionField::Password => {
                if self.password.is_empty() {
                    String::new()
                } else {
                    "*".repeat(self.password.len())
                }
            }
            ConnectionField::Vendor => self.current_vendor().to_string(),
            ConnectionField::Connect => "Validate connection and continue".to_string(),
        }
    }

    fn push_char(&mut self, c: char) {
        match self.selected() {
            ConnectionField::Address => self.address.push(c),
            ConnectionField::Port => {
                if c.is_ascii_digit() {
                    self.port.push(c);
                }
            }
            ConnectionField::Username => self.username.push(c),
            ConnectionField::Password => self.password.push(c),
            ConnectionField::Vendor | ConnectionField::Connect => {}
        }
    }

    fn backspace(&mut self) {
        match self.selected() {
            ConnectionField::Address => {
                self.address.pop();
            }
            ConnectionField::Port => {
                self.port.pop();
            }
            ConnectionField::Username => {
                self.username.pop();
            }
            ConnectionField::Password => {
                self.password.pop();
            }
            ConnectionField::Vendor | ConnectionField::Connect => {}
        }
    }

    fn into_config(&self) -> Result<CliConfig, String> {
        let address = self.address.trim();
        if address.is_empty() {
            return Err("Device address is required.".to_string());
        }

        let username = self.username.trim();
        if username.is_empty() {
            return Err("Username is required.".to_string());
        }

        if self.password.is_empty() {
            return Err("Password is required.".to_string());
        }

        let port: u16 = self
            .port
            .trim()
            .parse()
            .map_err(|_| "Port must be a valid integer.".to_string())?;

        Ok(CliConfig {
            address: address.to_string(),
            port,
            username: username.to_string(),
            password: self.password.clone(),
            vendor: self.current_vendor(),
        })
    }
}

fn default_vendor_index() -> usize {
    VENDOR_OPTIONS
        .iter()
        .position(|vendor| *vendor == CiscoVariant::IosLegacy)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HealthSection {
    System,
    Interfaces,
    Neighbors,
    Findings,
}

impl HealthSection {
    fn title(self) -> &'static str {
        match self {
            Self::System => "System",
            Self::Interfaces => "Interfaces",
            Self::Neighbors => "Neighbors",
            Self::Findings => "Findings",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    ConnectionSetup,
    Dashboard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadState {
    Idle,
    Loading,
    Ready,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GaugeView {
    ratio: u16,
    label: String,
    status: SectionStatus,
}

#[derive(Debug)]
struct RefreshResult {
    snapshot: Option<DeviceHealthSnapshot>,
    status: String,
    error: Option<String>,
}

enum ConnectionResult {
    Ready(CliConfig),
    Failed(String),
}

pub struct DeviceHealthFeature {
    config: Option<CliConfig>,
    connection_form: ConnectionForm,
    screen: Screen,
    health_selected: usize,
    connection_state: LoadState,
    health_state: LoadState,
    snapshot: Option<DeviceHealthSnapshot>,
    status: String,
    connection_rx: Option<Receiver<ConnectionResult>>,
    refresh_rx: Option<Receiver<RefreshResult>>,
}

impl DeviceHealthFeature {
    pub fn new() -> Self {
        Self {
            config: None,
            connection_form: ConnectionForm::new(),
            screen: Screen::ConnectionSetup,
            health_selected: 0,
            connection_state: LoadState::Idle,
            health_state: LoadState::Idle,
            snapshot: None,
            status: "Provide a device session for Device Health.".to_string(),
            connection_rx: None,
            refresh_rx: None,
        }
    }

    pub fn tick(&mut self) {
        self.poll_connection();
        self.poll_refresh();
    }

    pub fn handle_key(&mut self, key: KeyCode) -> FeatureSignal {
        match self.screen {
            Screen::ConnectionSetup => self.handle_connection_key(key),
            Screen::Dashboard => match key {
                KeyCode::Char('q') => FeatureSignal::ExitApp,
                KeyCode::Up => {
                    self.move_selection_up();
                    FeatureSignal::None
                }
                KeyCode::Down => {
                    self.move_selection_down();
                    FeatureSignal::None
                }
                KeyCode::Char('r') => {
                    self.start_refresh();
                    FeatureSignal::None
                }
                KeyCode::Esc | KeyCode::Backspace => FeatureSignal::BackToLauncher,
                _ => FeatureSignal::None,
            },
        }
    }

    pub fn header_title(&self) -> &'static str {
        "Device Health"
    }

    pub fn header_subtitle(&self) -> String {
        match (&self.snapshot, &self.config) {
            (Some(snapshot), _) if matches!(self.screen, Screen::Dashboard) => format!(
                "{} | {} | age {}s",
                snapshot.device.hostname,
                snapshot.device.management_address,
                snapshot.collected_at.elapsed().as_secs()
            ),
            (_, Some(config)) => format!("{} @ {}:{}", config.vendor, config.address, config.port),
            _ => "Feature-local device session setup".to_string(),
        }
    }

    pub fn footer_text(&self) -> String {
        let state = match self.screen {
            Screen::ConnectionSetup => match self.connection_state {
                LoadState::Idle => "connection idle",
                LoadState::Loading => "connecting",
                LoadState::Ready => "connection ready",
                LoadState::Failed => "connection failed",
            },
            Screen::Dashboard => match self.health_state {
                LoadState::Idle => "health idle",
                LoadState::Loading => "health loading",
                LoadState::Ready => "health ready",
                LoadState::Failed => "health failed",
            },
        };

        let keys = match self.screen {
            Screen::ConnectionSetup => {
                "Keys: ↑/↓ move, Tab next, ←/→ vendor, type edit, Enter connect, Esc back, q quit"
            }
            Screen::Dashboard => "Keys: ↑/↓ move, Esc back, r refresh, q quit",
        };

        format!("{} | state: {} | {}", self.status, state, keys)
    }

    pub fn render(&self, f: &mut Frame, area: Rect) {
        match self.screen {
            Screen::ConnectionSetup => self.render_connection_setup(f, area),
            Screen::Dashboard => self.render_health(f, area),
        }
    }

    fn handle_connection_key(&mut self, key: KeyCode) -> FeatureSignal {
        match key {
            KeyCode::Char('q') => FeatureSignal::ExitApp,
            KeyCode::Esc => FeatureSignal::BackToLauncher,
            KeyCode::Up => {
                self.connection_form.move_up();
                FeatureSignal::None
            }
            KeyCode::Down | KeyCode::Tab => {
                self.connection_form.move_down();
                FeatureSignal::None
            }
            KeyCode::BackTab => {
                self.connection_form.move_up();
                FeatureSignal::None
            }
            KeyCode::Left => {
                if self.connection_form.selected() == ConnectionField::Vendor {
                    self.connection_form.cycle_vendor_prev();
                }
                FeatureSignal::None
            }
            KeyCode::Right => {
                if self.connection_form.selected() == ConnectionField::Vendor {
                    self.connection_form.cycle_vendor_next();
                }
                FeatureSignal::None
            }
            KeyCode::Backspace => {
                self.connection_form.backspace();
                FeatureSignal::None
            }
            KeyCode::Enter => {
                if self.connection_form.selected() == ConnectionField::Connect {
                    self.start_connection_attempt();
                } else {
                    self.connection_form.move_down();
                }
                FeatureSignal::None
            }
            KeyCode::Char(c) => {
                if !c.is_control() {
                    self.connection_form.push_char(c);
                }
                FeatureSignal::None
            }
            _ => FeatureSignal::None,
        }
    }

    fn move_selection_up(&mut self) {
        if self.health_selected == 0 {
            self.health_selected = HEALTH_SECTIONS.len() - 1;
        } else {
            self.health_selected -= 1;
        }
    }

    fn move_selection_down(&mut self) {
        self.health_selected = (self.health_selected + 1) % HEALTH_SECTIONS.len();
    }

    fn start_refresh(&mut self) {
        let Some(config) = self.config.clone() else {
            self.status = "No validated connection is available yet.".to_string();
            return;
        };

        if self.refresh_rx.is_some() {
            self.status = "Refresh already in progress.".to_string();
            return;
        }

        let (tx, rx) = mpsc::channel();
        self.health_state = LoadState::Loading;
        self.status = "Collecting Cisco device health...".to_string();

        thread::spawn(move || {
            let result = collect_snapshot_thread(config);
            let _ = tx.send(result);
        });

        self.refresh_rx = Some(rx);
    }

    fn poll_refresh(&mut self) {
        let Some(result) = self.refresh_rx.as_ref().and_then(|rx| rx.try_recv().ok()) else {
            return;
        };

        self.refresh_rx = None;
        self.status = result.status;

        if let Some(snapshot) = result.snapshot {
            self.snapshot = Some(snapshot);
            self.health_state = LoadState::Ready;
        } else {
            self.health_state = LoadState::Failed;
        }

        if let Some(error) = result.error {
            self.status = error;
        }
    }

    fn start_connection_attempt(&mut self) {
        if self.connection_rx.is_some() {
            self.status = "Connection validation is already in progress.".to_string();
            return;
        }

        let config = match self.connection_form.into_config() {
            Ok(config) => config,
            Err(err) => {
                self.connection_state = LoadState::Failed;
                self.status = err;
                return;
            }
        };

        let (tx, rx) = mpsc::channel();
        self.connection_state = LoadState::Loading;
        self.status = "Validating device connection...".to_string();

        thread::spawn(move || {
            let result = validate_connection_thread(config);
            let _ = tx.send(result);
        });

        self.connection_rx = Some(rx);
    }

    fn poll_connection(&mut self) {
        let Some(result) = self
            .connection_rx
            .as_ref()
            .and_then(|rx| rx.try_recv().ok())
        else {
            return;
        };

        self.connection_rx = None;

        match result {
            ConnectionResult::Ready(config) => {
                self.config = Some(config);
                self.screen = Screen::Dashboard;
                self.connection_state = LoadState::Ready;
                self.status = "Connection validated. Collecting device health...".to_string();
                self.start_refresh();
            }
            ConnectionResult::Failed(error) => {
                self.connection_state = LoadState::Failed;
                self.status = error;
            }
        }
    }

    fn render_connection_setup(&self, f: &mut Frame, area: Rect) {
        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(44), Constraint::Min(0)])
            .split(area);

        let items: Vec<ListItem> = ConnectionField::all()
            .iter()
            .enumerate()
            .map(|(idx, field)| {
                let text = format!(
                    "{:<10} {}",
                    field.title(),
                    self.connection_form.field_value(*field)
                );
                let style = if idx == self.connection_form.selected_field {
                    selected_style()
                } else {
                    Style::default().fg(Color::White)
                };
                ListItem::new(Line::from(text)).style(style)
            })
            .collect();

        let form =
            List::new(items).block(Block::default().borders(Borders::ALL).title("Connection"));
        f.render_widget(form, layout[0]);

        let details = Paragraph::new(
            "Device Health owns its own setup flow.\n\nFill in the device address, port, username, password, and Cisco platform. Then select Connect to validate the SSH session before collecting a snapshot.\n\nKeys:\n- Up/Down or Tab: move field\n- Left/Right: change vendor\n- Type and Backspace: edit text fields\n- Enter on Connect: validate and continue\n- Esc: return to launcher",
        )
        .block(Block::default().borders(Borders::ALL).title("Instructions"))
        .wrap(Wrap { trim: true });
        f.render_widget(details, layout[1]);
    }

    fn render_health(&self, f: &mut Frame, area: Rect) {
        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(30), Constraint::Min(0)])
            .split(area);

        let items: Vec<ListItem> = HEALTH_SECTIONS
            .iter()
            .enumerate()
            .map(|(idx, section)| {
                let status = self
                    .snapshot
                    .as_ref()
                    .map(|snapshot| snapshot_section_status(snapshot, *section))
                    .unwrap_or(SectionStatus::Unknown);
                let text = format!("{:<12} {}", section.title(), status.label());
                let base = Style::default().fg(section_status_color(status));
                let style = if idx == self.health_selected {
                    base.patch(selected_style())
                } else {
                    base
                };
                ListItem::new(Line::from(text)).style(style)
            })
            .collect();

        let sections =
            List::new(items).block(Block::default().borders(Borders::ALL).title("Sections"));
        f.render_widget(sections, layout[0]);

        let details_block = Block::default().borders(Borders::ALL).title("Details");
        let inner = details_block.inner(layout[1]);
        f.render_widget(details_block, layout[1]);

        match (&self.snapshot, self.health_state) {
            (None, LoadState::Loading) => {
                render_empty_panel(f, inner, "Collecting first device-health snapshot...")
            }
            (None, _) => render_empty_panel(
                f,
                inner,
                "No snapshot available yet. Press r to retry once the device health screen is open.",
            ),
            (Some(snapshot), _) => match HEALTH_SECTIONS[self.health_selected] {
                HealthSection::System => render_system_dashboard(f, inner, snapshot),
                HealthSection::Interfaces => render_interfaces_dashboard(f, inner, snapshot),
                HealthSection::Neighbors => render_neighbors_dashboard(f, inner, snapshot),
                HealthSection::Findings => render_findings_dashboard(f, inner, snapshot),
            },
        }
    }
}

fn validate_connection_thread(config: CliConfig) -> ConnectionResult {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            return ConnectionResult::Failed(format!(
                "runtime initialization failed during connection validation: {err}"
            ));
        }
    };

    match runtime.block_on(async {
        let mut session = DeviceSession::connect(
            (config.address.as_str(), config.port),
            &config.username,
            &config.password,
            config.vendor,
        )
        .await
        .map_err(|err| format!("unable to connect to device: {err}"))?;

        session
            .close()
            .await
            .map_err(|err| format!("connected but could not close validation session: {err}"))?;

        Ok::<(), String>(())
    }) {
        Ok(()) => ConnectionResult::Ready(config),
        Err(err) => ConnectionResult::Failed(err),
    }
}

fn collect_snapshot_thread(config: CliConfig) -> RefreshResult {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            return RefreshResult {
                snapshot: None,
                status: "Failed to create async runtime".to_string(),
                error: Some(format!("runtime initialization failed: {err}")),
            };
        }
    };

    let health_config = HealthConnectionConfig::from(&config);
    match runtime.block_on(collect_cisco_device_health(&health_config)) {
        Ok(snapshot) => RefreshResult {
            snapshot: Some(snapshot),
            status: "Device health snapshot collected.".to_string(),
            error: None,
        },
        Err(err) => RefreshResult {
            snapshot: None,
            status: "Device health collection failed.".to_string(),
            error: Some(err),
        },
    }
}

fn snapshot_section_status(
    snapshot: &DeviceHealthSnapshot,
    section: HealthSection,
) -> SectionStatus {
    match section {
        HealthSection::System => snapshot.system.status,
        HealthSection::Interfaces => snapshot.interfaces.status,
        HealthSection::Neighbors => snapshot.neighbors.status,
        HealthSection::Findings => findings_status(&snapshot.findings),
    }
}

fn render_empty_panel(f: &mut Frame, area: Rect, message: &str) {
    let text = Paragraph::new(message)
        .style(Style::default().fg(Color::Gray))
        .wrap(Wrap { trim: true })
        .alignment(Alignment::Left);
    f.render_widget(text, area);
}

fn render_system_dashboard(f: &mut Frame, area: Rect, snapshot: &DeviceHealthSnapshot) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Min(8),
        ])
        .split(area);

    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(layout[0]);

    render_value_card(
        f,
        cards[0],
        "Hostname",
        &snapshot.device.hostname,
        snapshot.system.status,
        Some("Active device"),
    );
    render_value_card(
        f,
        cards[1],
        "Vendor",
        &snapshot.device.vendor,
        SectionStatus::Ok,
        Some(&snapshot.device.management_address),
    );
    render_value_card(
        f,
        cards[2],
        "Uptime",
        snapshot.system.uptime.as_deref().unwrap_or("Unknown"),
        status_from_option(snapshot.system.uptime.as_ref()),
        Some("Device reported"),
    );
    render_value_card(
        f,
        cards[3],
        "Freshness",
        &format!("{}s", snapshot.refresh_age_secs()),
        SectionStatus::Ok,
        Some("Snapshot age"),
    );

    let gauges = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(layout[1]);

    render_metric_gauge(
        f,
        gauges[0],
        "CPU Usage",
        gauge_view(snapshot.system.cpu_percent, 80.0, 90.0),
    );
    render_metric_gauge(
        f,
        gauges[1],
        "Memory Usage",
        gauge_view(snapshot.system.memory_percent, 85.0, 95.0),
    );

    let bottom = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(layout[2]);

    let summary = Paragraph::new(vec![status_summary_line(
        "System",
        snapshot.system.status,
        &format!(
            "{} checks",
            snapshot
                .metadata
                .iter()
                .filter(|item| {
                    ["System CPU", "System Memory", "Version", "Device Identity"]
                        .contains(&item.name)
                })
                .count()
        ),
    )])
    .block(Block::default().borders(Borders::ALL).title("Status Strip"))
    .wrap(Wrap { trim: true });
    f.render_widget(summary, bottom[0]);

    render_metadata_table(
        f,
        bottom[1],
        "Checks",
        snapshot,
        &["System CPU", "System Memory", "Version", "Device Identity"],
    );
}

fn render_interfaces_dashboard(f: &mut Frame, area: Rect, snapshot: &DeviceHealthSnapshot) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(4),
            Constraint::Min(7),
            Constraint::Length(6),
        ])
        .split(area);

    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(layout[0]);

    render_value_card(
        f,
        cards[0],
        "Total",
        &snapshot.interfaces.total.to_string(),
        snapshot.interfaces.status,
        Some("Interfaces"),
    );
    render_value_card(
        f,
        cards[1],
        "Up",
        &snapshot.interfaces.up.to_string(),
        SectionStatus::Ok,
        Some("Operational"),
    );
    render_value_card(
        f,
        cards[2],
        "Down",
        &snapshot.interfaces.down.to_string(),
        if snapshot.interfaces.down > 0 {
            SectionStatus::Warning
        } else {
            SectionStatus::Ok
        },
        Some("Requires review"),
    );
    render_value_card(
        f,
        cards[3],
        "Admin Down",
        &snapshot.interfaces.admin_down.to_string(),
        SectionStatus::Unknown,
        Some("Disabled"),
    );

    render_distribution_panel(f, layout[1], snapshot.interface_distribution(), &snapshot.interfaces);
    render_issue_table(f, layout[2], &snapshot.interfaces.notable_issues);
    render_metadata_table(f, layout[3], "Checks", snapshot, &["Interfaces"]);
}

fn render_neighbors_dashboard(f: &mut Frame, area: Rect, snapshot: &DeviceHealthSnapshot) {
    let summary = snapshot.neighbor_summary();
    let protocols_display = if snapshot.neighbors.protocols_seen.is_empty() {
        "none".to_string()
    } else {
        snapshot.neighbors.protocols_seen.join(" / ")
    };
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(8),
            Constraint::Length(6),
        ])
        .split(area);

    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(28),
            Constraint::Percentage(18),
            Constraint::Percentage(18),
            Constraint::Percentage(18),
            Constraint::Percentage(18),
        ])
        .split(layout[0]);

    render_value_card(
        f,
        cards[0],
        "Protocols",
        &protocols_display,
        snapshot.neighbors.status,
        Some("Neighbor discovery"),
    );
    render_value_card(
        f,
        cards[1],
        "Total",
        &summary.total.to_string(),
        snapshot.neighbors.status,
        Some("Neighbors"),
    );
    render_value_card(
        f,
        cards[2],
        "Reachable",
        &summary.reachable.to_string(),
        SectionStatus::Ok,
        Some("Ping ok"),
    );
    render_value_card(
        f,
        cards[3],
        "Unreachable",
        &summary.unreachable.to_string(),
        if summary.unreachable > 0 {
            SectionStatus::Warning
        } else {
            SectionStatus::Ok
        },
        Some("No reply"),
    );
    render_value_card(
        f,
        cards[4],
        "Unknown",
        &summary.unknown.to_string(),
        if summary.unknown > 0 {
            SectionStatus::Unknown
        } else {
            SectionStatus::Ok
        },
        Some("No mgmt IP"),
    );

    render_neighbors_table(f, layout[1], snapshot);
    render_metadata_table(f, layout[2], "Checks", snapshot, &["CDP Neighbors", "LLDP Neighbors"]);
}

fn render_findings_dashboard(f: &mut Frame, area: Rect, snapshot: &DeviceHealthSnapshot) {
    let summary = snapshot.finding_summary();
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(8),
            Constraint::Length(8),
        ])
        .split(area);

    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(layout[0]);

    render_value_card(
        f,
        cards[0],
        "Critical",
        &summary.critical.to_string(),
        if summary.critical > 0 {
            SectionStatus::Critical
        } else {
            SectionStatus::Ok
        },
        Some("Immediate action"),
    );
    render_value_card(
        f,
        cards[1],
        "Warning",
        &summary.warning.to_string(),
        if summary.warning > 0 {
            SectionStatus::Warning
        } else {
            SectionStatus::Ok
        },
        Some("Attention"),
    );
    render_value_card(
        f,
        cards[2],
        "Unknown",
        &summary.unknown.to_string(),
        if summary.unknown > 0 {
            SectionStatus::Unknown
        } else {
            SectionStatus::Ok
        },
        Some("Partial data"),
    );
    render_value_card(
        f,
        cards[3],
        "Freshness",
        &format!("{}s", snapshot.refresh_age_secs()),
        SectionStatus::Ok,
        Some("Snapshot age"),
    );

    render_findings_list(f, layout[1], snapshot);
    render_all_metadata_table(f, layout[2], snapshot);
}

fn render_value_card(
    f: &mut Frame,
    area: Rect,
    title: &str,
    value: &str,
    status: SectionStatus,
    subtitle: Option<&str>,
) {
    let mut lines = vec![Line::from(Span::styled(
        value.to_string(),
        Style::default()
            .fg(section_status_color(status))
            .add_modifier(Modifier::BOLD),
    ))];

    if let Some(subtitle) = subtitle {
        lines.push(Line::from(Span::styled(
            subtitle.to_string(),
            Style::default().fg(Color::Gray),
        )));
    }

    let card = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(section_status_color(status))),
        )
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });
    f.render_widget(card, area);
}

fn render_metric_gauge(f: &mut Frame, area: Rect, title: &str, gauge: GaugeView) {
    let widget = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(section_status_color(gauge.status))),
        )
        .gauge_style(
            Style::default()
                .fg(section_status_color(gauge.status))
                .add_modifier(Modifier::BOLD),
        )
        .label(gauge.label)
        .percent(gauge.ratio);
    f.render_widget(widget, area);
}

fn render_distribution_panel(
    f: &mut Frame,
    area: Rect,
    distribution: InterfaceDistribution,
    interfaces: &InterfaceHealth,
) {
    let lines = vec![
        interface_distribution_line(distribution),
        Line::from(vec![
            Span::styled(" UP ", Style::default().fg(Color::Black).bg(Color::Green)),
            Span::raw(format!(" {}  ", interfaces.up)),
            Span::styled(" DOWN ", Style::default().fg(Color::Black).bg(Color::Yellow)),
            Span::raw(format!(" {}  ", interfaces.down)),
            Span::styled(" ADMIN ", Style::default().fg(Color::Black).bg(Color::Blue)),
            Span::raw(format!(" {}", interfaces.admin_down)),
        ]),
    ];

    let panel = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Distribution"))
        .wrap(Wrap { trim: true });
    f.render_widget(panel, area);
}

fn render_issue_table(f: &mut Frame, area: Rect, issues: &[InterfaceIssue]) {
    if issues.is_empty() {
        let panel = Paragraph::new("No notable interface issues.")
            .block(Block::default().borders(Borders::ALL).title("Interface Issues"))
            .wrap(Wrap { trim: true });
        f.render_widget(panel, area);
        return;
    }

    let rows = issues.iter().map(|issue| {
        Row::new(vec![
            Cell::from(issue.name.clone()),
            Cell::from(issue.detail.clone()),
        ])
    });

    let table = Table::new(rows, [Constraint::Length(22), Constraint::Min(10)])
        .header(
            Row::new(vec!["Interface", "State"])
                .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan)),
        )
        .block(Block::default().borders(Borders::ALL).title("Interface Issues"))
        .column_spacing(1);

    f.render_widget(table, area);
}

fn render_neighbors_table(f: &mut Frame, area: Rect, snapshot: &DeviceHealthSnapshot) {
    if snapshot.neighbors.entries.is_empty() {
        let empty = Paragraph::new(vec![
            Line::from(status_summary_line(
                "Neighbors",
                snapshot.neighbors.status,
                "No usable CDP/LLDP neighbors",
            )),
            Line::from(" "),
            Line::from(Span::styled(
                "Discovery checks ran, but the snapshot did not produce any neighbor entries.",
                Style::default().fg(Color::Gray),
            )),
        ])
        .block(Block::default().borders(Borders::ALL).title("Neighbor Board"))
        .wrap(Wrap { trim: true });
        f.render_widget(empty, area);
        return;
    }

    let rows = snapshot.neighbors.entries.iter().map(|neighbor| {
        Row::new(vec![
            Cell::from(protocol_line(neighbor.protocol)),
            Cell::from(neighbor.neighbor_id.clone()),
            Cell::from(neighbor.local_interface.clone()),
            Cell::from(
                neighbor
                    .remote_interface
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
            ),
            Cell::from(
                neighbor
                    .management_ip
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            ),
            Cell::from(reachability_line(neighbor.reachability)),
        ])
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(18),
            Constraint::Length(15),
            Constraint::Length(15),
            Constraint::Length(16),
            Constraint::Length(12),
        ],
    )
    .header(
        Row::new(vec!["Proto", "Neighbor", "Local", "Remote", "Mgmt IP", "Reachability"])
            .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan)),
    )
    .block(Block::default().borders(Borders::ALL).title("Neighbor Board"))
    .column_spacing(1);

    f.render_widget(table, area);
}

fn render_findings_list(f: &mut Frame, area: Rect, snapshot: &DeviceHealthSnapshot) {
    if snapshot.findings.is_empty() {
        let panel = Paragraph::new(vec![
            Line::from(status_summary_line(
                "Findings",
                SectionStatus::Ok,
                "No active findings",
            )),
            Line::from(" "),
            Line::from(Span::styled(
                "All collected sections are within expected bounds for this snapshot.",
                Style::default().fg(Color::Gray),
            )),
        ])
        .block(Block::default().borders(Borders::ALL).title("Alerts"))
        .wrap(Wrap { trim: true });
        f.render_widget(panel, area);
        return;
    }

    let items: Vec<ListItem> = snapshot
        .findings
        .iter()
        .map(|finding| {
            ListItem::new(vec![status_summary_line("", finding.status, &finding.message)])
        })
        .collect();

    let list = List::new(items).block(Block::default().borders(Borders::ALL).title("Alerts"));
    f.render_widget(list, area);
}

fn render_metadata_table(
    f: &mut Frame,
    area: Rect,
    title: &str,
    snapshot: &DeviceHealthSnapshot,
    names: &[&str],
) {
    let rows: Vec<Row> = snapshot
        .metadata
        .iter()
        .filter(|item| names.contains(&item.name))
        .map(|item| {
            Row::new(vec![
                Cell::from(item.name.to_string()),
                Cell::from(status_line(item.status)),
                Cell::from(item.details.clone()),
            ])
        })
        .collect();

    if rows.is_empty() {
        let panel = Paragraph::new("No metadata available.")
            .block(Block::default().borders(Borders::ALL).title(title))
            .wrap(Wrap { trim: true });
        f.render_widget(panel, area);
        return;
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Length(10),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec!["Check", "Status", "Details"])
            .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan)),
    )
    .block(Block::default().borders(Borders::ALL).title(title))
    .column_spacing(1);
    f.render_widget(table, area);
}

fn render_all_metadata_table(f: &mut Frame, area: Rect, snapshot: &DeviceHealthSnapshot) {
    let rows: Vec<Row> = snapshot
        .metadata
        .iter()
        .map(|item| {
            Row::new(vec![
                Cell::from(item.name.to_string()),
                Cell::from(status_line(item.status)),
                Cell::from(item.details.clone()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Length(10),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec!["Check", "Status", "Details"])
            .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan)),
    )
    .block(Block::default().borders(Borders::ALL).title("Checks"))
    .column_spacing(1);
    f.render_widget(table, area);
}

fn gauge_view(value: Option<f32>, warning: f32, critical: f32) -> GaugeView {
    match value {
        Some(value) => GaugeView {
            ratio: value.clamp(0.0, 100.0).round() as u16,
            label: format!("{value:.1}%"),
            status: status_from_percent(value, warning, critical),
        },
        None => GaugeView {
            ratio: 0,
            label: "Unknown".to_string(),
            status: SectionStatus::Unknown,
        },
    }
}

fn status_from_option<T>(value: Option<T>) -> SectionStatus {
    if value.is_some() {
        SectionStatus::Ok
    } else {
        SectionStatus::Unknown
    }
}

fn interface_distribution_line(distribution: InterfaceDistribution) -> Line<'static> {
    let total_segments = 42usize;
    let up = (distribution.up_ratio * total_segments as f32).round() as usize;
    let down = (distribution.down_ratio * total_segments as f32).round() as usize;
    let admin = total_segments.saturating_sub(up + down);

    Line::from(vec![
        Span::styled("█".repeat(up), Style::default().fg(Color::Green)),
        Span::styled("█".repeat(down), Style::default().fg(Color::Yellow)),
        Span::styled("█".repeat(admin), Style::default().fg(Color::Blue)),
    ])
}

fn status_line(status: SectionStatus) -> Line<'static> {
    Line::from(vec![Span::styled(
        format!(" {} ", status.label()),
        Style::default()
            .fg(Color::Black)
            .bg(section_status_color(status))
            .add_modifier(Modifier::BOLD),
    )])
}

fn protocol_line(protocol: &str) -> Line<'static> {
    let color = match protocol {
        "CDP" => Color::Cyan,
        "LLDP" => Color::Magenta,
        _ => Color::Gray,
    };

    Line::from(vec![Span::styled(
        format!(" {} ", protocol),
        Style::default()
            .fg(Color::Black)
            .bg(color)
            .add_modifier(Modifier::BOLD),
    )])
}

fn reachability_line(status: ReachabilityStatus) -> Line<'static> {
    let color = match status {
        ReachabilityStatus::Reachable => Color::Green,
        ReachabilityStatus::Unreachable => Color::Red,
        ReachabilityStatus::Unknown => Color::Blue,
    };

    Line::from(vec![Span::styled(
        format!(" {} ", status.label()),
        Style::default()
            .fg(Color::Black)
            .bg(color)
            .add_modifier(Modifier::BOLD),
    )])
}

fn status_summary_line(prefix: &str, status: SectionStatus, message: &str) -> Line<'static> {
    let mut spans = Vec::new();

    if !prefix.is_empty() {
        spans.push(Span::styled(
            format!("{prefix} "),
            Style::default().add_modifier(Modifier::BOLD),
        ));
    }

    spans.push(Span::styled(
        format!(" {} ", status.label()),
        Style::default()
            .fg(Color::Black)
            .bg(section_status_color(status))
            .add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::raw(format!(" {message}")));

    Line::from(spans)
}

fn section_status_color(status: SectionStatus) -> Color {
    match status {
        SectionStatus::Ok => Color::Green,
        SectionStatus::Warning => Color::Yellow,
        SectionStatus::Critical => Color::Red,
        SectionStatus::Unknown => Color::Blue,
    }
}

fn selected_style() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnisor_health::{
        CheckMetadata, DeviceIdentity, Finding, InterfaceHealth, NeighborHealth,
        NeighborReachabilitySummary, NeighborsSection, SeveritySummary, SystemHealth,
    };
    use std::time::{Duration, Instant};

    fn sample_snapshot() -> DeviceHealthSnapshot {
        DeviceHealthSnapshot {
            device: DeviceIdentity {
                hostname: "router-1".to_string(),
                management_address: "192.0.2.10:22".to_string(),
                vendor: "Cisco IOS (Legacy)".to_string(),
            },
            system: SystemHealth {
                status: SectionStatus::Warning,
                cpu_percent: Some(82.0),
                memory_percent: None,
                uptime: Some("1 week".to_string()),
            },
            interfaces: InterfaceHealth {
                status: SectionStatus::Warning,
                total: 4,
                up: 2,
                down: 1,
                admin_down: 1,
                notable_issues: vec![InterfaceIssue {
                    name: "Fa0/1".to_string(),
                    detail: "status: down, protocol: down".to_string(),
                }],
            },
            neighbors: NeighborsSection {
                status: SectionStatus::Unknown,
                protocols_seen: vec!["CDP", "LLDP"],
                entries: vec![
                    NeighborHealth {
                        protocol: "CDP",
                        local_interface: "Fa0/0".to_string(),
                        neighbor_id: "sw1".to_string(),
                        remote_interface: Some("Gi0/24".to_string()),
                        management_ip: Some("10.0.0.2".to_string()),
                        reachability: ReachabilityStatus::Reachable,
                    },
                    NeighborHealth {
                        protocol: "LLDP",
                        local_interface: "Fa0/1".to_string(),
                        neighbor_id: "sw2".to_string(),
                        remote_interface: Some("Gi0/23".to_string()),
                        management_ip: None,
                        reachability: ReachabilityStatus::Unknown,
                    },
                    NeighborHealth {
                        protocol: "CDP",
                        local_interface: "Fa0/2".to_string(),
                        neighbor_id: "sw3".to_string(),
                        remote_interface: Some("Gi0/22".to_string()),
                        management_ip: Some("10.0.0.3".to_string()),
                        reachability: ReachabilityStatus::Unreachable,
                    },
                ],
            },
            findings: vec![
                Finding {
                    status: SectionStatus::Warning,
                    message: "A neighbor did not answer ping.".to_string(),
                },
                Finding {
                    status: SectionStatus::Unknown,
                    message: "Memory usage could not be parsed.".to_string(),
                },
            ],
            metadata: vec![CheckMetadata {
                name: &"System CPU",
                status: SectionStatus::Warning,
                details: "CPU one-minute usage 82.0%".to_string(),
            }],
            collected_at: Instant::now() - Duration::from_secs(5),
        }
    }

    #[test]
    fn connection_form_validates_required_fields() {
        let form = ConnectionForm::new();
        let err = form.into_config().unwrap_err();
        assert!(err.contains("Device address is required"));
    }

    #[test]
    fn connection_form_builds_config() {
        let mut form = ConnectionForm::new();
        form.address = "192.0.2.10".to_string();
        form.username = "admin".to_string();
        form.password = "pass".to_string();
        form.vendor_index = 3;

        let built = form.into_config().unwrap();
        assert_eq!(built.address, "192.0.2.10");
        assert_eq!(built.port, 22);
        assert_eq!(built.vendor, CiscoVariant::NxOs);
    }

    #[test]
    fn feature_starts_on_connection_setup() {
        let feature = DeviceHealthFeature::new();
        assert!(matches!(feature.screen, Screen::ConnectionSetup));
        assert!(feature.config.is_none());
    }

    #[test]
    fn neighbor_summary_counts_all_states() {
        let snapshot = sample_snapshot();
        let summary = snapshot.neighbor_summary();
        assert_eq!(
            summary,
            NeighborReachabilitySummary {
                total: 3,
                reachable: 1,
                unreachable: 1,
                unknown: 1,
            }
        );
    }

    #[test]
    fn finding_summary_counts_severities() {
        let snapshot = sample_snapshot();
        let summary = snapshot.finding_summary();
        assert_eq!(
            summary,
            SeveritySummary {
                ok: 0,
                warning: 1,
                critical: 0,
                unknown: 1,
            }
        );
    }

    #[test]
    fn interface_distribution_matches_counts() {
        let snapshot = sample_snapshot();
        let distribution = snapshot.interface_distribution();
        assert!((distribution.up_ratio - 0.5).abs() < f32::EPSILON);
        assert!((distribution.down_ratio - 0.25).abs() < f32::EPSILON);
        assert!((distribution.admin_down_ratio - 0.25).abs() < f32::EPSILON);
    }

    #[test]
    fn gauge_view_uses_unknown_for_missing_values() {
        let gauge = gauge_view(None, 80.0, 90.0);
        assert_eq!(
            gauge,
            GaugeView {
                ratio: 0,
                label: "Unknown".to_string(),
                status: SectionStatus::Unknown,
            }
        );
    }

    #[test]
    fn gauge_view_maps_thresholds_correctly() {
        let gauge = gauge_view(Some(92.0), 80.0, 90.0);
        assert_eq!(gauge.ratio, 92);
        assert_eq!(gauge.label, "92.0%");
        assert_eq!(gauge.status, SectionStatus::Critical);
    }
}
