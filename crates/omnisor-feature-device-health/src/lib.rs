mod worker;

use omnisor::{CiscoVariant, ServerCheckMethod, device::DeviceVendor};
use omnisor_health::{
    DeviceHealthSnapshot, HealthConnectionConfig, InterfaceDistribution, InterfaceHealth,
    InterfaceIssue, ReachabilityStatus, SectionStatus, findings_status, status_from_percent,
    supported_health_vendors,
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
    fmt,
    sync::mpsc::TryRecvError,
    time::{Duration, Instant},
};
use worker::{HealthWorker, RefreshResult};

const DEFAULT_REFRESH_SECONDS: u64 = 10;
const MIN_REFRESH_SECONDS: u64 = 5;
const MAX_REFRESH_SECONDS: u64 = 3600;

const HEALTH_SECTIONS: &[HealthSection] = &[
    HealthSection::System,
    HealthSection::Interfaces,
    HealthSection::Neighbors,
    HealthSection::Findings,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureSignal {
    None,
    BackToLauncher,
    ExitApp,
}

#[derive(Clone)]
struct CliConfig {
    address: String,
    port: u16,
    username: String,
    password: String,
    vendor: DeviceVendor,
    refresh_interval: Duration,
    host_trust: HostTrust,
}

impl fmt::Debug for CliConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CliConfig")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("vendor", &self.vendor)
            .field("refresh_interval", &self.refresh_interval)
            .field("host_trust", &self.host_trust)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostTrust {
    KnownHosts,
    InsecureLab,
}

impl HostTrust {
    fn label(self) -> &'static str {
        match self {
            Self::KnownHosts => "Verify known_hosts",
            Self::InsecureLab => "INSECURE (lab only)",
        }
    }

    fn toggle(&mut self) {
        *self = match self {
            Self::KnownHosts => Self::InsecureLab,
            Self::InsecureLab => Self::KnownHosts,
        };
    }

    fn server_check(self) -> ServerCheckMethod {
        match self {
            Self::KnownHosts => ServerCheckMethod::DefaultKnownHostsFile,
            Self::InsecureLab => ServerCheckMethod::NoCheck,
        }
    }
}

impl From<&CliConfig> for HealthConnectionConfig {
    fn from(value: &CliConfig) -> Self {
        Self {
            address: value.address.clone(),
            port: value.port,
            username: value.username.clone(),
            password: value.password.clone(),
            vendor: value.vendor.clone(),
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
    RefreshInterval,
    HostTrust,
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
            Self::RefreshInterval => "Interval",
            Self::HostTrust => "Host trust",
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
            Self::RefreshInterval,
            Self::HostTrust,
            Self::Connect,
        ]
    }
}

#[derive(Clone)]
struct ConnectionForm {
    address: String,
    port: String,
    username: String,
    password: String,
    refresh_seconds: String,
    host_trust: HostTrust,
    vendor_options: Vec<DeviceVendor>,
    vendor_index: usize,
    selected_field: usize,
}

impl ConnectionForm {
    fn new() -> Self {
        let vendor_options = supported_health_vendors();
        let vendor_index = default_vendor_index(&vendor_options);
        Self {
            address: String::new(),
            port: "22".to_string(),
            username: String::new(),
            password: String::new(),
            refresh_seconds: DEFAULT_REFRESH_SECONDS.to_string(),
            host_trust: HostTrust::KnownHosts,
            vendor_options,
            vendor_index,
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

    fn current_vendor(&self) -> DeviceVendor {
        self.vendor_options[self.vendor_index].clone()
    }

    fn current_vendor_label(&self) -> String {
        match self.current_vendor() {
            DeviceVendor::Cisco(variant) => variant.to_string(),
            DeviceVendor::Juniper(variant) => variant.to_string(),
            DeviceVendor::Custom(_) => "Custom Device Profile".to_string(),
            _ => "Device Vendor".to_string(),
        }
    }

    fn cycle_vendor_prev(&mut self) {
        if self.vendor_index == 0 {
            self.vendor_index = self.vendor_options.len() - 1;
        } else {
            self.vendor_index -= 1;
        }
    }

    fn cycle_vendor_next(&mut self) {
        self.vendor_index = (self.vendor_index + 1) % self.vendor_options.len();
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
            ConnectionField::Vendor => self.current_vendor_label(),
            ConnectionField::RefreshInterval => format!("{} seconds", self.refresh_seconds),
            ConnectionField::HostTrust => self.host_trust.label().to_string(),
            ConnectionField::Connect => "Connect and start live health".to_string(),
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
            ConnectionField::RefreshInterval => {
                if c.is_ascii_digit() {
                    self.refresh_seconds.push(c);
                }
            }
            ConnectionField::Vendor | ConnectionField::HostTrust | ConnectionField::Connect => {}
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
            ConnectionField::RefreshInterval => {
                self.refresh_seconds.pop();
            }
            ConnectionField::Vendor | ConnectionField::HostTrust | ConnectionField::Connect => {}
        }
    }

    fn to_config(&self) -> Result<CliConfig, String> {
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
        if port == 0 {
            return Err("Port must be between 1 and 65535.".to_string());
        }
        let refresh_seconds = self.refresh_seconds.parse::<u64>()
            .ok()
            .filter(|seconds| (MIN_REFRESH_SECONDS..=MAX_REFRESH_SECONDS).contains(seconds))
            .ok_or_else(|| format!("Refresh interval must be between {MIN_REFRESH_SECONDS} and {MAX_REFRESH_SECONDS} seconds."))?;

        Ok(CliConfig {
            address: address.to_string(),
            port,
            username: username.to_string(),
            password: self.password.clone(),
            vendor: self.current_vendor(),
            refresh_interval: Duration::from_secs(refresh_seconds),
            host_trust: self.host_trust,
        })
    }
}

fn default_vendor_index(vendors: &[DeviceVendor]) -> usize {
    vendors
        .iter()
        .position(|vendor| *vendor == DeviceVendor::Cisco(CiscoVariant::Ios))
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

#[derive(Clone, Copy)]
struct SnapshotFreshness {
    label: &'static str,
    status: SectionStatus,
}

/// Refreshes are spaced from completion, so slow devices never build a backlog.
struct RefreshSchedule {
    interval: Duration,
    paused: bool,
    in_flight: bool,
    next_due: Option<Instant>,
}

impl RefreshSchedule {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            paused: false,
            in_flight: false,
            next_due: None,
        }
    }

    fn started(&mut self) {
        self.in_flight = true;
        self.next_due = None;
    }

    fn completed(&mut self, now: Instant) {
        self.in_flight = false;
        self.next_due = Some(now + self.interval);
    }

    fn due(&self, now: Instant) -> bool {
        !self.paused && !self.in_flight && self.next_due.is_some_and(|due| now >= due)
    }

    fn toggle_paused(&mut self, now: Instant) {
        self.paused = !self.paused;
        if !self.paused && !self.in_flight {
            self.next_due = Some(now);
        }
    }

    fn label(&self, now: Instant) -> String {
        if self.paused {
            "auto-refresh paused".to_string()
        } else if self.in_flight {
            "collecting".to_string()
        } else if let Some(due) = self.next_due {
            let seconds = due.saturating_duration_since(now).as_secs_f64().ceil() as u64;
            format!("refresh in {seconds}s")
        } else {
            "waiting for first collection".to_string()
        }
    }
}

pub struct DeviceHealthFeature {
    config: Option<CliConfig>,
    connection_form: ConnectionForm,
    screen: Screen,
    health_selected: usize,
    connection_state: LoadState,
    health_state: LoadState,
    snapshot: Option<DeviceHealthSnapshot>,
    last_collection_failed: bool,
    status: String,
    worker: Option<HealthWorker>,
    refresh_schedule: RefreshSchedule,
}

impl Default for DeviceHealthFeature {
    fn default() -> Self {
        Self::new()
    }
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
            last_collection_failed: false,
            status: "Provide a device session for Device Health.".to_string(),
            worker: None,
            refresh_schedule: RefreshSchedule::new(Duration::from_secs(DEFAULT_REFRESH_SECONDS)),
        }
    }

    pub fn tick(&mut self) {
        self.tick_at(Instant::now());
    }

    fn tick_at(&mut self, now: Instant) {
        self.poll_refresh(now);
        if matches!(self.screen, Screen::Dashboard) && self.refresh_schedule.due(now) {
            self.start_refresh();
        }
    }

    pub fn handle_key(&mut self, key: KeyCode) -> FeatureSignal {
        match self.screen {
            Screen::ConnectionSetup => self.handle_connection_key(key),
            Screen::Dashboard => match key {
                KeyCode::Char('q') => {
                    self.stop_worker();
                    FeatureSignal::ExitApp
                }
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
                KeyCode::Char('p' | ' ') => {
                    self.refresh_schedule.toggle_paused(Instant::now());
                    self.status = if self.refresh_schedule.paused {
                        "Automatic refresh paused. An active collection may finish; r still refreshes.".to_string()
                    } else {
                        "Automatic refresh resumed.".to_string()
                    };
                    FeatureSignal::None
                }
                KeyCode::Esc | KeyCode::Backspace => {
                    self.stop_worker();
                    FeatureSignal::BackToLauncher
                }
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
                "{} | {} | age {}s | {}{}{}",
                snapshot.device.hostname,
                snapshot.device.management_address,
                snapshot.collected_at.elapsed().as_secs(),
                self.refresh_schedule.label(Instant::now()),
                if self.snapshot_is_stale_at(Instant::now()) {
                    " | STALE"
                } else {
                    ""
                },
                if self
                    .config
                    .as_ref()
                    .is_some_and(|config| config.host_trust == HostTrust::InsecureLab)
                {
                    " | INSECURE lab connection"
                } else {
                    ""
                }
            ),
            (_, Some(config)) => format!(
                "{} @ {}:{}",
                vendor_label(&config.vendor),
                config.address,
                config.port
            ),
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
                "Keys: ↑/↓ move, Tab next, ←/→ choose, type edit, Enter connect, Esc back"
            }
            Screen::Dashboard => "Keys: ↑/↓ move, p/Space pause, r refresh, Esc back, q quit",
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
            KeyCode::Esc => {
                self.stop_worker();
                FeatureSignal::BackToLauncher
            }
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
                match self.connection_form.selected() {
                    ConnectionField::Vendor => self.connection_form.cycle_vendor_prev(),
                    ConnectionField::HostTrust => self.connection_form.host_trust.toggle(),
                    _ => {}
                }
                FeatureSignal::None
            }
            KeyCode::Right => {
                match self.connection_form.selected() {
                    ConnectionField::Vendor => self.connection_form.cycle_vendor_next(),
                    ConnectionField::HostTrust => self.connection_form.host_trust.toggle(),
                    _ => {}
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

        if self.refresh_schedule.in_flight {
            self.status = "Refresh already in progress.".to_string();
            return;
        }

        if self.worker.is_none() {
            match HealthWorker::spawn(
                HealthConnectionConfig::from(&config),
                config.host_trust.server_check(),
            ) {
                Ok(worker) => self.worker = Some(worker),
                Err(error) => {
                    self.apply_refresh_result(RefreshResult::failed(error), Instant::now());
                    return;
                }
            }
        }
        if self
            .worker
            .as_ref()
            .expect("worker initialized")
            .refresh()
            .is_err()
        {
            self.worker_failed(Instant::now());
            return;
        }
        self.refresh_schedule.started();
        self.health_state = LoadState::Loading;
        self.status = "Collecting device health over the live SSH session...".to_string();
    }

    fn poll_refresh(&mut self, now: Instant) {
        let Some(worker) = self.worker.as_ref() else {
            return;
        };
        let result = match worker.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                self.worker_failed(now);
                return;
            }
        };
        self.apply_refresh_result(result, now);
    }

    fn apply_refresh_result(&mut self, result: RefreshResult, now: Instant) {
        self.refresh_schedule.completed(now);
        self.status = result.status;
        if let Some(snapshot) = result.snapshot {
            self.last_collection_failed = false;
            self.snapshot = Some(snapshot);
            self.health_state = LoadState::Ready;
            self.connection_state = LoadState::Ready;
            self.screen = Screen::Dashboard;
        } else {
            self.last_collection_failed = true;
            self.health_state = LoadState::Failed;
            if matches!(self.screen, Screen::ConnectionSetup) {
                self.connection_state = LoadState::Failed;
            }
        }
        if let Some(error) = result.error {
            self.status = error;
        }
    }

    fn start_connection_attempt(&mut self) {
        if self.refresh_schedule.in_flight {
            self.status =
                "Connecting and collecting the first snapshot is already in progress.".to_string();
            return;
        }

        let config = match self.connection_form.to_config() {
            Ok(config) => config,
            Err(err) => {
                self.connection_state = LoadState::Failed;
                self.status = err;
                return;
            }
        };

        self.stop_worker();
        self.snapshot = None;
        self.last_collection_failed = false;
        self.refresh_schedule = RefreshSchedule::new(config.refresh_interval);
        self.config = Some(config);
        self.connection_state = LoadState::Loading;
        self.start_refresh();
    }

    fn worker_failed(&mut self, now: Instant) {
        self.stop_worker();
        self.refresh_schedule.completed(now);
        self.health_state = LoadState::Failed;
        self.last_collection_failed = true;
        if matches!(self.screen, Screen::ConnectionSetup) {
            self.connection_state = LoadState::Failed;
            self.status =
                "Device health worker stopped unexpectedly. Select Connect to retry.".to_string();
        } else {
            self.status = "Device health worker stopped unexpectedly. Press r to retry or wait for auto-refresh.".to_string();
        }
    }

    fn stop_worker(&mut self) {
        self.worker = None;
        self.refresh_schedule.in_flight = false;
        self.refresh_schedule.next_due = None;
    }

    fn snapshot_is_stale_at(&self, now: Instant) -> bool {
        self.snapshot.as_ref().is_some_and(|snapshot| {
            self.last_collection_failed
                || now.saturating_duration_since(snapshot.collected_at)
                    > self.refresh_schedule.interval.saturating_mul(2)
        })
    }

    fn snapshot_freshness(&self, now: Instant) -> SnapshotFreshness {
        if self.snapshot_is_stale_at(now) {
            SnapshotFreshness {
                label: "STALE",
                status: SectionStatus::Unknown,
            }
        } else if self.refresh_schedule.paused {
            SnapshotFreshness {
                label: "Paused",
                status: SectionStatus::Warning,
            }
        } else {
            SnapshotFreshness {
                label: "Current",
                status: SectionStatus::Ok,
            }
        }
    }

    fn render_connection_setup(&self, f: &mut Frame, area: Rect) {
        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(44), Constraint::Min(0)])
            .split(area);

        let connection_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(9),
                Constraint::Length(1),
                Constraint::Length(5),
                Constraint::Min(0),
            ])
            .split(layout[0]);

        let fields: Vec<ListItem> = ConnectionField::all()
            .iter()
            .enumerate()
            .filter(|(_, field)| **field != ConnectionField::Connect)
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

        let form = List::new(fields).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Connection Parameters"),
        );
        f.render_widget(form, connection_layout[0]);

        let connect_selected = self.connection_form.selected() == ConnectionField::Connect;
        let connect_style = connect_button_style(connect_selected);
        let connect_block = Block::default()
            .borders(Borders::ALL)
            // .title("Action")
            .style(connect_style);
        let connect_label = if connect_selected {
            "[ Connect ]"
        } else {
            "  Connect  "
        };
        let connect_text = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(connect_label, connect_style)),
            // Line::from(Span::styled(
            // "Validate connection and continue",
            // connect_style,
            // )),
        ])
        .block(connect_block)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });
        f.render_widget(connect_text, connection_layout[2]);

        let details = Paragraph::new(
            "Connect to start periodic health snapshots over one reusable SSH session. The interval is measured after each collection completes; collections never overlap.\n\nHost trust defaults to verifying ~/.ssh/known_hosts. Establish trust with your normal SSH client first. Select INSECURE only for an isolated synthetic lab.\n\nKeys:\n- Up/Down or Tab: move field\n- Left/Right: choose vendor or host trust\n- Type and Backspace: edit fields\n- Enter on Connect: start\n- Esc: cancel and return\n\nOn the dashboard: p or Space pauses automatic refresh; r refreshes immediately, including while paused. A failed refresh retains the last successful snapshot and marks it stale.",
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

        let details_title = if self.snapshot_is_stale_at(Instant::now()) {
            "Details — last successful snapshot (STALE)"
        } else {
            "Details"
        };
        let details_block = Block::default().borders(Borders::ALL).title(details_title);
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
                HealthSection::System => render_system_dashboard(
                    f,
                    inner,
                    snapshot,
                    self.snapshot_freshness(Instant::now()),
                ),
                HealthSection::Interfaces => render_interfaces_dashboard(f, inner, snapshot),
                HealthSection::Neighbors => render_neighbors_dashboard(f, inner, snapshot),
                HealthSection::Findings => render_findings_dashboard(
                    f,
                    inner,
                    snapshot,
                    self.snapshot_freshness(Instant::now()),
                ),
            },
        }
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

fn render_system_dashboard(
    f: &mut Frame,
    area: Rect,
    snapshot: &DeviceHealthSnapshot,
    freshness: SnapshotFreshness,
) {
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
        &format!("{} · {}s", freshness.label, snapshot.refresh_age_secs()),
        freshness.status,
        Some("Last successful snapshot"),
    );

    let gauges = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(layout[1]);

    render_metric_gauge(
        f,
        gauges[0],
        "CPU Usage (1m)",
        gauge_view(snapshot.system.cpu_percent, 80.0, 90.0),
    );
    render_metric_gauge(
        f,
        gauges[1],
        "CPU Usage (5m)",
        gauge_view(snapshot.system.cpu_five_minute_percent, 80.0, 90.0),
    );
    render_metric_gauge(
        f,
        gauges[2],
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
                    [
                        "System CPU",
                        "System CPU (5m)",
                        "System Memory",
                        "Version",
                        "Device Identity",
                    ]
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
        &[
            "System CPU",
            "System CPU (5m)",
            "System Memory",
            "Version",
            "Device Identity",
        ],
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

    render_distribution_panel(
        f,
        layout[1],
        snapshot.interface_distribution(),
        &snapshot.interfaces,
    );
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
    render_metadata_table(
        f,
        layout[2],
        "Checks",
        snapshot,
        &["CDP Neighbors", "LLDP Neighbors"],
    );
}

fn render_findings_dashboard(
    f: &mut Frame,
    area: Rect,
    snapshot: &DeviceHealthSnapshot,
    freshness: SnapshotFreshness,
) {
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
        &format!("{} · {}s", freshness.label, snapshot.refresh_age_secs()),
        freshness.status,
        Some("Last successful snapshot"),
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
            Span::styled(
                " DOWN ",
                Style::default().fg(Color::Black).bg(Color::Yellow),
            ),
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
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Interface Issues"),
            )
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
            Row::new(vec!["Interface", "State"]).style(
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(Color::Cyan),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Interface Issues"),
        )
        .column_spacing(1);

    f.render_widget(table, area);
}

fn render_neighbors_table(f: &mut Frame, area: Rect, snapshot: &DeviceHealthSnapshot) {
    if snapshot.neighbors.entries.is_empty() {
        let empty = Paragraph::new(vec![
            status_summary_line(
                "Neighbors",
                snapshot.neighbors.status,
                "No usable CDP/LLDP neighbors",
            ),
            Line::from(" "),
            Line::from(Span::styled(
                "Discovery checks ran, but the snapshot did not produce any neighbor entries.",
                Style::default().fg(Color::Gray),
            )),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Neighbor Board"),
        )
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
        Row::new(vec![
            "Proto",
            "Neighbor",
            "Local",
            "Remote",
            "Mgmt IP",
            "Reachability",
        ])
        .style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Cyan),
        ),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Neighbor Board"),
    )
    .column_spacing(1);

    f.render_widget(table, area);
}

fn render_findings_list(f: &mut Frame, area: Rect, snapshot: &DeviceHealthSnapshot) {
    if snapshot.findings.is_empty() {
        let panel = Paragraph::new(vec![
            status_summary_line("Findings", SectionStatus::Ok, "No active findings"),
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
            ListItem::new(vec![status_summary_line(
                "",
                finding.status,
                &finding.message,
            )])
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
        Row::new(vec!["Check", "Status", "Details"]).style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Cyan),
        ),
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
        Row::new(vec!["Check", "Status", "Details"]).style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Cyan),
        ),
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

fn vendor_label(vendor: &DeviceVendor) -> String {
    match vendor {
        DeviceVendor::Cisco(variant) => variant.to_string(),
        DeviceVendor::Juniper(variant) => variant.to_string(),
        DeviceVendor::Custom(_) => "Custom Device Profile".to_string(),
        _ => "Device Vendor".to_string(),
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

fn connect_button_style(selected: bool) -> Style {
    if selected {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    }
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
                cpu_five_minute_percent: Some(62.0),
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
                name: "System CPU",
                status: SectionStatus::Warning,
                details: "CPU one-minute usage 82.0%".to_string(),
            }],
            collected_at: Instant::now() - Duration::from_secs(5),
        }
    }

    #[test]
    fn connection_form_validates_required_fields() {
        let form = ConnectionForm::new();
        let err = form.to_config().unwrap_err();
        assert!(err.contains("Device address is required"));
    }

    #[test]
    fn connection_form_builds_config() {
        let mut form = ConnectionForm::new();
        form.address = "192.0.2.10".to_string();
        form.username = "admin".to_string();
        form.password = "pass".to_string();
        form.vendor_index = form
            .vendor_options
            .iter()
            .position(|vendor| *vendor == DeviceVendor::Cisco(CiscoVariant::IosXe))
            .unwrap();

        let built = form.to_config().unwrap();
        assert_eq!(built.address, "192.0.2.10");
        assert_eq!(built.port, 22);
        assert_eq!(built.vendor, DeviceVendor::Cisco(CiscoVariant::IosXe));
    }

    #[test]
    fn vendor_picker_cycles_through_supported_health_profiles() {
        let supported = supported_health_vendors();
        let mut form = ConnectionForm::new();
        assert_eq!(
            form.current_vendor(),
            DeviceVendor::Cisco(CiscoVariant::Ios)
        );
        form.vendor_index = 0;

        let selected: Vec<DeviceVendor> = (0..supported.len())
            .map(|_| {
                let vendor = form.current_vendor();
                form.cycle_vendor_next();
                vendor
            })
            .collect();

        assert_eq!(selected, supported);
        assert_eq!(form.current_vendor(), supported[0]);
        form.cycle_vendor_prev();
        assert_eq!(form.current_vendor(), *supported.last().unwrap());
    }

    #[test]
    fn feature_starts_on_connection_setup() {
        let feature = DeviceHealthFeature::new();
        assert!(matches!(feature.screen, Screen::ConnectionSetup));
        assert!(feature.config.is_none());
    }

    fn valid_config() -> CliConfig {
        let mut form = ConnectionForm::new();
        form.address = "192.0.2.10".to_string();
        form.username = "admin".to_string();
        form.password = "secret-for-test".to_string();
        form.to_config().unwrap()
    }

    fn successful_refresh() -> RefreshResult {
        RefreshResult {
            snapshot: Some(sample_snapshot()),
            status: "Snapshot collected.".to_string(),
            error: None,
        }
    }

    #[test]
    fn host_trust_is_verified_by_default_and_password_debug_is_redacted() {
        let config = valid_config();
        assert_eq!(config.host_trust, HostTrust::KnownHosts);
        assert_eq!(config.refresh_interval, Duration::from_secs(10));
        assert!(!format!("{config:?}").contains("secret-for-test"));

        let mut feature = DeviceHealthFeature::new();
        feature.connection_form.selected_field = ConnectionField::all()
            .iter()
            .position(|field| *field == ConnectionField::HostTrust)
            .unwrap();
        feature.handle_key(KeyCode::Right);
        assert_eq!(feature.connection_form.host_trust, HostTrust::InsecureLab);
        feature.handle_key(KeyCode::Left);
        assert_eq!(feature.connection_form.host_trust, HostTrust::KnownHosts);
    }

    #[test]
    fn connection_form_bounds_refresh_interval_and_rejects_port_zero() {
        let mut form = ConnectionForm::new();
        form.address = "192.0.2.10".to_string();
        form.username = "admin".to_string();
        form.password = "pass".to_string();
        for seconds in ["", "0", "4", "3601", "invalid"] {
            form.refresh_seconds = seconds.to_string();
            assert!(form.to_config().unwrap_err().contains("Refresh interval"));
        }
        for seconds in ["5", "10", "3600"] {
            form.refresh_seconds = seconds.to_string();
            assert!(form.to_config().is_ok());
        }
        form.port = "0".to_string();
        assert!(
            form.to_config()
                .unwrap_err()
                .contains("Port must be between")
        );
    }

    #[test]
    fn automatic_refresh_waits_for_completion_then_interval_and_never_overlaps() {
        let mut feature = DeviceHealthFeature::new();
        let (worker, results, mut commands, _stop) = HealthWorker::test_channel();
        feature.worker = Some(worker);
        feature.config = Some(valid_config());
        feature.screen = Screen::Dashboard;
        feature.refresh_schedule.started();
        feature.health_state = LoadState::Loading;
        let completed_at = Instant::now() + Duration::from_secs(100);

        feature.tick_at(completed_at);
        assert!(commands.try_recv().is_err());
        results.send(successful_refresh()).unwrap();
        feature.tick_at(completed_at);
        assert_eq!(feature.health_state, LoadState::Ready);
        feature.tick_at(completed_at + Duration::from_secs(9));
        assert!(commands.try_recv().is_err());
        feature.tick_at(completed_at + Duration::from_secs(10));
        assert!(commands.try_recv().is_ok());
        assert!(feature.refresh_schedule.in_flight);
        feature.tick_at(completed_at + Duration::from_secs(100));
        feature.handle_key(KeyCode::Char('r'));
        assert!(commands.try_recv().is_err());
    }

    #[test]
    fn pause_blocks_automatic_refresh_but_allows_manual_refresh_and_resume() {
        let mut feature = DeviceHealthFeature::new();
        let (worker, results, mut commands, _stop) = HealthWorker::test_channel();
        feature.worker = Some(worker);
        feature.config = Some(valid_config());
        feature.apply_refresh_result(successful_refresh(), Instant::now());

        feature.handle_key(KeyCode::Char('p'));
        assert!(feature.refresh_schedule.paused);
        feature.tick_at(Instant::now() + Duration::from_secs(100));
        assert!(commands.try_recv().is_err());
        feature.handle_key(KeyCode::Char('r'));
        assert!(commands.try_recv().is_ok());
        results.send(successful_refresh()).unwrap();
        feature.tick();
        assert!(feature.refresh_schedule.paused);
        feature.tick_at(Instant::now() + Duration::from_secs(100));
        assert!(commands.try_recv().is_err());

        feature.handle_key(KeyCode::Char(' '));
        feature.tick();
        assert!(!feature.refresh_schedule.paused);
        assert!(commands.try_recv().is_ok());
    }

    #[test]
    fn failed_refresh_keeps_last_snapshot_stale_until_fresh_success() {
        let mut feature = DeviceHealthFeature::new();
        feature.apply_refresh_result(successful_refresh(), Instant::now());
        feature.apply_refresh_result(
            RefreshResult::failed("Connection lost".to_string()),
            Instant::now(),
        );
        assert_eq!(feature.health_state, LoadState::Failed);
        assert_eq!(
            feature.snapshot.as_ref().unwrap().device.hostname,
            "router-1"
        );
        assert!(feature.snapshot_is_stale_at(Instant::now()));
        assert!(feature.header_subtitle().contains("STALE"));

        let (worker, _results, _commands, _stop) = HealthWorker::test_channel();
        feature.worker = Some(worker);
        feature.config = Some(valid_config());
        feature.handle_key(KeyCode::Char('r'));
        assert_eq!(feature.health_state, LoadState::Loading);
        assert!(feature.snapshot_is_stale_at(Instant::now()));

        let mut fresh = successful_refresh();
        fresh.snapshot.as_mut().unwrap().collected_at = Instant::now();
        feature.apply_refresh_result(fresh, Instant::now());
        assert!(!feature.snapshot_is_stale_at(Instant::now()));
        assert!(feature.snapshot_is_stale_at(Instant::now() + Duration::from_secs(21)));
    }

    #[test]
    fn returning_to_launcher_cancels_an_active_worker_and_clears_the_schedule() {
        for screen in [Screen::ConnectionSetup, Screen::Dashboard] {
            let mut feature = DeviceHealthFeature::new();
            let (worker, _results, _commands, mut stop) = HealthWorker::test_channel();
            feature.worker = Some(worker);
            feature.screen = screen;
            feature.refresh_schedule.started();
            assert_eq!(
                feature.handle_key(KeyCode::Esc),
                FeatureSignal::BackToLauncher
            );
            assert!(feature.worker.is_none());
            assert!(!feature.refresh_schedule.in_flight);
            assert!(feature.refresh_schedule.next_due.is_none());
            assert!(stop.try_recv().is_ok());
        }
    }

    #[test]
    fn connection_fields_accept_q_as_text_input() {
        let mut feature = DeviceHealthFeature::new();

        for field in [
            ConnectionField::Address,
            ConnectionField::Username,
            ConnectionField::Password,
        ] {
            feature.connection_form.selected_field = ConnectionField::all()
                .iter()
                .position(|candidate| *candidate == field)
                .unwrap();
            assert_eq!(feature.handle_key(KeyCode::Char('q')), FeatureSignal::None);
        }

        assert_eq!(feature.connection_form.address, "q");
        assert_eq!(feature.connection_form.username, "q");
        assert_eq!(feature.connection_form.password, "q");
    }

    #[test]
    fn dashboard_quits_on_q() {
        let mut feature = DeviceHealthFeature::new();
        feature.screen = Screen::Dashboard;

        assert_eq!(
            feature.handle_key(KeyCode::Char('q')),
            FeatureSignal::ExitApp
        );
    }

    #[test]
    fn disconnected_connection_worker_fails_and_clears_pending_attempt() {
        let mut feature = DeviceHealthFeature::new();
        let (worker, tx, _commands, _stop) = HealthWorker::test_channel();
        feature.worker = Some(worker);
        feature.refresh_schedule.started();
        feature.connection_state = LoadState::Loading;
        drop(tx);

        feature.tick();

        assert_eq!(feature.connection_state, LoadState::Failed);
        assert!(feature.worker.is_none());
        assert!(matches!(feature.screen, Screen::ConnectionSetup));
        assert!(feature.status.contains("Select Connect to retry"));
    }

    #[test]
    fn disconnected_refresh_worker_fails_and_keeps_previous_snapshot() {
        let mut feature = DeviceHealthFeature::new();
        let (worker, tx, _commands, _stop) = HealthWorker::test_channel();
        feature.worker = Some(worker);
        feature.screen = Screen::Dashboard;
        feature.refresh_schedule.started();
        feature.health_state = LoadState::Loading;
        feature.snapshot = Some(sample_snapshot());
        drop(tx);

        feature.tick();

        assert_eq!(feature.health_state, LoadState::Failed);
        assert!(feature.worker.is_none());
        assert_eq!(feature.snapshot.unwrap().device.hostname, "router-1");
        assert!(feature.status.contains("Press r to retry"));
    }

    #[test]
    fn pending_workers_remain_loading_until_results_arrive() {
        let mut feature = DeviceHealthFeature::new();
        let (worker, _tx, _commands, _stop) = HealthWorker::test_channel();
        feature.worker = Some(worker);
        feature.refresh_schedule.started();
        feature.connection_state = LoadState::Loading;
        feature.health_state = LoadState::Loading;

        feature.tick();

        assert_eq!(feature.connection_state, LoadState::Loading);
        assert_eq!(feature.health_state, LoadState::Loading);
        assert!(feature.worker.is_some());
        assert!(feature.refresh_schedule.in_flight);
    }

    #[test]
    fn navigation_reaches_connect_selection() {
        let mut form = ConnectionForm::new();
        for _ in 0..ConnectionField::all().len() - 1 {
            form.move_down();
        }
        assert_eq!(form.selected(), ConnectionField::Connect);
    }

    #[test]
    fn connect_selection_ignores_text_input() {
        let mut form = ConnectionForm::new();
        form.address = "192.0.2.10".to_string();
        form.username = "admin".to_string();
        form.password = "pass".to_string();
        form.selected_field = ConnectionField::all().len() - 1;

        form.push_char('x');
        form.backspace();

        assert_eq!(form.address, "192.0.2.10");
        assert_eq!(form.username, "admin");
        assert_eq!(form.password, "pass");
        assert_eq!(form.selected(), ConnectionField::Connect);
    }

    #[test]
    fn enter_on_connect_rejects_invalid_config_without_starting_worker() {
        let mut feature = DeviceHealthFeature::new();
        feature.connection_form.selected_field = ConnectionField::all().len() - 1;

        let signal = feature.handle_key(KeyCode::Enter);

        assert_eq!(signal, FeatureSignal::None);
        assert!(feature.worker.is_none());
        assert_eq!(feature.connection_state, LoadState::Failed);
        assert!(matches!(feature.screen, Screen::ConnectionSetup));
        assert!(feature.status.contains("Device address is required"));
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
