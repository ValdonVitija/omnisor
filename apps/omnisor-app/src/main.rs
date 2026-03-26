use omnisor_feature_device_health::{DeviceHealthFeature, FeatureSignal};
use ratatui::{
    Frame, Terminal,
    backend::{Backend, CrosstermBackend},
    crossterm::{
        event::{self, Event, KeyCode},
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    },
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::{error::Error, io, time::Duration};

const LOGO: &[&str] = &[
    "   ___                 _                    ",
    "  / _ \\ _ __ ___  _ __ (_)___  ___  _ __    ",
    " | | | | '_ ` _ \\| '_ \\| / __|/ _ \\| '__|   ",
    " | |_| | | | | | | | | | \\__ \\ (_) | |      ",
    "  \\___/|_| |_| |_|_| |_|_|___/\\___/|_|      ",
];

const FEATURES: &[FeatureRegistration] = &[
    FeatureRegistration {
        id: FeatureId::DeviceHealth,
        title: "Device Health",
        description: "Live Cisco health snapshot with setup, checks, and drill-down sections.",
        badge: FeatureBadge::Live,
        enabled: true,
    },
    FeatureRegistration {
        id: FeatureId::ConfigAudit,
        title: "Configuration Audit",
        description: "Compare configs against expected baselines and policy rules.",
        badge: FeatureBadge::ComingSoon,
        enabled: false,
    },
    FeatureRegistration {
        id: FeatureId::ProtocolInspector,
        title: "Protocol Inspector",
        description: "Inspect protocol state from parsed device outputs and topology context.",
        badge: FeatureBadge::ComingSoon,
        enabled: false,
    },
    FeatureRegistration {
        id: FeatureId::InterfaceExplorer,
        title: "Interface Explorer",
        description: "Focus on interfaces, counters, and operational anomalies across views.",
        badge: FeatureBadge::Experimental,
        enabled: false,
    },
];

fn main() -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = App::new();
    let res = run_app(&mut terminal, app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("{err}");
    }

    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: App) -> io::Result<()>
where
    std::io::Error: From<<B as Backend>::Error>,
{
    loop {
        app.tick();
        terminal.draw(|f| ui(f, &app))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if app.handle_key(key.code) {
                    return Ok(());
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeatureId {
    DeviceHealth,
    ConfigAudit,
    ProtocolInspector,
    InterfaceExplorer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeatureBadge {
    Live,
    ComingSoon,
    Experimental,
}

impl FeatureBadge {
    fn label(self) -> &'static str {
        match self {
            Self::Live => "LIVE",
            Self::ComingSoon => "COMING SOON",
            Self::Experimental => "EXPERIMENTAL",
        }
    }

    fn color(self) -> Color {
        match self {
            Self::Live => Color::Green,
            Self::ComingSoon => Color::Blue,
            Self::Experimental => Color::Yellow,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FeatureRegistration {
    id: FeatureId,
    title: &'static str,
    description: &'static str,
    badge: FeatureBadge,
    enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Launcher,
    Feature,
}

enum ActiveFeature {
    DeviceHealth(DeviceHealthFeature),
}

impl ActiveFeature {
    fn title(&self) -> &'static str {
        match self {
            Self::DeviceHealth(feature) => feature.header_title(),
        }
    }

    fn subtitle(&self) -> String {
        match self {
            Self::DeviceHealth(feature) => feature.header_subtitle(),
        }
    }

    fn footer_text(&self) -> String {
        match self {
            Self::DeviceHealth(feature) => feature.footer_text(),
        }
    }

    fn tick(&mut self) {
        match self {
            Self::DeviceHealth(feature) => feature.tick(),
        }
    }

    fn handle_key(&mut self, key: KeyCode) -> FeatureSignal {
        match self {
            Self::DeviceHealth(feature) => feature.handle_key(key),
        }
    }

    fn render(&self, f: &mut Frame, area: Rect) {
        match self {
            Self::DeviceHealth(feature) => feature.render(f, area),
        }
    }
}

struct App {
    screen: Screen,
    launcher_selected: usize,
    active_feature: Option<ActiveFeature>,
    status: String,
}

impl App {
    fn new() -> Self {
        Self {
            screen: Screen::Launcher,
            launcher_selected: 0,
            active_feature: None,
            status: "Select a functionality to start. Disabled entries remain visible for future expansion.".to_string(),
        }
    }

    fn tick(&mut self) {
        if let Some(feature) = self.active_feature.as_mut() {
            feature.tick();
        }
    }

    fn handle_key(&mut self, key: KeyCode) -> bool {
        match self.screen {
            Screen::Launcher => self.handle_launcher_key(key),
            Screen::Feature => self.handle_feature_key(key),
        }
    }

    fn handle_launcher_key(&mut self, key: KeyCode) -> bool {
        match key {
            KeyCode::Char('q') => true,
            KeyCode::Up => {
                if self.launcher_selected == 0 {
                    self.launcher_selected = FEATURES.len() - 1;
                } else {
                    self.launcher_selected -= 1;
                }
                false
            }
            KeyCode::Down => {
                self.launcher_selected = (self.launcher_selected + 1) % FEATURES.len();
                false
            }
            KeyCode::Enter => {
                self.activate_selected_feature();
                false
            }
            _ => false,
        }
    }

    fn handle_feature_key(&mut self, key: KeyCode) -> bool {
        if key == KeyCode::Char('q') {
            return true;
        }

        let Some(feature) = self.active_feature.as_mut() else {
            self.screen = Screen::Launcher;
            return false;
        };

        match feature.handle_key(key) {
            FeatureSignal::None => false,
            FeatureSignal::ExitApp => true,
            FeatureSignal::BackToLauncher => {
                self.active_feature = None;
                self.screen = Screen::Launcher;
                self.status = "Returned to the Omnisor launcher.".to_string();
                false
            }
        }
    }

    fn activate_selected_feature(&mut self) {
        let feature = FEATURES[self.launcher_selected];
        if !feature.enabled {
            self.status = format!(
                "{} is not available yet. The launcher keeps disabled features visible for future growth.",
                feature.title
            );
            return;
        }

        self.active_feature = Some(match feature.id {
            FeatureId::DeviceHealth => ActiveFeature::DeviceHealth(DeviceHealthFeature::new()),
            FeatureId::ConfigAudit
            | FeatureId::ProtocolInspector
            | FeatureId::InterfaceExplorer => unreachable!("disabled feature activated"),
        });
        self.screen = Screen::Feature;
        self.status = format!("Opened {}.", feature.title);
    }
}

fn ui(f: &mut Frame, app: &App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(if matches!(app.screen, Screen::Feature) { 3 } else { 0 }),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.area());

    if matches!(app.screen, Screen::Feature) {
        render_feature_header(f, root[0], app);
    }

    match app.screen {
        Screen::Launcher => render_launcher(f, root[1], app),
        Screen::Feature => render_feature(f, root[1], app),
    }

    render_footer(f, root[2], app);
}

fn render_feature_header(f: &mut Frame, area: Rect, app: &App) {
    let Some(feature) = app.active_feature.as_ref() else {
        return;
    };

    let header = Paragraph::new(format!("{}\n{}", feature.title(), feature.subtitle()))
        .block(Block::default().borders(Borders::ALL).title("Session"))
        .wrap(Wrap { trim: true });
    f.render_widget(header, area);
}

fn render_launcher(f: &mut Frame, area: Rect, app: &App) {
    let launcher_width = area.width.saturating_sub(4).min(94).max(40);
    let launcher_height = area.height.saturating_sub(2).min(28).max(14);
    let centered = centered_rect(area, launcher_width, launcher_height);
    let card = Block::default()
        .borders(Borders::ALL)
        .title("Omnisor Launcher")
        .border_style(Style::default().fg(Color::DarkGray));
    let inner = card.inner(centered);
    f.render_widget(card, centered);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(LOGO.len() as u16 + 1),
            Constraint::Length(2),
            Constraint::Min(0),
        ])
        .split(inner);

    let logo_lines: Vec<Line> = LOGO
        .iter()
        .map(|line| {
            Line::from(Span::styled(
                (*line).to_string(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ))
        })
        .collect();
    let logo = Paragraph::new(logo_lines).alignment(Alignment::Center);
    f.render_widget(logo, layout[0]);

    let subtitle = Paragraph::new(vec![
        Line::from(Span::styled(
            "Choose a workflow",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "Feature crates plug into this launcher. Disabled entries stay visible but inactive.",
            Style::default().fg(Color::Gray),
        )),
    ])
    .alignment(Alignment::Center);
    f.render_widget(subtitle, layout[1]);

    let list_block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));
    let list_inner = list_block.inner(layout[2]);
    f.render_widget(list_block, layout[2]);

    let card_height: u16 = 4;
    let card_gap: u16 = 1;
    let visible_count = visible_feature_count(list_inner.height, card_height, card_gap);
    let (start, end) = feature_window(app.launcher_selected, FEATURES.len(), visible_count);
    let visible_features = &FEATURES[start..end];
    let content_height = visible_features.len() as u16 * card_height
        + visible_features
            .len()
            .saturating_sub(1) as u16
            * card_gap;
    let top_padding = list_inner.height.saturating_sub(content_height) / 2;
    let mut y = list_inner.y.saturating_add(top_padding);

    for (offset, feature) in visible_features.iter().enumerate() {
        let idx = start + offset;
        let rect = Rect {
            x: list_inner.x,
            y,
            width: list_inner.width,
            height: card_height.min(list_inner.bottom().saturating_sub(y)),
        };
        if rect.height >= 3 {
            render_feature_card(f, rect, feature, idx == app.launcher_selected);
        }
        y = y.saturating_add(card_height + card_gap);
    }

    if end < FEATURES.len() {
        let hint = Paragraph::new("More workflows below")
            .alignment(Alignment::Right)
            .style(Style::default().fg(Color::DarkGray));
        let hint_area = Rect {
            x: list_inner.x,
            y: list_inner.bottom().saturating_sub(1),
            width: list_inner.width,
            height: 1,
        };
        f.render_widget(hint, hint_area);
    }

    if start > 0 {
        let hint = Paragraph::new("More workflows above")
            .alignment(Alignment::Left)
            .style(Style::default().fg(Color::DarkGray));
        let hint_area = Rect {
            x: list_inner.x,
            y: list_inner.y,
            width: list_inner.width,
            height: 1,
        };
        f.render_widget(hint, hint_area);
    }
}

fn render_feature(f: &mut Frame, area: Rect, app: &App) {
    if let Some(feature) = app.active_feature.as_ref() {
        feature.render(f, area);
    }
}

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let message = match app.screen {
        Screen::Launcher => format!(
            "{} | state: launcher | Keys: ↑/↓ move, Enter open, q quit",
            app.status
        ),
        Screen::Feature => app
            .active_feature
            .as_ref()
            .map(|feature| feature.footer_text())
            .unwrap_or_else(|| "No active feature.".to_string()),
    };

    let footer = Paragraph::new(message)
        .block(Block::default().borders(Borders::ALL).title("Status"))
        .style(Style::default().fg(Color::Gray))
        .wrap(Wrap { trim: true });
    f.render_widget(footer, area);
}

fn render_feature_card(
    f: &mut Frame,
    area: Rect,
    feature: &FeatureRegistration,
    selected: bool,
) {
    let border_color = if selected {
        Color::Cyan
    } else {
        Color::DarkGray
    };
    let background = if selected {
        Color::Rgb(41, 48, 61)
    } else {
        Color::Reset
    };
    let title_color = if selected {
        Color::White
    } else if feature.enabled {
        Color::Gray
    } else {
        Color::DarkGray
    };
    let desc_color = if feature.enabled {
        Color::Gray
    } else {
        Color::DarkGray
    };
    let badge_style = if selected {
        Style::default()
            .fg(feature.badge.color())
            .bg(background)
            .add_modifier(Modifier::BOLD)
    } else if feature.enabled {
        Style::default()
            .fg(feature.badge.color())
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD)
    };
    let marker = if selected { "› " } else { "  " };
    let title_line = feature_title_line(area.width, marker, feature.title, feature.badge.label());

    let content = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                format!("{}{}", marker, title_line.0),
                Style::default()
                    .fg(title_color)
                    .bg(background)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(title_line.1, badge_style),
        ]),
        Line::from(Span::styled(
            feature.description,
            Style::default().fg(desc_color).bg(background),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    )
    .wrap(Wrap { trim: true });
    f.render_widget(content, area);
}

fn feature_title_line(
    width: u16,
    marker: &str,
    title: &str,
    badge: &str,
) -> (String, String) {
    let inner_width = width.saturating_sub(2) as usize;
    let left = format!("{marker}{title}");
    let badge_text = format!("[{badge}]");
    let spacing = inner_width.saturating_sub(left.len() + badge_text.len()).max(1);
    (format!("{title}{}", " ".repeat(spacing)), badge_text)
}

fn visible_feature_count(height: u16, card_height: u16, card_gap: u16) -> usize {
    if height < card_height {
        return 1;
    }

    let slot = card_height + card_gap;
    let count = ((height + card_gap) / slot).max(1);
    count as usize
}

fn feature_window(selected: usize, total: usize, visible: usize) -> (usize, usize) {
    if total <= visible {
        return (0, total);
    }

    let half = visible / 2;
    let mut start = selected.saturating_sub(half);
    if start + visible > total {
        start = total - visible;
    }

    (start, start + visible)
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;

    Rect {
        x,
        y,
        width,
        height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_starts_on_launcher() {
        let app = App::new();
        assert_eq!(app.screen, Screen::Launcher);
        assert!(app.active_feature.is_none());
    }

    #[test]
    fn launcher_navigation_wraps() {
        let mut app = App::new();
        app.handle_key(KeyCode::Up);
        assert_eq!(app.launcher_selected, FEATURES.len() - 1);
        app.handle_key(KeyCode::Down);
        assert_eq!(app.launcher_selected, 0);
    }

    #[test]
    fn disabled_feature_cannot_be_activated() {
        let mut app = App::new();
        app.launcher_selected = 1;
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.screen, Screen::Launcher);
        assert!(app.active_feature.is_none());
    }

    #[test]
    fn enabled_feature_is_opened_from_registry() {
        let mut app = App::new();
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.screen, Screen::Feature);
        assert!(app.active_feature.is_some());
    }

    #[test]
    fn feature_can_return_to_launcher() {
        let mut app = App::new();
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.screen, Screen::Feature);
        app.handle_key(KeyCode::Esc);
        assert_eq!(app.screen, Screen::Launcher);
        assert!(app.active_feature.is_none());
    }
}
