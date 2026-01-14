use ratatui::{
    Frame, Terminal,
    backend::{Backend, CrosstermBackend},
    crossterm::{
        event::{self, Event, KeyCode},
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    },
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use std::{error::Error, io};

struct App {
    selected: usize,
    options: Vec<&'static str>,
}

impl App {
    fn new() -> Self {
        App {
            selected: 0,
            options: vec![
                "Device Health",
                "Network Neighbours",
                "Network Topology",
                "Router/Switch Info",
                "Exit",
            ],
        }
    }

    fn next(&mut self) {
        self.selected = (self.selected + 1) % self.options.len();
    }

    fn prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        } else {
            self.selected = self.options.len() - 1;
        }
    }
}

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
        println!("{:?}", err);
    }

    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: App) -> io::Result<()>
where
    std::io::Error: From<<B as Backend>::Error>,
{
    loop {
        terminal.draw(|f| ui::<B>(f, &app))?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('q') => return Ok(()),
                KeyCode::Up => app.prev(),
                KeyCode::Down => app.next(),
                KeyCode::Enter => {
                    if app.selected == app.options.len() - 1 {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
    }
}

fn ui<B: Backend>(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(f.size());

    let title = Paragraph::new("Network Troubleshooting Tool")
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(title, chunks[0]);

    let items: Vec<ListItem> = app
        .options
        .iter()
        .enumerate()
        .map(|(idx, option)| {
            let style = if idx == app.selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(Line::from(*option)).style(style)
        })
        .collect();

    let list = List::new(items).block(Block::default().borders(Borders::ALL).title("Menu"));
    f.render_widget(list, chunks[1]);
}
