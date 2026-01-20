mod app;
mod event;
mod ui;

use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{DisableBracketedPaste, EnableBracketedPaste, poll, read},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend, layout::Rect};

use app::App;

/// Interactive GPG/OpenPGP packet inspector
#[derive(Parser)]
#[command(version, about, after_help = "\
Examples:
  gpg-inspector                              Start with empty input
  gpg-inspector -f key.asc                   Load from file
  gpg --export --armor KEY | gpg-inspector   Read from stdin
  cat message.asc | gpg-inspector            Pipe armored data")]
struct Cli {
    /// Load GPG data from a file
    #[arg(short, long, value_name = "FILE")]
    file: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load initial input from file or stdin
    let initial_input = load_initial_input(&cli)?;

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    if let Some(input) = initial_input {
        app.input = input;
        app.cursor_pos = app.input.len();
        app.parse_input();
    }

    let result = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableBracketedPaste
    )?;
    terminal.show_cursor()?;

    result
}

fn load_initial_input(cli: &Cli) -> Result<Option<String>> {
    // File takes precedence
    if let Some(path) = &cli.file {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;
        return Ok(Some(content));
    }

    // Check if stdin has data (not a terminal)
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        let mut input = String::new();
        stdin.lock().read_to_string(&mut input)
            .context("Failed to read from stdin")?;
        if !input.is_empty() {
            return Ok(Some(input));
        }
    }

    Ok(None)
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        if poll(Duration::from_millis(100))? {
            let evt = read()?;
            let term_size = terminal.size()?;
            let size = Rect::new(0, 0, term_size.width, term_size.height);
            event::handle_event(app, evt, size);
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}
