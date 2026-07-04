use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use crossterm::{
    event::{
        DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture, poll,
        read,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend, layout::Rect};

use gpg_inspector::app::App;
use gpg_inspector::output;
use gpg_inspector::{event, ui};

/// Interactive GPG/OpenPGP packet inspector
#[derive(Parser)]
#[command(
    version,
    about,
    after_help = "\
Examples:
  gpg-inspector                              Start with empty input
  gpg-inspector -f key.asc                   Load from file
  gpg --export --armor KEY | gpg-inspector   Read from stdin
  cat message.asc | gpg-inspector            Pipe armored data"
)]
struct Cli {
    /// Load GPG data from a file
    #[arg(short, long, value_name = "FILE")]
    file: Option<PathBuf>,

    /// Output as JSON
    #[cfg(feature = "serde")]
    #[arg(long, conflicts_with = "txt")]
    json: bool,

    /// Output as formatted text with hex dump
    #[arg(long)]
    txt: bool,

    /// Color theme for the TUI
    #[arg(long, value_parser = ["auto", "dark", "light"], default_value = "auto")]
    theme: String,
}

/// Requires TTY for terminal setup/teardown
#[cfg(not(tarpaulin_include))]
fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load initial input from file or stdin
    let initial_input = load_initial_input(&cli)?;

    // Non-interactive output modes
    #[cfg(feature = "serde")]
    let wants_output = cli.json || cli.txt;
    #[cfg(not(feature = "serde"))]
    let wants_output = cli.txt;

    if wants_output {
        let input = initial_input.ok_or_else(|| anyhow!("No input provided"))?;
        let (bytes, blocks, cleartext): (Arc<[u8]>, _, _) =
            if gpg_inspector_lib::looks_binary(&input) {
                (input.into(), Vec::new(), None)
            } else {
                let text = String::from_utf8(input)
                    .map_err(|_| anyhow!("Input is neither binary PGP data nor valid UTF-8"))?;
                let multi = gpg_inspector_lib::decode_armor_multi(&text)?;
                (multi.bytes, multi.blocks, multi.cleartext)
            };
        let packets = gpg_inspector_lib::parse_bytes(Arc::clone(&bytes))?;

        #[cfg(feature = "serde")]
        if cli.json {
            println!(
                "{}",
                output::output_json(&packets, &bytes, &blocks, cleartext.as_deref())
            );
            return Ok(());
        }
        #[cfg(not(feature = "serde"))]
        let _ = (&blocks, &cleartext);

        let use_color = std::io::stdout().is_terminal();
        println!("{}", output::output_txt(&packets, &bytes, use_color));
        return Ok(());
    }

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableBracketedPaste,
        EnableMouseCapture
    )?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    app.theme = gpg_inspector::ui::colors::Theme::resolve(
        &cli.theme,
        std::env::var("COLORFGBG").ok().as_deref(),
    );
    if let Some(input) = initial_input {
        if gpg_inspector_lib::looks_binary(&input) {
            let origin = cli
                .file
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "stdin".to_string());
            app.load_binary(input, origin);
        } else {
            app.input = String::from_utf8(input)
                .map_err(|_| anyhow!("Input is neither binary PGP data nor valid UTF-8"))?;
            app.cursor_pos = app.input.len();
            app.parse_input();
        }
    }

    let result = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableBracketedPaste,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

/// Requires stdin/file I/O mocking
#[cfg(not(tarpaulin_include))]
fn load_initial_input(cli: &Cli) -> Result<Option<Vec<u8>>> {
    // File takes precedence
    if let Some(path) = &cli.file {
        let content = std::fs::read(path)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;
        return Ok(Some(content));
    }

    // Check if stdin has data (not a terminal)
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        let mut input = Vec::new();
        stdin
            .lock()
            .read_to_end(&mut input)
            .context("Failed to read from stdin")?;
        if !input.is_empty() {
            return Ok(Some(input));
        }
    }

    Ok(None)
}

/// Requires TTY for terminal event loop
#[cfg(not(tarpaulin_include))]
fn run_app(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
) -> Result<()> {
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
