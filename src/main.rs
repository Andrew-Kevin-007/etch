use clap::{Parser, Subcommand};
use etch::chain::AuthorshipChain;
use etch::fingerprint;
use etch::identity::EtchIdentity;
use std::collections::HashMap;
use std::io::{self, stdout};
use std::process;
use std::time::SystemTime;

use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, BorderType, Clear},
    Terminal,
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

/// etch: A CLI tool for data integrity and provenance.
#[derive(Parser)]
#[command(author, version, about = "A CLI tool for data integrity and provenance", long_about = "etch allows you to sign files and maintain an immutable authorship chain, ensuring that file integrity and authorship history are cryptographically verifiable.")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to the identity file (~/.etch/identity.json)
    #[arg(long, env = "ETCH_IDENTITY_PATH")]
    identity_path: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new etch identity (~/.etch/identity.json)
    Init,
    /// Print the current identity's public key
    Whoami,
    /// Sign a file and append its fingerprint to the authorship chain
    Sign {
        /// The path to the file to sign
        path: String,
        /// Force signing even if contribution analysis fails
        #[arg(short, long)]
        force: bool,
        /// human-readable name for this file/module
        #[arg(long)]
        name: Option<String>,
        /// project name
        #[arg(long)]
        project: Option<String>,
        /// domain or category
        #[arg(long)]
        domain: Option<String>,
        /// comma-separated list of chain_ids that this file depends on
        #[arg(long, value_delimiter = ',')]
        depends_on: Option<Vec<String>>,
    },
    /// Verify the integrity and authorship chain of a signed file
    Verify {
        /// The path to the file to verify
        path: String,
        /// Output the full verification report as machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Show the current identity and status
    Status,
}

fn main() {
    let cli = Cli::parse();

    if let Some(path) = &cli.identity_path {
        unsafe {
            std::env::set_var("ETCH_IDENTITY_PATH", path);
        }
    }

    if EtchIdentity::load().is_err() && cli.command.is_some() {
        if !matches!(cli.command, Some(Commands::Init)) {
            println!("Welcome to etch! Looks like you haven't set up your identity yet.");
            println!("Run: etch init\n");
        }
    }

    if cli.command.is_none() {
        if io::IsTerminal::is_terminal(&io::stdout()) {
            if let Err(e) = run_interactive_tui() {
                eprintln!("Interactive TUI error: {}", e);
                process::exit(1);
            }
            return;
        } else {
            println!("No command specified. Use --help for usage information.");
            return;
        }
    }

    if let Err(e) = run(cli) {
        match e.downcast_ref::<std::io::Error>() {
            Some(io_err) if io_err.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("Error: Resource not found. Please check that the file path or identity exists.");
            }
            Some(io_err) if io_err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("Error: Permission denied. Please check your file system permissions.");
            }
            _ => eprintln!("Error: {}.", e),
        }
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Some(Commands::Init) => {
            let identity = EtchIdentity::generate();
            identity.save()?;
            println!("Identity initialized.");
            println!("Public Key: {}", identity.public_key_hex());
            Ok(())
        }
        Some(Commands::Whoami) => {
            let identity = EtchIdentity::load()?;
            println!("Public Key: {}", identity.public_key_hex());
            Ok(())
        }
        Some(Commands::Sign { path, force, name, project, domain, depends_on }) => {
            let identity = EtchIdentity::load()?;
            
            // Metadata gathering
            let mut metadata = HashMap::new();
            
            let name_val = match name {
                Some(n) => n,
                None => {
                    // Default to filename
                    std::path::Path::new(&path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(&path)
                        .to_string()
                }
            };
            if !name_val.is_empty() { metadata.insert("name".to_string(), name_val); }

            let project_val = match project {
                Some(p) => p,
                None => {
                    // Default to parent folder name
                    std::path::Path::new(&path)
                        .parent()
                        .and_then(|p| p.file_name())
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string()
                }
            };
            if !project_val.is_empty() { metadata.insert("project".to_string(), project_val); }

            // Preliminary contribution analysis for language detection
            let analysis_result = etch::analyzer::parse_file(&path);
            let language = analysis_result.as_ref().map(|res| res.0.language.clone()).unwrap_or_else(|_| "unknown".to_string());

            let domain_val = match domain {
                Some(d) => d,
                None => language.clone()
            };
            if !domain_val.is_empty() { metadata.insert("domain".to_string(), domain_val); }

            let metadata_opt = if metadata.is_empty() { None } else { Some(metadata) };

            // Contribution analysis
            let analysis_result = etch::analyzer::parse_file(&path);
            
            if let Err(e) = &analysis_result {
                if force {
                    eprintln!("Warning: Contribution analysis failed: {}. Proceeding due to --force.", e);
                    
                    let mut chain = AuthorshipChain::load_for_file(&path)?;
                    let prev_hash = if let Some(last) = chain.fingerprints.last() {
                        fingerprint::hash_fingerprint(last)?
                    } else {
                        "genesis".to_string()
                    };

                    let fingerprint = fingerprint::sign_file(&path, &identity, prev_hash, metadata_opt)?;
                    chain.append(fingerprint)?;
                    chain.save_for_file(&path)?;
                    
                    println!("File '{}' signed successfully (forced).", path);

                    // Anchoring to notarization server
                    let rt = tokio::runtime::Runtime::new()?;
                    let _ = rt.block_on(etch::notary::anchor_chain(&path, &chain, &identity));

                    if let Some(deps) = depends_on {
                        if !deps.is_empty() {
                            let _ = rt.block_on(etch::notary::register_dependencies(&path, deps));
                        }
                    }

                    return Ok(());
                } else {
                    return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())));
                }
            }

            let (analysis, tree, source) = analysis_result.unwrap();

            let logic = etch::analyzer::detect_logic(&tree, &source, &analysis.language);
            let arch = etch::analyzer::detect_architecture(&tree, &source, &analysis.language);
            let verdict = etch::analyzer::score_contribution(&analysis, &logic, &arch);

            println!("Contribution Analysis for: {}", path);
            println!("- Language: {}", analysis.language);
            println!("- Functions: {}", analysis.function_count);
            println!("- Abstractions: {}", analysis.new_abstractions);
            println!("- Complexity Score: {}", analysis.cyclomatic_complexity);
            println!("- Logic Present: {}", if logic.logic_present { "Yes" } else { "No" });
            println!("- Architecture Present: {}", if arch.architecture_present { "Yes" } else { "No" });
            println!("- Qualifies: {}", if verdict.qualifies { "YES" } else { "NO" });
            if !verdict.qualifies {
                println!("- Reason: {}", verdict.reason);
            }
            println!("- Score: {:.2}", verdict.score);
            println!("");

            if !verdict.qualifies && !force {
                eprintln!("Error: Contribution analysis failed and --force was not used.");
                process::exit(1);
            }

            let mut chain = AuthorshipChain::load_for_file(&path)?;
            
            let prev_hash = if let Some(last) = chain.fingerprints.last() {
                fingerprint::hash_fingerprint(last)?
            } else {
                "genesis".to_string()
            };

            let fingerprint = fingerprint::sign_file(&path, &identity, prev_hash, metadata_opt)?;
            chain.append(fingerprint)?;
            chain.save_for_file(&path)?;
            
            println!("File '{}' signed successfully.", path);

            // Anchoring to notarization server
            let rt = tokio::runtime::Runtime::new()?;
            let _ = rt.block_on(etch::notary::anchor_chain(&path, &chain, &identity));

            if let Some(deps) = depends_on {
                if !deps.is_empty() {
                    let _ = rt.block_on(etch::notary::register_dependencies(&path, deps));
                }
            }
            Ok(())
        }
        Some(Commands::Verify { path, json }) => {
            let mut report = etch::verify::verify_file(&path)?;
            
            // Server verification
            let rt = tokio::runtime::Runtime::new()?;
            let server_match = if let Ok(chain) = AuthorshipChain::load_for_file(&path) {
                rt.block_on(etch::notary::verify_with_server(&path, &chain)).unwrap_or(false)
            } else {
                false
            };

            report.results.push(etch::verify::CheckResult {
                check_id: "server_verification".to_string(),
                status: server_match,
                entry_index: None,
                expected: None,
                actual: None,
                reason_code: if server_match { None } else { Some("server_mismatch_or_unavailable".to_string()) },
            });

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                let chain_opt = AuthorshipChain::load_for_file(&path).ok();
                let author = if let Some(last) = chain_opt.as_ref().and_then(|c| c.fingerprints.last().cloned()) {
                    format!("{}...", &last.contributor_pubkey[..8])
                } else {
                    "unknown".to_string()
                };
                let depth = chain_opt.as_ref().map(|c| c.fingerprints.len()).unwrap_or(0);
                
                // Try TUI first, fallback to ASCII box
                if io::IsTerminal::is_terminal(&io::stdout()) {
                    if let Err(e) = draw_verify_tui(&path, &report, depth, &author, server_match) {
                        eprintln!("TUI error: {}. Falling back to plain text.", e);
                        print_verify_plain(&path, &report, depth, &author, server_match);
                    }
                } else {
                    print_verify_plain(&path, &report, depth, &author, server_match);
                }
            }
            if !report.verdict {
                process::exit(1);
            }
            Ok(())
        }
        Some(Commands::Status) => {
            let identity = EtchIdentity::load()?;
            
            // Number of files signed in current directory
            let mut signed_count = 0;
            let mut recent_files = Vec::new();
            if let Ok(entries) = std::fs::read_dir(".") {
                let mut entries: Vec<_> = entries.flatten().collect();
                // Sort by modification time for recent files
                entries.sort_by_key(|e| e.metadata().and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH));
                entries.reverse();

                for entry in entries {
                    if let Some(name) = entry.file_name().to_str() {
                        if name.ends_with(".etch") {
                            signed_count += 1;
                            if recent_files.len() < 3 {
                                recent_files.push(name.trim_end_matches(".etch").to_string());
                            }
                        }
                    }
                }
            }

            // Server connection status
            let rt = tokio::runtime::Runtime::new()?;
            let server_url = etch::notary::get_server_url();
            let client = reqwest::Client::new();
            let status = rt.block_on(async {
                client.get(&server_url).timeout(std::time::Duration::from_secs(2)).send().await
            });
            let server_connected = status.is_ok();

            if io::IsTerminal::is_terminal(&io::stdout()) {
                if let Err(e) = draw_status_tui(&identity, signed_count, server_connected, &recent_files) {
                    eprintln!("TUI error: {}. Falling back to plain text.", e);
                    print_status_plain(&identity, signed_count, server_connected);
                }
            } else {
                print_status_plain(&identity, signed_count, server_connected);
            }
            Ok(())
        }
        None => {
            // This is now handled in main
            Ok(())
        }
    }
}

fn run_interactive_tui() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut input_active = false;
    let mut input_buffer = String::new();
    let mut current_action: Option<&'static str> = None;
    let mut message: Option<(String, Color)> = None;

    let accent_color = Color::Rgb(0, 255, 157); // #00ff9d

    let mut last_server_check = std::time::Instant::now() - std::time::Duration::from_secs(10);
    let mut server_connected = false;

    loop {
        // Refresh data (lightweight)
        let identity_res = EtchIdentity::load();
        let pubkey = identity_res.as_ref().map(|i| i.public_key_hex()).unwrap_or_else(|_| "Not initialized".to_string());
        let truncated_pubkey = if pubkey.len() > 16 {
            format!("{}...{}", &pubkey[..8], &pubkey[pubkey.len()-8..])
        } else {
            pubkey.clone()
        };
        
        let current_dir = std::env::current_dir()?.to_string_lossy().to_string();
        
        // Throttled Server connection status
        if last_server_check.elapsed() > std::time::Duration::from_secs(5) {
            let server_url = etch::notary::get_server_url();
            if let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_millis(500))
                    .build();
                if let Ok(c) = client {
                    server_connected = rt.block_on(async { c.get(&server_url).send().await.is_ok() });
                }
            }
            last_server_check = std::time::Instant::now();
        }

        // Recent files
        let mut recent_files = Vec::new();
        if let Ok(entries) = std::fs::read_dir(".") {
            let mut files: Vec<_> = entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "etch"))
                .filter_map(|e| {
                    let metadata = e.metadata().ok()?;
                    let modified = metadata.modified().ok()?;
                    Some((e.path().to_string_lossy().into_owned(), modified))
                })
                .collect();
            files.sort_by(|a, b| b.1.cmp(&a.1));
            recent_files = files.into_iter().take(3).map(|(p, _)| p).collect();
        }

        terminal.draw(|f| {
            let size = f.area();
            
            // Layout
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1), // Top border/title
                    Constraint::Min(0),    // Main content
                    Constraint::Length(1), // Bottom bar
                ])
                .split(size);

            // Top bar
            let version = env!("CARGO_PKG_VERSION");
            let top_text = format!("── etch v{} ──────────────────────────────", version);
            f.render_widget(Paragraph::new(top_text).style(Style::default().fg(accent_color)), chunks[0]);

            // Main content split
            let main_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(33),
                    Constraint::Percentage(67),
                ])
                .split(chunks[1]);

            // Left Panel
            let logo = r#"
      _       _
  ___| |_ ___| |__
 / _ \ __/ __| '_ \
|  __/ || (__| | | |
 \___|\__\___|_| |_|
"#;
            let mut left_text = Vec::new();
            left_text.push(Line::from(Span::styled(logo, Style::default().fg(accent_color))));
            left_text.push(Line::from(""));
            left_text.push(Line::from(vec![
                Span::raw(" identity  "),
                Span::styled(truncated_pubkey, Style::default().add_modifier(Modifier::BOLD)),
            ]));
            left_text.push(Line::from(vec![
                Span::raw(" path      "),
                Span::styled(current_dir, Style::default().fg(Color::DarkGray)),
            ]));
            
            let status_dot = if server_connected { 
                Span::styled(" ● ", Style::default().fg(accent_color)) 
            } else { 
                Span::styled(" ● ", Style::default().fg(Color::Red)) 
            };
            left_text.push(Line::from(vec![
                Span::raw(" server   "),
                status_dot,
                Span::raw(if server_connected { "Connected" } else { "Disconnected" }),
            ]));

            let left_panel = Paragraph::new(left_text)
                .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)).padding(ratatui::widgets::Padding::horizontal(1)));
            f.render_widget(left_panel, main_chunks[0]);

            // Right Panel
            let mut right_text = Vec::new();
            right_text.push(Line::from(""));
            right_text.push(Line::from(Span::styled("  Quick start", Style::default().add_modifier(Modifier::BOLD))));
            right_text.push(Line::from(""));
            
            let commands = [
                ("etch init", "create your identity"),
                ("etch sign <file>", "sign a file"),
                ("etch verify <file>", "verify authorship"),
                ("etch status", "view your profile"),
            ];

            for (cmd, desc) in commands {
                right_text.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled("> ", Style::default().fg(accent_color)),
                    Span::styled(cmd, Style::default().fg(accent_color)),
                    Span::raw(format!(" — {}", desc)),
                ]));
            }

            right_text.push(Line::from(""));
            right_text.push(Line::from(Span::styled("  Recent signatures", Style::default().add_modifier(Modifier::BOLD))));
            right_text.push(Line::from(""));

            if recent_files.is_empty() {
                right_text.push(Line::from(Span::styled("    No recent signatures found.", Style::default().fg(Color::DarkGray))));
            } else {
                for file in &recent_files {
                    let display_name = file.strip_suffix(".etch").unwrap_or(file);
                    right_text.push(Line::from(vec![
                        Span::raw("    "),
                        Span::styled("✓ ", Style::default().fg(accent_color)),
                        Span::raw(display_name.to_string()),
                    ]));
                }
            }

            if let Some((msg, color)) = &message {
                right_text.push(Line::from(""));
                right_text.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(msg, Style::default().fg(*color)),
                ]));
            }

            let right_panel = Paragraph::new(right_text)
                .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray)));
            f.render_widget(right_panel, main_chunks[1]);

            // Bottom bar
            let footer = Line::from(vec![
                Span::styled(" ? ", Style::default().fg(Color::DarkGray)),
                Span::styled("help  ", Style::default().fg(Color::DarkGray)),
                Span::styled(" q ", Style::default().fg(Color::DarkGray)),
                Span::styled("quit  ", Style::default().fg(Color::DarkGray)),
                Span::styled(" s ", Style::default().fg(Color::DarkGray)),
                Span::styled("sign  ", Style::default().fg(Color::DarkGray)),
                Span::styled(" v ", Style::default().fg(Color::DarkGray)),
                Span::styled("verify  ", Style::default().fg(Color::DarkGray)),
                Span::styled(" i ", Style::default().fg(Color::DarkGray)),
                Span::styled("init  ", Style::default().fg(Color::DarkGray)),
                Span::raw(" ".repeat(size.width.saturating_sub(55) as usize)),
                Span::styled("etch protocol v1", Style::default().fg(Color::DarkGray)),
            ]);
            f.render_widget(Paragraph::new(footer), chunks[2]);

            // Input Modal
            if input_active {
                let area = centered_rect(60, 20, size);
                f.render_widget(Clear, area);
                let input_block = Block::default()
                    .title(format!(" Enter file to {} ", current_action.unwrap_or("process")))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(accent_color));
                let input_p = Paragraph::new(input_buffer.as_str())
                    .block(input_block);
                f.render_widget(input_p, area);
            }
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if input_active {
                    match key.code {
                        KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => break,
                        KeyCode::Enter => {
                            let path = input_buffer.trim().to_string();
                            let action = current_action;
                            input_active = false;
                            input_buffer.clear();
                            current_action = None;
                            
                            if !path.is_empty() {
                                if action == Some("sign") {
                                    // Run sign logic
                                    match handle_sign_action(&path) {
                                        Ok(_) => message = Some((format!("Successfully signed {}", path), accent_color)),
                                        Err(e) => message = Some((format!("Error: {}", e), Color::Red)),
                                    }
                                } else if action == Some("verify") {
                                    // Run verify logic
                                    match handle_verify_action(&path) {
                                        Ok(_) => message = Some((format!("Verification complete for {}", path), accent_color)),
                                        Err(e) => message = Some((format!("Error: {}", e), Color::Red)),
                                    }
                                }
                            }
                        }
                        KeyCode::Esc => {
                            input_active = false;
                            input_buffer.clear();
                            current_action = None;
                        }
                        KeyCode::Char(c) => {
                            input_buffer.push(c);
                        }
                        KeyCode::Backspace => {
                            input_buffer.pop();
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => break,
                        KeyCode::Char('q') => break,
                        KeyCode::Char('i') => {
                            let identity = EtchIdentity::generate();
                            if let Err(e) = identity.save() {
                                message = Some((format!("Error: {}", e), Color::Red));
                            } else {
                                message = Some(("Identity initialized successfully.".to_string(), accent_color));
                            }
                        }
                        KeyCode::Char('s') => {
                            input_active = true;
                            current_action = Some("sign");
                        }
                        KeyCode::Char('v') => {
                            input_active = true;
                            current_action = Some("verify");
                        }
                        KeyCode::Char('?') => {
                            message = Some(("Use i, s, v, q to interact with etch.".to_string(), Color::Yellow));
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn handle_sign_action(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let identity = EtchIdentity::load()?;
    let mut metadata = HashMap::new();
    
    let name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
        .to_string();
    metadata.insert("name".to_string(), name);
    
    let project = std::path::Path::new(path)
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    metadata.insert("project".to_string(), project);

    let analysis_result = etch::analyzer::parse_file(path);
    let language = analysis_result.as_ref().map(|res| res.0.language.clone()).unwrap_or_else(|_| "unknown".to_string());
    metadata.insert("domain".to_string(), language);

    let mut chain = AuthorshipChain::load_for_file(path)?;
    let prev_hash = if let Some(last) = chain.fingerprints.last() {
        fingerprint::hash_fingerprint(last)?
    } else {
        "genesis".to_string()
    };

    let fingerprint = fingerprint::sign_file(path, &identity, prev_hash, Some(metadata))?;
    chain.append(fingerprint)?;
    chain.save_for_file(path)?;

    let rt = tokio::runtime::Runtime::new()?;
    let _ = rt.block_on(etch::notary::anchor_chain(path, &chain, &identity));
    
    Ok(())
}

fn handle_verify_action(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let chain = AuthorshipChain::load_for_file(path)?;
    let report = etch::verify::verify_file(path)?;
    
    let rt = tokio::runtime::Runtime::new()?;
    let server_match = rt.block_on(etch::notary::verify_with_server(path, &chain)).unwrap_or(false);
    
    let depth = chain.fingerprints.len();
    let author = chain.fingerprints.last().map(|f| {
        let pk = &f.contributor_pubkey;
        format!("{}...{}", &pk[..8], &pk[pk.len()-8..])
    }).unwrap_or_else(|| "unknown".to_string());

    draw_verify_tui(path, &report, depth, &author, server_match)?;
    Ok(())
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn print_verify_plain(path: &str, report: &etch::verify::VerificationReport, depth: usize, author: &str, server_match: bool) {
    println!("╔════════════════════════════════════╗");
    println!("║  ETCH  ·  AUTHORSHIP VERIFIED  {}  ║", if report.verdict { "✓" } else { "✗" });
    println!("╠════════════════════════════════════╣");
    println!("║  file     {:<24} ║", if path.len() > 24 { format!("...{}", &path[path.len()-21..]) } else { path.to_string() });
    println!("║  depth    {:<2} signatures            ║", depth);
    println!("║  author   {:<24} ║", author);
    println!("║  server   {:<24} ║", if server_match { "ANCHORED ✓" } else { "NOT ANCHORED ✗" });
    println!("╚════════════════════════════════════╝");

    if !report.verdict {
        println!("\nCheck Details:");
        for result in &report.results {
            if !result.status {
                let entry_str = result.entry_index.map(|i| format!(" [Entry {}]", i)).unwrap_or_default();
                println!("- {}{}: FAILED", result.check_id, entry_str);
                if let Some(reason) = &result.reason_code {
                    println!("  Reason: {}", reason);
                }
            }
        }
    }
}

fn print_status_plain(identity: &EtchIdentity, signed_count: usize, server_connected: bool) {
    println!("Current identity: {}", identity.public_key_hex());
    println!("Files signed in current directory: {}", signed_count);
    println!("Server status: {}", if server_connected { "Connected (✓)" } else { "Disconnected (✗)" });
}

fn draw_status_tui(identity: &EtchIdentity, signed_count: usize, server_connected: bool, recent_files: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let pubkey = identity.public_key_hex();
    let truncated_pubkey = format!("{}...{}", &pubkey[..8], &pubkey[pubkey.len()-8..]);
    let current_dir = std::env::current_dir()?.to_string_lossy().to_string();
    let accent_color = Color::Rgb(0, 255, 157); // #00ff9d

    loop {
        terminal.draw(|f| {
            let size = f.area();
            
            // Layout
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1), // Top border/title
                    Constraint::Min(0),    // Main content
                    Constraint::Length(1), // Bottom bar
                ])
                .split(size);

            // Top bar
            let version = env!("CARGO_PKG_VERSION");
            let top_text = format!("── etch v{} ──────────────────────────────", version);
            f.render_widget(Paragraph::new(top_text).style(Style::default().fg(accent_color)), chunks[0]);

            // Main content split
            let main_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(50),
                    Constraint::Percentage(50),
                ])
                .split(chunks[1]);

            // Left Panel
            let logo = r#"
      _       _
  ___| |_ ___| |__
 / _ \ __/ __| '_ \
|  __/ || (__| | | |
 \___|\__\___|_| |_|
"#;
            let mut left_text = Vec::new();
            left_text.push(Line::from(Span::styled(logo, Style::default().fg(accent_color))));
            left_text.push(Line::from(""));
            left_text.push(Line::from(vec![
                Span::raw("identity  "),
                Span::styled(truncated_pubkey.clone(), Style::default().add_modifier(Modifier::BOLD)),
            ]));
            left_text.push(Line::from(vec![
                Span::raw("path      "),
                Span::styled(current_dir.clone(), Style::default().fg(Color::DarkGray)),
            ]));
            left_text.push(Line::from(""));
            left_text.push(Line::from(vec![
                Span::raw("signed    "),
                Span::styled(signed_count.to_string(), Style::default().fg(accent_color)),
                Span::raw(" files in this directory"),
            ]));

            f.render_widget(
                Paragraph::new(left_text)
                    .block(Block::default().borders(Borders::RIGHT).border_style(Style::default().fg(Color::DarkGray))),
                main_chunks[0]
            );

            // Right Panel
            let mut right_text = Vec::new();
            right_text.push(Line::from(Span::styled("Quick commands", Style::default().add_modifier(Modifier::BOLD))));
            right_text.push(Line::from(vec![
                Span::styled("  etch sign <file>  ", Style::default().fg(Color::Green)),
                Span::raw("sign a new file"),
            ]));
            right_text.push(Line::from(vec![
                Span::styled("  etch verify <file>", Style::default().fg(Color::Green)),
                Span::raw("verify authorship"),
            ]));
            right_text.push(Line::from(vec![
                Span::styled("  etch status       ", Style::default().fg(Color::Green)),
                Span::raw("show this screen"),
            ]));
            right_text.push(Line::from(""));
            right_text.push(Line::from(Span::styled("Recent activity", Style::default().add_modifier(Modifier::BOLD))));
            if recent_files.is_empty() {
                right_text.push(Line::from(Span::styled("  no recent activity", Style::default().fg(Color::DarkGray))));
            } else {
                for file in recent_files {
                    right_text.push(Line::from(vec![
                        Span::styled("  ✓ ", Style::default().fg(accent_color)),
                        Span::raw(file),
                    ]));
                }
            }

            f.render_widget(Paragraph::new(right_text).block(Block::default().padding(ratatui::widgets::Padding::horizontal(2))), main_chunks[1]);

            // Bottom bar
            let server_status = if server_connected {
                Span::styled("server online", Style::default().fg(accent_color))
            } else {
                Span::styled("server offline", Style::default().fg(Color::Red))
            };
            
            let bottom_content = Line::from(vec![
                Span::raw("? for help"),
                Span::raw(" ".repeat(size.width as usize - 30)),
                server_status,
                Span::raw("  etch protocol v1"),
            ]);
            f.render_widget(Paragraph::new(bottom_content), chunks[2]);
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char(' ') | KeyCode::Enter = key.code {
                    break;
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn draw_verify_tui(path: &str, report: &etch::verify::VerificationReport, depth: usize, author: &str, server_match: bool) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let accent_color = Color::Rgb(0, 255, 157); // #00ff9d
    let border_color = if report.verdict { accent_color } else { Color::Red };

    loop {
        terminal.draw(|f| {
            let size = f.area();
            let block_width = 50.min(size.width);
            let block_height = 12.min(size.height);
            let area = Rect::new(
                (size.width - block_width) / 2,
                (size.height - block_height) / 2,
                block_width,
                block_height,
            );

            let mut content = Vec::new();
            content.push(Line::from(vec![
                Span::styled("  ETCH  ·  AUTHORSHIP VERIFIED  ", Style::default().add_modifier(Modifier::BOLD)),
                if report.verdict {
                    Span::styled("✓", Style::default().fg(accent_color).add_modifier(Modifier::BOLD))
                } else {
                    Span::styled("✗", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                }
            ]));
            content.push(Line::from("─".repeat(block_width as usize - 2)));
            
            content.push(Line::from(vec![
                Span::styled("  file     ", Style::default().fg(Color::DarkGray)),
                Span::raw(if path.len() > 30 { format!("...{}", &path[path.len()-27..]) } else { path.to_string() }),
            ]));

            // Chain depth bar
            let max_depth = 10;
            let filled = depth.min(max_depth);
            let empty = max_depth - filled;
            let bar = format!("{}{}", "█".repeat(filled), "░".repeat(empty));
            content.push(Line::from(vec![
                Span::styled("  depth    ", Style::default().fg(Color::DarkGray)),
                Span::styled(bar, Style::default().fg(accent_color)),
                Span::raw(format!(" depth {}/{}", depth, max_depth)),
            ]));

            content.push(Line::from(vec![
                Span::styled("  author   ", Style::default().fg(Color::DarkGray)),
                Span::raw(author),
            ]));

            content.push(Line::from(vec![
                Span::styled("  server   ", Style::default().fg(Color::DarkGray)),
                if server_match {
                    Span::styled("ANCHORED ✓", Style::default().fg(accent_color))
                } else {
                    Span::styled("NOT ANCHORED ✗", Style::default().fg(Color::Red))
                }
            ]));

            content.push(Line::from(""));
            content.push(Line::from(Span::styled("  Check Details:", Style::default().add_modifier(Modifier::DIM))));
            
            for result in &report.results {
                let icon = if result.status {
                    Span::styled(" ✓ ", Style::default().fg(accent_color))
                } else {
                    Span::styled(" ✗ ", Style::default().fg(Color::Red))
                };
                content.push(Line::from(vec![
                    icon,
                    Span::styled(&result.check_id, Style::default().fg(if result.status { Color::White } else { Color::Red })),
                ]));
            }

            let paragraph = Paragraph::new(content)
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(border_color)));
            
            f.render_widget(paragraph, area);
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char(' ') | KeyCode::Enter = key.code {
                    break;
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
