use clap::{Parser, Subcommand};
use etch::chain::AuthorshipChain;
use etch::fingerprint;
use etch::identity::EtchIdentity;
use std::process;

/// etch: A CLI tool for data integrity and provenance.
#[derive(Parser)]
#[command(author, version, about = "A CLI tool for data integrity and provenance", long_about = "etch allows you to sign files and maintain an immutable authorship chain, ensuring that file integrity and authorship history are cryptographically verifiable.")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
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
        #[arg(short, long)]
        path: String,
        /// Force signing even if contribution analysis fails
        #[arg(short, long)]
        force: bool,
    },
    /// Verify the integrity and authorship chain of a signed file
    Verify {
        /// The path to the file to verify
        #[arg(short, long)]
        path: String,
        /// Output the full verification report as machine-readable JSON
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let cli = Cli::parse();

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
        }
        Some(Commands::Whoami) => {
            let identity = EtchIdentity::load()?;
            println!("Public Key: {}", identity.public_key_hex());
        }
        Some(Commands::Sign { path, force }) => {
            let identity = EtchIdentity::load()?;
            
            // Contribution analysis
            let analysis_result = etch::analyzer::parse_file(&path);
            
            let (analysis, tree, source) = match analysis_result {
                Ok(res) => res,
                Err(e) => {
                    if force {
                        eprintln!("Warning: Contribution analysis failed: {}. Proceeding due to --force.", e);
                        
                        let mut chain = AuthorshipChain::load_for_file(&path)?;
                        let prev_hash = if let Some(last) = chain.fingerprints.last() {
                            fingerprint::hash_fingerprint(last)?
                        } else {
                            "genesis".to_string()
                        };

                        let fingerprint = fingerprint::sign_file(&path, &identity, prev_hash)?;
                        chain.append(fingerprint)?;
                        chain.save_for_file(&path)?;
                        
                        println!("File '{}' signed successfully (forced).", path);

                        // Anchoring to notarization server
                        let rt = tokio::runtime::Runtime::new()?;
                        let _ = rt.block_on(etch::notary::anchor_chain(&path, &chain, &identity));

                        return Ok(());
                    } else {
                        return Err(e);
                    }
                }
            };

            let logic = etch::analyzer::detect_logic(&tree, &source);
            let arch = etch::analyzer::detect_architecture(&tree, &source);
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

            let fingerprint = fingerprint::sign_file(&path, &identity, prev_hash)?;
            chain.append(fingerprint)?;
            chain.save_for_file(&path)?;
            
            println!("File '{}' signed successfully.", path);

            // Anchoring to notarization server
            let rt = tokio::runtime::Runtime::new()?;
            let _ = rt.block_on(etch::notary::anchor_chain(&path, &chain, &identity));
        }
        Some(Commands::Verify { path, json }) => {
            let mut report = etch::verify::verify_file(&path)?;
            
            // Server verification
            let rt = tokio::runtime::Runtime::new()?;
            let head_hash = if let Ok(chain) = AuthorshipChain::load_for_file(&path) {
                chain.fingerprints.last().map(|f| f.code_hash.clone())
            } else {
                None
            };

            let server_match = if let Some(hash) = head_hash {
                rt.block_on(etch::notary::verify_with_server(&path, &hash)).unwrap_or(false)
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
                println!("Verification Report for: {}", path);
                println!("Verdict: {}", if report.verdict { "PASS" } else { "FAIL" });
                println!("Server Verified: {}", if server_match { "YES" } else { "NO" });
                if let Some(idx) = report.verified_through_index {
                    println!("Verified through entry index: {}", idx);
                } else {
                    println!("No entries verified.");
                }
                println!("\nCheck Details:");
                for result in report.results {
                    let entry_str = result.entry_index.map(|i| format!(" [Entry {}]", i)).unwrap_or_default();
                    let status_str = if result.status { "OK" } else { "FAILED" };
                    println!("- {}{}: {}", result.check_id, entry_str, status_str);
                    if let Some(reason) = result.reason_code {
                        println!("  Reason: {}", reason);
                    }
                    if let Some(expected) = result.expected {
                        println!("  Expected: {}", expected);
                    }
                    if let Some(actual) = result.actual {
                        println!("  Actual:   {}", actual);
                    }
                }
            }
            if !report.verdict {
                process::exit(1);
            }
        }
        None => {
            println!("No command specified. Use --help for usage information.");
        }
    }
    Ok(())
}
