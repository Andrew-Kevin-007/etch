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
        Some(Commands::Sign { path }) => {
            let identity = EtchIdentity::load()?;
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
        }
        Some(Commands::Verify { path, json }) => {
            let report = etch::verify::verify_file(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Verification Report for: {}", path);
                println!("Verdict: {}", if report.verdict { "PASS" } else { "FAIL" });
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
