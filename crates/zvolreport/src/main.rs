//! `zvolreport` — one document that a third party can check.
//!
//! Every other tool appends what it did to an evidence log. This one
//! consolidates those logs into a single report: what evidence was
//! examined, by which tool versions, with which commands, what came out
//! of it, and whether every file still matches the hash that was
//! recorded when it was written (COMPANIONS §4).
//!
//! It reads logs and files, and writes only the report it was asked for.

mod build;
mod markdown;
mod model;
mod sign;
mod verify;

use std::path::PathBuf;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use zvol_common::{exit, Global};

/// Consolidate evidence logs into a report, and check one back.
#[derive(Debug, Parser)]
#[command(name = "zvolreport", version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    global: Global,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Consolidate evidence logs into one report.
    Build {
        /// Evidence logs written by the other tools (JSON Lines).
        #[arg(value_name = "LOG", required = true)]
        logs: Vec<PathBuf>,
        /// Write the report here.
        #[arg(short, long, value_name = "report.json")]
        output: PathBuf,
        /// Also render the report as Markdown.
        #[arg(long, value_name = "report.md")]
        md: Option<PathBuf>,
        /// Case identifier, as it appears on the report.
        #[arg(long, value_name = "ID")]
        case: Option<String>,
        /// Who is doing the examination.
        #[arg(long, value_name = "NAME")]
        examiner: Option<String>,
        /// A note to carry in the report (repeatable).
        #[arg(long, value_name = "TEXT")]
        note: Vec<String>,
        /// Sign the report with this Ed25519 private key (unencrypted
        /// PKCS#8, the form `openssl genpkey -algorithm ed25519`
        /// writes), leaving the raw 64-byte signature beside it (R-07).
        #[arg(long, value_name = "KEYFILE")]
        sign: Option<PathBuf>,
        /// Write the signature here instead of next to the report.
        #[arg(long, value_name = "report.json.sig")]
        signature: Option<PathBuf>,
    },
    /// Recompute the hashes a report recorded and say what still matches.
    Verify {
        /// The report to check.
        #[arg(value_name = "report.json")]
        report: PathBuf,
        /// Look for the evidence under this directory instead of the
        /// path recorded (the disks are rarely mounted where they were).
        #[arg(long, value_name = "DIR")]
        evidence_root: Option<PathBuf>,
        /// Look for the extracted files under this directory.
        #[arg(long, value_name = "DIR")]
        outputs_root: Option<PathBuf>,
        /// Also check the report's signature against this Ed25519
        /// public key (SubjectPublicKeyInfo, the form
        /// `openssl pkey -pubout` writes).
        #[arg(long, value_name = "KEYFILE")]
        key: Option<PathBuf>,
        /// Read the signature here instead of next to the report.
        #[arg(long, value_name = "report.json.sig")]
        signature: Option<PathBuf>,
    },
    /// Write a new Ed25519 key pair to sign reports with.
    Keygen {
        /// Write the private key here, and the public key at `KEY.pub`.
        #[arg(short, long, value_name = "KEY")]
        output: PathBuf,
        /// Write the public key here instead of at `KEY.pub`.
        #[arg(long, value_name = "KEY.pub")]
        public: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    zvol_common::quiet_broken_pipe();
    let cli = Cli::parse();
    if let Err(code) = cli.global.enable_tracing("zvolreport") {
        return ExitCode::from(code);
    }
    let code = match cli.command {
        Command::Build {
            logs,
            output,
            md,
            case,
            examiner,
            note,
            sign,
            signature,
        } => build::run(
            &cli.global,
            &build::Options {
                logs,
                output,
                md,
                case,
                examiner,
                notes: note,
                sign,
                signature,
            },
        ),
        Command::Verify {
            report,
            evidence_root,
            outputs_root,
            key,
            signature,
        } => verify::run(
            &cli.global,
            &verify::Options {
                report,
                evidence_root,
                outputs_root,
                key,
                signature,
            },
        ),
        Command::Keygen { output, public } => keygen(&cli.global, &output, public),
    };
    ExitCode::from(code)
}

/// Write a key pair, and say where it went.
fn keygen(g: &Global, private: &std::path::Path, public: Option<PathBuf>) -> u8 {
    let public = public.unwrap_or_else(|| {
        let mut p = private.as_os_str().to_os_string();
        p.push(".pub");
        PathBuf::from(p)
    });
    match sign::keygen(private, &public) {
        Err(e) => {
            eprintln!("zvolreport: {e}");
            exit::USAGE
        }
        Ok(key) => {
            match g.format {
                zvol_common::Format::Json => println!(
                    "{}",
                    serde_json::json!({
                        "private": private, "public": public,
                        "public_key_pem": sign::public_pem(&key),
                    })
                ),
                zvol_common::Format::Text => {
                    println!("wrote {} (mode 0600)", private.display());
                    println!("wrote {}", public.display());
                }
            }
            0
        }
    }
}

/// Kept for the same reason the main binary keeps it: so a build that
/// forgets a phase says so instead of doing something surprising.
#[allow(dead_code)]
const _NOT_IMPLEMENTED: u8 = exit::NOT_IMPLEMENTED;
