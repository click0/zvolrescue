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
    },
}

fn main() -> ExitCode {
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
        } => build::run(
            &cli.global,
            &build::Options {
                logs,
                output,
                md,
                case,
                examiner,
                notes: note,
            },
        ),
        Command::Verify {
            report,
            evidence_root,
            outputs_root,
        } => verify::run(
            &cli.global,
            &verify::Options {
                report,
                evidence_root,
                outputs_root,
            },
        ),
    };
    ExitCode::from(code)
}

/// Kept for the same reason the main binary keeps it: so a build that
/// forgets a phase says so instead of doing something surprising.
#[allow(dead_code)]
const _NOT_IMPLEMENTED: u8 = exit::NOT_IMPLEMENTED;
