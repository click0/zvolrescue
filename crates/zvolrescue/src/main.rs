//! `zvolrescue` command-line interface.
//!
//! Command surface and exit codes follow `docs/SPEC.md` §7. Commands that
//! are not implemented yet say so and exit with [`exit::NOT_IMPLEMENTED`].

mod evidence;
mod scan;
mod timefmt;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Exit codes from SPEC §7.
pub mod exit {
    /// Usage error.
    pub const USAGE: u8 = 1;
    /// Evidence unreadable.
    pub const EVIDENCE: u8 = 2;
    /// Pool unrecoverable at the requested TXG.
    pub const UNRECOVERABLE: u8 = 3;
    /// Extraction completed with errors (`--strict`).
    pub const PARTIAL: u8 = 4;
    /// Refused: the operation would write to evidence.
    pub const REFUSED: u8 = 5;
    /// Command exists in the spec but is not implemented in this build.
    pub const NOT_IMPLEMENTED: u8 = 64;
}

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable text.
    Text,
    /// One JSON document on stdout.
    Json,
}

/// Global options shared by every command.
#[derive(Debug, Args)]
pub struct Global {
    /// Output format.
    #[arg(short = 'f', long, global = true, value_enum, default_value_t = Format::Text)]
    pub format: Format,
    /// Increase verbosity (repeatable).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Suppress non-essential output.
    #[arg(short, long, global = true)]
    pub quiet: bool,
    /// Append a JSON Lines evidence log to FILE.
    #[arg(long, global = true, value_name = "FILE")]
    pub evidence_log: Option<PathBuf>,
    /// Disable colour in text output.
    #[arg(long, global = true)]
    pub no_color: bool,
}

/// Open-source ZFS forensic & recovery utility. Never writes to evidence.
#[derive(Debug, Parser)]
#[command(name = "zvolrescue", version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    global: Global,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Detect ZFS labels and uberblocks on devices or image files.
    Scan {
        /// Devices, partitions or image files.
        #[arg(required = true, value_name = "DEV")]
        devices: Vec<PathBuf>,
    },
    /// Dump label nvlists (best copy, or all four).
    Labels {
        /// Device or image file.
        device: PathBuf,
        /// Show all four labels instead of the best one.
        #[arg(long)]
        all: bool,
    },
    /// Show the uberblock ring of every label.
    Uberblocks {
        /// Device or image file.
        device: PathBuf,
        /// Also list corrupt ring slots (bad magic).
        #[arg(long)]
        all: bool,
    },
    /// Assembled pool summary and health.
    Pool(PoolSpec),
    /// List datasets, zvols and snapshots at a TXG.
    List(PoolSpec),
    /// TXG ↔ time ↔ dataset events.
    Timeline(PoolSpec),
    /// Extract a zvol (or an object dump of a filesystem) to a file.
    Dump(PoolSpec),
    /// Find and reconstruct unlinked datasets.
    Carve(PoolSpec),
    /// Check every block pointer checksum of a dataset.
    Verify(PoolSpec),
    /// Consolidated forensic report.
    Report(PoolSpec),
}

/// Members of a pool, given as devices and/or images (SPEC §7 `POOLSPEC`).
#[derive(Debug, Args)]
pub struct PoolSpec {
    /// Devices or partitions that are members of the pool.
    #[arg(value_name = "DEV")]
    pub devices: Vec<PathBuf>,
    /// Image files that are members of the pool (repeatable).
    #[arg(long, value_name = "FILE")]
    pub image: Vec<PathBuf>,
    /// Select a pool by GUID when several are found.
    #[arg(long, value_name = "GUID")]
    pub pool_guid: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::Scan { devices } => scan::run(&cli.global, &devices, false, false),
        Cmd::Uberblocks { device, all } => scan::run(&cli.global, &[device], true, all),
        Cmd::Labels { .. }
        | Cmd::Pool(_)
        | Cmd::List(_)
        | Cmd::Timeline(_)
        | Cmd::Dump(_)
        | Cmd::Carve(_)
        | Cmd::Verify(_)
        | Cmd::Report(_) => {
            eprintln!(
                "zvolrescue: this command is specified (docs/SPEC.md §7) but not implemented yet; \
                 see the delivery phases in §10"
            );
            exit::NOT_IMPLEMENTED
        }
    };
    ExitCode::from(code)
}
