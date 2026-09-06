//! `zvolrescue` command-line interface.
//!
//! Exactly three commands — `scan`, `list`, `dump` — as fixed by
//! `docs/SPEC.md` §3.0 and §7. Commands that are not implemented yet say so
//! and exit with [`exit::NOT_IMPLEMENTED`].

mod evidence;
mod list;
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
    /// What is on these devices or images: labels, uberblocks, TXG window.
    ///
    /// `-v` adds the uberblock ring of every label (including corrupt
    /// slots), `-vv` will add the label nvlists once the parser lands.
    Scan {
        /// Devices, partitions or image files.
        #[arg(required = true, value_name = "DEV")]
        devices: Vec<PathBuf>,
    },
    /// List datasets, zvols and snapshots at a TXG.
    List {
        #[command(flatten)]
        pool: PoolSpec,
        /// Transaction group to read (default: newest valid).
        #[arg(long, value_name = "N", conflicts_with = "before")]
        txg: Option<u64>,
        /// Newest TXG synced at or before this time (RFC 3339 or unix seconds).
        #[arg(long, value_name = "TS")]
        before: Option<String>,
        /// Also show what was created or destroyed relative to this TXG.
        #[arg(long, value_name = "TXG2")]
        diff: Option<u64>,
        /// Also list snapshots.
        #[arg(short, long)]
        recursive: bool,
    },
    /// Extract a zvol (or an object dump of a filesystem) to a raw sparse image.
    ///
    /// The dataset comes first so that the variable-length list of pool
    /// members can follow it: `dump DATASET DEV... [--image FILE]...`.
    Dump {
        /// Dataset to extract, e.g. pool/vm/disk0.
        #[arg(value_name = "DATASET")]
        dataset: String,
        #[command(flatten)]
        pool: PoolSpec,
        /// Output image file. Refused if it resolves onto an input device.
        #[arg(short, long, value_name = "OUT.img")]
        output: PathBuf,
        /// Transaction group to read (default: newest that still has DATASET).
        #[arg(long, value_name = "N")]
        txg: Option<u64>,
        /// Abort on the first unreadable block instead of writing zeros.
        #[arg(long)]
        strict: bool,
        /// Encryption key: raw:FILE | hex:HEX | passphrase:FILE | prompt.
        #[arg(long, value_name = "KEYSPEC")]
        key: Option<String>,
        /// Continue an interrupted extraction of the same dataset and TXG.
        #[arg(long)]
        resume: bool,
    },
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

impl PoolSpec {
    /// All members in command-line order, or a usage error when none were given.
    pub fn members(&self) -> Result<Vec<PathBuf>, String> {
        let all: Vec<PathBuf> = self.devices.iter().chain(&self.image).cloned().collect();
        if all.is_empty() {
            return Err("no pool members given: name devices and/or --image FILE".into());
        }
        Ok(all)
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::Scan { devices } => scan::run(&cli.global, &devices),
        Cmd::List {
            pool,
            txg,
            before,
            diff,
            recursive,
        } => list::run(
            &cli.global,
            &pool,
            &list::Options {
                txg,
                before,
                diff,
                recursive,
            },
        ),
        Cmd::Dump { pool, .. } => {
            if let Err(e) = pool.members() {
                eprintln!("zvolrescue: {e}");
                return ExitCode::from(exit::USAGE);
            }
            eprintln!(
                "zvolrescue: this command is specified (docs/SPEC.md §7) but not implemented yet; \
                 it arrives with phase 1 (§10)"
            );
            exit::NOT_IMPLEMENTED
        }
    };
    ExitCode::from(code)
}
