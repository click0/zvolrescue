//! `zvolrescue` command-line interface.
//!
//! Exactly three commands — `scan`, `list`, `dump` — as fixed by
//! `docs/SPEC.md` §3.0 and §7. Options whose phase has not arrived yet say
//! so and exit with [`exit::NOT_IMPLEMENTED`].

mod dump;
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
    /// Trace every read decision (labels, uberblocks, blocks, dnodes, ZAPs,
    /// DSL walk) with hex dumps on failures, to stderr.
    #[arg(long, global = true)]
    pub debug: bool,
    /// Write the --debug trace to FILE instead of stderr (implies --debug).
    #[arg(long, global = true, value_name = "FILE")]
    pub debug_log: Option<PathBuf>,
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
        /// Search for the vdev's zero point even when its labels are
        /// readable. The search runs by itself on a member whose four
        /// label configurations are all unusable.
        #[arg(long)]
        zero_point: bool,
        /// Search the whole member, not just its first and last 64 MiB.
        #[arg(long)]
        zero_point_whole: bool,
        /// Physical size to assume for the vdev when testing the rear
        /// label pair (repeatable); the front pair needs no hypothesis.
        #[arg(long, value_name = "BYTES")]
        psize: Vec<u64>,
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
        /// Output image file (a directory with -r). Refused if it resolves onto an input device.
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
        /// Continue an interrupted extraction of the same dataset and TXG
        /// (state is kept in OUT.img.resume.json while a run is in progress).
        #[arg(long)]
        resume: bool,
        /// Extract every volume under DATASET into the directory OUT, one
        /// image per volume plus manifest.json.
        #[arg(short, long)]
        recursive: bool,
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
    if cli.global.debug || cli.global.debug_log.is_some() {
        let file = match &cli.global.debug_log {
            Some(p) => match std::fs::File::create(p) {
                Ok(f) => Some(f),
                Err(e) => {
                    eprintln!("zvolrescue: cannot create debug log {}: {e}", p.display());
                    return ExitCode::from(exit::USAGE);
                }
            },
            None => None,
        };
        zvolrescue_io::trace::enable(file);
        zvolrescue_io::trace!(
            "cli",
            "zvolrescue {} argv {:?}",
            env!("CARGO_PKG_VERSION"),
            std::env::args().collect::<Vec<_>>()
        );
    }
    let code = match cli.cmd {
        Cmd::Scan {
            devices,
            zero_point,
            zero_point_whole,
            psize,
        } => scan::run(
            &cli.global,
            &devices,
            &scan::ZeroPointOpts {
                always: zero_point || zero_point_whole || !psize.is_empty(),
                whole: zero_point_whole,
                psize_hints: psize,
            },
        ),
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
        Cmd::Dump {
            dataset,
            pool,
            output,
            txg,
            strict,
            key,
            resume,
            recursive,
        } => dump::run(
            &cli.global,
            &pool,
            &dump::Options {
                dataset,
                output,
                txg,
                strict,
                key,
                resume,
                recursive,
            },
        ),
    };
    ExitCode::from(code)
}
