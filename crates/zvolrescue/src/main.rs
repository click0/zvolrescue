//! `zvolrescue` command-line interface.
//!
//! Exactly three commands — `scan`, `list`, `dump` — as fixed by
//! `docs/SPEC.md` §3.0 and §7. Options whose phase has not arrived yet say
//! so and exit with [`exit::NOT_IMPLEMENTED`].

mod dump;
mod list;
mod scan;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use zvol_common::{exit, Global, PoolSpec};

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
        /// Describe the layout by hand (SPEC F-65): the JSON template
        /// `--emit-label` turns into a label.
        #[arg(long, value_name = "FILE")]
        hints: Option<PathBuf>,
        /// Write the label the layout describes for one member to FILE:
        /// a 256 KiB image with the configuration nvlist sealed for its
        /// label position, to place on a *copy* of the disk (SPEC F-67).
        /// The geometry goes to FILE.json beside it. Nothing is ever
        /// written to the evidence.
        #[arg(long, value_name = "FILE", requires = "hints")]
        emit_label: Option<PathBuf>,
        /// Which member of the layout the emitted label belongs to, as
        /// `TOP:LEAF` (default `0:0`).
        #[arg(long, value_name = "TOP:LEAF", requires = "emit_label")]
        emit_for: Option<String>,
        /// Which of the four label positions to seal the emitted label
        /// for (default 0). A label verifies only at the offset it was
        /// sealed for.
        #[arg(long, value_name = "N", requires = "emit_label")]
        emit_label_index: Option<usize>,
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
            hints,
            emit_label,
            emit_for,
            emit_label_index,
        } => scan::run(
            &cli.global,
            &devices,
            &scan::ZeroPointOpts {
                always: zero_point || zero_point_whole || !psize.is_empty(),
                whole: zero_point_whole,
                psize_hints: psize,
            },
            &scan::EmitOpts {
                hints,
                emit_label,
                emit_for,
                emit_label_index,
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
