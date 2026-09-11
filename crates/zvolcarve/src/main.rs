//! `zvolcarve` — find zvols that no uberblock points at any more.
//!
//! When the ring has rolled past the last transaction group that
//! referenced a dataset, there is no path from any uberblock down to its
//! dnode, and `zvolrescue list` cannot see it at any transaction group.
//! The blocks are usually still on the disk. This tool scans raw vdev
//! space for metadata that is recognisable on its own, ranks what it
//! finds, and extracts the candidate the operator picks — through
//! exactly the same code, and the same checksum verification, as
//! `zvolrescue dump` (COMPANIONS §3).
//!
//! Read-only: the members are opened `O_RDONLY` and the only thing
//! written is the carve workspace and the image asked for.

mod dump;
mod list;
mod model;
mod scan;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use zvol_common::{exit, Global, PoolSpec};

/// Scan raw vdev space for volumes nothing points at any more.
#[derive(Debug, Parser)]
#[command(name = "zvolcarve", version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    global: Global,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan the members and record what could be a volume.
    Scan {
        #[command(flatten)]
        pool: PoolSpec,
        /// Carve workspace: the candidate index and the resume state.
        #[arg(short, long, value_name = "DIR")]
        output: PathBuf,
        #[command(flatten)]
        profile: scan::ProfileArgs,
        /// Only this byte range of each member, as START-END.
        #[arg(long, value_name = "START-END")]
        range: Option<String>,
        /// Continue a scan that was interrupted.
        #[arg(long)]
        resume: bool,
        /// Read every block a candidate claims when ranking it, rather
        /// than a sample. Slow, and rarely worth it before a `dump`.
        #[arg(long)]
        full_assess: bool,
        /// Stop after this many candidates.
        #[arg(long, value_name = "N", default_value_t = 100_000)]
        max_hits: usize,
        /// Report what the first N hits look like instead of filtering,
        /// so a profile can be picked from the disk (C-19).
        #[arg(long, value_name = "N")]
        sample: Option<usize>,
        /// Compressions to try at each allocation-aligned offset:
        /// `lz4,lzjb,gzip,zstd` (the default), a subset, or `none` for
        /// the plaintext pass alone. Metadata is lz4 on any modern pool
        /// and lzjb on one made before the `lz4_compress` feature; each
        /// one costs a pass, and dropping the wrong one finds nothing.
        #[arg(long, value_name = "LIST", default_value = "lz4,lzjb,gzip,zstd")]
        compressed: String,
    },
    /// Show the candidates a previous scan found.
    List {
        /// The carve workspace.
        #[arg(value_name = "DIR")]
        dir: PathBuf,
    },
    /// Extract one candidate, verifying every block by its checksum.
    Dump {
        /// The carve workspace.
        #[arg(value_name = "DIR")]
        dir: PathBuf,
        /// Candidate id, as `list` prints it.
        #[arg(value_name = "CANDIDATE")]
        candidate: String,
        #[command(flatten)]
        pool: PoolSpec,
        /// Write the image here.
        #[arg(short, long, value_name = "OUT.img")]
        output: PathBuf,
        /// Stop at the first block that cannot be read.
        #[arg(long)]
        strict: bool,
        /// Extract this many bytes instead of what the dnode implies.
        #[arg(long, value_name = "BYTES")]
        size: Option<u64>,
    },
}

fn main() -> ExitCode {
    zvol_common::quiet_broken_pipe();
    let cli = Cli::parse();
    if let Err(code) = cli.global.enable_tracing("zvolcarve") {
        return ExitCode::from(code);
    }
    let code = match cli.command {
        Command::Scan {
            pool,
            output,
            profile,
            range,
            resume,
            full_assess,
            max_hits,
            sample,
            compressed,
        } => scan::run(
            &cli.global,
            &pool,
            &scan::Options {
                output,
                profile,
                range,
                resume,
                full_assess,
                max_hits,
                sample,
                compressed,
            },
        ),
        Command::List { dir } => list::run(&cli.global, &dir),
        Command::Dump {
            dir,
            candidate,
            pool,
            output,
            strict,
            size,
        } => dump::run(
            &cli.global,
            &pool,
            &dump::Options {
                dir,
                candidate,
                output,
                strict,
                size,
            },
        ),
    };
    ExitCode::from(code)
}

/// Kept for the same reason the main binary keeps it: so a build that
/// forgets a phase says so instead of doing something surprising.
#[allow(dead_code)]
const _NOT_IMPLEMENTED: u8 = exit::NOT_IMPLEMENTED;
