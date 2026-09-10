//! `zvoltimeline` — what happened to this pool, and when.
//!
//! Every transaction group whose uberblock still verifies is a snapshot of
//! the pool as it was at that moment. Read consecutively, they say when a
//! dataset appeared, when it was renamed, and — the question that brings
//! most people here — at which transaction group something was destroyed,
//! and which one still had it (COMPANIONS §2).
//!
//! Read-only like everything in this workspace: it opens members through
//! the same code the main binary does, and writes nothing but its report.

mod events;
mod report;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use zvol_common::{exit, Global, PoolSpec};

/// Turn the surviving transaction groups into a history of the pool.
#[derive(Debug, Parser)]
#[command(name = "zvoltimeline", version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    global: Global,
    #[command(flatten)]
    pool: PoolSpec,
    /// Oldest transaction group to read (default: the oldest that verifies).
    #[arg(long, value_name = "TXG")]
    from: Option<u64>,
    /// Newest transaction group to read (default: the newest that verifies).
    #[arg(long, value_name = "TXG")]
    to: Option<u64>,
    /// Only events about this object: a dataset name at any TXG, or a GUID.
    #[arg(long, value_name = "NAME|GUID")]
    dataset: Option<String>,
    /// Write the report to FILE instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Err(code) = cli.global.enable_tracing("zvoltimeline") {
        return ExitCode::from(code);
    }
    ExitCode::from(report::run(
        &cli.global,
        &cli.pool,
        &report::Options {
            from: cli.from,
            to: cli.to,
            dataset: cli.dataset,
            output: cli.output,
        },
    ))
}

/// Kept for the same reason the main binary keeps it: so a build that
/// forgets a phase says so instead of doing something surprising.
#[allow(dead_code)]
const _NOT_IMPLEMENTED: u8 = exit::NOT_IMPLEMENTED;
