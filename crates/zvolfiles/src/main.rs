//! `zvolfiles` — files out of filesystem datasets.
//!
//! The main binary treats a filesystem dataset as an object dump at
//! most. This one understands the ZFS POSIX layer: directories, files,
//! symlinks, ownership and timestamps — and, when the POSIX metadata is
//! too damaged to walk, falls back to one file per object so the
//! contents are still recoverable (COMPANIONS §5).
//!
//! Read-only: members are opened `O_RDONLY`, and the only thing written
//! is the output directory.

mod common;
mod extract;
mod list;
mod objects;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use zvol_common::{exit, Global, PoolSpec};

/// Read a filesystem dataset as files and directories.
#[derive(Debug, Parser)]
#[command(name = "zvolfiles", version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    global: Global,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show what is in the dataset.
    List {
        /// Dataset to read, e.g. tank/home.
        #[arg(value_name = "DATASET")]
        dataset: String,
        #[command(flatten)]
        pool: PoolSpec,
        #[command(flatten)]
        at: common::AtArgs,
        /// Path inside the dataset; the root when absent.
        ///
        /// A flag rather than a trailing word: the member list is
        /// variable-length, so a bare path after it could not be told
        /// from another member.
        #[arg(long, value_name = "PATH")]
        path: Option<std::ffi::OsString>,
        /// Descend into subdirectories.
        #[arg(short = 'R', long)]
        recursive: bool,
    },
    /// Write the tree out as files.
    Extract {
        /// Dataset to read.
        #[arg(value_name = "DATASET")]
        dataset: String,
        #[command(flatten)]
        pool: PoolSpec,
        #[command(flatten)]
        at: common::AtArgs,
        /// Path inside the dataset, repeatable; everything when absent.
        ///
        /// A flag rather than trailing words: the member list is
        /// variable-length, so a bare path after it could not be told
        /// from another member.
        #[arg(long = "path", value_name = "PATH")]
        paths: Vec<std::ffi::OsString>,
        /// Write the tree here.
        #[arg(short, long, value_name = "DIR")]
        output: PathBuf,
        /// Stop at the first block that cannot be read.
        #[arg(long)]
        strict: bool,
        /// Metadata to restore: any of `times`, `mode` (comma-separated).
        #[arg(long, value_name = "LIST", default_value = "times,mode")]
        preserve: String,
    },
    /// One file per object, for when the POSIX metadata is gone.
    Objects {
        /// Dataset to read.
        #[arg(value_name = "DATASET")]
        dataset: String,
        #[command(flatten)]
        pool: PoolSpec,
        #[command(flatten)]
        at: common::AtArgs,
        /// Write the objects here.
        #[arg(short, long, value_name = "DIR")]
        output: PathBuf,
        /// Stop at the first block that cannot be read.
        #[arg(long)]
        strict: bool,
    },
}

fn main() -> ExitCode {
    zvol_common::quiet_broken_pipe();
    let cli = Cli::parse();
    if let Err(code) = cli.global.enable_tracing("zvolfiles") {
        return ExitCode::from(code);
    }
    let code = match cli.command {
        Command::List {
            dataset,
            pool,
            at,
            path,
            recursive,
        } => list::run(
            &cli.global,
            &pool,
            &dataset,
            &at,
            path.as_deref(),
            recursive,
        ),
        Command::Extract {
            dataset,
            pool,
            at,
            paths,
            output,
            strict,
            preserve,
        } => extract::run(
            &cli.global,
            &pool,
            &dataset,
            &at,
            &extract::Options {
                paths,
                output,
                strict,
                preserve,
            },
        ),
        Command::Objects {
            dataset,
            pool,
            at,
            output,
            strict,
        } => objects::run(&cli.global, &pool, &dataset, &at, &output, strict),
    };
    ExitCode::from(code)
}

/// Kept for the same reason the main binary keeps it: so a build that
/// forgets a phase says so instead of doing something surprising.
#[allow(dead_code)]
const _NOT_IMPLEMENTED: u8 = exit::NOT_IMPLEMENTED;
