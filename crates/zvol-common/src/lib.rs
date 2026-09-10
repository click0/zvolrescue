//! What every zvolrescue binary shares (COMPANIONS §1).
//!
//! The main binary and each companion take the same arguments, use the
//! same exit codes, open members the same way — including the recovery
//! paths for labels that are gone (SPEC F-61, F-62, F-65) — and write the
//! same evidence records. That contract lives here so there is one copy
//! of it, and so a companion cannot drift from it by accident.

pub mod evidence;
pub mod hints;
pub mod members;
pub mod timefmt;

use std::path::PathBuf;

use clap::{Args, ValueEnum};

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

/// Members of a pool, given as devices and/or images (SPEC §7 `POOLSPEC`).
#[derive(Debug, Args)]
pub struct PoolSpec {
    /// Devices or partitions that are members of the pool.
    #[arg(value_name = "DEV")]
    pub devices: Vec<PathBuf>,
    /// Image files that are members of the pool (repeatable).
    #[arg(long, value_name = "FILE")]
    pub image: Vec<PathBuf>,
    /// Describe the layout by hand when the labels cannot: a JSON file
    /// with ashift, the top-level vdevs and their members in vdev order
    /// (SPEC F-65). Used exactly as a label would be; every block read
    /// through it is still verified by its checksum.
    #[arg(long, value_name = "FILE")]
    pub hints: Option<PathBuf>,
    /// Try every member order the layout leaves open and keep the one the
    /// checksums accept (SPEC F-66). Only for raidz/draid, where order is
    /// what a DVA addresses.
    #[arg(long, requires = "hints")]
    pub search_order: bool,
    /// Select a pool by GUID when several are found.
    #[arg(long, value_name = "GUID")]
    pub pool_guid: Option<String>,
    /// Treat a member whose labels are gone as a leaf the configuration
    /// says is missing: `PATH` when only one leaf is missing, or
    /// `PATH=GUID` to name it. Repeatable. Nothing is taken on trust —
    /// every block read through it is still verified by its checksum.
    #[arg(long, value_name = "PATH[=GUID]")]
    pub assume_member: Vec<String>,
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

    /// `--assume-member` as `(path, leaf guid)` pairs.
    pub fn assumed(&self) -> Result<Vec<(PathBuf, Option<u64>)>, String> {
        self.assume_member
            .iter()
            .map(|spec| match spec.split_once('=') {
                None => Ok((PathBuf::from(spec), None)),
                Some((path, guid)) => {
                    let g = guid.trim().trim_start_matches("0x");
                    let g = u64::from_str_radix(g, 16)
                        .map_err(|_| format!("--assume-member {spec}: GUID must be hexadecimal"))?;
                    Ok((PathBuf::from(path), Some(g)))
                }
            })
            .collect()
    }
}
