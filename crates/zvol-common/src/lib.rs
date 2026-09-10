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
    /// A long scan was interrupted and left a resumable state file
    /// (COMPANIONS §1.2).
    pub const INTERRUPTED: u8 = 6;
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
    /// Also record the SHA-256 of every input in the evidence log.
    ///
    /// Off by default: hashing a shelf of disk images means reading all
    /// of them through, which can take hours. Outputs are always hashed.
    #[arg(long, global = true)]
    pub hash_inputs: bool,
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

impl Global {
    /// Turn on the read trace when `--debug`/`--debug-log` asked for it.
    ///
    /// Returns the exit code to use when the log file cannot be created,
    /// so a caller can `return` it: a run that was asked to record what
    /// it did must not silently do it without recording.
    pub fn enable_tracing(&self, tool: &str) -> Result<(), u8> {
        if !self.debug && self.debug_log.is_none() {
            return Ok(());
        }
        let file = match &self.debug_log {
            Some(p) => match std::fs::File::create(p) {
                Ok(f) => Some(f),
                Err(e) => {
                    eprintln!("{tool}: cannot create debug log {}: {e}", p.display());
                    return Err(exit::USAGE);
                }
            },
            None => None,
        };
        zvolrescue_io::trace::enable(file);
        zvolrescue_io::trace!("cli", "{}", std::env::args().collect::<Vec<_>>().join(" "));
        Ok(())
    }
}

impl Global {
    /// Append this run to the evidence log, when one was asked for, and
    /// give back the exit code to use.
    ///
    /// A run that was asked to record what it did and could not is a
    /// usage error, not a success: the record is part of the result.
    pub fn log_evidence(
        &self,
        tool: &str,
        result: &serde_json::Value,
        status: u8,
        inputs: &[PathBuf],
        outputs: Vec<evidence::FileRef>,
    ) -> u8 {
        let Some(log) = &self.evidence_log else {
            return status;
        };
        let rec = evidence::Record::new(tool, result, status)
            .with_inputs(inputs, self.hash_inputs)
            .with_outputs(outputs);
        if let Err(e) = evidence::append(log, &rec) {
            eprintln!("{tool}: cannot write evidence log {}: {e}", log.display());
            return exit::USAGE;
        }
        status
    }
}

/// Quote one argument for a POSIX shell.
///
/// A command line printed for someone to paste has to survive the paste:
/// a device under `/dev/disk/by-id/` is fine bare, an image called
/// `vm disk.img` is not.
pub fn shell_quote(s: &str) -> String {
    let safe = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/=@:+,-".contains(&b));
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
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

    /// The spec written back out as command-line arguments.
    ///
    /// What made a pool readable in this run is what makes it readable in
    /// the next one: a recovery command printed for the operator that
    /// dropped `--hints` or `--assume-member` would name a dataset nobody
    /// can reach. Arguments come out in the order a command takes them,
    /// quoted for a POSIX shell.
    pub fn as_arguments(&self) -> Vec<String> {
        let mut args = Vec::new();
        for d in &self.devices {
            args.push(shell_quote(&d.display().to_string()));
        }
        for i in &self.image {
            args.push("--image".into());
            args.push(shell_quote(&i.display().to_string()));
        }
        if let Some(h) = &self.hints {
            args.push("--hints".into());
            args.push(shell_quote(&h.display().to_string()));
        }
        if self.search_order {
            args.push("--search-order".into());
        }
        if let Some(g) = &self.pool_guid {
            args.push("--pool-guid".into());
            args.push(shell_quote(g));
        }
        for a in &self.assume_member {
            args.push("--assume-member".into());
            args.push(shell_quote(a));
        }
        args
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        pool: PoolSpec,
    }

    fn spec(args: &[&str]) -> PoolSpec {
        Cli::parse_from(std::iter::once("t").chain(args.iter().copied())).pool
    }

    #[test]
    fn a_plain_path_is_left_alone() {
        assert_eq!(
            shell_quote("/dev/disk/by-id/ata-X_1-part1"),
            "/dev/disk/by-id/ata-X_1-part1"
        );
    }

    #[test]
    fn anything_a_shell_would_read_is_quoted() {
        assert_eq!(shell_quote("vm disk.img"), "'vm disk.img'");
        assert_eq!(shell_quote("a$b"), "'a$b'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    /// A printed command has to reach the pool the same way this run did:
    /// every part of the specification comes back out.
    #[test]
    fn the_spec_comes_back_as_the_arguments_it_was_given() {
        let s = spec(&[
            "/dev/sda1",
            "--image",
            "/tmp/b.img",
            "--hints",
            "/tmp/layout.json",
            "--search-order",
            "--pool-guid",
            "0x1234",
            "--assume-member",
            "/dev/sdc1=0xabc",
        ]);
        assert_eq!(
            s.as_arguments(),
            [
                "/dev/sda1",
                "--image",
                "/tmp/b.img",
                "--hints",
                "/tmp/layout.json",
                "--search-order",
                "--pool-guid",
                "0x1234",
                "--assume-member",
                "/dev/sdc1=0xabc",
            ]
        );
    }

    #[test]
    fn a_member_whose_name_needs_quoting_is_quoted() {
        let s = spec(&["--image", "/tmp/vm disk.img"]);
        assert_eq!(s.as_arguments(), ["--image", "'/tmp/vm disk.img'"]);
    }

    #[test]
    fn a_guid_may_be_given_with_or_without_the_prefix() {
        let s = spec(&["/dev/sda1", "--assume-member", "/dev/sdb1=abc"]);
        assert_eq!(s.assumed().unwrap(), [("/dev/sdb1".into(), Some(0xabc))]);
    }
}
