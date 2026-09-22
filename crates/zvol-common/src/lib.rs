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
pub mod resume;
pub mod timefmt;

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock};

use clap::{Args, ValueEnum};
use zvolrescue_io::medium::{Incident, Ledger};
use zvolrescue_io::{ddrescue, FileSource};

/// Exit codes from SPEC §7.
pub mod exit {
    /// Usage error.
    pub const USAGE: u8 = 1;
    /// Evidence unreadable.
    pub const EVIDENCE: u8 = 2;
    /// Pool unrecoverable at the requested TXG.
    pub const UNRECOVERABLE: u8 = 3;
    /// The image is not the whole volume: blocks were written as zeros
    /// because they could not be read, or `--strict` aborted at the
    /// first one. Either way the run says so in its output; this is so
    /// that a caller reading only the status is told too.
    pub const PARTIAL: u8 = 4;
    /// Refused: the operation would write to evidence.
    pub const REFUSED: u8 = 5;
    /// A long scan was interrupted and left a resumable state file
    /// (COMPANIONS §1.2).
    pub const INTERRUPTED: u8 = 6;
    /// The medium refused a read: a device, not an image, returned an
    /// I/O error and the run stopped there (SPEC F-33, N-10). The
    /// incident is on stderr and in the evidence record; the disk is
    /// for an imager now.
    pub const MEDIUM: u8 = 7;
    /// Command exists in the spec but is not implemented in this build.
    pub const NOT_IMPLEMENTED: u8 = 64;

    /// The status an extraction ends with, given how it went and what an
    /// earlier volume of the same run already produced.
    ///
    /// Blocks written as zeros, or an abort at the first one, make the
    /// image not the volume: that is [`PARTIAL`]. A code is never
    /// lowered — with `-r`, a volume refused earlier ([`REFUSED`]) is not
    /// overwritten by one that was merely partial, which is the mistake
    /// this replaces.
    pub fn after_extraction(prior: u8, aborted: bool, blocks_zeroed: u64) -> u8 {
        if aborted || blocks_zeroed > 0 {
            prior.max(PARTIAL)
        } else {
            prior
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_whole_image_leaves_the_code_alone() {
            assert_eq!(after_extraction(0, false, 0), 0);
            assert_eq!(after_extraction(UNRECOVERABLE, false, 0), UNRECOVERABLE);
        }

        #[test]
        fn zeros_or_an_abort_make_it_partial_without_strict() {
            assert_eq!(after_extraction(0, false, 1), PARTIAL);
            assert_eq!(after_extraction(0, true, 0), PARTIAL);
        }

        /// The bug this function replaced: `-r` with a refused volume
        /// and then a partial one came out 4, not 5.
        #[test]
        fn a_partial_volume_never_lowers_what_an_earlier_one_produced() {
            assert_eq!(after_extraction(REFUSED, false, 3), REFUSED);
            assert_eq!(after_extraction(INTERRUPTED, true, 0), INTERRUPTED);
            assert_eq!(after_extraction(UNRECOVERABLE, false, 1), PARTIAL);
        }
    }
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

/// Leave a pipeline quietly when the far end has gone away.
///
/// `zvolcarve list DIR | head -4` closes the pipe as soon as it has its
/// four lines, and the writes that follow fail with `EPIPE`. Rust turns
/// that into a panic: a backtrace on stderr and exit 101, for an
/// operator who did nothing wrong. `head` is not an error, and neither
/// is quitting `less` half way down a candidate list — so a write that
/// fails for that one reason ends the run with 0 and says nothing.
///
/// It is a panic hook rather than the usual `signal(SIGPIPE, SIG_DFL)`
/// because this workspace forbids `unsafe` and links no system
/// libraries. Nothing else is caught: every other panic reaches the
/// hook that was there before, message and all.
///
/// Call it first thing in `main`, before anything can print.
pub fn quiet_broken_pipe() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        if is_broken_pipe_panic(message) {
            std::process::exit(0);
        }
        previous(info);
    }));
}

/// Whether an I/O error is the reader on the other end having gone away.
///
/// The companion to [`quiet_broken_pipe`], for the writes that do not go
/// through `println!`. A tool that builds its report into an explicit
/// sink gets an `Err` rather than a panic, and turning that into "writing
/// the report failed" is the same lie in a different shape: `head` closing
/// the pipe is not a failed run.
pub fn is_broken_pipe(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::BrokenPipe
}

/// Whether a panic message is std's "the reader has gone" and nothing
/// else.
///
/// The message std raises is `failed printing to stdout: {e}`. The errno
/// is what is matched and not the text beside it: 32 is `EPIPE` on Linux
/// and on FreeBSD alike, while the words `strerror` puts there belong to
/// whatever locale happens to be set.
fn is_broken_pipe_panic(message: &str) -> bool {
    message.starts_with("failed printing to std") && message.contains("os error 32")
}

#[cfg(test)]
mod broken_pipe_tests {
    use super::is_broken_pipe_panic;

    /// The message the runtime actually produced when `zvolcarve list`
    /// was piped into `head -4`, kept verbatim.
    #[test]
    fn the_message_a_closed_pipe_really_gives() {
        assert!(is_broken_pipe_panic(
            "failed printing to stdout: Broken pipe (os error 32)"
        ));
        assert!(is_broken_pipe_panic(
            "failed printing to stderr: Broken pipe (os error 32)"
        ));
    }

    /// The other half of the same story: a write that returns an error
    /// rather than panicking. `zvoltimeline` builds its report into an
    /// explicit sink, so a closed pipe reached it as `Err` and was
    /// reported as "writing the report failed" with exit 1 — which is
    /// what the CI step caught after it was made to say what it saw.
    #[test]
    fn a_closed_pipe_is_recognised_as_an_error_too() {
        use std::io::{Error, ErrorKind};
        assert!(super::is_broken_pipe(&Error::from(ErrorKind::BrokenPipe)));
        for other in [
            ErrorKind::NotFound,
            ErrorKind::PermissionDenied,
            ErrorKind::WriteZero,
            ErrorKind::UnexpectedEof,
        ] {
            assert!(!super::is_broken_pipe(&Error::from(other)), "{other:?}");
        }
    }

    /// Everything else is somebody else's panic and must be left alone:
    /// swallowing one would turn a real fault into a silent exit 0.
    #[test]
    fn nothing_else_is_swallowed() {
        for other in [
            "",
            "a full disk is not a closed pipe",
            "failed printing to stdout: No space left on device (os error 28)",
            "called `Option::unwrap()` on a `None` value",
            "assertion failed: os error 32",
        ] {
            assert!(!is_broken_pipe_panic(other), "{other:?}");
        }
    }
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
        self.log_evidence_with_incidents(tool, result, status, inputs, outputs, &[])
    }

    /// [`log_evidence`](Self::log_evidence), with the device reads the
    /// run had refused on the record (SPEC F-33, N-10).
    pub fn log_evidence_with_incidents(
        &self,
        tool: &str,
        result: &serde_json::Value,
        status: u8,
        inputs: &[PathBuf],
        outputs: Vec<evidence::FileRef>,
        incidents: &[Incident],
    ) -> u8 {
        let Some(log) = &self.evidence_log else {
            return status;
        };
        let rec = evidence::Record::new(tool, result, status)
            .with_inputs(inputs, self.hash_inputs)
            .with_outputs(outputs)
            .with_incidents(incidents);
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
    /// Read a pool whose active feature flags this build cannot account
    /// for (SPEC F-70).
    ///
    /// Without this the run refuses and names them. With it the pool is
    /// read as though the features were not there, which can be wrong in
    /// a way no checksum objects to: a reflowed raidz hands back the
    /// checksums of other blocks, and they agree.
    #[arg(long)]
    pub ignore_unknown_features: bool,
    /// The GNU ddrescue mapfile an image was made with, as
    /// `MEMBER=MAPFILE` (SPEC F-72). Repeatable. Sectors the imager
    /// could not read are refused before they are read, so a block that
    /// crosses them is kept as far as the imager did read it and the
    /// rest is zeros with the reason — not a checksum failure with none.
    #[arg(long, value_name = "MEMBER=MAPFILE")]
    pub map: Vec<String>,
    /// Go on after a device refuses a read (SPEC F-33, N-10). Without
    /// this the first refused read on a device stops the run with exit
    /// 7, and the disk is for an imager. With it the refused range is
    /// skipped once — zeros, the reason logged, nothing read twice — and
    /// the run stops anyway after 8 incidents. For the operator who has
    /// weighed it and needs one small object off a disk that cannot be
    /// imaged.
    #[arg(long)]
    pub device_may_fail: bool,
    /// Search the surface of a block device — for uberblock anchors when
    /// its labels are gone, for a root when no uberblock survives, for
    /// carving (SPEC N-10). Refused without this: a surface scan is what
    /// a disk with defects survives least. Image the disk first, and
    /// scan the image.
    #[arg(long)]
    pub surface_scan_on_device: bool,
    /// The run's ledger of refused device reads (SPEC F-33, N-10): made
    /// once, shared by every member opened from this spec, and read at
    /// the end of every run — the ones that failed while opening or
    /// before writing a byte included — so that a device's refusal is
    /// on stderr and in the evidence record whichever way the run ended.
    #[arg(skip)]
    pub run_ledger: std::sync::OnceLock<Arc<Ledger>>,
}

/// How members are opened: what a device's refusal does, whether its
/// surface may be searched, and what an imager's map says of an image
/// (SPEC N-10, F-33, F-72).
#[derive(Debug, Clone)]
pub struct OpenOpts {
    /// The run's ledger of refused device reads, shared by every member.
    pub ledger: Arc<Ledger>,
    /// `--surface-scan-on-device`.
    pub surface_scan_on_device: bool,
    /// `(member, mapfile)` pairs.
    pub maps: Vec<(PathBuf, PathBuf)>,
}

impl Default for OpenOpts {
    fn default() -> Self {
        OpenOpts {
            ledger: Arc::new(Ledger::stop_at_first()),
            surface_scan_on_device: false,
            maps: Vec::new(),
        }
    }
}

impl OpenOpts {
    /// Parse `MEMBER=MAPFILE` specs and set the medium policy.
    pub fn parse(
        device_may_fail: bool,
        surface_scan_on_device: bool,
        maps: &[String],
    ) -> Result<OpenOpts, String> {
        let ledger = Arc::new(if device_may_fail {
            Ledger::may_fail()
        } else {
            Ledger::stop_at_first()
        });
        Self::with_ledger(ledger, surface_scan_on_device, maps)
    }

    /// Parse `MEMBER=MAPFILE` specs onto a ledger the run already has.
    pub fn with_ledger(
        ledger: Arc<Ledger>,
        surface_scan_on_device: bool,
        maps: &[String],
    ) -> Result<OpenOpts, String> {
        let maps = maps
            .iter()
            .map(|spec| match spec.split_once('=') {
                Some((m, f)) if !m.is_empty() && !f.is_empty() => {
                    Ok((PathBuf::from(m), PathBuf::from(f)))
                }
                _ => Err(format!("--map {spec}: want MEMBER=MAPFILE")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(OpenOpts {
            ledger,
            surface_scan_on_device,
            maps,
        })
    }

    /// The mapfiles, for the evidence record: they are inputs too.
    pub fn map_files(&self) -> Vec<PathBuf> {
        self.maps.iter().map(|(_, f)| f.clone()).collect()
    }

    /// Open `path` read-only on the run's ledger and, when one was named
    /// for it, with its imager's map.
    pub fn open(&self, path: &Path) -> std::io::Result<FileSource> {
        let mut src = FileSource::open(path)?.with_ledger(self.ledger.clone());
        if let Some((_, file)) = self.maps.iter().find(|(m, _)| m == path) {
            let text = std::fs::read_to_string(file)
                .map_err(|e| std::io::Error::other(format!("--map {}: {e}", file.display())))?;
            let map = ddrescue::Map::parse(&text)
                .map_err(|e| std::io::Error::other(format!("--map {}: {e}", file.display())))?;
            src = src.with_map(map);
        }
        Ok(src)
    }
}

impl PoolSpec {
    /// How the members are to be opened: on this spec's one ledger.
    pub fn open_opts(&self) -> Result<OpenOpts, String> {
        OpenOpts::with_ledger(self.ledger(), self.surface_scan_on_device, &self.map)
    }

    /// The run's ledger (SPEC F-33, N-10), made on first use with the
    /// medium policy the flags chose, and the same one every time after.
    pub fn ledger(&self) -> Arc<Ledger> {
        self.run_ledger
            .get_or_init(|| {
                Arc::new(if self.device_may_fail {
                    Ledger::may_fail()
                } else {
                    Ledger::stop_at_first()
                })
            })
            .clone()
    }

    /// Every file a run on this spec reads, for the evidence record:
    /// the members and the imagers' maps named for them (SPEC F-72).
    pub fn inputs(&self) -> Vec<PathBuf> {
        let mut v = self.members().unwrap_or_default();
        v.extend(
            self.map
                .iter()
                .filter_map(|m| m.split_once('=').map(|(_, f)| PathBuf::from(f))),
        );
        v
    }

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

/// The flag a SIGINT or SIGTERM sets, installed on first use.
///
/// A long extraction looks at it between blocks and ends there with its
/// state written, so `--resume` continues from the block it was about to
/// read (exit 6) — instead of the default action, which kills the run
/// with whatever the last five seconds' checkpoint said. A second signal
/// while the flag is already set is the default action after all: a run
/// that does not come round to the flag can still be stopped.
///
/// The same `Arc` comes back on every call; the handlers are installed
/// once, by the first.
pub fn interrupt_flag() -> Arc<AtomicBool> {
    static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    FLAG.get_or_init(|| {
        let flag = Arc::new(AtomicBool::new(false));
        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            // Order matters: the conditional default first, so that the
            // plain registration below is what sets the flag the first
            // time and the default runs only the second time.
            let _ = signal_hook::flag::register_conditional_default(signal, Arc::clone(&flag));
            let _ = signal_hook::flag::register(signal, Arc::clone(&flag));
        }
        flag
    })
    .clone()
}

/// Peak resident set of this process so far, in KiB (SPEC N-03): Linux
/// keeps it as `VmHWM` in `/proc/self/status`; elsewhere there is no
/// answer without a system call this workspace does not make.
pub fn peak_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

#[cfg(all(test, target_os = "linux"))]
mod rss_tests {
    #[test]
    fn linux_reports_a_peak_resident_set() {
        let kib = super::peak_rss_kib().expect("VmHWM in /proc/self/status");
        assert!(kib > 100, "{kib} KiB is not a running process");
    }
}

/// The end of every run, however it ended: the medium incidents on
/// stderr and the stop, when one stopped the run, as the exit code
/// (SPEC F-33, N-10); then the evidence record, with them. `code` is
/// what the run would otherwise end with.
pub fn end_run(
    g: &Global,
    tool: &str,
    result: &serde_json::Value,
    code: u8,
    inputs: &[PathBuf],
    written: Vec<evidence::FileRef>,
    ledger: &Ledger,
) -> u8 {
    let code = report_medium(ledger).unwrap_or(code);
    g.log_evidence_with_incidents(tool, result, code, inputs, written, &ledger.incidents())
}

/// [`end_run`] for a run that produced nothing: it failed opening or
/// choosing among the members, or before the first byte of output. A
/// device may have refused a read on the way, and that ends the run
/// the same way as one refused later — exit 7, the incident on stderr
/// and on record — instead of the bare code the failure came with.
pub fn end_early(g: &Global, tool: &str, spec: &PoolSpec, code: u8) -> u8 {
    let inputs = spec.inputs();
    let result = serde_json::json!({
        "members": inputs.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "produced": false,
    });
    end_run(g, tool, &result, code, &inputs, Vec::new(), &spec.ledger())
}

/// Say what the medium did, and what to do about it (SPEC F-33, N-10):
/// every incident of the run on stderr, and the stop — when one
/// stopped the run — with the way forward. Returns [`exit::MEDIUM`]
/// when the run was stopped, else `None`.
pub fn report_medium(ledger: &Ledger) -> Option<u8> {
    let incidents = ledger.incidents();
    if incidents.is_empty() {
        return None;
    }
    for i in &incidents {
        eprintln!(
            "zvolrescue: MEDIUM INCIDENT: {i}{}",
            if i.stopped {
                " — stopped here"
            } else {
                " — skipped (--device-may-fail)"
            }
        );
    }
    let stopped = ledger.stopped()?;
    eprintln!(
        "zvolrescue: {} refused a read and the run stopped there (SPEC F-33, N-10). \
         Nothing on it was read twice. This tool reads healthy media; a disk with \
         defects is for an imager: image it with a tool made for failing media, \
         with a map (ddrescue -d -r0 with a mapfile for the simple case; PC-3000 \
         Data Extractor or HDDSuperClone where the defect has to be understood \
         first), then continue on the image with --map IMAGE=MAPFILE and --resume.",
        stopped.path.display()
    );
    Some(exit::MEDIUM)
}

/// The incidents of a run as the evidence record carries them.
pub fn incidents_json(incidents: &[Incident]) -> Vec<serde_json::Value> {
    incidents
        .iter()
        .map(|i| {
            serde_json::json!({
                "path": i.path.display().to_string(),
                "offset": i.offset,
                "len": i.len,
                "lba": i.lba(),
                "sectors": i.sectors(),
                "error": i.error,
                "at": i.at,
                "stopped": i.stopped,
            })
        })
        .collect()
}
