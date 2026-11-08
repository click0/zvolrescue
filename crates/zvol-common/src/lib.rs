//! What every zvolrescue binary shares (COMPANIONS §1).
//!
//! The main binary and each companion take the same arguments, use the
//! same exit codes, open members the same way — including the recovery
//! paths for labels that are gone (SPEC F-61, F-62, F-65) — and write the
//! same evidence records. That contract lives here so there is one copy
//! of it, and so a companion cannot drift from it by accident.

/// Print a message on standard error under the running program's name
/// ([`tool`]): the messages this crate prints on a tool's behalf used to
/// say `zvolrescue:` whichever of the five had printed them.
#[macro_export]
macro_rules! say {
    ($($arg:tt)*) => {
        eprintln!("{}: {}", $crate::tool(), format_args!($($arg)*))
    };
}

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
pub use zvolrescue_io::refuse_if_evidence;
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
mod command_line_paths_tests {
    use super::paths_on_command_line;
    use std::path::PathBuf;

    fn paths(args: &[&str]) -> Vec<PathBuf> {
        paths_on_command_line(args.iter().map(|a| a.into()))
    }

    #[test]
    fn every_word_that_may_be_a_file_is_named_and_the_logs_are_not() {
        let got = paths(&[
            "--debug-log",
            "trace.txt",
            "--evidence-log=case.jsonl",
            "-q",
            "dump",
            "tank/vm",
            "/dev/ada0p3",
            "--image=disk.img",
            "--map",
            "disk.img=disk.map",
            "--key",
            "passphrase:pw.txt",
            "hex:@hex.txt",
            "-o",
            "out.img",
        ]);
        for want in [
            "tank/vm",
            "/dev/ada0p3",
            "disk.img",
            "disk.map",
            "pw.txt",
            "hex.txt",
            "out.img",
        ] {
            assert!(
                got.contains(&PathBuf::from(want)),
                "{want} missing: {got:?}"
            );
        }
        for not in ["trace.txt", "case.jsonl", "-q", "--map", "-o"] {
            assert!(!got.contains(&PathBuf::from(not)), "{not} named: {got:?}");
        }
    }

    /// A file named in bytes that are not text is found; a path inside a
    /// dataset given with `--path` is not a file, and may be any bytes.
    #[cfg(unix)]
    #[test]
    fn a_file_name_that_is_not_text_is_found_and_a_dataset_path_is_not() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(b"m\xff.img".to_vec());
        let word = |s: &str| OsString::from(s);
        assert_eq!(
            super::file_name_not_text([word("list"), bad.clone()]),
            Some(bad.clone())
        );
        assert_eq!(
            super::file_name_not_text([
                word("extract"),
                word("--path"),
                bad.clone(),
                word("m0.img")
            ]),
            None
        );
        let mut eq = b"--path=".to_vec();
        eq.extend(b"caf\xe9.txt");
        assert_eq!(
            super::file_name_not_text([word("list"), OsString::from_vec(eq)]),
            None
        );
    }

    /// A value given as `--long=VALUE` is read like the same word on its
    /// own: `--map=M=F` names the mapfile and `--key=passphrase:FILE` the
    /// key file. Read whole, the first wrote a trace over the mapfile.
    #[test]
    fn a_value_after_an_equals_sign_is_read_like_a_word() {
        let got = paths(&[
            "--debug-log",
            "trace.txt",
            "scan",
            "--map=member0.img=m0.map",
            "--key=passphrase:pw.txt",
            "--key=hex:@hex.txt",
        ]);
        for want in ["member0.img", "m0.map", "pw.txt", "hex.txt"] {
            assert!(
                got.contains(&PathBuf::from(want)),
                "{want} missing: {got:?}"
            );
        }
    }
}

#[cfg(test)]
mod write_guard_tests {
    use super::*;

    fn global(debug_log: Option<&Path>, evidence_log: Option<&Path>) -> Global {
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            global: Global,
        }
        let mut args = vec!["t".to_string()];
        if let Some(p) = debug_log {
            args.extend(["--debug-log".into(), p.display().to_string()]);
        }
        if let Some(p) = evidence_log {
            args.extend(["--evidence-log".into(), p.display().to_string()]);
        }
        <Cli as clap::Parser>::parse_from(args).global
    }

    /// An output that is an input, a map, the hints or a key file is
    /// refused, and so is one that is where a log goes, though neither
    /// exists yet: the evidence log is written at the end, after the
    /// image, and appended to it.
    #[test]
    fn an_output_is_refused_over_any_input_and_over_either_log() {
        let dir = std::env::temp_dir().join(format!("zvol-common-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let member = dir.join("member0.img");
        let map = dir.join("m0.map");
        std::fs::write(&member, [1u8; 4096]).unwrap();
        std::fs::write(&map, "0x0 +\n").unwrap();
        let g = global(None, Some(&dir.join("case.jsonl")));
        let guard = WriteGuard::new(&g, &[member.clone(), map.clone()]);
        assert!(guard.check(&member).is_err());
        assert!(guard.check(&map).is_err());
        let why = guard.check(&dir.join("case.jsonl")).unwrap_err();
        assert!(why.contains("--evidence-log"), "{why}");
        // Spelled another way, still the same place.
        let why = guard.check(&dir.join(".").join("case.jsonl")).unwrap_err();
        assert!(why.contains("--evidence-log"), "{why}");
        assert!(guard.check(&dir.join("out.img")).is_ok());
        assert_eq!(guard.refuse("t", "-o", &member), Err(exit::REFUSED));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Two names for a file that does not exist yet are one file: under
    /// a directory not made yet, and through a link that dangles.
    #[test]
    fn same_file_sees_through_links_and_missing_directories() {
        let dir = std::env::temp_dir().join(format!("zvol-common-same-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ws = dir.join("ws");
        assert!(same_file(
            &ws.join("candidates.json"),
            &dir.join("ws/./candidates.json")
        ));
        assert!(!same_file(
            &ws.join("candidates.json"),
            &ws.join("state.json")
        ));
        std::os::unix::fs::symlink("out.img", dir.join("case.jsonl")).unwrap();
        assert!(same_file(&dir.join("case.jsonl"), &dir.join("out.img")));
        assert!(!same_file(&dir.join("case.jsonl"), &dir.join("other.img")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The spec names its maps, hints and assumed members as reads.
    #[test]
    fn a_pool_spec_names_everything_it_reads() {
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            pool: PoolSpec,
        }
        let spec = <Cli as clap::Parser>::parse_from([
            "t",
            "/dev/ada0p3",
            "--image",
            "m1.img",
            "--hints",
            "layout.hints",
            "--map",
            "m1.img=m1.map",
            "--assume-member",
            "m2.img=0x1234",
        ])
        .pool;
        let reads = spec.reads();
        for want in ["/dev/ada0p3", "m1.img", "layout.hints", "m1.map", "m2.img"] {
            assert!(reads.contains(&PathBuf::from(want)), "{want}: {reads:?}");
        }
    }
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
    /// Refuse a `--debug-log` or `--evidence-log` that would write over
    /// something this run reads, before anything is opened.
    ///
    /// `-o` has been checked against the inputs since the first release
    /// (`refuse_if_evidence`); the two logs were not, and they are opened
    /// first: `--debug-log disk.img scan disk.img` truncated the image to
    /// the size of a trace line, `--evidence-log disk.img` appended JSON
    /// to it and exited 0. A log may not be any path the command line
    /// names — members, images, maps, hints, key files, an `-o` that
    /// exists — nor live on a device among them, nor be the other log.
    /// An output that does not exist yet is the other side's business:
    /// [`WriteGuard`] refuses it when it is one of the logs. A refusal is
    /// exit 5, as a refused `-o` is.
    pub fn refuse_logs_over_inputs(&self, tool: &str) -> Result<(), u8> {
        self.refuse_logs_over(tool, &[])
    }

    /// [`refuse_logs_over_inputs`](Self::refuse_logs_over_inputs), with
    /// `more` besides what the command line names: files the run reads or
    /// writes that no word names — the files a report names, which
    /// `zvolreport verify` reads and hashes; a dump's resume state; a
    /// carve's index. These are found by name as well as by file, since
    /// some of them do not exist yet: a debug log opened at the start was
    /// a resume state or an index truncated to a trace before anything
    /// checked it.
    pub fn refuse_logs_over(&self, tool: &str, more: &[PathBuf]) -> Result<(), u8> {
        if let Some(word) = file_name_not_text(std::env::args_os().skip(1)) {
            eprintln!(
                "{tool}: {:?} is not valid UTF-8. The JSON output and the evidence record name every file as text, and this name cannot be written as one without changing it; reach the file through a link whose name is (ln -s)",
                word.to_string_lossy()
            );
            return Err(exit::USAGE);
        }
        let mut named = paths_on_command_line(std::env::args_os().skip(1));
        named.extend(more.iter().cloned());
        for (flag, log) in [
            ("--debug-log", &self.debug_log),
            ("--evidence-log", &self.evidence_log),
        ] {
            let Some(log) = log else { continue };
            if let Err(e) = zvolrescue_io::refuse_if_evidence(log, &named) {
                eprintln!("{tool}: refusing {flag} {}: {e}", log.display());
                return Err(exit::REFUSED);
            }
            if let Some(file) = more.iter().find(|m| same_file(log, m)) {
                eprintln!(
                    "{tool}: refusing {flag} {}: it is {}, which this run reads or writes",
                    log.display(),
                    file.display()
                );
                return Err(exit::REFUSED);
            }
        }
        if let (Some(d), Some(e)) = (&self.debug_log, &self.evidence_log) {
            // Neither may exist yet, so the paths are compared as well as
            // the files.
            if same_file(d, e) {
                eprintln!(
                    "{tool}: refusing --debug-log {}: it is the evidence log, which the trace would overwrite",
                    d.display()
                );
                return Err(exit::REFUSED);
            }
        }
        Ok(())
    }

    /// Turn on the read trace when `--debug`/`--debug-log` asked for it,
    /// after [`refuse_logs_over_inputs`](Self::refuse_logs_over_inputs).
    ///
    /// Returns the exit code to use when the log file cannot be created,
    /// so a caller can `return` it: a run that was asked to record what
    /// it did must not silently do it without recording.
    pub fn enable_tracing(&self, tool: &str) -> Result<(), u8> {
        self.enable_tracing_over(tool, &[])
    }

    /// [`enable_tracing`](Self::enable_tracing), with the logs checked
    /// against `more` as [`refuse_logs_over`](Self::refuse_logs_over)
    /// checks them, before the debug log is created.
    pub fn enable_tracing_over(&self, tool: &str, more: &[PathBuf]) -> Result<(), u8> {
        self.refuse_logs_over(tool, more)?;
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

/// Whether `a` and `b` are one file: the same inode when both exist, the
/// same place once resolved when either does not yet — two outputs a
/// run is about to create can collide too.
pub fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    if let (Ok(x), Ok(y)) = (std::fs::metadata(a), std::fs::metadata(b)) {
        return x.dev() == y.dev() && x.ino() == y.ino();
    }
    resolved(a).is_some() && resolved(a) == resolved(b)
}

/// Where `path` will be once it is made: a link at its end followed,
/// dangling or not, and the deepest directory above it that exists
/// resolved, the rest of the path kept as it is spelled. Resolving only
/// the parent missed a log in a workspace not made yet — it was then
/// appended to the scan index made there — and a log that was a link
/// to the image, whose record went onto the end of the image after its
/// hash was taken.
fn resolved(path: &Path) -> Option<PathBuf> {
    let target = zvolrescue_io::final_target(path);
    let absolute = if target.is_absolute() {
        target
    } else {
        std::env::current_dir().ok()?.join(target)
    };
    let mut rest = Vec::new();
    let mut at = absolute.as_path();
    loop {
        if let Ok(found) = std::fs::canonicalize(at) {
            return Some(rest.iter().rev().fold(found, |p, c| p.join(c)));
        }
        rest.push(at.file_name()?.to_owned());
        at = at.parent()?;
    }
}

/// `path` with the directory above it resolved and its own last
/// component kept as it is — a link there is not followed.
fn name_resolved(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    Some(resolved(dir)?.join(name))
}

static TOOL: OnceLock<&'static str> = OnceLock::new();

/// Name the running program, once, first thing in `main`.
pub fn set_tool(name: &'static str) {
    let _ = TOOL.set(name);
}

/// The running program's name, for the messages printed on its behalf:
/// what [`set_tool`] said, else `zvolrescue`.
pub fn tool() -> &'static str {
    TOOL.get().copied().unwrap_or("zvolrescue")
}

/// Every path a command line names, for [`Global::refuse_logs_over_inputs`].
///
/// Deliberately generous: any word that is not an option, the value of a
/// `--long=VALUE`, both sides of a `MEMBER=MAPFILE` and what follows the
/// format of a key spec (`raw:FILE`, `passphrase:FILE`, `hex:@FILE`). A
/// word that names nothing on disk costs a failed `stat` and nothing
/// else; one left out is a file a log could be written over. The logs'
/// own values are left out, or every log would name itself.
pub fn paths_on_command_line<I>(args: I) -> Vec<PathBuf>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    const LOGS: [&str; 2] = ["--debug-log", "--evidence-log"];
    let mut out = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if std::mem::take(&mut skip_next) {
            continue;
        }
        let s = arg.to_string_lossy();
        if LOGS.contains(&s.as_ref()) {
            skip_next = true;
            continue;
        }
        if let Some(long) = s.strip_prefix("--") {
            // `--map=M=F`, `--key=passphrase:FILE`: the value is read the
            // way the same word is read on its own.
            if let Some((name, value)) = long.split_once('=') {
                if !LOGS.contains(&format!("--{name}").as_str()) {
                    push_word(&mut out, value);
                }
            }
            continue;
        }
        if s.len() > 1 && s.starts_with('-') {
            continue;
        }
        out.push(PathBuf::from(&arg));
        push_parts(&mut out, &s);
    }
    out
}

/// The first word of a command line that is not UTF-8, if any — other
/// than the value of `--path`, which names a file *inside* a dataset as
/// the bytes it has on disk (`zvolfiles`), and is recorded as those.
///
/// Every file a run reads or writes is named in its JSON and in its
/// evidence record, and JSON holds text: a member called `m\xff.img`
/// made the serialiser fail and every tool panicked at the end of the
/// run — after `dump` had written the whole image, with no hash printed
/// and no record kept. A name changed to fit would be worse: the record
/// would name a file that is not the evidence.
pub fn file_name_not_text<I>(args: I) -> Option<std::ffi::OsString>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut inside_dataset = false;
    for arg in args {
        if std::mem::take(&mut inside_dataset) {
            continue;
        }
        if arg == "--path" {
            inside_dataset = true;
            continue;
        }
        if arg.to_str().is_none() {
            let lossy = arg.to_string_lossy();
            if !lossy.starts_with("--path=") {
                return Some(arg);
            }
        }
    }
    None
}

/// A word, and the paths inside it.
fn push_word(out: &mut Vec<PathBuf>, word: &str) {
    out.push(PathBuf::from(word));
    push_parts(out, word);
}

/// Both sides of `MEMBER=MAPFILE`, and the file after a key spec's format.
fn push_parts(out: &mut Vec<PathBuf>, word: &str) {
    if let Some((a, b)) = word.split_once('=') {
        out.push(PathBuf::from(a));
        out.push(PathBuf::from(b));
    }
    if let Some((_, rest)) = word.split_once(':') {
        out.push(PathBuf::from(rest.strip_prefix('@').unwrap_or(rest)));
    }
}

/// Every write a run makes, asked about against everything the run reads
/// and against its own logs (SPEC §8.3, invariant 2).
///
/// Made once the inputs are known, and asked before each file is opened
/// for writing: an image and its resume state, every image and the
/// manifest of `dump -r`, every file `zvolfiles extract` makes, every
/// report. A check made once for an output directory left the files
/// inside it free to land on a member that happened to share a name with
/// one of them; a check against the members alone left the maps, the
/// hints and the key files free; and a log that did not exist yet was no
/// file to compare an output with.
#[derive(Debug, Clone)]
pub struct WriteGuard {
    evidence: zvolrescue_io::Evidence,
    logs: Vec<(&'static str, PathBuf)>,
    /// What the run reads, as it was named.
    reads: Vec<PathBuf>,
}

impl WriteGuard {
    /// `reads` is whatever the run reads: [`PoolSpec::reads`], the
    /// members as opened, key files, anything else a tool takes in.
    pub fn new(global: &Global, reads: &[PathBuf]) -> WriteGuard {
        let logs = [
            ("--debug-log", &global.debug_log),
            ("--evidence-log", &global.evidence_log),
        ]
        .into_iter()
        .filter_map(|(flag, p)| p.clone().map(|p| (flag, p)))
        .collect();
        WriteGuard {
            evidence: zvolrescue_io::Evidence::new(reads),
            logs,
            reads: reads.to_vec(),
        }
    }

    /// Why `path` itself — the name, not what a link there leads to — may
    /// not be removed: it is the name the run reads an input by, or where
    /// a log goes. A link that merely points at an input can go; one that
    /// is how the run was told to reach it cannot.
    pub fn check_name(&self, path: &Path) -> Result<(), String> {
        let here = name_resolved(path);
        if here.is_none() {
            return Ok(());
        }
        for r in &self.reads {
            if name_resolved(r) == here {
                return Err(format!(
                    "{} is the name this run reads {} by",
                    path.display(),
                    r.display()
                ));
            }
        }
        for (flag, log) in &self.logs {
            if name_resolved(log) == here {
                return Err(format!("{} is where {flag} goes", path.display()));
            }
        }
        Ok(())
    }

    /// Why writing `path` would be wrong, if it would: it is an input or
    /// shares bytes with one, or it is where one of the run's logs goes.
    pub fn check(&self, path: &Path) -> Result<(), String> {
        self.evidence.check(path).map_err(|e| e.to_string())?;
        for (flag, log) in &self.logs {
            if same_file(path, log) {
                return Err(format!("{} is where {flag} goes", path.display()));
            }
        }
        Ok(())
    }

    /// [`check`](Self::check), said on stderr as `TOOL: refusing WHAT
    /// PATH: why`, with the exit code to return.
    pub fn refuse(&self, tool: &str, what: &str, path: &Path) -> Result<(), u8> {
        self.check(path).map_err(|why| {
            eprintln!("{tool}: refusing {what} {}: {why}", path.display());
            exit::REFUSED
        })
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

    /// Every file this spec names for reading, wider than
    /// [`inputs`](Self::inputs): the members, the hints, both sides of
    /// each `--map`, the paths `--assume-member` names. A run's outputs
    /// stay off all of them ([`WriteGuard`]).
    pub fn reads(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = self.devices.iter().chain(&self.image).cloned().collect();
        v.extend(self.hints.iter().cloned());
        for m in &self.map {
            if let Some((member, file)) = m.split_once('=') {
                v.push(member.into());
                v.push(file.into());
            }
        }
        for a in &self.assume_member {
            v.push(a.split_once('=').map_or(a.as_str(), |(p, _)| p).into());
        }
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
        for m in &self.map {
            args.push("--map".into());
            args.push(shell_quote(m));
        }
        if self.ignore_unknown_features {
            args.push("--ignore-unknown-features".into());
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
        say!(
            "MEDIUM INCIDENT: {i}{}",
            if i.stopped {
                " — stopped here"
            } else {
                " — skipped (--device-may-fail)"
            }
        );
    }
    let stopped = ledger.stopped()?;
    say!(
        "{} refused a read and the run stopped there (SPEC F-33, N-10). \
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
