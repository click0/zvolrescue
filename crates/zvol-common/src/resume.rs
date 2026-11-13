//! The state an interrupted extraction leaves, and how a run takes it up
//! (SPEC F-32, COMPANIONS C-07).
//!
//! One file next to the output image, `OUT.img.resume.json`, says which
//! dataset the image is of, at which TXG, how big it is, and how many
//! blocks from the start are complete. A run that is asked to `--resume`
//! reads it back, refuses it if it describes something else, hashes the
//! prefix the image already holds, and goes on from the block the state
//! names. `zvolrescue dump` and `zvolcarve dump` share this so that the
//! file one writes is the file the other would write — there is one
//! extraction pipeline, not two that agree by luck.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zfs_read::hash::{Digests, Extra};
use zfs_read::zvol::{BadRange, Report};
use zvolrescue_io::SparseFile;

/// Resume state written next to the output image.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    /// Format version of this file; 1.
    pub version: u32,
    /// The dataset — or the carve candidate — the image is of.
    pub dataset: String,
    /// Its GUID as `0x…`, or what the tool has instead of one.
    pub dataset_guid: String,
    /// The TXG it is read at; 0 where there is none (a carved candidate).
    pub txg: u64,
    /// Bytes the finished image will hold.
    pub volsize: u64,
    /// Data block size of the volume.
    pub blocksize: u64,
    /// Blocks `0..blocks_done` are complete in the output.
    pub blocks_done: u64,
    /// What those blocks lost: the ranges written as zeros, and how many
    /// blocks were. Absent in a state with nothing lost, and in one an
    /// earlier version wrote.
    #[serde(default, skip_serializing_if = "Lost::is_empty")]
    pub lost: Lost,
    /// SHA-256 of the image's first `blocks_done` blocks as the run
    /// wrote them. A resume reads them back to hash them, and takes the
    /// state up only when they still come to this: a state for
    /// `/dev/sdb` was taken up on whatever disk had that name the next
    /// time, and an image written over since was hashed as the volume.
    /// Absent in a state an earlier version wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_sha256: Option<String>,
}

impl State {
    /// What has to agree for a state to belong to an image: everything
    /// but how far it got, what it lost on the way and what that came to.
    pub fn key(&self) -> State {
        State {
            blocks_done: 0,
            lost: Lost::default(),
            prefix_sha256: None,
            ..self.clone()
        }
    }
}

/// What the blocks before a resume point lost.
///
/// A resume used to know only where to go on from. The blocks an
/// interrupted run had written as zeros were in its summary, which
/// nobody kept, and nowhere else: the run that finished the image
/// reported only what it met itself, and an image with holes in it came
/// out of a resumed dump with exit 0 and no unreadable range listed. The
/// state carries them, and the run that takes it up reports them as its
/// own.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Lost {
    /// The unreadable ranges, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bad: Vec<LostRange>,
    /// Blocks written as zeros.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub blocks_zeroed: u64,
    /// Blocks written with their unreadable sectors zeroed.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub blocks_salvaged: u64,
}

/// One unreadable range, as [`zfs_read::zvol::BadRange`] has it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LostRange {
    /// Block id.
    pub blkid: u64,
    /// Byte offset in the volume.
    pub offset: u64,
    /// Length in bytes.
    pub len: u64,
    /// Why.
    pub reason: String,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Lost {
    /// Nothing lost.
    pub fn is_empty(&self) -> bool {
        self.bad.is_empty() && self.blocks_zeroed == 0 && self.blocks_salvaged == 0
    }

    /// These, and what `report` lost in the blocks before `blocks_done`.
    ///
    /// Every block `report` counts as zeroed or salvaged lies before the
    /// point a run records: the last one it visited, the block a signal
    /// stopped it at, or the block an abort stopped at — which is not
    /// counted, and whose range is left out here, because the resume
    /// reads it again.
    pub fn and(&self, report: &Report, blocks_done: u64) -> Lost {
        let mut bad = self.bad.clone();
        bad.extend(
            report
                .bad
                .iter()
                .filter(|b| b.blkid < blocks_done)
                .map(|b| LostRange {
                    blkid: b.blkid,
                    offset: b.offset,
                    len: b.len,
                    reason: b.reason.clone(),
                }),
        );
        Lost {
            bad,
            blocks_zeroed: self.blocks_zeroed + report.blocks_zeroed,
            blocks_salvaged: self.blocks_salvaged + report.blocks_salvaged,
        }
    }

    /// Put these in `report`, ahead of what it lost itself: its ranges
    /// and counts are then those of the whole image.
    pub fn into_report(self, report: &mut Report) {
        let mut bad: Vec<BadRange> = self
            .bad
            .into_iter()
            .map(|b| BadRange {
                offset: b.offset,
                len: b.len,
                blkid: b.blkid,
                reason: b.reason,
            })
            .collect();
        bad.append(&mut report.bad);
        report.bad = bad;
        report.blocks_zeroed += self.blocks_zeroed;
        report.blocks_salvaged += self.blocks_salvaged;
    }
}

/// Where the state of `output` lives: `OUT.img.resume.json`, or, for an
/// image written to a device, `dev_da1.resume.json` in the current
/// directory (see [`device_state`]).
pub fn path(output: &Path) -> PathBuf {
    if let Some(p) = device_state(output) {
        return p;
    }
    let mut p = output.as_os_str().to_owned();
    p.push(".resume.json");
    PathBuf::from(p)
}

/// The state of an image written to a device, kept in the current
/// directory under the device's path: `/dev/da1` gives
/// `dev_da1.resume.json`, and `/dev/disk/by-id/…`, a link, the name of
/// the disk it leads to.
///
/// Next to the device it was nowhere a state can be kept: FreeBSD's
/// devfs takes no file, so none was written and the run promised a
/// resume it had no state for, and a Linux `/dev` is memory that the
/// next boot empties. `None` for anything that is not a device.
#[cfg(unix)]
fn device_state(output: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::FileTypeExt;
    let ft = std::fs::metadata(output).ok()?.file_type();
    if !(ft.is_block_device() || ft.is_char_device()) {
        return None;
    }
    let real = std::fs::canonicalize(output).unwrap_or_else(|_| output.to_path_buf());
    let flat = real
        .to_string_lossy()
        .trim_start_matches('/')
        .replace('/', "_");
    Some(PathBuf::from(format!("{flat}.resume.json")))
}

/// Not a device anywhere this is built without `unix`.
#[cfg(not(unix))]
fn device_state(_output: &Path) -> Option<PathBuf> {
    None
}

/// The name a state is written under before it is renamed into place:
/// `OUT.img.resume.json.tmp`. A run writes this file too, so it is one
/// of the paths a caller puts to its `WriteGuard` before the first
/// write.
pub fn tmp_path(state_path: &Path) -> PathBuf {
    let mut p = state_path.as_os_str().to_owned();
    p.push(".tmp");
    PathBuf::from(p)
}

/// Every file an extraction to `output` writes besides the image: the
/// state and the name it is written under first.
pub fn sidecars(output: &Path) -> [PathBuf; 2] {
    let state = path(output);
    let tmp = tmp_path(&state);
    [state, tmp]
}

/// Why [`write`] wrote no state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unwritten {
    /// The image could not be flushed: the blocks given to it are not
    /// known to be on the medium. No state may count them — not this
    /// one, nor a later one, as a flush that failed once can succeed the
    /// next time with the blocks it failed on gone — and the run that
    /// gave them has nothing more to give it.
    Flush(String),
    /// The image is on the medium, and the state could not be put where
    /// it goes.
    State(String),
}

/// Record that blocks `0..blocks_done` of `image` are complete — once
/// they are on stable storage — and what they lost.
///
/// The image is flushed first, and the state is written beside it under
/// a temporary name and renamed into place. Without the flush a crash
/// could keep a state that names blocks the image never received: the
/// image is sparse, the missing blocks read back as zeros, and a resume
/// would hash them and carry on as though they were the volume. Without
/// the rename a crash could leave half a state. A flush that fails
/// writes no state — the next resume starts earlier, never wrong. What
/// was not written is said, for the run to say: it used to be passed
/// over, and a run whose state was never written ended with "--resume
/// continues there" all the same.
pub fn write(
    image: &Path,
    state_path: &Path,
    expected: &State,
    blocks_done: u64,
    lost: &Lost,
    prefix_sha256: Option<&str>,
) -> Result<(), Unwritten> {
    use std::io::Write;
    let state_err = |e: std::io::Error| Unwritten::State(format!("{}: {e}", state_path.display()));
    std::fs::OpenOptions::new()
        .write(true)
        .open(image)
        .and_then(|f| {
            let dense = !f.metadata()?.is_file();
            // The blocks counted end where the state says, holes and
            // zeroed blocks included; a sparse file ends at the last
            // block written. Left short, the state outlived a crash and
            // the resume found the image "shorter than the bytes the
            // resume state claims", and started over.
            let prefix = blocks_done
                .saturating_mul(expected.blocksize)
                .min(expected.volsize);
            if !dense && f.metadata()?.len() < prefix {
                f.set_len(prefix)?;
            }
            match f.sync_data() {
                // A character device has nothing to flush, as
                // `SparseFile::finish` knows.
                Err(e) if dense && e.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
                other => other,
            }
        })
        .map_err(|e| Unwritten::Flush(format!("{}: {e}", image.display())))?;
    let s = State {
        blocks_done,
        lost: lost.clone(),
        prefix_sha256: prefix_sha256.map(str::to_owned),
        ..expected.key()
    };
    let json = serde_json::to_vec(&s).map_err(|e| Unwritten::State(e.to_string()))?;
    // Whatever is at the temporary name goes first — a stale one from a
    // run that died, or a link — and the file is made new: `create`
    // would follow a link there, and a link to a mapfile, a key or a
    // member got the state written over it.
    let tmp = tmp_path(state_path);
    if let Err(e) = std::fs::remove_file(&tmp) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(state_err(e));
        }
    }
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(&json)?;
            f.sync_all()
        })
        .and_then(|()| std::fs::rename(&tmp, state_path));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(state_err(e));
    }
    // The rename is an entry in the directory; flush that too — the
    // current one when the path is relative and has no directory part.
    let dir = match state_path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    Ok(())
}

/// The states one extraction writes, and what a resume of its image can
/// rely on when it ends.
///
/// `zvolrescue dump` and `zvolcarve dump` keep one each: the progress
/// callback saves through it, the end of the run concludes through it,
/// and what the run then says of a resume is what the states on disk
/// will bear out — the block the last state written names, not the
/// block the run would have liked to name.
pub struct Saver<'a> {
    image: &'a Path,
    path: PathBuf,
    expected: &'a State,
    /// The blocks the state on disk counts: where a resume starts.
    saved: u64,
    /// Why the last state was not written, when the image was on the
    /// medium and the state could not be put beside it.
    unwritten: Option<String>,
    /// A flush of the image failed: no state may be written after it.
    unflushed: Option<String>,
    /// Which blocks reached the output is not known — a flush failed, or
    /// the image could not be finished — past the state on disk.
    unknown: bool,
    /// The image went where nothing is kept (`/dev/null`): there is no
    /// state to write and nothing to resume.
    kept_nowhere: bool,
}

impl<'a> Saver<'a> {
    /// The saver of an extraction to `image` that starts at block
    /// `start_block`, as [`open`] found it.
    pub fn new(image: &'a Path, expected: &'a State, start_block: u64) -> Saver<'a> {
        Saver {
            image,
            path: path(image),
            expected,
            saved: start_block,
            unwritten: None,
            unflushed: None,
            unknown: false,
            kept_nowhere: crate::evidence::keeps_nothing(image),
        }
    }

    /// Where the state goes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record blocks `0..blocks_done`, what they lost and the SHA-256
    /// they came to. `false` when the image could not be flushed, now or
    /// before: the run is to stop, as nothing it writes from here on can
    /// be counted.
    pub fn save(&mut self, blocks_done: u64, lost: &Lost, prefix_sha256: &str) -> bool {
        if self.unflushed.is_some() {
            return false;
        }
        if self.kept_nowhere {
            return true;
        }
        match write(
            self.image,
            &self.path,
            self.expected,
            blocks_done,
            lost,
            Some(prefix_sha256),
        ) {
            Ok(()) => {
                self.saved = blocks_done;
                self.unwritten = None;
                true
            }
            Err(Unwritten::State(e)) => {
                self.unwritten = Some(e);
                true
            }
            Err(Unwritten::Flush(e)) => {
                self.unflushed = Some(e);
                self.unknown = true;
                false
            }
        }
    }

    /// Why the image could not be flushed, when it could not.
    pub fn unflushed(&self) -> Option<&str> {
        self.unflushed.as_deref()
    }

    /// The end of the run: a state for an image that stopped short —
    /// at the block a signal or the output stopped it at, or at the one
    /// an abort stopped at, which is read again — and none for a whole
    /// one. `earlier` is what the run that was resumed lost. Returns
    /// where a resume starts, or `None` for a whole image.
    pub fn conclude(&mut self, report: &Report, earlier: &Lost, start_block: u64) -> Option<u64> {
        let stopped = report.aborted
            || report.interrupted_at.is_some()
            || report.output_failed.is_some()
            || self.unflushed.is_some();
        if !stopped {
            clear(&self.path);
            return None;
        }
        if self.kept_nowhere {
            return Some(0);
        }
        if !report.finished || self.unknown {
            // What reached the output is not known: the state on disk,
            // written after a flush that held, is all a resume can go on.
            self.unknown = true;
            return Some(self.saved);
        }
        let done = report
            .interrupted_at
            .or_else(|| report.bad.last().map(|b| b.blkid))
            .unwrap_or(start_block);
        // The run stopped at `done` and its digests at the same block:
        // the report's hash is that of the image it leaves.
        self.save(done, &earlier.and(report, done), &report.sha256);
        Some(self.saved)
    }

    /// What the run says of the image it left and of a resume of it,
    /// after [`Saver::conclude`]: that the image holds the blocks before
    /// the one it stopped at, and `there` — "--resume continues there",
    /// or "after a repair" — when the state on disk names that block;
    /// otherwise where a resume will in fact start, and why.
    pub fn words(&self, there: &str) -> String {
        let from = |what: &str| {
            if self.saved > 0 {
                format!(
                    "{what}: --resume continues from block {}, where the last state written says",
                    self.saved
                )
            } else {
                format!("{what}: --resume starts again from block 0")
            }
        };
        if self.kept_nowhere {
            format!(
                "the image went to {}, which keeps nothing: there is nothing to resume",
                self.image.display()
            )
        } else if self.unknown {
            from("which of the blocks given to the output reached it is not known")
        } else if let Some(why) = &self.unwritten {
            from(&format!(
                "the image holds the blocks before it, but its state could not be written ({why})"
            ))
        } else if device_state(self.image).is_some() {
            format!(
                "the image holds the blocks before it, {there} (its state is {}, in this directory: resume from here)",
                self.path.display()
            )
        } else {
            format!("the image holds the blocks before it, {there}")
        }
    }
}

/// The image is whole: nothing to resume.
pub fn clear(state_path: &Path) {
    let _ = std::fs::remove_file(state_path);
}

/// Open the output for writing, resuming when asked and when the state
/// on disk describes this very image.
///
/// Returns the block to start at, the digests fed with the prefix the
/// image already holds, the sink, and what that prefix lost — for the
/// caller to report with what it loses itself. Without `resume`, or with
/// a state that describes something else, the image starts over from
/// block 0 — said on stderr, never silently. `Err` is the message for
/// an output that cannot be opened at all.
pub fn open(
    tool: &str,
    name: &str,
    output: &Path,
    expected: &State,
    extra: Extra,
    resume: bool,
    quiet: bool,
) -> Result<(u64, Digests, SparseFile, Lost), String> {
    // An image is written at offsets, holes skipped: a pipe cannot take
    // that, and `-o /dev/stdout | …` failed on the first seek as exit 3,
    // "unrecoverable", as if the pool were at fault.
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        // `/dev/stdout` is the stream itself where the system keeps it
        // as a device of its own (FreeBSD's devfs, macOS): what it leads
        // to is what the stream is.
        let named = stream_named(output);
        if let Some(m) = named
            .as_ref()
            .map(|(_, m)| m.clone())
            .or_else(|| std::fs::metadata(output).ok())
        {
            let ft = m.file_type();
            if ft.is_fifo() || ft.is_socket() {
                return Err(format!(
                    "{}: a pipe cannot take an image, which is written at offsets with its holes left out; give a file or a disk",
                    output.display()
                ));
            }
        }
        // `-o /dev/stdout > img` names a file — the one the shell opened
        // for standard output — and the image went into it at offsets
        // while the summary went into it from the start, over the image's
        // first bytes: the sha256 recorded was of bytes the file no longer
        // held, with exit 0.
        let own = match named {
            Some((stream, m)) => (m.is_file() || m.file_type().is_block_device()).then_some(stream),
            None => own_stream(output),
        };
        if let Some(stream) = own {
            return Err(format!(
                "{}: this is the {stream} of the run, where its summary goes, and the summary would be written over the image; name the file itself",
                output.display()
            ));
        }
    }
    let state_path = path(output);
    let mut start_block = 0u64;
    let mut digests = Digests::new(extra);
    let mut lost = Lost::default();
    let sink = if resume {
        // No state is said: `--resume` used to start from block 0 without
        // a word when there was none to take up, or none that could be
        // read, and the operator learnt it from the time it took.
        let state: Result<State, String> = match std::fs::read(&state_path) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|e| format!("{} is not a resume state ({e})", state_path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(format!("no resume state at {}", state_path.display()))
            }
            Err(e) => Err(format!("cannot read {}: {e}", state_path.display())),
        };
        match state {
            Ok(s) if s.key() == expected.key() => {
                start_block = s.blocks_done;
                let blocks = expected.volsize.div_ceil(expected.blocksize.max(1));
                if start_block > blocks {
                    eprintln!(
                        "{tool}: {} counts {start_block} blocks done of a volume of {blocks}; starting over",
                        state_path.display()
                    );
                    start_block = 0;
                }
                let prefix = start_block
                    .saturating_mul(expected.blocksize)
                    .min(expected.volsize);
                match std::fs::File::open(output) {
                    Ok(mut f) => {
                        let mut left = prefix;
                        let mut buf = vec![0u8; 1 << 20];
                        while left > 0 {
                            let n = (left as usize).min(buf.len());
                            if f.read_exact(&mut buf[..n]).is_err() {
                                eprintln!(
                                    "{tool}: {}: shorter than the {prefix} bytes the resume state claims; starting over",
                                    output.display()
                                );
                                start_block = 0;
                                digests = Digests::new(extra);
                                break;
                            }
                            digests.update(&buf[..n]);
                            left -= n as u64;
                        }
                        let read_back = digests.clone().finish().sha256;
                        if let Some(was) = s.prefix_sha256.as_ref().filter(|_| start_block > 0) {
                            if *was != read_back {
                                eprintln!(
                                    "{tool}: {}: its first {prefix} bytes are not the ones the resume state counted (another disk under that name, or written since); starting over",
                                    output.display()
                                );
                                start_block = 0;
                                digests = Digests::new(extra);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "{tool}: cannot read {} to resume: {e}; starting over",
                            output.display()
                        );
                        start_block = 0;
                    }
                }
                if !quiet {
                    eprintln!("  resuming {name} at block {start_block}");
                }
                if start_block > 0 {
                    lost = s.lost;
                    SparseFile::open_existing(output, prefix)
                } else {
                    SparseFile::create(output)
                }
            }
            Ok(_) => {
                eprintln!(
                    "{tool}: {} describes a different dataset/txg/size than {name}; starting over",
                    state_path.display()
                );
                SparseFile::create(output)
            }
            Err(why) => {
                eprintln!("{tool}: {why}; starting from block 0");
                SparseFile::create(output)
            }
        }
    } else {
        SparseFile::create(output)
    }
    .map_err(|e| format!("cannot open {}: {e}", output.display()))?;
    if start_block == 0 {
        // The image starts over, and a state left from before names
        // blocks this run has yet to write: were this run to write none
        // of its own, a resume would take that one up and hash what is
        // not there.
        clear(&state_path);
    }
    Ok((start_block, digests, sink, lost))
}

/// The stream of this process `output` names as `/dev/stdout`,
/// `/dev/stderr` or `/dev/fd/1` and `2`, with what that stream is —
/// where the system keeps those names as devices of their own, as
/// FreeBSD's devfs and macOS do, rather than as links to the file the
/// stream goes to, as Linux's `/proc` does: a device that, opened, is
/// the stream again, and that `stat` calls a character device whatever
/// the stream leads to.
#[cfg(unix)]
fn stream_named(output: &Path) -> Option<(&'static str, std::fs::Metadata)> {
    use std::os::fd::AsFd;
    let which = match std::fs::canonicalize(output).ok()?.to_str()? {
        "/dev/fd/1" | "/dev/stdout" => 1,
        "/dev/fd/2" | "/dev/stderr" => 2,
        _ => return None,
    };
    let (out, err) = (std::io::stdout(), std::io::stderr());
    let (name, fd) = if which == 1 {
        ("standard output", out.as_fd())
    } else {
        ("standard error", err.as_fd())
    };
    let m = std::fs::File::from(fd.try_clone_to_owned().ok()?)
        .metadata()
        .ok()?;
    Some((name, m))
}

/// Whether `output` is the file or disk this process's standard output
/// or standard error goes to — `/dev/stdout`, `/dev/fd/2`, or the file
/// itself by its name. A terminal or `/dev/null` is not one: nothing
/// written there lands in an image.
#[cfg(unix)]
fn own_stream(output: &Path) -> Option<&'static str> {
    use std::os::fd::AsFd;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let m = std::fs::metadata(output).ok()?;
    if !(m.is_file() || m.file_type().is_block_device()) {
        return None;
    }
    let same = |fd: std::os::fd::BorrowedFd<'_>| {
        fd.try_clone_to_owned()
            .ok()
            .map(std::fs::File::from)
            .and_then(|f| f.metadata().ok())
            .is_some_and(|s| s.dev() == m.dev() && s.ino() == m.ino())
    };
    if same(std::io::stdout().as_fd()) {
        Some("standard output")
    } else if same(std::io::stderr().as_fd()) {
        Some("standard error")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zvolrescue_io::BlockSink;

    fn scratch(name: &str) -> crate::scratch::Scratch {
        crate::scratch::Scratch::new("zvol-common-resume", name)
    }

    fn expected() -> State {
        State {
            version: 1,
            dataset: "tank/vm/disk0".into(),
            dataset_guid: "0x00000000000000a3".into(),
            txg: 7,
            volsize: 4096 * 4,
            blocksize: 4096,
            blocks_done: 0,
            lost: Lost::default(),
            prefix_sha256: None,
        }
    }

    /// A state remembers what its blocks came to, and a resume takes it
    /// up only on an image whose first blocks still come to that: the
    /// state of an image written to `/dev/sdb` was taken up on whatever
    /// disk had that name the next time, and the disk's bytes hashed as
    /// the volume's.
    #[test]
    fn a_state_is_taken_up_only_on_the_bytes_it_counted() {
        let dir = scratch("prefix-hash");
        let out = dir.join("out.img");
        let exp = expected();
        let prefix: Vec<u8> = (0..8192u32).map(|i| (i % 249) as u8).collect();
        std::fs::write(&out, &prefix).unwrap();
        let mut d = Digests::new(Extra::none());
        d.update(&prefix);
        let counted = d.finish().sha256;
        write(&out, &path(&out), &exp, 2, &Lost::default(), Some(&counted)).unwrap();
        let resume = |out: &Path| {
            open(
                "test",
                "tank/vm/disk0",
                out,
                &exp,
                Extra::none(),
                true,
                true,
            )
            .unwrap()
            .0
        };
        assert_eq!(resume(&out), 2);

        // Another medium under the name: the same length, other bytes.
        write(&out, &path(&out), &exp, 2, &Lost::default(), Some(&counted)).unwrap();
        let mut other = prefix.clone();
        other[4096] ^= 1;
        std::fs::write(&out, &other).unwrap();
        assert_eq!(resume(&out), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A state counts the blocks before it, holes at the end of them
    /// included, and the sparse image is made that long before the state
    /// is written: it ended at the last block written, and a resume after
    /// a crash found it "shorter than the bytes the resume state claims"
    /// and started over. A state counting more blocks than the volume
    /// has starts over too.
    #[test]
    fn a_state_makes_the_image_as_long_as_the_blocks_it_counts() {
        let dir = scratch("holes-at-end");
        let out = dir.join("out.img");
        let exp = expected();
        std::fs::write(&out, [9u8; 4096]).unwrap();
        write(&out, &path(&out), &exp, 3, &Lost::default(), None).unwrap();
        assert_eq!(std::fs::metadata(&out).unwrap().len(), 3 * 4096);
        let (start, ..) = open(
            "test",
            "tank/vm/disk0",
            &out,
            &exp,
            Extra::none(),
            true,
            true,
        )
        .unwrap();
        assert_eq!(start, 3);

        write(&out, &path(&out), &exp, 99, &Lost::default(), None).unwrap();
        assert_eq!(std::fs::metadata(&out).unwrap().len(), exp.volsize);
        let (start, ..) = open(
            "test",
            "tank/vm/disk0",
            &out,
            &exp,
            Extra::none(),
            true,
            true,
        )
        .unwrap();
        assert_eq!(start, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A state that names this image resumes it: the prefix is hashed
    /// back and the sink keeps it; one that names another starts over
    /// and says so; none at all starts over quietly.
    #[test]
    fn a_state_is_taken_up_only_when_it_describes_this_image() {
        let dir = scratch("takeup");
        let out = dir.join("out.img");
        let exp = expected();
        // Two blocks of a four-block image, then a state that says so.
        let prefix: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&out, &prefix).unwrap();
        write(&out, &path(&out), &exp, 2, &Lost::default(), None).unwrap();

        let (start, digests, mut sink, lost) = open(
            "test",
            "tank/vm/disk0",
            &out,
            &exp,
            Extra::none(),
            true,
            true,
        )
        .unwrap();
        assert_eq!(start, 2);
        assert!(lost.is_empty());
        sink.write_at(8192, &[7u8; 8192]).unwrap();
        sink.finish(16384).unwrap();
        let mut whole = prefix.clone();
        whole.extend_from_slice(&[7u8; 8192]);
        assert_eq!(std::fs::read(&out).unwrap(), whole);
        let mut direct = Digests::new(Extra::none());
        direct.update(&prefix);
        assert_eq!(digests.finish().sha256, direct.finish().sha256);

        // The same state against another dataset: from the start, and
        // the file is truncated by the create.
        let other = State {
            dataset: "tank/vm/disk1".into(),
            ..exp.clone()
        };
        let (start, _, _, _) =
            open("test", "disk1", &out, &other, Extra::none(), true, true).unwrap();
        assert_eq!(start, 0);
        assert_eq!(std::fs::metadata(&out).unwrap().len(), 0);

        // Not asked to resume: from the start, whatever the state says.
        write(&out, &path(&out), &exp, 2, &Lost::default(), None).unwrap();
        let (start, _, _, _) = open(
            "test",
            "tank/vm/disk0",
            &out,
            &exp,
            Extra::none(),
            false,
            true,
        )
        .unwrap();
        assert_eq!(start, 0);

        // A state whose prefix the image no longer holds starts over
        // rather than hashing bytes that are not there.
        write(&out, &path(&out), &exp, 2, &Lost::default(), None).unwrap();
        std::fs::write(&out, &prefix[..100]).unwrap();
        let (start, _, _, _) = open(
            "test",
            "tank/vm/disk0",
            &out,
            &exp,
            Extra::none(),
            true,
            true,
        )
        .unwrap();
        assert_eq!(start, 0);

        clear(&path(&out));
        assert!(!path(&out).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A state is written only for an image that could be flushed, in one
    /// piece, with nothing left beside it.
    #[test]
    fn a_state_follows_the_image_to_disk() {
        let dir = scratch("durable");
        let out = dir.join("out.img");
        let exp = expected();
        assert!(matches!(
            write(&out, &path(&out), &exp, 1, &Lost::default(), None),
            Err(Unwritten::Flush(_))
        ));
        assert!(
            !path(&out).exists(),
            "a state for an image that is not there"
        );
        std::fs::write(&out, [9u8; 4096]).unwrap();
        write(&out, &path(&out), &exp, 1, &Lost::default(), None).unwrap();
        let back: State = serde_json::from_slice(&std::fs::read(path(&out)).unwrap()).unwrap();
        assert_eq!(back.blocks_done, 1);
        assert_eq!(back.key(), exp.key());
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Whatever is at the temporary name is not written through: a link
    /// there to a mapfile got the state over the mapfile, and the rename
    /// then left the state's name pointing at it.
    #[test]
    fn the_temporary_name_is_never_written_through() {
        let dir = scratch("tmp-link");
        let out = dir.join("out.img");
        std::fs::write(&out, [9u8; 4096]).unwrap();
        let victim = dir.join("member0.map");
        std::fs::write(&victim, b"# Mapfile\n0x0 0x1000 +\n").unwrap();
        let state = path(&out);
        std::os::unix::fs::symlink(&victim, tmp_path(&state)).unwrap();
        write(&out, &state, &expected(), 1, &Lost::default(), None).unwrap();
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"# Mapfile\n0x0 0x1000 +\n"
        );
        let meta = std::fs::symlink_metadata(&state).unwrap();
        assert!(meta.is_file(), "the state is a file of its own");
        let back: State = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
        assert_eq!(back.blocks_done, 1);
        assert!(!tmp_path(&state).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What an interrupted run lost goes into its state and comes back
    /// to the run that takes it up, ahead of what that one loses; the
    /// block an abort stopped at is not among it, as it is read again.
    #[test]
    fn what_was_lost_before_a_resume_is_carried_to_its_end() {
        let range = |blkid: u64, reason: &str| BadRange {
            offset: blkid * 4096,
            len: 4096,
            blkid,
            reason: reason.into(),
        };
        let report = |bad: Vec<BadRange>, zeroed: u64| Report {
            volsize: 4096 * 4,
            blocksize: 4096,
            blocks_total: 4,
            blocks_read: 0,
            blocks_holes: 0,
            blocks_zeroed: zeroed,
            blocks_salvaged: 0,
            bytes_written: 0,
            bad,
            aborted: false,
            stopped_by_medium: None,
            interrupted_at: None,
            image_bytes: 0,
            output_failed: None,
            finished: true,
            sha256: String::new(),
            sha1: None,
            md5: None,
        };
        // The first run zeroed block 0 and stopped at block 2, which a
        // device refused: block 2 is read again, block 0 is lost.
        let first = report(vec![range(0, "checksum"), range(2, "refused")], 1);
        let lost = Lost::default().and(&first, 2);
        assert_eq!(lost.blocks_zeroed, 1);
        assert_eq!(lost.bad.len(), 1);
        assert_eq!(lost.bad[0].blkid, 0);

        let dir = scratch("lost");
        let out = dir.join("out.img");
        std::fs::write(&out, [0u8; 8192]).unwrap();
        write(&out, &path(&out), &expected(), 2, &lost, None).unwrap();
        let (start, _, _, back) = open(
            "test",
            "tank/vm/disk0",
            &out,
            &expected(),
            Extra::none(),
            true,
            true,
        )
        .unwrap();
        assert_eq!((start, &back), (2, &lost));

        // The run that takes it up zeroes block 3: the image has lost
        // both, in order.
        let mut second = report(vec![range(3, "checksum")], 1);
        back.into_report(&mut second);
        assert_eq!(second.blocks_zeroed, 2);
        let blkids: Vec<u64> = second.bad.iter().map(|b| b.blkid).collect();
        assert_eq!(blkids, [0, 3]);
        assert_eq!(second.bad[0].reason, "checksum");

        // A state with nothing lost says nothing of it, as before.
        write(&out, &path(&out), &expected(), 2, &Lost::default(), None).unwrap();
        let text = std::fs::read_to_string(path(&out)).unwrap();
        assert!(!text.contains("lost"), "{text}");
    }

    /// An image named by the stream the summary goes to is refused: the
    /// summary would land on the image's first bytes.
    #[test]
    fn the_runs_own_output_is_not_an_image() {
        let dir = scratch("own-stream");
        let out = dir.join("out.img");
        std::fs::write(&out, b"").unwrap();
        assert_eq!(own_stream(&out), None, "a file of its own");
        assert_eq!(own_stream(&dir.join("absent.img")), None);
        assert_eq!(own_stream(Path::new("/dev/null")), None);
    }

    /// What a run says of a resume is what the state on disk bears out:
    /// a state that could not be written is said, with the block the last
    /// one written names — or block 0 — and not "--resume continues
    /// there"; an image that could not be flushed stops the saving.
    #[test]
    fn a_run_promises_no_resume_its_state_cannot_keep() {
        let dir = scratch("saver");
        let out = dir.join("out.img");
        std::fs::write(&out, [9u8; 16384]).unwrap();
        let exp = expected();
        let mut report = Report {
            volsize: 4096 * 4,
            blocksize: 4096,
            blocks_total: 4,
            blocks_read: 3,
            blocks_holes: 0,
            blocks_zeroed: 0,
            blocks_salvaged: 0,
            bytes_written: 0,
            bad: Vec::new(),
            aborted: false,
            stopped_by_medium: None,
            interrupted_at: Some(3),
            image_bytes: 3 * 4096,
            output_failed: None,
            finished: true,
            sha256: String::new(),
            sha1: None,
            md5: None,
        };

        // Written: the block it stopped at.
        let mut saver = Saver::new(&out, &exp, 0);
        assert!(saver.save(1, &Lost::default(), "x"));
        assert_eq!(saver.conclude(&report, &Lost::default(), 0), Some(3));
        assert_eq!(
            saver.words("--resume continues there"),
            "the image holds the blocks before it, --resume continues there"
        );

        // A directory where the state goes first: nothing can be written
        // there, and the run says from where a resume will go on.
        std::fs::create_dir(tmp_path(&path(&out))).unwrap();
        let mut saver = Saver::new(&out, &exp, 0);
        assert!(saver.save(2, &Lost::default(), "x"), "the image is flushed");
        assert_eq!(saver.conclude(&report, &Lost::default(), 0), Some(0));
        let words = saver.words("--resume continues there");
        assert!(
            words.contains("but its state could not be written (")
                && words.ends_with(": --resume starts again from block 0"),
            "{words}"
        );
        std::fs::remove_dir(tmp_path(&path(&out))).unwrap();
        let mut saver = Saver::new(&out, &exp, 0);
        assert!(saver.save(2, &Lost::default(), "x"));
        std::fs::create_dir(tmp_path(&path(&out))).unwrap();
        assert_eq!(saver.conclude(&report, &Lost::default(), 0), Some(2));
        assert!(
            saver
                .words("--resume continues there")
                .ends_with(": --resume continues from block 2, where the last state written says"),
            "{}",
            saver.words("--resume continues there")
        );
        std::fs::remove_dir(tmp_path(&path(&out))).unwrap();

        // An image not finished: what reached it is not known, and the
        // state on disk is all a resume has.
        report.finished = false;
        report.output_failed = Some("the output could not be finished".into());
        let mut saver = Saver::new(&out, &exp, 0);
        assert_eq!(saver.conclude(&report, &Lost::default(), 0), Some(0));
        assert_eq!(
            saver.words("--resume continues there"),
            "which of the blocks given to the output reached it is not known: --resume starts again from block 0"
        );

        // An image that is not there to flush stops the saving.
        let gone = dir.join("gone.img");
        let mut saver = Saver::new(&gone, &exp, 0);
        assert!(!saver.save(1, &Lost::default(), "x"));
        assert!(saver.unflushed().is_some());
        assert!(
            !saver.save(2, &Lost::default(), "x"),
            "and nothing after it"
        );
        assert!(!path(&gone).exists());

        // A whole image: no state, and nothing to say.
        report.finished = true;
        report.output_failed = None;
        report.interrupted_at = None;
        let mut saver = Saver::new(&out, &exp, 0);
        assert_eq!(saver.conclude(&report, &Lost::default(), 0), None);
        assert!(!path(&out).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
