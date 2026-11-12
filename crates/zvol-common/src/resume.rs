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
}

impl State {
    /// What has to agree for a state to belong to an image: everything
    /// but how far it got and what it lost on the way.
    pub fn key(&self) -> State {
        State {
            blocks_done: 0,
            lost: Lost::default(),
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

/// Where the state of `output` lives: `OUT.img.resume.json`.
pub fn path(output: &Path) -> PathBuf {
    let mut p = output.as_os_str().to_owned();
    p.push(".resume.json");
    PathBuf::from(p)
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

/// Record that blocks `0..blocks_done` of `image` are complete — once
/// they are on stable storage — and what they lost.
///
/// The image is flushed first, and the state is written beside it under
/// a temporary name and renamed into place. Without the flush a crash
/// could keep a state that names blocks the image never received: the
/// image is sparse, the missing blocks read back as zeros, and a resume
/// would hash them and carry on as though they were the volume. Without
/// the rename a crash could leave half a state. A flush that fails
/// writes no state — the next resume starts earlier, never wrong — and
/// otherwise this is best effort: a state that cannot be written costs
/// a resume, not the run.
pub fn write(image: &Path, state_path: &Path, expected: &State, blocks_done: u64, lost: &Lost) {
    use std::io::Write;
    let flushed = std::fs::OpenOptions::new()
        .write(true)
        .open(image)
        .and_then(|f| f.sync_data());
    if flushed.is_err() {
        return;
    }
    let s = State {
        blocks_done,
        lost: lost.clone(),
        ..expected.key()
    };
    let Ok(json) = serde_json::to_vec(&s) else {
        return;
    };
    // Whatever is at the temporary name goes first — a stale one from a
    // run that died, or a link — and the file is made new: `create`
    // would follow a link there, and a link to a mapfile, a key or a
    // member got the state written over it.
    let tmp = tmp_path(state_path);
    if let Err(e) = std::fs::remove_file(&tmp) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return;
        }
    }
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(&json)?;
            f.sync_all()
        });
    if written.is_err() || std::fs::rename(&tmp, state_path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return;
    }
    // The rename is an entry in the directory; flush that too — the
    // current one when the path is relative and has no directory part.
    let dir = match state_path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
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
        if let Ok(m) = std::fs::metadata(output) {
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
        if let Some(stream) = own_stream(output) {
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
        let state: Option<State> = std::fs::read(&state_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        match state {
            Some(s) if s.key() == expected.key() => {
                start_block = s.blocks_done;
                let prefix = start_block * expected.blocksize;
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
                    SparseFile::open_existing(output, start_block * expected.blocksize)
                } else {
                    SparseFile::create(output)
                }
            }
            Some(_) => {
                eprintln!(
                    "{tool}: {} describes a different dataset/txg/size than {name}; starting over",
                    state_path.display()
                );
                SparseFile::create(output)
            }
            None => SparseFile::create(output),
        }
    } else {
        SparseFile::create(output)
    }
    .map_err(|e| format!("cannot open {}: {e}", output.display()))?;
    Ok((start_block, digests, sink, lost))
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
        }
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
        write(&out, &path(&out), &exp, 2, &Lost::default());

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
        write(&out, &path(&out), &exp, 2, &Lost::default());
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
        std::fs::write(&out, &prefix[..100]).unwrap();
        write(&out, &path(&out), &exp, 2, &Lost::default());
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
        write(&out, &path(&out), &exp, 1, &Lost::default());
        assert!(
            !path(&out).exists(),
            "a state for an image that is not there"
        );
        std::fs::write(&out, [9u8; 4096]).unwrap();
        write(&out, &path(&out), &exp, 1, &Lost::default());
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
        write(&out, &state, &expected(), 1, &Lost::default());
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
        write(&out, &path(&out), &expected(), 2, &lost);
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
        write(&out, &path(&out), &expected(), 2, &Lost::default());
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
}
