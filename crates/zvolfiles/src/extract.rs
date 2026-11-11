//! `zvolfiles extract` — the tree out as files (Z-03, Z-05, Z-06).
//!
//! Every block goes through the pool reader, so a block that cannot be
//! read or does not verify is a hole of zeros in the output and a line
//! in the manifest, never a silent short file. `--strict` stops at the
//! first one instead.

use std::collections::BTreeSet;
use std::io::{Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use serde::Serialize;
use zfs_ondisk::zpl::{FileType, Time, Znode};
use zfs_read::zpl::{walk_from, Entry, Filesystem};
use zvol_common::evidence::FileRef;
use zvol_common::timefmt::iso8601_ns;
use zvol_common::{exit, Format, Global, PoolSpec};

use crate::common::{resolve_path, with_dataset, AtArgs, Zeroed};
use crate::out::{OutError, OutTree};

/// Options of an `extract` run.
pub struct Options {
    pub paths: Vec<std::ffi::OsString>,
    pub output: PathBuf,
    pub strict: bool,
    pub preserve: String,
}

/// One line of `manifest.json` (Z-05).
#[derive(Debug, Serialize)]
pub struct Extracted {
    pub path: String,
    /// The path's exact bytes as hex, present only when the name is not
    /// UTF-8 and `path` therefore shows something else (Z-09). The file
    /// is written under these bytes either way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_hex: Option<String>,
    pub object: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub mode: String,
    pub size: u64,
    pub uid: u64,
    pub gid: u64,
    /// Project id, present only where the dataset keeps one (Z-10).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projid: Option<u64>,
    /// Modification time, in seconds either side of the epoch.
    pub mtime: i64,
    /// All four times to the nanosecond (Z-05); absent when the metadata
    /// could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub times: Option<Times>,
    /// A character or block device's number, which a device file is
    /// nothing without.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdev: Option<Rdev>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The earlier path this one is a hard link to (Z-07).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardlink_to: Option<String>,
    /// Extended attributes, recorded rather than applied (Z-04).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub xattrs: Vec<Xattr>,
    /// Sets of extended attributes that could not be read at all.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub xattr_errors: Vec<String>,
    /// Blocks that could not be read whole and were written as zeros,
    /// in whole or in part.
    pub errors: u64,
    /// Which bytes those are, and why (Z-06).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub zeroed: Vec<Zeroed>,
    /// Recorded here and not made: a fifo, a device or a socket, which
    /// this build does not make. Not a failure — the dataset is whole —
    /// and so not counted as one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_made: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The error was a refusal: writing it would have reached what the
    /// run reads (exit 5).
    #[serde(skip)]
    pub refused: bool,
}

/// A file's four times, as text to the nanosecond.
#[derive(Debug, Serialize)]
pub struct Times {
    pub atime: String,
    pub mtime: String,
    pub ctime: String,
    pub crtime: String,
}

impl Times {
    fn of(z: &Znode) -> Times {
        let t = |t: Time| iso8601_ns(t.secs, t.nanos);
        Times {
            atime: t(z.atime),
            mtime: t(z.mtime),
            ctime: t(z.ctime),
            crtime: t(z.crtime),
        }
    }
}

/// A device number, as stored and as the major and minor it packs: the
/// major in the high 32 bits, the minor in the low (`zfs_expldev`).
#[derive(Debug, Serialize)]
pub struct Rdev {
    pub raw: u64,
    pub major: u64,
    pub minor: u64,
}

impl Rdev {
    fn of(z: &Znode) -> Option<Rdev> {
        matches!(z.file_type(), FileType::CharDevice | FileType::BlockDevice).then_some(Rdev {
            raw: z.rdev,
            major: z.rdev >> 32,
            minor: z.rdev & 0xffff_ffff,
        })
    }
}

/// One extended attribute, as the manifest records it.
///
/// The value is in exactly one of two fields, and which one it is in
/// says what it is. Writing hex into the same field that holds text
/// leaves the two indistinguishable: `"deadbeef"` is a perfectly good
/// four-byte value and a perfectly good eight-character one, and a
/// manifest that cannot tell a reader which it meant has made something
/// up. A reader that wants the value and finds `value` absent is
/// missing it loudly, which is the outcome to prefer.
///
/// The name has no such pair. An extended-attribute name that is not
/// UTF-8 loses its exact bytes before this point — `xattr=sa` packs the
/// names into an nvlist, and nvlist strings are decoded lossily
/// throughout this workspace — so there is nothing here to record. Such
/// a name is not something ZFS or any platform this runs on produces.
#[derive(Debug, Serialize)]
pub struct Xattr {
    pub name: String,
    /// The value as text, when every byte of it is text and none is a
    /// NUL. Absent when it is not: see `value_hex`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// The value's exact bytes as hex, present when and only when
    /// `value` is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_hex: Option<String>,
    /// The value's length on disk.
    pub bytes: u64,
    /// How much of it is recorded, present only when that is less: a
    /// value is read up to 64 KiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recorded: Option<usize>,
    /// Why the value could not be read; neither `value` nor `value_hex`
    /// is there then. An unreadable value was recorded as an empty one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The first name an object was written under, so a later name for the
/// same object becomes a hard link to it rather than a second copy.
#[derive(Debug, Clone)]
struct Written {
    path: String,
    raw_path: Vec<u8>,
    sha256: Option<String>,
}

type WrittenObjects = std::collections::BTreeMap<u64, Written>;

#[derive(Debug, Serialize)]
struct ManifestOut {
    dataset: String,
    txg: u64,
    output: PathBuf,
    files: Vec<Extracted>,
    directories: usize,
    /// Files with at least one block written as zeros.
    incomplete: usize,
    /// Entries that could not be written at all.
    failed: usize,
    /// Files written as hard links to an earlier path.
    hardlinks: usize,
    /// Fifos, devices and sockets: recorded, not made.
    #[serde(skip_serializing_if = "is_zero")]
    special: usize,
    /// `--strict` ended the run at this block (exit 4): the file it was
    /// in is `failed`, and nothing after it was looked at.
    #[serde(skip_serializing_if = "Option::is_none")]
    stopped: Option<String>,
    /// A SIGINT ended the run (exit 6): every entry listed before it is
    /// as recorded, the one it cut is `failed` with the reason, and
    /// nothing after it was looked at. Re-run with `--path` for the
    /// rest.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    interrupted: bool,
    /// What `--preserve` asked for and the platform would not do, each
    /// reason once: ownership as anyone but root, a time past what the
    /// clock can hold.
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    not_restored: BTreeSet<String>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// "1 entry", "2 entries".
fn entries(n: usize) -> String {
    format!("{n} entr{}", if n == 1 { "y" } else { "ies" })
}

/// What `--preserve` asked to put back (Z-03).
#[derive(Debug, Clone, Copy, Default)]
pub struct Preserve {
    times: bool,
    mode: bool,
    owner: bool,
}

impl Preserve {
    /// `times`, `mode` and `owner`, comma-separated; `none` for nothing.
    /// Anything else is a usage error: `--preserve bogus,owner` used to
    /// be taken, and turned off the mode it did not name.
    pub fn parse(list: &str) -> Result<Preserve, String> {
        let mut p = Preserve::default();
        for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match item {
                "times" => p.times = true,
                "mode" => p.mode = true,
                "owner" => p.owner = true,
                "none" => {}
                other => {
                    return Err(format!(
                        "--preserve {list}: {other:?} is not one of times, mode, owner, none"
                    ))
                }
            }
        }
        Ok(p)
    }
}

/// The metadata of one written path, put back after its contents — and
/// for a directory after everything in it, deepest first, so that
/// writing a child neither bumps a restored time nor meets a directory
/// already made read-only.
#[derive(Debug, Clone)]
struct Meta {
    path: PathBuf,
    mode: u32,
    mtime: Time,
    atime: Time,
    uid: u64,
    gid: u64,
    /// Written as a file holding a link's target.
    link_target: bool,
}

impl Meta {
    fn of(path: &Path, z: &zfs_ondisk::zpl::Znode) -> Meta {
        Meta {
            path: path.to_path_buf(),
            mode: z.permissions(),
            mtime: z.mtime,
            atime: z.atime,
            uid: z.uid,
            gid: z.gid,
            link_target: z.file_type() == FileType::Symlink,
        }
    }

    /// Times first, then the owner, then the mode: `chown` clears the
    /// set-id bits, and a mode can take away the access a time needs.
    ///
    /// The set-user-ID and set-group-ID bits are kept only on a file
    /// whose owner was put back too: on a file the extraction owns —
    /// root's, most often — they would make a program of the dataset
    /// run as root. A file holding a link's target is not a program at
    /// all and is never executable, whatever mode the link had.
    fn restore(&self, p: Preserve, notes: &mut BTreeSet<String>) {
        if p.times {
            match (system_time(self.mtime), system_time(self.atime)) {
                (Some(m), Some(a)) => {
                    let t = std::fs::FileTimes::new().set_modified(m).set_accessed(a);
                    if let Err(e) = std::fs::File::open(&self.path).and_then(|f| f.set_times(t)) {
                        notes.insert(format!("times: {e}"));
                    }
                }
                _ => {
                    notes.insert("times: a time this platform's clock cannot hold".into());
                }
            }
        }
        let mut owned = false;
        #[cfg(unix)]
        if p.owner {
            match (u32::try_from(self.uid), u32::try_from(self.gid)) {
                (Ok(u), Ok(g)) => match std::os::unix::fs::chown(&self.path, Some(u), Some(g)) {
                    Ok(()) => owned = true,
                    Err(e) => {
                        notes.insert(format!("owner: {e}"));
                    }
                },
                _ => {
                    notes.insert("owner: an id wider than 32 bits".into());
                }
            }
        }
        if p.mode {
            let mode = if self.link_target {
                0o644
            } else if owned {
                self.mode
            } else {
                self.mode & !0o6000
            };
            if let Err(e) = set_mode(&self.path, mode) {
                notes.insert(format!("mode: {e}"));
            }
        }
    }
}

/// A file's time as the clock holds it: before the epoch too, and to
/// the nanosecond. `None` for one the platform cannot hold.
fn system_time(t: Time) -> Option<std::time::SystemTime> {
    use std::time::{Duration, UNIX_EPOCH};
    let whole = if t.secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(t.secs.unsigned_abs()))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(t.secs.unsigned_abs()))
    };
    whole?.checked_add(Duration::from_nanos(u64::from(t.nanos)))
}

/// One path component, as the operating system spells names.
///
/// On Unix a file name is any byte string without `/` or NUL, so the
/// bytes go through unchanged and a file keeps the name it had, whatever
/// `utf8only` was set to. Elsewhere a name is text, and one that is not
/// text cannot be written at all — which is said rather than mangled.
#[cfg(unix)]
fn os_component(part: &[u8]) -> Option<std::ffi::OsString> {
    use std::os::unix::ffi::OsStringExt;
    Some(std::ffi::OsString::from_vec(part.to_vec()))
}

#[cfg(not(unix))]
fn os_component(part: &[u8]) -> Option<std::ffi::OsString> {
    std::str::from_utf8(part).ok().map(std::ffi::OsString::from)
}

/// A path from the dataset, made safe to join onto the output directory.
///
/// A name from damaged metadata is not to be trusted with the shape of
/// the filesystem it is being written into: anything that would climb
/// out of the output directory, or start from its root, is refused.
///
/// The path arrives as bytes rather than as text, because that is what
/// it is on disk (Z-09).
/// Every component must be one a file can have: an empty one or a `.`
/// is refused rather than skipped, because skipping it made two
/// different paths of the dataset one path of the output.
fn safe_join(root: &Path, path: &[u8]) -> Option<PathBuf> {
    let mut out = root.to_path_buf();
    for part in path.split(|&b| b == b'/') {
        if !zfs_read::zpl::is_component(part) {
            return None;
        }
        out.push(os_component(part)?);
    }
    Some(out)
}

/// How a file's copy can end short of the file.
enum CopyError {
    /// It could not be written, or the run was interrupted.
    Out(OutError),
    /// `--strict`, and a block that could not be read: the run ends.
    Strict(String),
}

impl From<OutError> for CopyError {
    fn from(e: OutError) -> CopyError {
        CopyError::Out(e)
    }
}

/// What a copied file came to.
struct Copied {
    sha256: String,
    zeroed: Vec<Zeroed>,
}

/// A file whose size runs this far past its last block is said to on
/// standard error: the rest is a hole, hashed as zeros without a read,
/// and a forged size of a petabyte hashes for days.
const TAIL_NOTE: u64 = 1 << 30;

/// Record `length` bytes at `offset` as zeros, merged into the run
/// before when it is the same failure going on: a forged size over a
/// block size of nothing is one entry, not one per block.
fn zero(zeroed: &mut Vec<Zeroed>, block: u64, offset: u64, length: u64, reason: String) {
    if let Some(last) = zeroed.last_mut() {
        if last.offset + last.length == offset && last.reason == reason {
            last.length += length;
            return;
        }
    }
    zeroed.push(Zeroed {
        block,
        offset,
        length,
        reason,
    });
}

/// Copy one file's blocks out, zeroing what cannot be read (Z-06).
#[allow(clippy::too_many_arguments)]
fn copy_file(
    fs: &Filesystem<'_, '_>,
    tree: &OutTree,
    object: u64,
    size: u64,
    to: &Path,
    shown: &str,
    strict: bool,
    stop: &AtomicBool,
) -> Result<Copied, CopyError> {
    let fail = |e: String| OutError::Failed(e);
    let obj = fs.object(object).map_err(|e| fail(e.to_string()))?;
    let bs = obj.dnode().datablksz().max(512);
    // Past its last block a file is a hole, and its zeros need no read.
    let blocks_end = obj.dnode().maxblkid.saturating_add(1).saturating_mul(bs);
    if size.saturating_sub(blocks_end) > TAIL_NOTE {
        eprintln!(
            "zvolfiles: {shown}: {size} bytes, and its blocks end at byte {blocks_end}: the rest is a hole, hashed as zeros (a sparse file, or a damaged size; SIGINT stops the run)"
        );
    }
    let mut file = tree.create(to)?;
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    let mut zeroed = Vec::new();
    let zeros = vec![0u8; bs as usize];
    while written < size {
        if stop.load(Ordering::Relaxed) {
            return Err(fail(format!("interrupted after {written} of {size} bytes")).into());
        }
        let want = (size - written).min(bs) as usize;
        let blkid = written / bs;
        let read = if written >= blocks_end {
            Ok(None)
        } else {
            obj.read_blkid(blkid).map(Some)
        };
        let piece: Vec<u8> = match read {
            Ok(None) => zeros[..want].to_vec(),
            Ok(Some(mut chunk)) if chunk.len() < want => {
                // Shorter than the file has here — a block size of
                // nothing, or a block that is not the size its dnode
                // says. Taken as it came, the copy stopped there: a short
                // file, the hash of what it held, and no error at all.
                let reason = format!(
                    "the block holds {} of the {want} bytes the file has here",
                    chunk.len()
                );
                if strict {
                    return Err(CopyError::Strict(format!("block {blkid}: {reason}")));
                }
                let had = chunk.len() as u64;
                zero(&mut zeroed, blkid, written + had, want as u64 - had, reason);
                chunk.resize(want, 0);
                chunk
            }
            Ok(Some(mut chunk)) => {
                chunk.truncate(want);
                chunk
            }
            Err(e) => {
                if strict {
                    return Err(CopyError::Strict(format!(
                        "block {blkid} (bytes {written}–{}): {e}",
                        written + want as u64
                    )));
                }
                zero(&mut zeroed, blkid, written, want as u64, e.to_string());
                zeros[..want].to_vec()
            }
        };
        hasher.update(&piece);
        // Holes stay holes: a block of zeros is left unwritten and the
        // length set at the end. A file of 256 MiB with one block used
        // to take 256 MiB of the disk it was extracted to.
        if piece.iter().any(|&b| b != 0) {
            file.seek(SeekFrom::Start(written))
                .and_then(|_| file.write_all(&piece))
                .map_err(|e| fail(format!("{}: {e}", to.display())))?;
        }
        written += want as u64;
    }
    file.set_len(written)
        .map_err(|e| fail(format!("{}: {e}", to.display())))?;
    let sha256 = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(Copied { sha256, zeroed })
}

/// Whether `path` is inside the directory `dir`, both as bytes; the
/// root, empty, holds everything.
fn under(dir: &[u8], path: &[u8]) -> bool {
    (dir.is_empty() && !path.is_empty())
        || (path.len() > dir.len() && path.starts_with(dir) && path[dir.len()] == b'/')
}

/// Everything one `extract` run keeps track of as it goes.
#[derive(Default)]
struct Run {
    files: Vec<Extracted>,
    directories: usize,
    /// Z-07: an object already written under another name is linked to
    /// rather than copied, so the tree keeps the shape it had.
    written_objects: WrittenObjects,
    /// Every output path written so far: two entries of a damaged
    /// dataset can still come to one path, and the second would be
    /// written over the first while the manifest listed both.
    taken: BTreeSet<PathBuf>,
    dirs: Vec<Meta>,
    not_restored: BTreeSet<String>,
    /// Directories that were not written, as bytes and as shown. What
    /// is under one is not written either: the children of a directory
    /// refused for taking another's path went into that other one —
    /// a 0700 directory's files into a 0755 one.
    unwritten_dirs: Vec<(Vec<u8>, String, u64)>,
    /// `--strict` ended the run, at this file and block.
    stopped: Option<String>,
}

/// Run `extract`.
pub fn run(g: &Global, spec: &PoolSpec, dataset: &str, at: &AtArgs, opts: &Options) -> u8 {
    // From here a SIGINT ends the run at the next entry, or the next
    // block of the file being written, with the manifest saying which.
    let interrupt = zvol_common::interrupt_flag();
    let preserve = match Preserve::parse(&opts.preserve) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("zvolfiles: {e}");
            return exit::USAGE;
        }
    };
    let result = with_dataset(spec, dataset, at, false, |fs, opened| {
        let tree = OutTree::open(g, spec, at, opened, &opts.output)?;

        // Nothing given means the whole dataset. A path is taken as the
        // dataset spells it (Z-09) — `./sub` is `sub`, and a name found
        // by folding case is written under the name on disk — and one
        // inside another given is written once, with the other: both
        // used to be written, the second refused as a path already
        // taken, and the run ended 4 over a tree that was whole.
        let mut roots: Vec<(u64, Vec<u8>)> = Vec::new();
        if opts.paths.is_empty() {
            roots.push((fs.root, Vec::new()));
        }
        let shown = |raw: &[u8]| {
            if raw.is_empty() {
                "/".to_string()
            } else {
                String::from_utf8_lossy(raw).into_owned()
            }
        };
        for p in &opts.paths {
            let (obj, raw) = resolve_path(fs, p, opened.txg)?;
            if let Some((_, outer)) = roots.iter().find(|(_, r)| *r == raw || under(r, &raw)) {
                eprintln!(
                    "zvolfiles: --path {}: within --path {}; written once",
                    p.to_string_lossy(),
                    shown(outer)
                );
                continue;
            }
            roots.retain(|(_, r)| {
                let inside = under(&raw, r);
                if inside {
                    eprintln!(
                        "zvolfiles: --path {}: within --path {}; written once",
                        shown(r),
                        p.to_string_lossy()
                    );
                }
                !inside
            });
            roots.push((obj, raw));
        }

        let mut run = Run::default();
        for (obj, raw_prefix) in roots {
            if interrupt.load(Ordering::Relaxed) || run.stopped.is_some() {
                break;
            }
            let prefix = String::from_utf8_lossy(&raw_prefix).into_owned();
            let (znode, error) = match fs.znode(obj) {
                Ok(z) => (Some(z), None),
                Err(e) => (None, Some(e.to_string())),
            };
            let is_dir = znode.as_ref().map(Znode::file_type) == Some(FileType::Dir);
            // The path itself, a file or a directory: the directory a
            // `--path` named was made with the extraction's time and mode
            // and recorded nowhere, and an empty one not made at all.
            // The dataset's root is the output directory, and is not.
            if !raw_prefix.is_empty() || !is_dir {
                let e = Entry {
                    raw_path: raw_prefix.clone(),
                    path: prefix.clone(),
                    object: obj,
                    znode,
                    error,
                    walked_at: None,
                };
                extract_entry(fs, &tree, &e, opts, preserve, &mut run, &interrupt);
            }
            if is_dir {
                for e in walk_from(fs, obj, &prefix, &raw_prefix, true) {
                    if interrupt.load(Ordering::Relaxed) || run.stopped.is_some() {
                        break;
                    }
                    extract_entry(fs, &tree, &e, opts, preserve, &mut run, &interrupt);
                }
            }
        }
        // Directories last, deepest first: their contents are written.
        for m in run.dirs.iter().rev() {
            m.restore(preserve, &mut run.not_restored);
        }
        for n in &run.not_restored {
            eprintln!("zvolfiles: --preserve: {n} (the manifest records what each file had)");
        }
        let interrupted = interrupt.load(Ordering::Relaxed);
        if interrupted {
            eprintln!(
                "zvolfiles: interrupted; the manifest lists what was written, re-run with --path for the rest (exit 6)"
            );
        }
        if let Some(at) = &run.stopped {
            eprintln!(
                "zvolfiles: --strict: {at}; the run stops here, and the manifest lists what was written (exit 4)"
            );
        }
        let files = run.files;
        let incomplete = files
            .iter()
            .filter(|f| {
                f.errors > 0
                    || !f.xattr_errors.is_empty()
                    || f.xattrs.iter().any(|x| x.error.is_some())
            })
            .count();
        let failed = files.iter().filter(|f| f.error.is_some()).count();
        let refused = files.iter().filter(|f| f.refused).count();
        if refused > 0 {
            eprintln!(
                "zvolfiles: {} refused: the path holds something this run reads (exit 5)",
                entries(refused)
            );
        }
        let hardlinks = files.iter().filter(|f| f.hardlink_to.is_some()).count();
        let special = files.iter().filter(|f| f.not_made.is_some()).count();
        Ok((
            ManifestOut {
                dataset: dataset.to_string(),
                txg: opened.txg,
                output: opts.output.clone(),
                files,
                directories: run.directories,
                incomplete,
                failed,
                hardlinks,
                special,
                stopped: run.stopped,
                interrupted,
                not_restored: run.not_restored,
            },
            opened.members.paths.clone(),
            opened.members.ledger.clone(),
            tree,
            refused,
            run.taken,
        ))
    });
    let (out, paths, ledger, tree, refused, taken) = match result {
        Ok(v) => v,
        // Nothing was produced — the members did not open, or the
        // dataset was not reached — but a device may have refused a
        // read on the way, and that ends the run the same way as one
        // refused later (SPEC F-33, N-10).
        Err(code) => return zvol_common::end_early(g, "zvolfiles", spec, code),
    };

    let json = serde_json::to_value(&out).expect("serialisable");
    // The manifest goes beside the tree under a name neither the tree
    // nor an earlier run took: a dataset with a `manifest.json` of its
    // own had that file replaced by the manifest, which then vouched for
    // its hash, and a second run — `--path` for what the first did not
    // finish — wrote over the first run's manifest, the one record of
    // what that run wrote.
    let manifest = std::iter::once("manifest.json".to_string())
        .chain((1..).map(|n| format!("manifest.{n}.json")))
        .map(|name| opts.output.join(name))
        .find(|p| !taken.contains(p) && std::fs::symlink_metadata(p).is_err())
        .expect("an unbounded supply of names");
    let wrote = tree.create(&manifest).and_then(|mut f| {
        f.write_all((serde_json::to_string_pretty(&json).expect("serialisable") + "\n").as_bytes())
            .map_err(|e| OutError::Failed(format!("{}: {e}", manifest.display())))
    });
    if let Err(e) = wrote {
        eprintln!("zvolfiles: {}: {e}", manifest.display());
        return if matches!(e, OutError::Refused(_)) {
            exit::REFUSED
        } else {
            exit::USAGE
        };
    }
    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialisable")
        ),
        Format::Text => {
            println!(
                "{} at txg {}: {} file(s), {} director{} -> {}",
                out.dataset,
                out.txg,
                out.files.len() - out.directories,
                out.directories,
                if out.directories == 1 { "y" } else { "ies" },
                out.output.display()
            );
            if out.incomplete > 0 {
                println!(
                    "  {} file(s) not read whole: blocks written as zeros, or extended attributes missing",
                    out.incomplete
                );
            }
            if out.failed > 0 {
                println!("  {} could not be written", entries(out.failed));
            }
            if out.hardlinks > 0 {
                println!("  {} hard link(s)", out.hardlinks);
            }
            if out.special > 0 {
                println!(
                    "  {} fifo(s), device(s) or socket(s) recorded in the manifest, not made",
                    out.special
                );
            }
            if let Some(at) = &out.stopped {
                println!("  STOPPED (--strict, exit 4) at {at}");
            }
            if out.interrupted {
                println!("  INTERRUPTED (exit 6): the entries above are what was written; re-run with --path for the rest");
            }
            println!("  manifest: {}", manifest.display());
        }
    }
    let code = if out.interrupted {
        exit::INTERRUPTED
    } else if refused > 0 {
        exit::REFUSED
    } else if out.failed > 0 || out.incomplete > 0 || out.stopped.is_some() {
        exit::PARTIAL
    } else {
        0
    };
    let written = FileRef::hashed(&manifest)
        .map(|f| vec![f])
        .unwrap_or_default();
    // A device refused a read: every incident on stderr, and the stop —
    // when one stopped the run — as the exit code (SPEC F-33, N-10).
    let code = zvol_common::report_medium(&ledger).unwrap_or(code);
    g.log_evidence_with_incidents(
        "zvolfiles",
        &json,
        code,
        &paths,
        written,
        &ledger.incidents(),
    )
}

/// What the manifest records of an entry whose metadata was read.
fn record_of(fs: &Filesystem<'_, '_>, e: &Entry, z: &Znode) -> Extracted {
    let xattrs = xattrs_of(fs, z);
    Extracted {
        path: e.path.clone(),
        path_hex: path_hex(e),
        object: e.object,
        kind: z.file_type().as_char().to_string(),
        mode: format!("{:04o}", z.permissions()),
        size: z.size,
        uid: z.uid,
        gid: z.gid,
        projid: z.projid,
        mtime: z.mtime.secs,
        times: Some(Times::of(z)),
        rdev: Rdev::of(z),
        sha256: None,
        target: None,
        hardlink_to: None,
        xattrs: xattrs.0,
        xattr_errors: xattrs.1,
        errors: 0,
        zeroed: Vec::new(),
        not_made: None,
        error: None,
        refused: false,
    }
}

/// Write one entry out and record what happened to it.
fn extract_entry(
    fs: &Filesystem<'_, '_>,
    tree: &OutTree,
    e: &Entry,
    opts: &Options,
    preserve: Preserve,
    run: &mut Run,
    stop: &AtomicBool,
) {
    if let Some((_, dir, obj)) = run
        .unwritten_dirs
        .iter()
        .find(|(d, _, _)| under(d, &e.raw_path))
    {
        let why = format!(
            "inside {dir}, object {obj}, which was not written; the object is under `objects`"
        );
        run.files.push(match &e.znode {
            Some(z) => Extracted {
                error: Some(why),
                ..record_of(fs, e, z)
            },
            None => failed(e, &why),
        });
        return;
    }
    let Some(z) = &e.znode else {
        run.files.push(failed(
            e,
            e.error.as_deref().unwrap_or("metadata unreadable"),
        ));
        return;
    };
    let is_dir = z.file_type() == FileType::Dir;
    let mut record = record_of(fs, e, z);
    // Not written, and when it is a directory, nothing under it is.
    let reject = |run: &mut Run, mut record: Extracted, why: String| {
        record.error = Some(why);
        if is_dir {
            run.unwritten_dirs
                .push((e.raw_path.clone(), e.path.clone(), e.object));
        }
        run.files.push(record);
    };
    if let Some(first) = &e.walked_at {
        record.error = Some(format!(
            "the same directory as {first}, whose contents are written there and not again (a directory has one name: this is damage)"
        ));
        run.files.push(record);
        return;
    }
    let Some(to) = safe_join(&opts.output, &e.raw_path) else {
        reject(
            run,
            record,
            "the path is not one a file can have here; the object is under `objects`".into(),
        );
        return;
    };
    if !run.taken.insert(to.clone()) {
        reject(
            run,
            record,
            "another entry of the dataset was already written at this path; the object is under `objects`".into(),
        );
        return;
    }
    let fail = |record: &mut Extracted, err: OutError| {
        record.refused = matches!(err, OutError::Refused(_));
        record.error = Some(err.to_string());
    };
    match z.file_type() {
        FileType::Dir => {
            run.directories += 1;
            if let Err(err) = tree.dir(&to) {
                fail(&mut record, err);
                run.unwritten_dirs
                    .push((e.raw_path.clone(), e.path.clone(), e.object));
            }
        }
        FileType::Symlink => match fs.symlink_target(e.object, z) {
            Ok(t) => {
                let target = String::from_utf8_lossy(&t).into_owned();
                record.target = Some(target.clone());
                // Written as a file holding the target rather than as a
                // symbolic link: a link out of a recovered tree would
                // point at whatever happens to be there now.
                let wrote = tree.create(&to).and_then(|mut f| {
                    f.write_all(&t)
                        .map_err(|err| OutError::Failed(format!("{}: {err}", to.display())))
                });
                if let Err(err) = wrote {
                    fail(&mut record, err);
                }
            }
            Err(err) => record.error = Some(err.to_string()),
        },
        FileType::Regular => {
            // The same object under a second name is a hard link, and
            // reading its blocks again would only prove that twice.
            if let Some(first) = run.written_objects.get(&e.object).cloned() {
                match safe_join(&opts.output, &first.raw_path)
                    .ok_or_else(|| {
                        OutError::Failed("the first name is not one this platform can write".into())
                    })
                    .and_then(|from| tree.hard_link(&from, &to))
                {
                    Ok(()) => {
                        record.hardlink_to = Some(first.path.clone());
                        record.sha256 = first.sha256.clone();
                    }
                    Err(err) => fail(&mut record, err),
                }
                run.files.push(record);
                return;
            }
            match copy_file(fs, tree, e.object, z.size, &to, &e.path, opts.strict, stop) {
                Ok(copied) => {
                    if let Some(first) = copied.zeroed.first() {
                        eprintln!(
                            "zvolfiles: {}: {} run(s) of bytes written as zeros, the first {}–{}: {} (the manifest lists each)",
                            e.path,
                            copied.zeroed.len(),
                            first.offset,
                            first.offset + first.length,
                            first.reason
                        );
                    }
                    record.sha256 = Some(copied.sha256.clone());
                    record.errors = copied.zeroed.len() as u64;
                    record.zeroed = copied.zeroed;
                    // Only now, and only for an object that has more
                    // names to come: the hash is what a later link
                    // records, and reading the blocks again would prove
                    // the same thing twice (Z-07).
                    if z.links > 1 {
                        run.written_objects.insert(
                            e.object,
                            Written {
                                path: e.path.clone(),
                                raw_path: e.raw_path.clone(),
                                sha256: Some(copied.sha256),
                            },
                        );
                    }
                }
                Err(CopyError::Out(err)) => fail(&mut record, err),
                // The run ends here: what is in the file is the bytes
                // before the block, and the manifest says so.
                Err(CopyError::Strict(why)) => {
                    record.error = Some(format!(
                        "{why}; --strict stops the run here, and the file holds the bytes before it"
                    ));
                    run.stopped = Some(format!("{}: {why}", e.path));
                }
            }
        }
        // There is no call for these without the platform's library,
        // and a fifo or a device made by a recovery is not evidence of
        // anything: recorded, with the device's number, and not made.
        // Counted as failures, they ended every extraction of a whole
        // dataset that held one with exit 4.
        FileType::Fifo | FileType::CharDevice | FileType::BlockDevice | FileType::Socket => {
            let what = match z.file_type() {
                FileType::Fifo => "a fifo",
                FileType::CharDevice => "a character device",
                FileType::BlockDevice => "a block device",
                _ => "a socket",
            };
            run.taken.remove(&to);
            record.not_made = Some(format!(
                "{what}: recorded here, not made (this build writes files, directories and links)"
            ));
        }
        other => {
            record.error = Some(format!("not written: {other:?}"));
        }
    }
    if record.error.is_none() && record.not_made.is_none() {
        if is_dir {
            run.dirs.push(Meta::of(&to, z));
        } else {
            Meta::of(&to, z).restore(preserve, &mut run.not_restored);
        }
    }
    run.files.push(record);
}

/// The exact bytes of a path, but only where printing them lost
/// something; a name that is text needs no second spelling.
fn path_hex(e: &Entry) -> Option<String> {
    (!e.path_is_text()).then(|| e.raw_path.iter().map(|b| format!("{b:02x}")).collect())
}

fn failed(e: &Entry, why: &str) -> Extracted {
    Extracted {
        path: e.path.clone(),
        path_hex: path_hex(e),
        object: e.object,
        kind: "?".into(),
        mode: "????".into(),
        size: 0,
        uid: 0,
        gid: 0,
        // Nothing was read, so nothing is claimed about a project.
        projid: None,
        mtime: 0,
        times: None,
        rdev: None,
        sha256: None,
        target: None,
        hardlink_to: None,
        xattrs: Vec::new(),
        xattr_errors: Vec::new(),
        errors: 0,
        zeroed: Vec::new(),
        not_made: None,
        error: Some(why.to_string()),
        refused: false,
    }
}

/// Restore the permission bits, where the platform has them.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

/// Extended attributes as the manifest records them (Z-04).
///
/// Recorded, not applied: setting an extended attribute needs the
/// platform's own call, and this workspace links no system libraries.
/// The manifest is where a recovery reads them back from, and a value
/// that is text is written as text so it can be read at all.
fn xattrs_of(fs: &Filesystem<'_, '_>, z: &Znode) -> (Vec<Xattr>, Vec<String>) {
    let read = fs.xattrs(z);
    let values = read
        .values
        .into_iter()
        .map(|x| {
            let bytes = &x.value;
            let (value, value_hex) = if x.error.is_some() {
                (None, None)
            } else {
                match std::str::from_utf8(bytes) {
                    Ok(t) if !t.contains('\0') => (Some(t.to_string()), None),
                    _ => (
                        None,
                        Some(bytes.iter().map(|b| format!("{b:02x}")).collect()),
                    ),
                }
            };
            Xattr {
                name: x.name,
                value,
                value_hex,
                bytes: x.size,
                recorded: (x.error.is_none() && (bytes.len() as u64) < x.size)
                    .then_some(bytes.len()),
                error: x.error,
            }
        })
        .collect();
    (values, read.errors)
}

#[cfg(test)]
mod tests {
    use super::{safe_join, Meta, Preserve};
    use std::collections::BTreeSet;
    use std::path::Path;

    /// The set-id bits go only with the owner, a link's target is never
    /// executable, and a time is put back as the dataset had it; an item
    /// `--preserve` does not know is refused.
    #[cfg(unix)]
    #[test]
    fn what_preserve_puts_back() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("zvolfiles-meta-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("prog");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        let at = |secs| zfs_ondisk::zpl::Time { secs, nanos: 0 };
        let meta = |link_target| Meta {
            path: f.clone(),
            mode: 0o4755,
            mtime: at(1_757_100_001),
            atime: at(1_757_100_002),
            uid: u64::MAX,
            gid: 0,
            link_target,
        };
        let p = Preserve::parse("times,mode").unwrap();
        let mut notes = BTreeSet::new();
        meta(false).restore(p, &mut notes);
        let m = std::fs::metadata(&f).unwrap();
        assert_eq!(m.permissions().mode() & 0o7777, 0o755);
        assert_eq!(m.mtime(), 1_757_100_001);
        meta(true).restore(p, &mut notes);
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        assert!(notes.is_empty(), "{notes:?}");
        // An owner that cannot be set is said once, and set-id stays off.
        let mut notes = BTreeSet::new();
        meta(false).restore(Preserve::parse("mode,owner").unwrap(), &mut notes);
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o7777,
            0o755
        );
        assert_eq!(notes.len(), 1, "{notes:?}");
        // Before the epoch is before it, to the nanosecond: read as an
        // unsigned count, a day before 1970 was the year 584 554 051 223,
        // and "a time past what this platform's clock holds".
        let mut old = meta(false);
        old.mtime = zfs_ondisk::zpl::Time {
            secs: -86_400,
            nanos: 123_456_789,
        };
        let mut notes = BTreeSet::new();
        old.restore(p, &mut notes);
        assert!(notes.is_empty(), "{notes:?}");
        let m = std::fs::metadata(&f).unwrap();
        assert_eq!((m.mtime(), m.mtime_nsec()), (-86_400, 123_456_789));
        // One no clock holds is at most a note, never a panic.
        for secs in [i64::MAX, i64::MIN] {
            let mut far = meta(false);
            far.mtime = at(secs);
            let mut notes = BTreeSet::new();
            far.restore(p, &mut notes);
            assert!(notes.len() <= 1, "{notes:?}");
        }
        assert!(Preserve::parse("bogus,owner").is_err());
        assert!(Preserve::parse("none").is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A path whose components could not all be names of files is not
    /// joined at all: an empty or `.` component used to be skipped, so
    /// `a//b` and `a/./b` became `a/b`, written over the real one.
    #[test]
    fn a_path_joins_only_when_every_component_is_a_name() {
        let root = Path::new("/out");
        assert_eq!(
            safe_join(root, b"sub/deep.txt").as_deref(),
            Some(Path::new("/out/sub/deep.txt"))
        );
        for bad in [
            &b""[..],
            b"/etc/passwd",
            b"a//b",
            b"a/./b",
            b"a/../b",
            b"..",
            b"a/b\0c",
            b"a/",
        ] {
            assert_eq!(
                safe_join(root, bad),
                None,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
