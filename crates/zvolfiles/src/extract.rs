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
use zfs_ondisk::zpl::FileType;
use zfs_read::zpl::{walk_from, Filesystem};
use zvol_common::evidence::FileRef;
use zvol_common::{exit, Format, Global, PoolSpec};

use crate::common::{with_dataset, AtArgs};
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
    pub mtime: u64,
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
    /// Blocks that could not be read and were written as zeros.
    pub errors: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The error was a refusal: writing it would have reached what the
    /// run reads (exit 5).
    #[serde(skip)]
    pub refused: bool,
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
    pub bytes: usize,
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
    mtime: u64,
    atime: u64,
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
        use std::time::{Duration, UNIX_EPOCH};
        if p.times {
            let at = |s: u64| UNIX_EPOCH.checked_add(Duration::from_secs(s));
            match (at(self.mtime), at(self.atime)) {
                (Some(m), Some(a)) => {
                    let t = std::fs::FileTimes::new().set_modified(m).set_accessed(a);
                    if let Err(e) = std::fs::File::open(&self.path).and_then(|f| f.set_times(t)) {
                        notes.insert(format!("times: {e}"));
                    }
                }
                _ => {
                    notes.insert("times: a time past what this platform's clock holds".into());
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

/// Copy one file's blocks out, zeroing what cannot be read (Z-06).
#[allow(clippy::too_many_arguments)]
fn copy_file(
    fs: &Filesystem<'_, '_>,
    tree: &OutTree,
    object: u64,
    size: u64,
    to: &Path,
    strict: bool,
    stop: &AtomicBool,
) -> Result<(String, u64), OutError> {
    let fail = |e: String| OutError::Failed(e);
    let obj = fs.object(object).map_err(|e| fail(e.to_string()))?;
    let bs = obj.dnode().datablksz().max(512);
    let mut file = tree.create(to)?;
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    let mut errors = 0u64;
    let zeros = vec![0u8; bs as usize];
    while written < size {
        if stop.load(Ordering::Relaxed) {
            return Err(fail(format!("interrupted after {written} of {size} bytes")));
        }
        let want = (size - written).min(bs) as usize;
        let blkid = written / bs;
        let chunk = match obj.read_blkid(blkid) {
            Ok(b) => b,
            Err(e) => {
                if strict {
                    return Err(fail(format!("block {blkid}: {e}")));
                }
                errors += 1;
                zeros.clone()
            }
        };
        let piece = &chunk[..want.min(chunk.len())];
        hasher.update(piece);
        // Holes stay holes: a block of zeros is left unwritten and the
        // length set at the end. A file of 256 MiB with one block used
        // to take 256 MiB of the disk it was extracted to.
        if piece.iter().any(|&b| b != 0) {
            file.seek(SeekFrom::Start(written))
                .and_then(|_| file.write_all(piece))
                .map_err(|e| fail(format!("{}: {e}", to.display())))?;
        }
        written += piece.len() as u64;
        if piece.is_empty() {
            break;
        }
    }
    file.set_len(written)
        .map_err(|e| fail(format!("{}: {e}", to.display())))?;
    let hex = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok((hex, errors))
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

        // Nothing given means the whole dataset.
        let roots: Vec<(u64, Vec<u8>)> = if opts.paths.is_empty() {
            vec![(fs.root, Vec::new())]
        } else {
            let mut v = Vec::new();
            for p in &opts.paths {
                let asked = crate::common::os_bytes(p);
                let obj = fs.lookup_bytes(&asked).map_err(|e| {
                    eprintln!("zvolfiles: {}: {e}", p.to_string_lossy());
                    exit::UNRECOVERABLE
                })?;
                let trimmed: Vec<u8> = asked
                    .split(|&b| b == b'/')
                    .filter(|c| !c.is_empty())
                    .collect::<Vec<_>>()
                    .join(&b'/');
                v.push((obj, trimmed));
            }
            v
        };

        let mut files = Vec::new();
        let mut directories = 0usize;
        // Every output path written so far: two entries of a damaged
        // dataset can still come to one path, and the second would be
        // written over the first while the manifest listed both.
        let mut taken = std::collections::BTreeSet::new();
        let mut dirs: Vec<Meta> = Vec::new();
        let mut not_restored = BTreeSet::new();
        // Z-07: an object already written under another name is linked
        // to rather than copied, so the tree keeps the shape it had.
        let mut written_objects: WrittenObjects = std::collections::BTreeMap::new();
        for (obj, raw_prefix) in roots {
            if interrupt.load(Ordering::Relaxed) {
                break;
            }
            let prefix = String::from_utf8_lossy(&raw_prefix).into_owned();
            // A path that names a file rather than a directory is
            // extracted on its own.
            let z = fs.znode(obj).ok();
            if z.as_ref().map(|z| z.file_type()) == Some(FileType::Dir) {
                for e in walk_from(fs, obj, &prefix, &raw_prefix, true) {
                    if interrupt.load(Ordering::Relaxed) {
                        break;
                    }
                    extract_entry(
                        fs,
                        &tree,
                        &e,
                        opts,
                        preserve,
                        &mut files,
                        &mut directories,
                        &mut written_objects,
                        &mut taken,
                        &mut dirs,
                        &mut not_restored,
                        &interrupt,
                    );
                }
            } else {
                let e = zfs_read::zpl::Entry {
                    raw_path: raw_prefix.clone(),
                    path: prefix.clone(),
                    object: obj,
                    znode: z,
                    error: None,
                };
                extract_entry(
                    fs,
                    &tree,
                    &e,
                    opts,
                    preserve,
                    &mut files,
                    &mut directories,
                    &mut written_objects,
                    &mut taken,
                    &mut dirs,
                    &mut not_restored,
                    &interrupt,
                );
            }
        }
        // Directories last, deepest first: their contents are written.
        for m in dirs.iter().rev() {
            m.restore(preserve, &mut not_restored);
        }
        for n in &not_restored {
            eprintln!("zvolfiles: --preserve: {n} (the manifest records what each file had)");
        }
        let interrupted = interrupt.load(Ordering::Relaxed);
        if interrupted {
            eprintln!(
                "zvolfiles: interrupted; the manifest lists what was written, re-run with --path for the rest (exit 6)"
            );
        }
        let incomplete = files.iter().filter(|f| f.errors > 0).count();
        let failed = files.iter().filter(|f| f.error.is_some()).count();
        let refused = files.iter().filter(|f| f.refused).count();
        if refused > 0 {
            eprintln!(
                "zvolfiles: {refused} entr(y|ies) refused: the path holds something this run reads (exit 5)"
            );
        }
        let hardlinks = files.iter().filter(|f| f.hardlink_to.is_some()).count();
        Ok((
            ManifestOut {
                dataset: dataset.to_string(),
                txg: opened.txg,
                output: opts.output.clone(),
                files,
                directories,
                incomplete,
                failed,
                hardlinks,
                interrupted,
                not_restored,
            },
            opened.members.paths.clone(),
            opened.members.ledger.clone(),
            tree,
            refused,
            taken,
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
    // The manifest goes beside the tree under a name the tree did not
    // take: a dataset with a `manifest.json` of its own had that file
    // replaced by the manifest, which then vouched for its hash.
    let manifest = std::iter::once("manifest.json".to_string())
        .chain((1..).map(|n| format!("manifest.{n}.json")))
        .map(|name| opts.output.join(name))
        .find(|p| !taken.contains(p))
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
                println!("  {} file(s) have blocks written as zeros", out.incomplete);
            }
            if out.failed > 0 {
                println!("  {} entr(y|ies) could not be written", out.failed);
            }
            if out.hardlinks > 0 {
                println!("  {} hard link(s)", out.hardlinks);
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
    } else if out.failed > 0 || out.incomplete > 0 {
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

/// Write one entry out and record what happened to it.
#[allow(clippy::too_many_arguments)]
fn extract_entry(
    fs: &Filesystem<'_, '_>,
    tree: &OutTree,
    e: &zfs_read::zpl::Entry,
    opts: &Options,
    preserve: Preserve,
    files: &mut Vec<Extracted>,
    directories: &mut usize,
    written_objects: &mut WrittenObjects,
    taken: &mut std::collections::BTreeSet<PathBuf>,
    dirs: &mut Vec<Meta>,
    not_restored: &mut BTreeSet<String>,
    stop: &AtomicBool,
) {
    let Some(z) = &e.znode else {
        files.push(failed(
            e,
            e.error.as_deref().unwrap_or("metadata unreadable"),
        ));
        return;
    };
    let Some(to) = safe_join(&opts.output, &e.raw_path) else {
        files.push(failed(
            e,
            "the path is not one a file can have here; the object is under `objects`",
        ));
        return;
    };
    if !taken.insert(to.clone()) {
        files.push(failed(
            e,
            "another entry of the dataset was already written at this path; the object is under `objects`",
        ));
        return;
    }
    let mut record = Extracted {
        path: e.path.clone(),
        path_hex: path_hex(e),
        object: e.object,
        kind: z.file_type().as_char().to_string(),
        mode: format!("{:04o}", z.permissions()),
        size: z.size,
        uid: z.uid,
        gid: z.gid,
        projid: z.projid,
        mtime: z.mtime,
        sha256: None,
        target: None,
        hardlink_to: None,
        xattrs: xattrs_of(fs, z),
        errors: 0,
        error: None,
        refused: false,
    };
    let fail = |record: &mut Extracted, err: OutError| {
        record.refused = matches!(err, OutError::Refused(_));
        record.error = Some(err.to_string());
    };
    match z.file_type() {
        FileType::Dir => {
            *directories += 1;
            if let Err(err) = tree.dir(&to) {
                fail(&mut record, err);
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
            if let Some(first) = written_objects.get(&e.object).cloned() {
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
                files.push(record);
                return;
            }
            match copy_file(fs, tree, e.object, z.size, &to, opts.strict, stop) {
                Ok((hash, errors)) => {
                    record.sha256 = Some(hash.clone());
                    record.errors = errors;
                    // Only now, and only for an object that has more
                    // names to come: the hash is what a later link
                    // records, and reading the blocks again would prove
                    // the same thing twice (Z-07).
                    if z.links > 1 {
                        written_objects.insert(
                            e.object,
                            Written {
                                path: e.path.clone(),
                                raw_path: e.raw_path.clone(),
                                sha256: Some(hash),
                            },
                        );
                    }
                }
                Err(err) => fail(&mut record, err),
            }
        }
        other => {
            record.error = Some(format!("not written: {other:?}"));
        }
    }
    if record.error.is_none() {
        if z.file_type() == FileType::Dir {
            dirs.push(Meta::of(&to, z));
        } else {
            Meta::of(&to, z).restore(preserve, not_restored);
        }
    }
    files.push(record);
}

/// The exact bytes of a path, but only where printing them lost
/// something; a name that is text needs no second spelling.
fn path_hex(e: &zfs_read::zpl::Entry) -> Option<String> {
    (!e.path_is_text()).then(|| e.raw_path.iter().map(|b| format!("{b:02x}")).collect())
}

fn failed(e: &zfs_read::zpl::Entry, why: &str) -> Extracted {
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
        sha256: None,
        target: None,
        hardlink_to: None,
        xattrs: Vec::new(),
        errors: 0,
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
fn xattrs_of(fs: &Filesystem<'_, '_>, z: &zfs_ondisk::zpl::Znode) -> Vec<Xattr> {
    fs.xattrs(z)
        .into_iter()
        .map(|(name, bytes)| {
            let (value, value_hex) = match std::str::from_utf8(&bytes) {
                Ok(t) if !t.contains('\0') => (Some(t.to_string()), None),
                _ => (
                    None,
                    Some(bytes.iter().map(|b| format!("{b:02x}")).collect()),
                ),
            };
            Xattr {
                name,
                value,
                value_hex,
                bytes: bytes.len(),
            }
        })
        .collect()
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
        let meta = |link_target| Meta {
            path: f.clone(),
            mode: 0o4755,
            mtime: 1_757_100_001,
            atime: 1_757_100_002,
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
        // A time no clock holds is a note, not a panic.
        let mut far = meta(false);
        far.mtime = u64::MAX;
        let mut notes = BTreeSet::new();
        far.restore(p, &mut notes);
        assert_eq!(notes.len(), 1, "{notes:?}");
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
