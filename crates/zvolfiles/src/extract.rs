//! `zvolfiles extract` — the tree out as files (Z-03, Z-05, Z-06).
//!
//! Every block goes through the pool reader, so a block that cannot be
//! read or does not verify is a hole of zeros in the output and a line
//! in the manifest, never a silent short file. `--strict` stops at the
//! first one instead.

use std::io::Write;

use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use zfs_ondisk::zpl::FileType;
use zfs_read::zpl::{walk, Filesystem};
use zvol_common::evidence::FileRef;
use zvol_common::{exit, Format, Global, PoolSpec};
use zvolrescue_io::refuse_if_evidence;

use crate::common::{with_dataset, AtArgs};

/// Options of an `extract` run.
pub struct Options {
    pub paths: Vec<String>,
    pub output: PathBuf,
    pub strict: bool,
    pub preserve: String,
}

/// One line of `manifest.json` (Z-05).
#[derive(Debug, Serialize)]
pub struct Extracted {
    pub path: String,
    pub object: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub mode: String,
    pub size: u64,
    pub uid: u64,
    pub gid: u64,
    pub mtime: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Blocks that could not be read and were written as zeros.
    pub errors: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

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
}

/// A path from the dataset, made safe to join onto the output directory.
///
/// A name from damaged metadata is not to be trusted with the shape of
/// the filesystem it is being written into: anything that would climb
/// out of the output directory, or start from its root, is refused.
fn safe_join(root: &Path, path: &str) -> Option<PathBuf> {
    let mut out = root.to_path_buf();
    for c in Path::new(path).components() {
        match c {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (out != root).then_some(out)
}

/// Copy one file's blocks out, zeroing what cannot be read (Z-06).
fn copy_file(
    fs: &Filesystem<'_, '_>,
    object: u64,
    size: u64,
    to: &Path,
    strict: bool,
) -> Result<(String, u64), String> {
    let obj = fs.object(object).map_err(|e| e.to_string())?;
    let bs = obj.dnode().datablksz().max(512);
    let mut file = std::fs::File::create(to).map_err(|e| format!("{}: {e}", to.display()))?;
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    let mut errors = 0u64;
    let zeros = vec![0u8; bs as usize];
    while written < size {
        let want = (size - written).min(bs) as usize;
        let blkid = written / bs;
        let chunk = match obj.read_blkid(blkid) {
            Ok(b) => b,
            Err(e) => {
                if strict {
                    return Err(format!("block {blkid}: {e}"));
                }
                errors += 1;
                zeros.clone()
            }
        };
        let piece = &chunk[..want.min(chunk.len())];
        hasher.update(piece);
        file.write_all(piece)
            .map_err(|e| format!("{}: {e}", to.display()))?;
        written += piece.len() as u64;
        if piece.is_empty() {
            break;
        }
    }
    let hex = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok((hex, errors))
}

/// Run `extract`.
pub fn run(g: &Global, spec: &PoolSpec, dataset: &str, at: &AtArgs, opts: &Options) -> u8 {
    let preserve: Vec<&str> = opts.preserve.split(',').map(str::trim).collect();
    let result = with_dataset(spec, dataset, at, |fs, opened| {
        if let Err(e) = refuse_if_evidence(&opts.output, &opened.members.paths) {
            eprintln!("zvolfiles: {e}");
            return Err(exit::REFUSED);
        }
        std::fs::create_dir_all(&opts.output).map_err(|e| {
            eprintln!("zvolfiles: {}: {e}", opts.output.display());
            exit::USAGE
        })?;

        // Nothing given means the whole dataset.
        let roots: Vec<(u64, String)> = if opts.paths.is_empty() {
            vec![(fs.root, String::new())]
        } else {
            let mut v = Vec::new();
            for p in &opts.paths {
                let obj = fs.lookup(p).map_err(|e| {
                    eprintln!("zvolfiles: {p}: {e}");
                    exit::UNRECOVERABLE
                })?;
                v.push((obj, p.trim_matches('/').to_string()));
            }
            v
        };

        let mut files = Vec::new();
        let mut directories = 0usize;
        for (obj, prefix) in roots {
            // A path that names a file rather than a directory is
            // extracted on its own.
            let z = fs.znode(obj).ok();
            if z.as_ref().map(|z| z.file_type()) == Some(FileType::Dir) {
                for e in walk(fs, obj, &prefix, true) {
                    extract_entry(fs, &e, opts, &preserve, &mut files, &mut directories);
                }
            } else {
                let e = zfs_read::zpl::Entry {
                    path: prefix.clone(),
                    object: obj,
                    znode: z,
                    error: None,
                };
                extract_entry(fs, &e, opts, &preserve, &mut files, &mut directories);
            }
        }
        let incomplete = files.iter().filter(|f| f.errors > 0).count();
        let failed = files.iter().filter(|f| f.error.is_some()).count();
        Ok((
            ManifestOut {
                dataset: dataset.to_string(),
                txg: opened.txg,
                output: opts.output.clone(),
                files,
                directories,
                incomplete,
                failed,
            },
            opened.members.paths.clone(),
        ))
    });
    let (out, paths) = match result {
        Ok(v) => v,
        Err(code) => return code,
    };

    let json = serde_json::to_value(&out).expect("serialisable");
    let manifest = opts.output.join("manifest.json");
    if let Err(e) = std::fs::write(
        &manifest,
        serde_json::to_string_pretty(&json).expect("serialisable") + "\n",
    ) {
        eprintln!("zvolfiles: {}: {e}", manifest.display());
        return exit::USAGE;
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
            println!("  manifest: {}", manifest.display());
        }
    }
    let code = if out.failed > 0 || out.incomplete > 0 {
        exit::PARTIAL
    } else {
        0
    };
    let written = FileRef::hashed(&manifest)
        .map(|f| vec![f])
        .unwrap_or_default();
    g.log_evidence("zvolfiles", &json, code, &paths, written)
}

/// Write one entry out and record what happened to it.
fn extract_entry(
    fs: &Filesystem<'_, '_>,
    e: &zfs_read::zpl::Entry,
    opts: &Options,
    preserve: &[&str],
    files: &mut Vec<Extracted>,
    directories: &mut usize,
) {
    let Some(z) = &e.znode else {
        files.push(failed(e, "metadata unreadable"));
        return;
    };
    let Some(to) = safe_join(&opts.output, &e.path) else {
        files.push(failed(e, "name would climb out of the output directory"));
        return;
    };
    let mut record = Extracted {
        path: e.path.clone(),
        object: e.object,
        kind: z.file_type().as_char().to_string(),
        mode: format!("{:04o}", z.permissions()),
        size: z.size,
        uid: z.uid,
        gid: z.gid,
        mtime: z.mtime,
        sha256: None,
        target: None,
        errors: 0,
        error: None,
    };
    match z.file_type() {
        FileType::Dir => {
            *directories += 1;
            if let Err(err) = std::fs::create_dir_all(&to) {
                record.error = Some(err.to_string());
            }
        }
        FileType::Symlink => match fs.symlink_target(e.object, z) {
            Ok(t) => {
                let target = String::from_utf8_lossy(&t).into_owned();
                record.target = Some(target.clone());
                // Written as a file holding the target rather than as a
                // symbolic link: a link out of a recovered tree would
                // point at whatever happens to be there now.
                if let Err(err) = std::fs::write(&to, &t) {
                    record.error = Some(err.to_string());
                }
            }
            Err(err) => record.error = Some(err.to_string()),
        },
        FileType::Regular => {
            if let Some(parent) = to.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match copy_file(fs, e.object, z.size, &to, opts.strict) {
                Ok((hash, errors)) => {
                    record.sha256 = Some(hash);
                    record.errors = errors;
                }
                Err(err) => record.error = Some(err),
            }
        }
        other => {
            record.error = Some(format!("not written: {other:?}"));
        }
    }
    if record.error.is_none() && preserve.contains(&"mode") {
        set_mode(&to, z.permissions());
    }
    files.push(record);
}

fn failed(e: &zfs_read::zpl::Entry, why: &str) -> Extracted {
    Extracted {
        path: e.path.clone(),
        object: e.object,
        kind: "?".into(),
        mode: "????".into(),
        size: 0,
        uid: 0,
        gid: 0,
        mtime: 0,
        sha256: None,
        target: None,
        errors: 0,
        error: Some(why.to_string()),
    }
}

/// Restore the permission bits, where the platform has them.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}
