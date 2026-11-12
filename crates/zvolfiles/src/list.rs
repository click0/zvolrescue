//! `zvolfiles list` — what is in the dataset.

use serde::Serialize;
use zfs_ondisk::zpl::{FileType, Znode};
use zfs_read::zpl::{walk_from, Entry};
use zvol_common::timefmt::iso8601_ns;
use zvol_common::{exit, Format, Global, PoolSpec};

use crate::common::{resolve_path, with_dataset, AtArgs};

#[derive(Debug, Serialize)]
struct FileOut {
    path: String,
    /// The path's exact bytes as hex, present only when the name is not
    /// UTF-8 and `path` therefore shows something else (Z-09).
    #[serde(skip_serializing_if = "Option::is_none")]
    path_hex: Option<String>,
    object: u64,
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gid: Option<u64>,
    /// Project id, present only where the dataset keeps one (Z-10).
    /// Absent is not the same as project zero, so absent is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    projid: Option<u64>,
    /// Modification time, to the nanosecond, either side of the epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    mtime: Option<String>,
    /// A device's number as `major,minor`.
    #[serde(skip_serializing_if = "Option::is_none")]
    rdev: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    /// Extended attributes, in name order (Z-04).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    xattrs: Vec<String>,
    /// Extended attributes, or sets of them, that could not be read.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    xattr_errors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ListOut {
    dataset: String,
    txg: u64,
    root: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    properties: std::collections::BTreeMap<String, u64>,
    files: Vec<FileOut>,
    /// A signal ended the walk (exit 6): the entries listed are what was
    /// walked before it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    interrupted: bool,
}

/// Turn one walked entry into the report's shape.
fn describe(
    e: &Entry,
    target: Option<String>,
    xattrs: Vec<String>,
    xattr_errors: Vec<String>,
) -> FileOut {
    let z = e.znode.as_ref();
    FileOut {
        path: e.path.clone(),
        path_hex: (!e.path_is_text())
            .then(|| e.raw_path.iter().map(|b| format!("{b:02x}")).collect()),
        object: e.object,
        kind: e
            .file_type()
            .map_or("?".to_string(), |t| t.as_char().to_string()),
        mode: z.map(|z| format!("{:04o}", z.permissions())),
        size: z.map(|z: &Znode| z.size),
        links: z.map(|z| z.links),
        uid: z.map(|z| z.uid),
        gid: z.map(|z| z.gid),
        projid: z.and_then(|z| z.projid),
        mtime: z.map(|z| iso8601_ns(z.mtime.secs, z.mtime.nanos)),
        rdev: z
            .filter(|z| matches!(z.file_type(), FileType::CharDevice | FileType::BlockDevice))
            .map(|z| format!("{},{}", z.rdev >> 32, z.rdev & 0xffff_ffff)),
        target,
        xattrs,
        xattr_errors,
        // Met a second time, a directory is listed where it was met
        // first: said, where it used to be an empty directory.
        error: e.error.clone().or_else(|| {
            e.walked_at
                .as_ref()
                .map(|first| format!("the same directory as {first}, listed there (a directory has one name: this is damage)"))
        }),
    }
}

/// Run `list`.
pub fn run(
    g: &Global,
    spec: &PoolSpec,
    dataset: &str,
    at: &AtArgs,
    path: Option<&std::ffi::OsStr>,
    recursive: bool,
) -> u8 {
    // A tree of many directories takes as long as it takes; a SIGINT
    // ends the walk at the next directory, with what was listed. It was
    // the default action: the run died with nothing printed.
    let interrupt = zvol_common::interrupt_flag();
    let result = with_dataset(spec, dataset, at, false, |fs, opened| {
        // As the dataset spells it (Z-09): `./sub` lists as `sub/…`, and
        // a name found by folding case as the name on disk.
        let (from, raw_prefix) = match path {
            None => (fs.root, Vec::new()),
            Some(p) => resolve_path(fs, p, opened.txg)?,
        };
        let prefix = String::from_utf8_lossy(&raw_prefix).into_owned();
        // A path that names a file is that one entry, as `extract` takes
        // it: walking it as a directory said "object is not a ZAP", with
        // the file's metadata as `?`, and exit 4.
        let z = fs.znode(from).ok();
        let entries =
            if path.is_some() && z.as_ref().is_some_and(|z| z.file_type() != FileType::Dir) {
                vec![Entry {
                    path: prefix.clone(),
                    raw_path: raw_prefix.clone(),
                    object: from,
                    znode: z,
                    error: None,
                    walked_at: None,
                }]
            } else {
                walk_from(fs, from, &prefix, &raw_prefix, recursive, Some(&interrupt))
            };
        let files: Vec<FileOut> = entries
            .iter()
            .map(|e| {
                let target = e
                    .znode
                    .as_ref()
                    .filter(|z| z.symlink.is_some())
                    .and_then(|z| {
                        fs.symlink_target(e.object, z)
                            .ok()
                            .map(|t| String::from_utf8_lossy(&t).into_owned())
                    });
                let read = e.znode.as_ref().map(|z| fs.xattrs(z)).unwrap_or_default();
                let mut xattr_errors = read.errors;
                xattr_errors.extend(
                    read.values
                        .iter()
                        .filter_map(|x| x.error.as_ref().map(|err| format!("{}: {err}", x.name))),
                );
                let xattrs = read.values.into_iter().map(|x| x.name).collect();
                describe(e, target, xattrs, xattr_errors)
            })
            .collect();
        let unreadable = files
            .iter()
            .filter(|f| f.error.is_some() || !f.xattr_errors.is_empty())
            .count();
        Ok((
            ListOut {
                dataset: dataset.to_string(),
                txg: opened.txg,
                root: fs.root,
                path: path.map(|p| p.to_string_lossy().into_owned()),
                properties: fs.properties.clone(),
                files,
                interrupted: interrupt.load(std::sync::atomic::Ordering::Relaxed),
            },
            unreadable,
            opened.members.paths.clone(),
            opened.members.ledger.clone(),
        ))
    });
    let (out, unreadable, paths, ledger) = match result {
        Ok(v) => v,
        // Nothing was produced — the members did not open, or the
        // dataset was not reached — but a device may have refused a
        // read on the way, and that ends the run the same way as one
        // refused later (SPEC F-33, N-10).
        Err(code) => return zvol_common::end_early(g, "zvolfiles", spec, code),
    };

    let json = serde_json::to_value(&out).expect("serialisable");
    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialisable")
        ),
        Format::Text => {
            println!(
                "{} at txg {}: {} entr{}",
                out.dataset,
                out.txg,
                out.files.len(),
                if out.files.len() == 1 { "y" } else { "ies" }
            );
            for f in &out.files {
                println!(
                    "{}{:<5} {:>4}/{:<4} {:>12} {:<22} {}{}",
                    f.kind,
                    f.mode.as_deref().unwrap_or("????"),
                    f.uid.map_or("?".to_string(), |v| v.to_string()),
                    f.gid.map_or("?".to_string(), |v| v.to_string()),
                    f.size.map_or("?".to_string(), |v| v.to_string()),
                    f.mtime.as_deref().unwrap_or("—"),
                    f.path,
                    f.target
                        .as_ref()
                        .map_or(String::new(), |t| format!(" -> {t}"))
                );
                if !f.xattrs.is_empty() {
                    println!("       xattrs: {}", f.xattrs.join(", "));
                }
                if let Some(r) = &f.rdev {
                    println!("       device {r}");
                }
                for x in &f.xattr_errors {
                    println!("       xattrs: {x}");
                }
                if let Some(e) = &f.error {
                    println!("       {e}");
                }
            }
        }
    }
    let code = if out.interrupted {
        eprintln!("zvolfiles: interrupted; what is listed is what was walked (exit 6)");
        exit::INTERRUPTED
    } else if unreadable > 0 {
        exit::PARTIAL
    } else {
        0
    };
    // A device refused a read: every incident on stderr, and the stop —
    // when one stopped the run — as the exit code (SPEC F-33, N-10).
    let code = zvol_common::report_medium(&ledger).unwrap_or(code);
    g.log_evidence_with_incidents(
        "zvolfiles",
        &json,
        code,
        &paths,
        Vec::new(),
        &ledger.incidents(),
    )
}
