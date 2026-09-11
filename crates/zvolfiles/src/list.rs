//! `zvolfiles list` — what is in the dataset.

use serde::Serialize;
use zfs_ondisk::zpl::Znode;
use zfs_read::zpl::{walk_from, Entry};
use zvol_common::timefmt::iso8601;
use zvol_common::{exit, Format, Global, PoolSpec};

use crate::common::{os_bytes, with_dataset, AtArgs};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    mtime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    /// Extended attributes, in name order (Z-04).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    xattrs: Vec<String>,
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
}

/// Turn one walked entry into the report's shape.
fn describe(e: &Entry, target: Option<String>, xattrs: Vec<String>) -> FileOut {
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
        mtime: z.map(|z| iso8601(z.mtime)),
        target,
        xattrs,
        error: e.error.clone(),
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
    let asked = path.map(os_bytes).unwrap_or_default();
    let result = with_dataset(spec, dataset, at, |fs, opened| {
        let from = match path {
            None => fs.root,
            Some(p) => fs.lookup_bytes(&asked).map_err(|e| {
                eprintln!("zvolfiles: {}: {e}", p.to_string_lossy());
                exit::UNRECOVERABLE
            })?,
        };
        let raw_prefix: Vec<u8> = asked
            .split(|&b| b == b'/')
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join(&b'/');
        let prefix = String::from_utf8_lossy(&raw_prefix).into_owned();
        let entries = walk_from(fs, from, &prefix, &raw_prefix, recursive);
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
                let xattrs = e
                    .znode
                    .as_ref()
                    .map(|z| fs.xattrs(z).into_iter().map(|(n, _)| n).collect())
                    .unwrap_or_default();
                describe(e, target, xattrs)
            })
            .collect();
        let unreadable = files.iter().filter(|f| f.error.is_some()).count();
        Ok((
            ListOut {
                dataset: dataset.to_string(),
                txg: opened.txg,
                root: fs.root,
                path: path.map(|p| p.to_string_lossy().into_owned()),
                properties: fs.properties.clone(),
                files,
            },
            unreadable,
            opened.members.paths.clone(),
        ))
    });
    let (out, unreadable, paths) = match result {
        Ok(v) => v,
        Err(code) => return code,
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
                if let Some(e) = &f.error {
                    println!("       {e}");
                }
            }
        }
    }
    let code = if unreadable > 0 { exit::PARTIAL } else { 0 };
    g.log_evidence("zvolfiles", &json, code, &paths, Vec::new())
}
