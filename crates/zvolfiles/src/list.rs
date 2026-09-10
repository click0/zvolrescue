//! `zvolfiles list` — what is in the dataset.

use serde::Serialize;
use zfs_ondisk::zpl::Znode;
use zfs_read::zpl::{walk, Entry};
use zvol_common::timefmt::iso8601;
use zvol_common::{exit, Format, Global, PoolSpec};

use crate::common::{with_dataset, AtArgs};

#[derive(Debug, Serialize)]
struct FileOut {
    path: String,
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
fn describe(e: &Entry, target: Option<String>) -> FileOut {
    let z = e.znode.as_ref();
    FileOut {
        path: e.path.clone(),
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
        error: e.error.clone(),
    }
}

/// Run `list`.
pub fn run(
    g: &Global,
    spec: &PoolSpec,
    dataset: &str,
    at: &AtArgs,
    path: Option<&str>,
    recursive: bool,
) -> u8 {
    let result = with_dataset(spec, dataset, at, |fs, opened| {
        let from = match path {
            None => fs.root,
            Some(p) => fs.lookup(p).map_err(|e| {
                eprintln!("zvolfiles: {p}: {e}");
                exit::UNRECOVERABLE
            })?,
        };
        let prefix = path.unwrap_or("").trim_matches('/').to_string();
        let entries = walk(fs, from, &prefix, recursive);
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
                describe(e, target)
            })
            .collect();
        let unreadable = files.iter().filter(|f| f.error.is_some()).count();
        Ok((
            ListOut {
                dataset: dataset.to_string(),
                txg: opened.txg,
                root: fs.root,
                path: path.map(str::to_string),
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
                if let Some(e) = &f.error {
                    println!("       {e}");
                }
            }
        }
    }
    let code = if unreadable > 0 { exit::PARTIAL } else { 0 };
    g.log_evidence("zvolfiles", &json, code, &paths, Vec::new())
}
