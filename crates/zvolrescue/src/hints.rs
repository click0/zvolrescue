//! Reading a hand-written layout (`--hints FILE`, SPEC F-65).
//!
//! JSON, because the tool already parses JSON and a recovery host should
//! not need another dependency to describe four disks:
//!
//! ```json
//! {
//!   "name": "tank",
//!   "guid": "0x3fa1...",
//!   "ashift": 12,
//!   "tops": [
//!     { "kind": "raidz", "nparity": 2,
//!       "members": ["/dev/ada0p3", "/dev/ada1p3", null, "/dev/ada3p3"] }
//!   ]
//! }
//! ```
//!
//! A member is the path as given on the command line, `null` for one that
//! is known to exist but was not supplied, or an object when its vdev does
//! not start at offset 0: `{"path": "/dev/ada1p3", "base": 1048576}`. A
//! vdev that nests — one being replaced, one backed by a spare, or the
//! mirror-of-raidz shapes ztest builds — carries `children` instead of
//! `members`, each child a vdev of the same form.
//! Order is the vdev's own order — it is what a DVA addresses — so it
//! matters, and getting it wrong shows up as failed checksums, never as
//! wrong data.

use std::path::{Path, PathBuf};

use serde_json::Value as Json;
use zfs_read::hints::{LayoutHints, TopHint};

/// A parsed hints file: the layout plus the base offset of each member.
pub struct Hints {
    /// The layout, with members resolved to indices into `paths`.
    pub layout: LayoutHints,
    /// Base offsets, indexed like `paths`.
    pub bases: Vec<u64>,
}

fn as_u64(v: &Json, what: &str) -> Result<u64, String> {
    match v {
        Json::Number(n) => n
            .as_u64()
            .ok_or_else(|| format!("{what}: not a whole number")),
        Json::String(s) => {
            let t = s.trim();
            let (radix, digits) = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(d) => (16, d),
                None => (10, t),
            };
            u64::from_str_radix(digits, radix).map_err(|_| format!("{what}: {s:?} is not a number"))
        }
        _ => Err(format!("{what}: expected a number")),
    }
}

/// One vdev of the template, with its members or its nested groups.
fn top_hint(
    t: &serde_json::Map<String, Json>,
    what: &str,
    paths: &[PathBuf],
    bases: &mut [u64],
) -> Result<TopHint, String> {
    let kind = t
        .get("kind")
        .and_then(Json::as_str)
        .ok_or_else(|| format!("hints: {what}.kind is required (mirror, raidz, draid, disk)"))?
        .to_string();
    let mut members = Vec::new();
    let mut children = Vec::new();
    match (t.get("members"), t.get("children")) {
        (Some(_), Some(_)) => {
            return Err(format!(
                "hints: {what} has both members and children; a vdev holds one or the other"
            ))
        }
        (None, None) => return Err(format!("hints: {what} needs members or children")),
        (Some(list), None) => {
            let list = list
                .as_array()
                .ok_or_else(|| format!("hints: {what}.members must be an array"))?;
            for (m, entry) in list.iter().enumerate() {
                let (path, base) = match entry {
                    Json::Null => {
                        members.push(None);
                        continue;
                    }
                    Json::String(s) => (s.clone(), 0),
                    Json::Object(o) => {
                        let p = o
                            .get("path")
                            .and_then(Json::as_str)
                            .ok_or_else(|| format!("hints: {what}.members[{m}] needs a path"))?;
                        let b = match o.get("base") {
                            Some(v) => as_u64(v, "base")?,
                            None => 0,
                        };
                        (p.to_string(), b)
                    }
                    _ => {
                        return Err(format!(
                            "hints: {what}.members[{m}] must be a path, an object or null"
                        ))
                    }
                };
                let device = paths
                    .iter()
                    .position(|p| p.as_os_str() == path.as_str())
                    .ok_or_else(|| {
                        format!("hints: {path} is not among the members given on the command line")
                    })?;
                bases[device] = base;
                members.push(Some(device));
            }
        }
        (None, Some(list)) => {
            let list = list
                .as_array()
                .ok_or_else(|| format!("hints: {what}.children must be an array"))?;
            for (c, child) in list.iter().enumerate() {
                let child = child
                    .as_object()
                    .ok_or_else(|| format!("hints: {what}.children[{c}] must be an object"))?;
                children.push(top_hint(
                    child,
                    &format!("{what}.children[{c}]"),
                    paths,
                    bases,
                )?);
            }
        }
    }
    Ok(TopHint {
        kind,
        nparity: t.get("nparity").map(|v| as_u64(v, "nparity")).transpose()?,
        draid_ndata: t
            .get("draid_ndata")
            .map(|v| as_u64(v, "draid_ndata"))
            .transpose()?,
        draid_nspares: t
            .get("draid_nspares")
            .map(|v| as_u64(v, "draid_nspares"))
            .transpose()?,
        draid_ngroups: t
            .get("draid_ngroups")
            .map(|v| as_u64(v, "draid_ngroups"))
            .transpose()?,
        members,
        children,
    })
}

/// Parse `file`, resolving member paths against the members given on the
/// command line.
pub fn load(file: &Path, paths: &[PathBuf]) -> Result<Hints, String> {
    let text = std::fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let json: Json = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;
    let obj = json
        .as_object()
        .ok_or("hints: the file must hold one JSON object")?;

    let ashift = match obj.get("ashift") {
        Some(v) => as_u64(v, "ashift")?,
        None => {
            return Err(
                "hints: ashift is required — it is what a DVA's offset is measured in".into(),
            )
        }
    };
    let mut bases = vec![0u64; paths.len()];
    let mut tops = Vec::new();
    let list = obj
        .get("tops")
        .and_then(Json::as_array)
        .ok_or("hints: tops must be an array of top-level vdevs")?;
    for (i, t) in list.iter().enumerate() {
        let t = t
            .as_object()
            .ok_or_else(|| format!("hints: tops[{i}] must be an object"))?;
        tops.push(top_hint(t, &format!("tops[{i}]"), paths, &mut bases)?);
    }
    if tops.is_empty() {
        return Err("hints: no top-level vdev described".into());
    }
    Ok(Hints {
        layout: LayoutHints {
            name: obj.get("name").and_then(Json::as_str).map(str::to_string),
            guid: obj.get("guid").map(|v| as_u64(v, "guid")).transpose()?,
            ashift,
            tops,
        },
        bases,
    })
}
