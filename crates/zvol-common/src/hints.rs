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
                // A base at or past the end leaves no vdev on the member:
                // reads there wrapped or ran off the end, and failed as
                // checksums.
                if base > 0 {
                    if let Some(len) = zvolrescue_io::FileSource::open(&paths[device])
                        .ok()
                        .map(|f| zvolrescue_io::BlockSource::size(&f))
                    {
                        if base >= len {
                            return Err(format!(
                                "hints: {what}.members[{m}]: base {base} is not inside {path}, which is {len} bytes"
                            ));
                        }
                    }
                }
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
    // A kind the reader has no layout for, or a vdev with nothing in it,
    // was taken as written and failed later as "no verified uberblock
    // matches the requested TXG; available: " — exit 3, an empty list,
    // and no word about the layout file.
    const KINDS: [&str; 7] = [
        "mirror",
        "raidz",
        "draid",
        "disk",
        "file",
        "replacing",
        "spare",
    ];
    if !KINDS.contains(&kind.as_str()) {
        return Err(format!(
            "hints: {what}.kind {kind:?} is no vdev this reads; one of {}",
            KINDS.join(", ")
        ));
    }
    if members.is_empty() && children.is_empty() {
        return Err(format!("hints: {what} has no members"));
    }
    if !members.is_empty() && members.iter().all(Option::is_none) && children.is_empty() {
        return Err(format!(
            "hints: {what}: every member is null — at least one has to be given to read anything through it"
        ));
    }
    let nparity = t.get("nparity").map(|v| as_u64(v, "nparity")).transpose()?;
    if matches!(kind.as_str(), "disk" | "file") && (members.len() != 1 || !children.is_empty()) {
        return Err(format!(
            "hints: {what}: a {kind} vdev is one member; {} given",
            members.len() + children.len()
        ));
    }
    if matches!(kind.as_str(), "raidz" | "draid") {
        let width = members.len() + children.len();
        let p = nparity.unwrap_or(1);
        if !(1..=3).contains(&p) || (kind == "raidz" && p as usize >= width) {
            return Err(format!(
                "hints: {what}: {kind} with nparity {p} over {width} member(s); parity is 1 to 3, and a raidz needs more members than parity"
            ));
        }
    }
    let draid_ndata = t
        .get("draid_ndata")
        .map(|v| as_u64(v, "draid_ndata"))
        .transpose()?;
    let draid_nspares = t
        .get("draid_nspares")
        .map(|v| as_u64(v, "draid_nspares"))
        .transpose()?;
    let draid_ngroups = t
        .get("draid_ngroups")
        .map(|v| as_u64(v, "draid_ngroups"))
        .transpose()?;
    // A dRAID the numbers cannot make is the layout file's mistake, said
    // with the fields it is in (exit 1): it was taken, and every read
    // then failed "top-level vdev type draid (…) not supported yet",
    // exit 3, as if this build could not read what the file described.
    if kind == "draid" {
        let width = (members.len() + children.len()) as u64;
        if let Err(e) = zfs_ondisk::draid::Config::new(
            draid_ndata.unwrap_or(0),
            nparity.unwrap_or(0),
            draid_nspares.unwrap_or(0),
            width,
            draid_ngroups.unwrap_or(0),
        ) {
            return Err(format!(
                "hints: {what}: no dRAID of {width} member(s) has draid_ndata {}, nparity {}, draid_nspares {}, draid_ngroups {} ({e}); give the four as the pool was made",
                draid_ndata.map_or("absent".into(), |n| n.to_string()),
                nparity.map_or("absent".into(), |n| n.to_string()),
                draid_nspares.map_or("absent".into(), |n| n.to_string()),
                draid_ngroups.map_or("absent".into(), |n| n.to_string()),
            ));
        }
    }
    Ok(TopHint {
        kind,
        nparity,
        draid_ndata,
        draid_nspares,
        draid_ngroups,
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
    if !(9..=16).contains(&ashift) {
        return Err(format!(
            "hints: ashift {ashift}: a vdev's sectors are 2^9 to 2^16 bytes (ashift 9 to 16)"
        ));
    }
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
