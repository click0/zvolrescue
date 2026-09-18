//! `scan`: what is on these devices — labels, configuration, uberblocks,
//! TXG window, and the pools that can be assembled from them.
//!
//! Verbosity drives the detail: `-v` lists every uberblock and corrupt ring
//! slot; `-vv` prints the full configuration nvlist of each device's best
//! label.

use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{json, Map, Value as Json};
use zfs_ondisk::checksum::ChecksumStatus;
use zfs_ondisk::geom::GeomMeta;
use zfs_ondisk::label::{pool_state_name, LabelConfig};
use zfs_ondisk::nvlist::{NvList, Value};
use zfs_read::dsl::removed_tops_of;
use zfs_read::pool::{assemble, PoolAssembly};
use zfs_read::vdev::{DeviceScan, LabelScan};
use zfs_read::zeropoint::{
    find as find_zero_point, geom_metadata, partition_table, scan_with_recovered_base_opts, Search,
};
use zvolrescue_io::{BlockSource, FileSource};

use zvol_common::timefmt::iso8601;
use zvol_common::{evidence, exit, Format, Global, OpenOpts};

#[derive(Debug, Serialize)]
struct UberblockOut {
    slot: usize,
    txg: u64,
    timestamp: u64,
    time: String,
    version: u64,
    guid_sum: String,
    rootbp_birth: u64,
    endian: &'static str,
    checksum: &'static str,
    mmp: bool,
    checkpoint_txg: u64,
}

#[derive(Debug, Serialize)]
struct CorruptSlot {
    slot: usize,
    reason: String,
}

#[derive(Debug, Serialize)]
struct LabelOut {
    index: usize,
    offset: u64,
    config_checksum: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_error: Option<String>,
    label_txg: Option<u64>,
    slot_shift: u32,
    slots: usize,
    valid: usize,
    verified: usize,
    empty_slots: usize,
    corrupt_slots: usize,
    best_txg: Option<u64>,
    best_time: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    uberblocks: Vec<UberblockOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    corrupt: Vec<CorruptSlot>,
}

#[derive(Debug, Serialize)]
struct ConfigOut {
    name: Option<String>,
    pool_guid: Option<String>,
    state: Option<&'static str>,
    txg: Option<u64>,
    version: Option<u64>,
    vdev_guid: Option<String>,
    top_guid: Option<String>,
    top_vdev: Option<String>,
    ashift: Option<u64>,
    vdev_children: Option<u64>,
    hostid: Option<String>,
    hostname: Option<String>,
    features_for_read: Vec<String>,
    /// Active read-incompatible features this build cannot account for
    /// (SPEC F-70). Present whenever there are any: `scan` is the
    /// command that says what is on a disk, and this is on it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unaccounted_features: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DeviceOut {
    path: PathBuf,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    best_label: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<ConfigOut>,
    /// Full nvlist of the best label (only with `-vv`).
    #[serde(skip_serializing_if = "Option::is_none")]
    nvlist: Option<Json>,
    labels: Vec<LabelOut>,
    /// Highest verified TXG across all labels — where `zpool import` would start.
    newest_txg: Option<u64>,
    /// Lowest verified TXG still present — how far back a rollback could reach.
    oldest_txg: Option<u64>,
    /// Zero points confirmed from uberblock checksums, best first. Filled
    /// in when the labels cannot say where the vdev starts, or on request.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    zero_point: Vec<ZeroPointOut>,
    /// The labels do not verify and the surface was not searched for
    /// anchors: a block device, without `--surface-scan-on-device`
    /// (SPEC N-10).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    surface_scan_refused: bool,
    /// Where this device's vdev begins, when that is not offset 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    vdev_base: Option<u64>,
    /// How that was arrived at.
    #[serde(skip_serializing_if = "Option::is_none")]
    vdev_base_from: Option<&'static str>,
    /// The partition table of a whole-disk image, if it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    partitions: Option<TableOut>,
    /// Bytes the vdev occupies from its base, when something said it is
    /// shorter than what was opened: a partition's length, or the
    /// provider size GEOM metadata records (SPEC F-71).
    #[serde(skip_serializing_if = "Option::is_none")]
    vdev_size: Option<u64>,
    /// GEOM metadata in the device's last sector (SPEC F-71).
    #[serde(skip_serializing_if = "Option::is_none")]
    geom: Option<GeomOut>,
    /// What the imager's map says of this image (SPEC F-72), when one
    /// was given with `--map`.
    #[serde(skip_serializing_if = "Option::is_none")]
    map: Option<MapOut>,
    /// Every device node an operating system would offer this device
    /// or its partitions under, from what the disk itself says:
    /// `/dev/gpt/NAME`, `/dev/gptid/GUID`, `/dev/label/NAME`, and the
    /// Linux `by-partlabel`/`by-partuuid` forms. A pool's labels record
    /// one of these as a member's `path`, so a member whose own labels
    /// are gone can be matched to the leaf its siblings describe.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    names: Vec<String>,
}

/// What an imager could not read of an image (SPEC F-72).
#[derive(Debug, Clone, Serialize)]
struct MapOut {
    /// The mapfile.
    path: PathBuf,
    /// Bytes the imager did not finish.
    unreadable_bytes: u64,
    /// Ranges it did not finish, `[start, len]`, merged.
    unreadable: Vec<(u64, u64)>,
    /// Bytes per map status: `+` finished, `-` bad sector, `/`
    /// non-scraped, `*` non-trimmed, `?` non-tried.
    by_status: std::collections::BTreeMap<char, u64>,
    /// Label positions (0..=3) the unfinished ranges touch: where the
    /// pool's own account of itself was never read.
    labels_touched: Vec<usize>,
}

/// What a GEOM class left in a provider's last sector (SPEC F-71).
#[derive(Debug, Clone, Serialize)]
struct GeomOut {
    class: &'static str,
    version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provsize: Option<u64>,
    /// The device node the class offered: `/dev/label/NAME`,
    /// `/dev/mirror/NAME`.
    #[serde(skip_serializing_if = "Option::is_none")]
    device: Option<String>,
}

fn geom_out(m: &GeomMeta) -> GeomOut {
    GeomOut {
        class: m.class,
        version: m.version,
        name: m.name.clone(),
        provsize: m.provsize,
        device: m.device_name(),
    }
}

/// How `scan` should look for a vdev's zero point (SPEC F-61).
#[derive(Debug, Default, Clone)]
pub struct ZeroPointOpts {
    /// Search every member, not only those whose labels are unusable.
    pub always: bool,
    /// Search the whole member instead of its first and last 64 MiB.
    pub whole: bool,
    /// Physical sizes to assume for the vdev when testing rear labels.
    pub psize_hints: Vec<u64>,
}

#[derive(Debug, Serialize)]
struct PartitionOut {
    index: usize,
    start: u64,
    length: u64,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    /// The unique partition GUID: `gptid` on FreeBSD, `partuuid` on
    /// Linux.
    #[serde(skip_serializing_if = "Option::is_none")]
    guid: Option<String>,
    zfs: bool,
    /// GEOM metadata in the partition's last sector, when a class was
    /// configured on the partition itself (SPEC F-71).
    #[serde(skip_serializing_if = "Option::is_none")]
    geom: Option<GeomOut>,
}

#[derive(Debug, Serialize)]
struct TableOut {
    scheme: &'static str,
    sector: u64,
    partitions: Vec<PartitionOut>,
}

#[derive(Debug, Serialize)]
struct ZeroPointOut {
    /// Confirmed vdev base: subtract it from a physical offset.
    base: u64,
    /// Number of uberblocks whose checksum verified for this base.
    anchors: usize,
    /// Labels the anchors came from, e.g. `["L0", "L1"]`.
    labels: Vec<String>,
    /// TXG range the anchors cover.
    oldest_txg: u64,
    newest_txg: u64,
    /// Vdev size implied by a rear-label anchor, when one was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    psize: Option<u64>,
    /// Logical birth of the root pointer in the newest anchor: the MOS
    /// this base would be read through.
    rootbp_birth: u64,
}

#[derive(Debug, Serialize)]
struct MemberOut {
    guid: String,
    path: Option<String>,
    present: Option<PathBuf>,
    /// A scanned device that carries this member's `path` as one of its
    /// own names — a GPT label, a `gptid`, a `glabel` — while no label
    /// on it says which leaf it is (SPEC F-71). The name is the disk's
    /// own account of what it was called; the binding is still
    /// confirmed by reading, which is what `--assume-member` does.
    #[serde(skip_serializing_if = "Option::is_none")]
    named_by: Option<PathBuf>,
}

/// A vdev as a layout template: the same shape `--hints` takes, so the
/// scan of a healthy pool can be kept and used to read a damaged one.
#[derive(Debug, Serialize)]
struct TreeOut {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    nparity: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    draid_ndata: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    draid_nspares: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    draid_ngroups: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    members: Option<Vec<Option<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    children: Option<Vec<TreeOut>>,
}

fn tree_out(node: &zfs_ondisk::label::VdevNode, members: &[MemberOut]) -> TreeOut {
    let leaf_path = |guid: u64| {
        members
            .iter()
            .find(|m| m.guid == hex(guid))
            .and_then(|m| m.present.as_ref())
            .map(|p| p.display().to_string())
    };
    let nested = node.children.iter().any(|c| !c.children.is_empty());
    TreeOut {
        kind: node.kind.clone(),
        nparity: node.nparity,
        draid_ndata: node.draid_ndata,
        draid_nspares: node.draid_nspares,
        draid_ngroups: node.draid_ngroups,
        members: (!nested && !node.children.is_empty())
            .then(|| node.children.iter().map(|c| leaf_path(c.guid)).collect()),
        children: nested.then(|| node.children.iter().map(|c| tree_out(c, members)).collect()),
    }
}

#[derive(Debug, Serialize)]
struct TopOut {
    id: u64,
    guid: String,
    name: String,
    kind: String,
    nparity: Option<u64>,
    ashift: Option<u64>,
    readable: bool,
    members: Vec<MemberOut>,
    /// The vdev as a layout template, in the shape `--hints` takes.
    tree: TreeOut,
}

#[derive(Debug, Serialize)]
struct PoolOut {
    name: String,
    guid: String,
    state: Option<&'static str>,
    txg: Option<u64>,
    vdev_children: Option<u64>,
    missing_tops: Vec<u64>,
    /// Top-level vdevs the pool's own configuration says were removed
    /// (SPEC F-69): counted, described by no label, and not missing.
    /// Their blocks live on the vdevs that remain and are read through
    /// the mapping each left in the MOS.
    removed_tops: Vec<u64>,
    /// `device_removal` is active. When `missing_tops` is not empty as
    /// well, the MOS could not be asked which of them were removed —
    /// or they really are missing.
    device_removal: bool,
    readable: bool,
    hosts: Vec<HostOut>,
    devices: Vec<PathBuf>,
    tops: Vec<TopOut>,
    stale: Vec<StaleOut>,
    /// Devices this pool does not account for whose disk names contain
    /// the pool's name (SPEC F-71): `tank-d2` on a disk with no labels,
    /// next to a pool called `tank`. A hint about where the disk
    /// belonged, not evidence of it — nothing binds on this.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    name_hints: Vec<NameHintOut>,
}

#[derive(Debug, Serialize)]
struct NameHintOut {
    device: PathBuf,
    name: String,
}

/// Whether a member's recorded `path` and a device's name are the same
/// node. Labels record `/dev/gpt/tank-d0`; older ones, or ones written
/// on Linux, may drop the `/dev/`.
fn same_node(path: &str, name: &str) -> bool {
    let tail = |s: &str| s.strip_prefix("/dev/").unwrap_or(s).to_string();
    tail(path) == tail(name)
}

/// Every name each scanned device answers to, in device order.
fn device_names(out: &DeviceOut) -> Vec<String> {
    out.names.clone()
}

#[derive(Debug, Serialize)]
struct StaleOut {
    device: PathBuf,
    guid: Option<String>,
    txg: Option<u64>,
    reason: String,
}

#[derive(Debug, Serialize)]
struct HostOut {
    hostid: Option<String>,
    hostname: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScanOut {
    devices: Vec<DeviceOut>,
    pools: Vec<PoolOut>,
}

fn hex(v: u64) -> String {
    format!("{v:#018x}")
}

/// Generic nvlist → JSON, for `-vv`.
fn nv_json(nv: &NvList) -> Json {
    let mut m = Map::new();
    for (name, v) in &nv.pairs {
        m.insert(name.clone(), value_json(v));
    }
    Json::Object(m)
}

fn value_json(v: &Value) -> Json {
    match v {
        Value::Boolean => Json::Bool(true),
        Value::Bool(b) => Json::Bool(*b),
        Value::Int(i) => json!(i),
        Value::Uint64(u) => json!(u),
        Value::Int64(i) => json!(i),
        Value::Double(d) => json!(d),
        Value::String(s) => Json::String(s.clone()),
        Value::Bytes(b) => json!(b),
        Value::IntArray(a) => json!(a),
        Value::Uint64Array(a) => json!(a),
        Value::Int64Array(a) => json!(a),
        Value::BoolArray(a) => json!(a),
        Value::StringArray(a) => json!(a),
        Value::List(l) => nv_json(l),
        Value::ListArray(a) => Json::Array(a.iter().map(nv_json).collect()),
        Value::Unknown { type_code, nelem } => json!({"unknown_type": type_code, "nelem": nelem}),
    }
}

fn config_out(c: &LabelConfig) -> ConfigOut {
    ConfigOut {
        name: c.name.clone(),
        pool_guid: c.pool_guid.map(hex),
        state: c.state.map(pool_state_name),
        txg: c.txg,
        version: c.version,
        vdev_guid: c.guid.map(hex),
        top_guid: c.top_guid.map(hex),
        top_vdev: c.tree.as_ref().map(|t| t.display_name()),
        ashift: c.ashift(),
        vdev_children: c.vdev_children,
        hostid: c.hostid.map(hex),
        hostname: c.hostname.clone(),
        features_for_read: c.features_for_read.clone(),
        unaccounted_features: zfs_ondisk::features::unaccounted(&c.features_for_read)
            .into_iter()
            .map(|(n, _)| n.to_string())
            .collect(),
    }
}

fn label_out(l: &LabelScan, detail: bool) -> LabelOut {
    let best = l.best();
    let empty_slots = l.empty_slots();
    let corrupt_slots = l.invalid.len() - empty_slots;
    let corrupt = if detail {
        l.invalid
            .iter()
            .filter(|(_, e)| *e != zfs_ondisk::ParseError::BadMagic(0))
            .map(|(slot, e)| CorruptSlot {
                slot: *slot,
                reason: e.to_string(),
            })
            .collect()
    } else {
        Vec::new()
    };
    let uberblocks = if detail {
        let mut list: Vec<UberblockOut> = l
            .uberblocks
            .iter()
            .map(|s| UberblockOut {
                slot: s.slot,
                txg: s.ub.txg,
                timestamp: s.ub.timestamp,
                time: iso8601(s.ub.timestamp),
                version: s.ub.version,
                guid_sum: hex(s.ub.guid_sum),
                rootbp_birth: s.ub.rootbp_birth(),
                endian: match s.ub.endian {
                    zfs_ondisk::Endian::Little => "little",
                    zfs_ondisk::Endian::Big => "big",
                },
                checksum: s.checksum.as_str(),
                mmp: s.ub.mmp_magic != 0,
                checkpoint_txg: s.ub.checkpoint_txg,
            })
            .collect();
        list.sort_by_key(|u| std::cmp::Reverse((u.txg, u.timestamp)));
        list
    } else {
        Vec::new()
    };
    LabelOut {
        index: l.index,
        offset: l.offset,
        config_checksum: l.phys_checksum.as_str(),
        config_error: l.config_error.as_ref().map(|e| e.to_string()),
        label_txg: l.config.as_ref().and_then(|c| c.u64("txg")),
        slot_shift: l.slot_shift,
        slots: l.slots,
        valid: l.uberblocks.len(),
        verified: l
            .uberblocks
            .iter()
            .filter(|s| s.checksum == ChecksumStatus::Ok)
            .count(),
        empty_slots,
        corrupt_slots,
        best_txg: best.map(|s| s.ub.txg),
        best_time: best.map(|s| iso8601(s.ub.timestamp)),
        uberblocks,
        corrupt,
    }
}

fn device_out(
    path: &Path,
    scan: &Option<DeviceScan>,
    size: u64,
    error: Option<String>,
    verbose: u8,
) -> DeviceOut {
    let mut out = DeviceOut {
        path: path.to_path_buf(),
        size,
        error,
        best_label: None,
        config: None,
        nvlist: None,
        labels: Vec::new(),
        newest_txg: None,
        oldest_txg: None,
        zero_point: Vec::new(),
        surface_scan_refused: false,
        vdev_base: None,
        vdev_base_from: None,
        partitions: None,
        vdev_size: None,
        geom: None,
        map: None,
        names: Vec::new(),
    };
    if let Some(s) = scan {
        out.vdev_base = (s.base != 0).then_some(s.base);
        out.vdev_base_from = s.base_source;
        out.vdev_size = (s.psize != s.size.saturating_sub(s.base)).then_some(s.psize);
        out.best_label = s.best_label;
        out.config = s.config().as_ref().map(config_out);
        if verbose >= 2 {
            out.nvlist = s
                .best_label
                .and_then(|i| s.labels[i].config.as_ref())
                .map(nv_json);
        }
        out.labels = s
            .labels
            .iter()
            .map(|l| label_out(l, verbose >= 1))
            .collect();
        out.newest_txg = s.newest_txg();
        out.oldest_txg = s.oldest_txg();
    }
    out
}

fn pool_out(p: &PoolAssembly, paths: &[PathBuf], names: &[Vec<String>]) -> PoolOut {
    // A device that carries the name a vacant leaf was recorded under.
    // Only a device that is not already a member of some pool and has
    // no verified configuration of its own is a candidate: a device
    // whose labels say what it is needs no name to say so.
    let unplaced: Vec<usize> = (0..paths.len())
        .filter(|&i| !p.devices.contains(&i) && !p.stale.iter().any(|m| m.device == i))
        .collect();
    let named_by = |path: &Option<String>| -> Option<PathBuf> {
        let path = path.as_deref()?;
        unplaced
            .iter()
            .find(|&&i| names[i].iter().any(|n| same_node(path, n)))
            .map(|&i| paths[i].clone())
    };
    let member_out = |m: &zfs_read::pool::Member| MemberOut {
        guid: hex(m.guid),
        path: m.path.clone(),
        present: m.present.map(|i| paths[i].clone()),
        named_by: m.present.is_none().then(|| named_by(&m.path)).flatten(),
    };
    let claimed: Vec<PathBuf> = p
        .tops
        .iter()
        .flat_map(|t| t.members.iter())
        .filter(|m| m.present.is_none())
        .filter_map(|m| named_by(&m.path))
        .collect();
    let pool_name = p.name.to_ascii_lowercase();
    let name_hints: Vec<NameHintOut> = unplaced
        .iter()
        .filter(|&&i| !claimed.contains(&paths[i]))
        .flat_map(|&i| {
            names[i]
                .iter()
                .filter(|n| {
                    let tail = n.rsplit('/').next().unwrap_or(n).to_ascii_lowercase();
                    !pool_name.is_empty() && tail.contains(&pool_name)
                })
                .map(move |n| NameHintOut {
                    device: paths[i].clone(),
                    name: n.clone(),
                })
        })
        .collect();
    PoolOut {
        name_hints,
        name: p.name.clone(),
        guid: hex(p.guid),
        state: p.state.map(pool_state_name),
        txg: p.txg,
        vdev_children: p.vdev_children,
        missing_tops: p.missing_tops(),
        removed_tops: p.removed_tops.clone(),
        device_removal: p
            .features_for_read
            .iter()
            .any(|f| f == "com.delphix:device_removal"),
        readable: p.readable(),
        hosts: p
            .hosts
            .iter()
            .map(|(id, name)| HostOut {
                hostid: id.map(hex),
                hostname: name.clone(),
            })
            .collect(),
        devices: p.devices.iter().map(|&i| paths[i].clone()).collect(),
        stale: p
            .stale
            .iter()
            .map(|m| StaleOut {
                device: paths[m.device].clone(),
                guid: m.guid.map(hex),
                txg: m.txg,
                reason: m.reason.clone(),
            })
            .collect(),
        tops: p
            .tops
            .iter()
            .map(|t| TopOut {
                id: t.id,
                guid: hex(t.guid),
                name: t.name.clone(),
                kind: t.kind.clone(),
                nparity: t.nparity,
                ashift: t.ashift,
                readable: t.readable(),
                members: t.members.iter().map(member_out).collect(),
                tree: tree_out(
                    &t.tree,
                    &t.members.iter().map(member_out).collect::<Vec<_>>(),
                ),
            })
            .collect(),
    }
}

/// One line for a GEOM class found in a last sector.
fn print_geom(indent: &str, m: &GeomOut, vdev_size: Option<u64>) {
    let mut line = format!(
        "{indent}GEOM::{} v{} in the last sector",
        m.class.to_uppercase(),
        m.version
    );
    if let Some(d) = &m.device {
        line.push_str(&format!(": this was {d}"));
    }
    if let Some(p) = m.provsize {
        line.push_str(&format!(", provider {p} bytes"));
    }
    match m.class {
        "eli" => line.push_str(
            "; the member is geli-encrypted — attach it on a copy (geli attach) and scan the plaintext provider",
        ),
        "label" | "mirror" | "stripe" | "concat" | "raid3" | "raid" | "journal" | "cache"
        | "virstor" | "shsec" => {
            if let Some(v) = vdev_size {
                line.push_str(&format!("; the vdev is {v} bytes and its rear labels were read there"));
            }
        }
        _ => {}
    }
    println!("{line}");
}

fn print_text(out: &ScanOut, verbose: u8) {
    for d in &out.devices {
        println!("{}: {} bytes", d.path.display(), d.size);
        if let Some(e) = &d.error {
            println!("  error: {e}");
            if d.surface_scan_refused {
                println!(
                    "  zero point: not searched — a block device is not searched for anchors (SPEC N-10); image it and scan the image, or --surface-scan-on-device"
                );
            }
            continue;
        }
        if let Some(t) = &d.partitions {
            println!(
                "  {} table, {}-byte sectors, {} partition(s):",
                t.scheme,
                t.sector,
                t.partitions.len()
            );
            for p in &t.partitions {
                println!(
                    "    {:>2}  {:>14} + {:>14}  {}{}{}",
                    p.index,
                    p.start,
                    p.length,
                    p.kind,
                    match (&p.name, &p.guid) {
                        (Some(n), Some(g)) => format!("  {n:?}  gptid {g}"),
                        (Some(n), None) => format!("  {n:?}"),
                        (None, Some(g)) => format!("  gptid {g}"),
                        (None, None) => String::new(),
                    },
                    if p.zfs {
                        "  <- a ZFS partition type"
                    } else {
                        ""
                    },
                );
            }
        }
        if let (Some(base), Some(from)) = (d.vdev_base, d.vdev_base_from) {
            println!("  this member's vdev begins at byte {base} ({from})");
        }
        if let Some(m) = &d.geom {
            print_geom("  ", m, d.vdev_size);
        }
        if let Some(t) = &d.partitions {
            for p in &t.partitions {
                if let Some(m) = &p.geom {
                    print_geom(&format!("    partition {}: ", p.index), m, None);
                }
            }
        }
        if !d.names.is_empty() {
            println!("  named: {}", d.names.join("  "));
        }
        if let Some(m) = &d.map {
            println!(
                "  imager's map {}: {} byte(s) in {} range(s) never read{}; they are refused, not trusted (SPEC F-72)",
                m.path.display(),
                m.unreadable_bytes,
                m.unreadable.len(),
                if m.labels_touched.is_empty() {
                    String::new()
                } else {
                    format!(
                        ", touching label(s) {}",
                        m.labels_touched
                            .iter()
                            .map(|i| format!("L{i}"))
                            .collect::<Vec<_>>()
                            .join(",")
                    )
                }
            );
        }
        match &d.config {
            Some(c) => {
                println!(
                    "  pool {:?} guid {}  state {}  label txg {}  host {:?} ({})",
                    c.name.as_deref().unwrap_or("?"),
                    c.pool_guid.as_deref().unwrap_or("?"),
                    c.state.unwrap_or("?"),
                    c.txg.map_or("?".to_string(), |t| t.to_string()),
                    c.hostname.as_deref().unwrap_or("?"),
                    c.hostid.as_deref().unwrap_or("?"),
                );
                println!(
                    "  vdev guid {}  ashift {}  in {} (top guid {}, pool has {} top-level vdev(s))",
                    c.vdev_guid.as_deref().unwrap_or("?"),
                    c.ashift.map_or("?".to_string(), |a| a.to_string()),
                    c.top_vdev.as_deref().unwrap_or("?"),
                    c.top_guid.as_deref().unwrap_or("?"),
                    c.vdev_children.map_or("?".to_string(), |n| n.to_string()),
                );
                if verbose >= 1 && !c.features_for_read.is_empty() {
                    println!("  features_for_read: {}", c.features_for_read.join(" "));
                }
                // Not behind -v: a feature in use that this build cannot
                // account for is the difference between an answer and a
                // guess, and `scan` is where an operator looks first.
                if !c.unaccounted_features.is_empty() {
                    println!(
                        "  NOT ACCOUNTED FOR: {} — reading this pool needs \
                         --ignore-unknown-features, and may be wrong (SPEC F-70)",
                        c.unaccounted_features.join(" ")
                    );
                }
            }
            None => println!("  no readable ZFS label configuration"),
        }
        for l in &d.labels {
            let best = match (l.best_txg, &l.best_time) {
                (Some(t), Some(ts)) => format!("best txg {t} ({ts})"),
                _ => "no valid uberblocks".to_string(),
            };
            println!(
                "  L{} @ {:>12}: config {}{}, uberblocks {}/{} valid ({} verified, {} empty, {} corrupt), {}{}",
                l.index,
                l.offset,
                l.config_checksum,
                l.label_txg.map_or(String::new(), |t| format!(" txg {t}")),
                l.valid,
                l.slots,
                l.verified,
                l.empty_slots,
                l.corrupt_slots,
                best,
                if d.best_label == Some(l.index) { "  <- best" } else { "" },
            );
            if let Some(e) = &l.config_error {
                println!("      config: {e}");
            }
            for c in &l.corrupt {
                println!("      slot {:>3}  {}", c.slot, c.reason);
            }
            for u in &l.uberblocks {
                println!(
                    "      slot {:>3}  txg {:>12}  {}  v{}  rootbp birth {}  checksum {}{}{}",
                    u.slot,
                    u.txg,
                    u.time,
                    u.version,
                    u.rootbp_birth,
                    u.checksum,
                    if u.mmp { "  mmp" } else { "" },
                    if u.checkpoint_txg != 0 {
                        format!("  checkpoint {}", u.checkpoint_txg)
                    } else {
                        String::new()
                    }
                );
            }
        }
        match (d.oldest_txg, d.newest_txg) {
            (Some(lo), Some(hi)) => println!("  verified txg window: {lo}..={hi}"),
            _ => println!("  no verified ZFS uberblocks found"),
        }
        for z in &d.zero_point {
            println!(
                "  zero point: base {} confirmed by {} uberblock checksum(s) in {}, txg {}..={}, vdev size {}, root pointer born txg {}",
                z.base,
                z.anchors,
                z.labels.join(","),
                z.oldest_txg,
                z.newest_txg,
                z.psize
                    .map_or("unknown".to_string(), |p| p.to_string()),
                z.rootbp_birth,
            );
        }
        if d.surface_scan_refused {
            println!(
                "  zero point: not searched — a block device is not searched for anchors (SPEC N-10); image it and scan the image, or --surface-scan-on-device"
            );
        } else if d.config.is_none() && d.zero_point.is_empty() && d.error.is_none() {
            println!("  zero point: no uberblock anchor found either");
        }
        if let Some(nv) = &d.nvlist {
            println!("  label nvlist (L{}):", d.best_label.unwrap_or(0));
            let pretty = serde_json::to_string_pretty(nv).expect("serialisable");
            for line in pretty.lines() {
                println!("    {line}");
            }
        }
    }
    for p in &out.pools {
        println!();
        println!(
            "pool {:?} guid {}: state {}, newest label txg {}, {} top-level vdev(s), {}",
            p.name,
            p.guid,
            p.state.unwrap_or("?"),
            p.txg.map_or("?".to_string(), |t| t.to_string()),
            p.vdev_children.map_or("?".to_string(), |n| n.to_string()),
            if p.readable() {
                "READABLE from scanned members"
            } else {
                "NOT readable from scanned members"
            }
        );
        for h in &p.hosts {
            println!(
                "  seen on host {:?} ({})",
                h.hostname.as_deref().unwrap_or("?"),
                h.hostid.as_deref().unwrap_or("?")
            );
        }
        for t in &p.tops {
            println!(
                "  {} (guid {}, ashift {}){}",
                t.name,
                t.guid,
                t.ashift.map_or("?".to_string(), |a| a.to_string()),
                if t.readable() { "" } else { "  NOT READABLE" }
            );
            for m in &t.members {
                println!(
                    "    {} {:<24} {}",
                    m.guid,
                    m.path.as_deref().unwrap_or("-"),
                    match (&m.present, &m.named_by) {
                        (Some(p), _) => format!("present: {}", p.display()),
                        (None, Some(d)) => format!(
                            "MISSING; {} is named {} on its own disk (SPEC F-71) — bind it with --assume-member {}={} and the read confirms or refuses it",
                            d.display(),
                            m.path.as_deref().unwrap_or("-"),
                            d.display(),
                            m.guid
                        ),
                        (None, None) => "MISSING".to_string(),
                    }
                );
            }
        }
        for h in &p.name_hints {
            println!(
                "  hint: {} is named {}, which contains this pool's name; a name says where a disk was, not what it is — nothing binds on it",
                h.device.display(),
                h.name
            );
        }
        for id in &p.removed_tops {
            println!(
                "  top-level vdev #{id}: removed; its blocks live on the vdevs that remain and are read through the mapping it left in the MOS (SPEC F-69)"
            );
        }
        for id in &p.missing_tops {
            println!("  top-level vdev #{id}: no scanned member describes it  MISSING");
        }
        // A removed vdev is counted by `vdev_children` like any other and
        // has no member to find. The pool's configuration object is what
        // tells it from one whose disks were not given, and it was asked
        // above; a vdev still listed as missing here is one the MOS could
        // not vouch for — because it could not be read, or because the
        // vdev really is missing.
        if p.device_removal && !p.missing_tops.is_empty() {
            println!(
                "  note: device_removal is active and the MOS could not say whether the vdev(s) above were removed; reading the pool at a txg whose MOS survives is what settles it (SPEC F-69)"
            );
        }
        for m in &p.stale {
            println!(
                "  {} {} NOT USED: {}",
                m.guid.as_deref().unwrap_or("?"),
                m.device.display(),
                m.reason
            );
        }
    }
}

impl PoolOut {
    fn readable(&self) -> bool {
        self.readable
    }
}

impl TopOut {
    fn readable(&self) -> bool {
        self.readable
    }
}

/// Look for the vdev base of one member with [`zfs_read::zeropoint`].
fn zero_points(
    src: &FileSource,
    opts: &ZeroPointOpts,
    surface_scan_on_device: bool,
) -> (Vec<ZeroPointOut>, bool) {
    let search = Search {
        windows: if opts.whole {
            vec![(0, src.size())]
        } else {
            Vec::new()
        },
        psize_hints: opts.psize_hints.clone(),
        surface_scan_on_device,
        ..Search::default()
    };
    let found = match find_zero_point(src, &search) {
        Ok(f) => f,
        // The one refusal the search makes on its own: a block device
        // without --surface-scan-on-device (SPEC N-10).
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return (Vec::new(), true),
        Err(_) => return (Vec::new(), false),
    };
    let out = found
        .iter()
        .map(|z| {
            let mut labels: Vec<String> = z
                .anchors
                .iter()
                .map(|a| match a.label {
                    Some(l) => format!("L{l}"),
                    None => "L?".to_string(),
                })
                .collect();
            labels.sort();
            labels.dedup();
            ZeroPointOut {
                base: z.base,
                anchors: z.anchors.len(),
                labels,
                oldest_txg: z.anchors.iter().map(|a| a.ub.txg).min().unwrap_or(0),
                newest_txg: z.newest_txg(),
                psize: z.implied_psize(),
                rootbp_birth: z.best().map(|a| a.ub.rootbp_birth()).unwrap_or(0),
            }
        })
        .collect();
    (out, false)
}

/// What `scan --emit-label` should write (SPEC F-67).
#[derive(Debug, Default, Clone)]
pub struct EmitOpts {
    /// Layout template to build the label from.
    pub hints: Option<PathBuf>,
    /// Where to write the label image.
    pub emit_label: Option<PathBuf>,
    /// Which member of the layout, as `TOP:LEAF`.
    pub emit_for: Option<String>,
    /// Which of the four label positions to seal it for.
    pub emit_label_index: Option<usize>,
}

/// Write the label a layout describes for one member (SPEC F-67).
///
/// The bytes go where the operator asked and nowhere else: this never
/// touches an input, and the file it writes is a *template* to place on a
/// copy of the disk. It carries what the layout knows — pool name, TXG,
/// vdev type, parity, ashift, member order — with synthetic vdev GUIDs,
/// since the real ones went with the labels. Feature flags are not in it:
/// nothing surviving says which the pool had, and `zpool import` will want
/// them added by hand.
fn emit_label(
    g: &Global,
    devices: &[PathBuf],
    opts: &EmitOpts,
    txg: Option<u64>,
    psize: u64,
) -> Result<Vec<PathBuf>, String> {
    let (Some(file), Some(out)) = (&opts.hints, &opts.emit_label) else {
        return Ok(Vec::new());
    };
    let hints = zvol_common::hints::load(file, devices)?;
    let (top, leaf) = match &opts.emit_for {
        None => (0usize, 0usize),
        Some(spec) => {
            let (t, l) = spec
                .split_once(':')
                .ok_or_else(|| format!("--emit-for {spec}: expected TOP:LEAF"))?;
            (
                t.trim()
                    .parse()
                    .map_err(|_| format!("--emit-for {spec}: TOP is not a number"))?,
                l.trim()
                    .parse()
                    .map_err(|_| format!("--emit-for {spec}: LEAF is not a number"))?,
            )
        }
    };
    let hint_top = hints.layout.tops.get(top).ok_or_else(|| {
        format!(
            "--emit-for: the layout has {} top-level vdev(s)",
            hints.layout.tops.len()
        )
    })?;
    if leaf >= hint_top.members.len() {
        return Err(format!(
            "--emit-for: top {top} has {} member(s)",
            hint_top.members.len()
        ));
    }
    let index = opts.emit_label_index.unwrap_or(0);
    let nv = zfs_read::hints::label_nvlist(&hints.layout, top, leaf, txg.unwrap_or(0), None);
    let img = zfs_read::hints::label_image(&nv, index, psize)?;
    std::fs::write(out, &img).map_err(|e| format!("{}: {e}", out.display()))?;
    let meta = out.with_extension("json");
    let json = json!({
        "label_index": index,
        "label_bytes": img.len(),
        "sealed_for_vdev_size": psize,
        "top": top,
        "leaf": leaf,
        "pool": hints.layout.name,
        "ashift": hints.layout.ashift,
        "txg": txg,
        "kind": hint_top.kind,
        "nparity": hint_top.nparity,
        "members": hint_top
            .members
            .iter()
            .map(|m| m.map(|i| devices[i].display().to_string()))
            .collect::<Vec<_>>(),
        "note": "template only: synthetic vdev GUIDs, no feature flags; place on a copy of the disk, never on the evidence",
    });
    std::fs::write(
        &meta,
        serde_json::to_string_pretty(&json).expect("serialisable") + "\n",
    )
    .map_err(|e| format!("{}: {e}", meta.display()))?;
    if !g.quiet {
        eprintln!(
            "zvolrescue: wrote L{index} of {}:{} to {} ({} bytes) and its geometry to {}",
            top,
            leaf,
            out.display(),
            img.len(),
            meta.display()
        );
    }
    Ok(vec![out.clone(), meta])
}

/// Run `scan`.
pub fn run(
    g: &Global,
    devices: &[PathBuf],
    open: &OpenOpts,
    zp: &ZeroPointOpts,
    emit: &EmitOpts,
) -> u8 {
    for (member, file) in &open.maps {
        if !devices.contains(member) {
            eprintln!(
                "zvolrescue: --map {}={}: {} is not among the devices given",
                member.display(),
                file.display(),
                member.display()
            );
            return exit::USAGE;
        }
    }
    let mut scans: Vec<Option<DeviceScan>> = Vec::with_capacity(devices.len());
    let mut outs: Vec<DeviceOut> = Vec::with_capacity(devices.len());
    // Kept open past the loop: telling a removed top-level vdev from a
    // missing one means asking the pool's MOS (SPEC F-69).
    let mut sources: Vec<Option<FileSource>> = Vec::with_capacity(devices.len());
    for path in devices {
        let (scan, size, error, zero_point, surface_scan_refused, table, source) =
            match open.open(path) {
                Ok(src) => {
                    let (scan, error) =
                        match scan_with_recovered_base_opts(&src, open.surface_scan_on_device) {
                            Ok(s) => (Some(s), None),
                            Err(e) => (None, Some(e.to_string())),
                        };
                    let table = partition_table(&src).ok().flatten();
                    // A member whose four label configurations are all
                    // unusable still has its uberblock rings, and one slot
                    // fixes the base (SPEC F-61).
                    let unusable = scan.as_ref().is_none_or(|s| s.config().is_none());
                    let (zero_point, surface_scan_refused) = if zp.always || unusable {
                        zero_points(&src, zp, open.surface_scan_on_device)
                    } else {
                        (Vec::new(), false)
                    };
                    let surface_scan_refused = surface_scan_refused
                        || scan.as_ref().is_some_and(|s| s.surface_scan_refused);
                    (
                        scan,
                        src.size(),
                        error,
                        zero_point,
                        surface_scan_refused,
                        table,
                        Some(src),
                    )
                }
                Err(e) => (None, 0, Some(e.to_string()), Vec::new(), false, None, None),
            };
        let mut out = device_out(path, &scan, size, error, g.verbose);
        out.zero_point = zero_point;
        out.surface_scan_refused = surface_scan_refused;
        // What the disk says it is called (SPEC F-71): the GEOM class in
        // its last sector, and the name and GUID of each partition, with
        // any GEOM class configured on the partition itself.
        let src = source.as_ref();
        out.map = src.and_then(|s| s.map()).map(|m| {
            let labels_touched = out
                .labels
                .iter()
                .filter(|l| m.touches(l.offset, zfs_ondisk::label::LABEL_SIZE))
                .map(|l| l.index)
                .collect();
            MapOut {
                path: open
                    .maps
                    .iter()
                    .find(|(mem, _)| mem == path)
                    .map(|(_, f)| f.clone())
                    .unwrap_or_default(),
                unreadable_bytes: m.unreadable_bytes(),
                unreadable: m.unreadable().to_vec(),
                by_status: m.by_status.clone(),
                labels_touched,
            }
        });
        let geom_at = |end: u64| src.and_then(|s| geom_metadata(s, end).ok().flatten());
        out.geom = geom_at(size).map(|m| geom_out(&m));
        let mut names: Vec<String> = Vec::new();
        out.partitions = table.map(|t| TableOut {
            scheme: t.scheme,
            sector: t.sector,
            partitions: t
                .partitions
                .into_iter()
                .map(|p| {
                    names.extend(p.device_names());
                    let geom = geom_at(p.start + p.length).map(|m| geom_out(&m));
                    names.extend(geom.as_ref().and_then(|m| m.device.clone()));
                    PartitionOut {
                        index: p.index,
                        start: p.start,
                        length: p.length,
                        kind: p.kind,
                        name: p.name,
                        guid: p.guid,
                        zfs: p.zfs,
                        geom,
                    }
                })
                .collect(),
        });
        names.extend(out.geom.as_ref().and_then(|m| m.device.clone()));
        names.dedup();
        out.names = names;
        outs.push(out);
        scans.push(scan);
        sources.push(source);
        // The run is stopped: the devices after this one are not opened
        // (SPEC F-33, N-10).
        if open.ledger.stopped().is_some() {
            break;
        }
    }
    let mut assembled = assemble(&scans);
    {
        let opened: Vec<Option<&dyn BlockSource>> = sources
            .iter()
            .map(|s| s.as_ref().map(|s| s as &dyn BlockSource))
            .collect();
        let bases: Vec<u64> = scans
            .iter()
            .map(|s| s.as_ref().map_or(0, |s| s.base))
            .collect();
        for pool in &mut assembled {
            let removed = removed_tops_of(&scans, opened.clone(), &bases, pool);
            pool.note_removed_tops(removed);
        }
    }
    let names: Vec<Vec<String>> = outs.iter().map(device_names).collect();
    let pools: Vec<PoolOut> = assembled
        .iter()
        .map(|p| pool_out(p, devices, &names))
        .collect();
    let out = ScanOut {
        devices: outs,
        pools,
    };

    let json = serde_json::to_value(&out).expect("serialisable");
    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json).expect("serialisable")
        ),
        Format::Text => print_text(&out, g.verbose),
    }
    let mut written: Vec<evidence::FileRef> = Vec::new();
    if emit.emit_label.is_some() {
        // Seal it for a vdev the size of the smallest member scanned: the
        // rear labels' position depends on it, and a label sealed for the
        // wrong size verifies nowhere.
        let psize = out.devices.iter().map(|d| d.size).min().unwrap_or(0);
        // The TXG the labels would have carried: the newest any member
        // verified, whether that came from a ring inside a label or from
        // an anchor found without one.
        let txg = out
            .devices
            .iter()
            .filter_map(|d| {
                d.newest_txg
                    .into_iter()
                    .chain(d.zero_point.iter().map(|z| z.newest_txg))
                    .max()
            })
            .max();
        match emit_label(g, devices, emit, txg, psize) {
            Ok(files) => written.extend(
                files
                    .iter()
                    .filter_map(|p| evidence::FileRef::hashed(p).ok()),
            ),
            Err(e) => {
                eprintln!("zvolrescue: {e}");
                return exit::USAGE;
            }
        }
    }
    let mut code = if out.devices.iter().any(|d| d.error.is_some()) {
        exit::EVIDENCE
    } else {
        0
    };
    if out.devices.iter().any(|d| d.surface_scan_refused) {
        code = code.max(exit::REFUSED);
    }
    // A device refused a read: every incident on stderr, and the stop —
    // when one stopped the run — as the exit code (SPEC F-33, N-10).
    if let Some(medium) = zvol_common::report_medium(&open.ledger) {
        code = medium;
    }
    let mut inputs = devices.to_vec();
    inputs.extend(open.map_files());
    g.log_evidence_with_incidents(
        "zvolrescue",
        &json,
        code,
        &inputs,
        written,
        &open.ledger.incidents(),
    )
}
