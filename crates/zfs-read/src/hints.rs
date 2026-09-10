//! A layout described by hand, used exactly as a label would be (F-65).
//!
//! When every `vdev_phys` on every member is gone, nothing on disk says
//! what the pool looked like. The practitioner usually knows anyway — from
//! the other disks, from the case file, from `zpool status` output kept
//! before the incident — and by hand would edit a `vdev_phys` template and
//! carry on. This is that template: type of the top-level vdev, the
//! members in order, `nparity`, `ashift`, and where each member's vdev
//! begins.
//!
//! The template lives in memory and in the evidence log only. Nothing is
//! written to the devices (N-01), and nothing here is taken on trust: what
//! it produces is a topology to *read through*, and every block read that
//! way is verified by its own checksum.

use zfs_ondisk::label::VdevNode;

use crate::pool::{Member, PoolAssembly, TopVdev};

/// One top-level vdev of a hand-written layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopHint {
    /// `mirror`, `raidz`, `draid`, or `disk` for a single-device top.
    pub kind: String,
    /// Parity level for raidz/draid.
    pub nparity: Option<u64>,
    /// Data columns per dRAID group.
    pub draid_ndata: Option<u64>,
    /// Distributed spares of a dRAID.
    pub draid_nspares: Option<u64>,
    /// Groups per dRAID slice.
    pub draid_ngroups: Option<u64>,
    /// Indices into the scanned device list, in vdev order. `None` marks a
    /// member that is known to exist but was not supplied.
    pub members: Vec<Option<usize>>,
}

/// A whole pool described by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutHints {
    /// Pool name, if known; only used for reporting.
    pub name: Option<String>,
    /// Pool GUID, if known.
    pub guid: Option<u64>,
    /// `ashift` of every top-level vdev.
    pub ashift: u64,
    /// Top-level vdevs in order; their index is their vdev id, which is
    /// what a DVA names.
    pub tops: Vec<TopHint>,
}

impl LayoutHints {
    /// Turn the template into the assembly the reader takes.
    ///
    /// GUIDs are invented (a label would carry real ones, and nothing in
    /// reading a block depends on them): each leaf gets a stable synthetic
    /// GUID so reports and bindings can name it.
    pub fn assemble(&self) -> PoolAssembly {
        let mut tops = Vec::with_capacity(self.tops.len());
        let mut devices = Vec::new();
        for (id, hint) in self.tops.iter().enumerate() {
            let mut members = Vec::with_capacity(hint.members.len());
            let mut children = Vec::with_capacity(hint.members.len());
            for (i, present) in hint.members.iter().enumerate() {
                let guid = synthetic_guid(id, i);
                members.push(Member {
                    guid,
                    path: None,
                    present: *present,
                });
                if let Some(d) = present {
                    if !devices.contains(d) {
                        devices.push(*d);
                    }
                }
                children.push(VdevNode {
                    kind: "disk".into(),
                    id: i as u64,
                    guid,
                    path: None,
                    ashift: Some(self.ashift),
                    asize: None,
                    nparity: None,
                    draid_ndata: None,
                    draid_nspares: None,
                    draid_ngroups: None,
                    is_log: false,
                    children: Vec::new(),
                });
            }
            let top_guid = synthetic_guid(id, usize::MAX);
            let tree = VdevNode {
                kind: hint.kind.clone(),
                id: id as u64,
                guid: top_guid,
                path: None,
                ashift: Some(self.ashift),
                asize: None,
                nparity: hint.nparity,
                draid_ndata: hint.draid_ndata,
                draid_nspares: hint.draid_nspares,
                draid_ngroups: hint.draid_ngroups,
                is_log: false,
                children,
            };
            tops.push(TopVdev {
                id: id as u64,
                guid: top_guid,
                name: format!("{}-{id}", display_kind(hint)),
                kind: hint.kind.clone(),
                nparity: hint.nparity,
                ashift: Some(self.ashift),
                members,
                tree,
            });
        }
        devices.sort_unstable();
        PoolAssembly {
            name: self.name.clone().unwrap_or_else(|| "?".into()),
            guid: self.guid.unwrap_or(0),
            state: None,
            txg: None,
            vdev_children: Some(self.tops.len() as u64),
            tops,
            hosts: Vec::new(),
            devices,
            stale: Vec::new(),
        }
    }

    /// Every member index the template refers to, in vdev order.
    pub fn devices(&self) -> Vec<usize> {
        self.tops
            .iter()
            .flat_map(|t| t.members.iter().flatten().copied())
            .collect()
    }
}

fn display_kind(hint: &TopHint) -> String {
    match (hint.kind.as_str(), hint.nparity) {
        ("raidz", Some(p)) | ("draid", Some(p)) => format!("{}{p}", hint.kind),
        _ => hint.kind.clone(),
    }
}

/// A stable, obviously synthetic GUID: high bits mark it as invented, so
/// it can never be mistaken for something read off a disk.
fn synthetic_guid(top: usize, leaf: usize) -> u64 {
    // A fixed marker in the top half, so a report never shows one of
    // these as if it had come off a disk.
    0x_1117_0000_0000_0000u64 | ((top as u64 & 0xffff) << 32) | (leaf as u64 & 0xffff_ffff)
}

// ---------------------------------------------------------------------------
// Searching what the template leaves open (F-66)
// ---------------------------------------------------------------------------

use crate::dsl::{open_mos, walk};
use crate::pool::uberblock_candidates;
use crate::vdev::DeviceScan;
use crate::zio::PoolReader;
use zvolrescue_io::{trace, BlockSource};

/// How a candidate layout fared when the pool was read through it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trial {
    /// The layout tried.
    pub layout: LayoutHints,
    /// Datasets the walk reached, or `None` when it did not complete.
    pub datasets: Option<usize>,
    /// Blocks whose checksum failed on the data as first read. The right
    /// order of a healthy pool produces none; a wrong one produces them
    /// wherever a column was read from the wrong member.
    pub mismatches: u64,
}

impl Trial {
    /// Whether the pool read at all through this layout.
    pub fn read(&self) -> bool {
        self.datasets.is_some()
    }
}

/// Read the pool through `layout` and report how well it fitted.
pub fn try_layout(
    layout: &LayoutHints,
    scans: &[Option<DeviceScan>],
    devices: &[Option<&dyn BlockSource>],
    bases: &[u64],
) -> Trial {
    let pool = layout.assemble();
    let mut trial = Trial {
        layout: layout.clone(),
        datasets: None,
        mismatches: 0,
    };
    let candidates = uberblock_candidates(scans, &pool);
    let Some(best) = candidates.first() else {
        return trial;
    };
    let reader = PoolReader::new(&pool, devices.to_vec()).with_base_offsets(bases);
    if let Ok(mos) = open_mos(&reader, &best.ub) {
        if let Ok(tree) = walk(&mos, &pool.name) {
            trial.datasets = Some(tree.datasets.len());
        }
    }
    trial.mismatches = reader.mismatches();
    trial
}

/// Every ordering of the members of one top-level vdev, as layouts.
fn permutations(layout: &LayoutHints, top: usize) -> Vec<LayoutHints> {
    let members = layout.tops[top].members.clone();
    let mut out = Vec::new();
    let mut order: Vec<usize> = (0..members.len()).collect();
    permute(&mut order, 0, &mut |o| {
        let mut l = layout.clone();
        l.tops[top].members = o.iter().map(|&i| members[i]).collect();
        out.push(l);
    });
    out
}

fn permute(order: &mut Vec<usize>, k: usize, f: &mut impl FnMut(&[usize])) {
    if k == order.len() {
        f(order);
        return;
    }
    for i in k..order.len() {
        order.swap(k, i);
        permute(order, k + 1, f);
        order.swap(k, i);
    }
}

/// The largest member count whose orderings are worth enumerating: 7! is
/// 5040 walks, which is minutes; beyond that the hint has to narrow it.
pub const MAX_SEARCHED_MEMBERS: usize = 7;

/// Try every member order of one top-level vdev and rank what fits.
///
/// A wrong order does not usually *fail* — parity reconstructs around the
/// columns that do not verify, which is why order cannot be settled by
/// "did it read". It is settled by how much had to be repaired: read
/// through the right order, a healthy pool produces no checksum mismatch
/// at all, and every wrong order produces one per block that touches the
/// swapped members.
///
/// Returns the trials that read, best first. Ties are left for the caller
/// to judge: on a mirror every order is equally right.
pub fn search_order(
    layout: &LayoutHints,
    top: usize,
    scans: &[Option<DeviceScan>],
    devices: &[Option<&dyn BlockSource>],
    bases: &[u64],
) -> Result<Vec<Trial>, String> {
    let n = layout.tops.get(top).map_or(0, |t| t.members.len());
    if n > MAX_SEARCHED_MEMBERS {
        return Err(format!(
            "{n} members is {}! orderings — name the order in the layout, or split the search",
            n
        ));
    }
    let mut trials: Vec<Trial> = permutations(layout, top)
        .iter()
        .map(|l| {
            let t = try_layout(l, scans, devices, bases);
            trace!(
                "pool",
                "order {:?}: {} datasets, {} mismatch(es)",
                l.tops[top].members,
                t.datasets.map_or("no".to_string(), |d| d.to_string()),
                t.mismatches
            );
            t
        })
        .filter(Trial::read)
        .collect();
    trials.sort_by_key(|t| (t.mismatches, std::cmp::Reverse(t.datasets.unwrap_or(0))));
    Ok(trials)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{destroyed_zvol_members, Pool};
    use crate::vdev::scan_device;
    use zfs_ondisk::label::{LABEL_SIZE, VDEV_PHYS_OFFSET, VDEV_PHYS_SIZE};
    use zvolrescue_io::MemSource;

    const SIZE: u64 = 64 * 262_144;

    fn label_less_raidz2() -> Vec<MemSource> {
        let mut pool = Pool::raidz("tank", 0x1000, 12, 4, 2).txgs(&[(100, 1), (200, 2)]);
        let (mut members, _, _) = destroyed_zvol_members(&mut pool, SIZE);
        for img in &mut members {
            let aligned = img.len() as u64 & !(LABEL_SIZE - 1);
            for off in [
                0,
                LABEL_SIZE,
                aligned - 2 * LABEL_SIZE,
                aligned - LABEL_SIZE,
            ] {
                let at = (off + VDEV_PHYS_OFFSET) as usize;
                img[at..at + VDEV_PHYS_SIZE as usize].fill(0);
            }
        }
        members.into_iter().map(MemSource::new).collect()
    }

    fn layout(order: &[usize]) -> LayoutHints {
        LayoutHints {
            name: Some("tank".into()),
            guid: None,
            ashift: 12,
            tops: vec![TopHint {
                kind: "raidz".into(),
                nparity: Some(2),
                draid_ndata: None,
                draid_nspares: None,
                draid_ngroups: None,
                members: order.iter().map(|&i| Some(i)).collect(),
            }],
        }
    }

    #[test]
    fn a_layout_reads_a_pool_whose_labels_are_all_gone() {
        let sources = label_less_raidz2();
        let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
        // Not one label parses, so nothing places these members.
        assert!(scans.iter().flatten().all(|s| !s.config_verified()));

        let assembly = layout(&[0, 1, 2, 3]).assemble();
        assert_eq!(assembly.tops.len(), 1);
        assert_eq!(assembly.tops[0].name, "raidz2-0");
        assert_eq!(assembly.tops[0].members.len(), 4);
        assert!(assembly.readable());
        assert_eq!(assembly.devices, vec![0, 1, 2, 3]);
    }

    #[test]
    fn an_emitted_label_is_one_the_reader_accepts() {
        use zfs_ondisk::checksum::ChecksumStatus;
        use zfs_ondisk::label::{label_offsets, parse_vdev_phys, VDEV_PHYS_OFFSET, VDEV_PHYS_SIZE};

        let l = layout(&[0, 1, 2, 3]);
        let nv = label_nvlist(&l, 0, 1, 4816229, Some(SIZE - 4 * 1024 * 1024));
        for index in 0..4 {
            let img = label_image(&nv, index, SIZE).expect("fits in a label");
            // The ring is not part of it: placing this cannot destroy the
            // uberblocks that are still on the disk.
            assert_eq!(img.len(), 128 * 1024);
            let at = VDEV_PHYS_OFFSET as usize;
            let phys = &img[at..at + VDEV_PHYS_SIZE as usize];
            let offset = label_offsets(SIZE).expect("four labels")[index];
            let parsed = parse_vdev_phys(phys, offset);
            assert_eq!(parsed.checksum, ChecksumStatus::Ok, "label {index}");
            let cfg = parsed.config.expect("nvlist parses");
            assert_eq!(cfg.str("name"), Some("tank"));
            assert_eq!(cfg.u64("txg"), Some(4816229));
            assert_eq!(cfg.u64("vdev_children"), Some(1));
            let tree = cfg.list("vdev_tree").expect("vdev_tree");
            assert_eq!(tree.str("type"), Some("raidz"));
            assert_eq!(tree.u64("nparity"), Some(2));
            assert_eq!(tree.u64("ashift"), Some(12));
            let node = zfs_ondisk::label::VdevNode::from_nvlist(tree);
            assert_eq!(node.children.len(), 4);
            // The label names this member: the second leaf of that raidz.
            assert_eq!(cfg.u64("guid"), Some(node.children[1].guid));
        }
        // Sealed for one position, it does not verify at another.
        let img = label_image(&nv, 0, SIZE).expect("fits");
        let at = VDEV_PHYS_OFFSET as usize;
        let phys = &img[at..at + VDEV_PHYS_SIZE as usize];
        let elsewhere = label_offsets(SIZE).expect("four labels")[2];
        assert_eq!(
            parse_vdev_phys(phys, elsewhere).checksum,
            ChecksumStatus::Bad
        );
    }

    #[test]
    fn the_right_member_order_is_the_one_with_no_mismatches() {
        let sources = label_less_raidz2();
        // The uberblocks have to come from the members themselves, which
        // means the anchors, since no label survives.
        let scans: Vec<_> = sources
            .iter()
            .map(|s| crate::zeropoint::scan_with_recovered_base(s).ok())
            .collect();
        let devices: Vec<Option<&dyn BlockSource>> = sources
            .iter()
            .map(|s| Some(s as &dyn BlockSource))
            .collect();
        let bases = vec![0u64; sources.len()];

        let right = try_layout(&layout(&[0, 1, 2, 3]), &scans, &devices, &bases);
        assert!(right.read());
        assert_eq!(right.mismatches, 0);

        // Two columns swapped: parity carries it, so it still reads — and
        // every block that touches them fails its checksum first.
        let swapped = try_layout(&layout(&[0, 2, 1, 3]), &scans, &devices, &bases);
        assert!(swapped.read(), "raidz2 reconstructs around two bad columns");
        assert!(swapped.mismatches > 0);

        let trials = search_order(&layout(&[0, 2, 1, 3]), 0, &scans, &devices, &bases)
            .expect("4 members is a small search");
        let best = trials.first().expect("some order reads");
        assert_eq!(best.mismatches, 0);
        assert_eq!(
            best.layout.tops[0].members,
            vec![Some(0), Some(1), Some(2), Some(3)]
        );
        assert_eq!(trials.iter().filter(|t| t.mismatches == 0).count(), 1);
    }
}

// ---------------------------------------------------------------------------
// Handing the result on (F-67)
// ---------------------------------------------------------------------------

use zfs_ondisk::nvlist::{encode, NvList, Value};

/// Build the `vdev_phys` configuration nvlist for one leaf of a layout.
///
/// This is the template a practitioner would otherwise edit by hand: what
/// a label of that member would have said. `pool_guid`, `txg` and the
/// pool name come from whatever survived — the uberblocks give the TXG,
/// the operator gives the rest — and the vdev GUIDs are the synthetic ones
/// the layout hands out, since the real ones are gone with the labels.
pub fn label_nvlist(
    layout: &LayoutHints,
    top: usize,
    leaf: usize,
    txg: u64,
    asize: Option<u64>,
) -> NvList {
    let assembly = layout.assemble();
    let t = &assembly.tops[top];
    let children: Vec<NvList> = t
        .tree
        .children
        .iter()
        .map(|c| {
            encode::list(vec![
                ("type", Value::String("disk".into())),
                ("id", Value::Uint64(c.id)),
                ("guid", Value::Uint64(c.guid)),
                ("whole_disk", Value::Uint64(0)),
                ("create_txg", Value::Uint64(4)),
            ])
        })
        .collect();
    let mut tree = vec![
        ("type", Value::String(t.kind.clone())),
        ("id", Value::Uint64(t.id)),
        ("guid", Value::Uint64(t.guid)),
        ("ashift", Value::Uint64(layout.ashift)),
        ("create_txg", Value::Uint64(4)),
    ];
    if let Some(p) = t.nparity {
        tree.push(("nparity", Value::Uint64(p)));
    }
    if let Some(a) = asize {
        tree.push(("asize", Value::Uint64(a)));
    }
    if t.kind == "disk" {
        // A single-device top is the leaf itself, not a wrapper.
        tree.retain(|(k, _)| *k != "type");
        tree.insert(0, ("type", Value::String("disk".into())));
        tree.push(("guid", Value::Uint64(t.members[leaf].guid)));
    } else {
        tree.push(("children", Value::ListArray(children)));
    }
    encode::list(vec![
        ("version", Value::Uint64(5000)),
        (
            "name",
            Value::String(layout.name.clone().unwrap_or_else(|| "recovered".into())),
        ),
        ("state", Value::Uint64(0)),
        ("txg", Value::Uint64(txg)),
        ("pool_guid", Value::Uint64(layout.guid.unwrap_or(0))),
        ("vdev_children", Value::Uint64(layout.tops.len() as u64)),
        ("guid", Value::Uint64(assembly.tops[top].members[leaf].guid)),
        ("top_guid", Value::Uint64(t.guid)),
        ("vdev_tree", Value::List(encode::list(tree))),
    ])
}

/// Render the front 128 KiB of a label carrying that configuration,
/// sealed for label position `index` (0..=3) of a vdev of `psize` bytes.
///
/// Only the blank area, the boot header and the `vdev_phys` — everything
/// before the uberblock ring. An uberblock cannot be forged, and the ones
/// that survive are already on the disk, so an image that stopped short
/// of the ring can be placed without destroying them. Nothing here writes
/// anything: the caller decides what to do with the bytes, and never on
/// the evidence (N-01).
pub fn label_image(nv: &NvList, index: usize, psize: u64) -> Result<Vec<u8>, String> {
    use zfs_ondisk::checksum::seal_label;
    use zfs_ondisk::label::{
        label_offsets, UBERBLOCK_RING_OFFSET, VDEV_PHYS_OFFSET, VDEV_PHYS_SIZE,
    };

    let packed = encode::pack(nv);
    if packed.len() + 40 > VDEV_PHYS_SIZE as usize {
        return Err(format!(
            "the configuration is {} bytes, more than the {} a label holds",
            packed.len(),
            VDEV_PHYS_SIZE
        ));
    }
    let offsets = label_offsets(psize)
        .ok_or_else(|| format!("a vdev of {psize} bytes is too small to hold four labels"))?;
    let offset = *offsets
        .get(index)
        .ok_or_else(|| format!("label index {index} is not 0..=3"))?;
    let mut img = vec![0u8; UBERBLOCK_RING_OFFSET as usize];
    let phys = &mut img[VDEV_PHYS_OFFSET as usize..(VDEV_PHYS_OFFSET + VDEV_PHYS_SIZE) as usize];
    phys[..packed.len()].copy_from_slice(&packed);
    seal_label(phys, offset + VDEV_PHYS_OFFSET);
    Ok(img)
}
