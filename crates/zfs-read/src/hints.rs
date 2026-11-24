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

/// One vdev of a hand-written layout: a top-level vdev, or a group
/// nested inside one.
///
/// A node has either `members` (leaves) or `children` (groups). Real
/// pools are usually one level deep — a raidz of disks, a mirror of disks
/// — but a vdev being replaced or backed by a spare nests, and so does
/// anything ztest builds, which wraps parity vdevs in a mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopHint {
    /// `mirror`, `raidz`, `draid`, `replacing`, `spare`, or `disk` for a
    /// single-device top.
    pub kind: String,
    /// Parity level for raidz/draid.
    pub nparity: Option<u64>,
    /// Data columns per dRAID group.
    pub draid_ndata: Option<u64>,
    /// Distributed spares of a dRAID.
    pub draid_nspares: Option<u64>,
    /// Groups per dRAID slice.
    pub draid_ngroups: Option<u64>,
    /// `ashift` of this vdev, where it is not the pool's: a pool grown
    /// with 4Kn disks has vdevs of 9 beside vdevs of 12. Read on a
    /// top-level vdev only — what is under one shares its.
    pub ashift: Option<u64>,
    /// Indices into the scanned device list, in vdev order. `None` marks a
    /// member that is known to exist but was not supplied.
    pub members: Vec<Option<usize>>,
    /// Groups under this one, when the vdev nests.
    pub children: Vec<TopHint>,
}

impl TopHint {
    /// Every leaf under this node, in vdev order.
    pub fn leaves(&self) -> Vec<Option<usize>> {
        if self.children.is_empty() {
            return self.members.clone();
        }
        self.children.iter().flat_map(|c| c.leaves()).collect()
    }
}

/// A whole pool described by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutHints {
    /// Pool name, if known: the first part of every dataset's name. When
    /// it is not, the pool's configuration in its MOS gives it, where
    /// that reads ([`crate::dsl::walk`]), and `?` stands for it otherwise.
    pub name: Option<String>,
    /// Pool GUID, if known.
    pub guid: Option<u64>,
    /// `ashift` of every top-level vdev that does not give its own
    /// ([`TopHint::ashift`]).
    pub ashift: u64,
    /// Top-level vdevs in order; their index is their vdev id, which is
    /// what a DVA names.
    pub tops: Vec<TopHint>,
}

impl LayoutHints {
    /// `ashift` of top-level vdev `top`: its own, or the pool's.
    pub fn ashift_of(&self, top: usize) -> u64 {
        self.tops
            .get(top)
            .and_then(|t| t.ashift)
            .unwrap_or(self.ashift)
    }

    /// Turn the template into the assembly the reader takes.
    ///
    /// GUIDs are invented (a label would carry real ones, and nothing in
    /// reading a block depends on them): each leaf gets a stable synthetic
    /// GUID so reports and bindings can name it.
    pub fn assemble(&self) -> PoolAssembly {
        let mut tops = Vec::with_capacity(self.tops.len());
        let mut devices = Vec::new();
        for (id, hint) in self.tops.iter().enumerate() {
            let mut members = Vec::new();
            let mut count = Count::default();
            // The tree carries the vdev's own id, as a label's does: it
            // is what places a member's top among the pool's. Written 0
            // for every top, the labels made from a layout of several
            // put them all in the place of the first.
            let ashift = self.ashift_of(id);
            let tree = self.node(hint, (id, ashift), id as u64, &mut count, &mut members);
            for m in &members {
                if let Some(d) = m.present {
                    if !devices.contains(&d) {
                        devices.push(d);
                    }
                }
            }
            tops.push(TopVdev {
                id: id as u64,
                guid: tree.guid,
                name: format!("{}-{id}", display_kind(hint)),
                kind: hint.kind.clone(),
                nparity: hint.nparity,
                ashift: Some(ashift),
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
            // A hand-written layout describes where the members are, not
            // what the pool has turned on; nothing here claims otherwise.
            features_for_read: Vec::new(),
            tops,
            removed_tops: Vec::new(),
            removed_maps: Default::default(),
            former: Vec::new(),
            hosts: Vec::new(),
            host_txgs: Vec::new(),
            devices,
            stale: Vec::new(),
        }
    }

    /// One node of the tree of top-level vdev `top`, whose `ashift`
    /// comes with it, numbering leaves in vdev order.
    fn node(
        &self,
        hint: &TopHint,
        (top, ashift): (usize, u64),
        id: u64,
        count: &mut Count,
        members: &mut Vec<Member>,
    ) -> VdevNode {
        let Count { leaf, group } = count;
        let mut children = Vec::new();
        // A top-level vdev of one disk is that disk: the leaf itself, as
        // a label describes a plain stripe. Wrapped in a "disk" node of
        // its own, it was a vdev type the reader does not know.
        if matches!(hint.kind.as_str(), "disk" | "file")
            && hint.children.is_empty()
            && hint.members.len() == 1
        {
            let guid = synthetic_guid(top, *leaf);
            members.push(Member {
                guid,
                path: None,
                present: hint.members[0],
            });
            *leaf += 1;
            return VdevNode {
                kind: hint.kind.clone(),
                id,
                guid,
                path: None,
                ashift: Some(ashift),
                asize: None,
                metaslab_array: None,
                metaslab_shift: None,
                nparity: None,
                draid_ndata: None,
                draid_nspares: None,
                draid_ngroups: None,
                is_log: false,
                indirect_object: None,
                children: Vec::new(),
            };
        }
        if hint.children.is_empty() {
            for present in &hint.members {
                let guid = synthetic_guid(top, *leaf);
                members.push(Member {
                    guid,
                    path: None,
                    present: *present,
                });
                children.push(VdevNode {
                    kind: "disk".into(),
                    id: children.len() as u64,
                    guid,
                    path: None,
                    ashift: Some(ashift),
                    asize: None,
                    metaslab_array: None,
                    metaslab_shift: None,
                    nparity: None,
                    draid_ndata: None,
                    draid_nspares: None,
                    draid_ngroups: None,
                    is_log: false,
                    indirect_object: None,
                    children: Vec::new(),
                });
                *leaf += 1;
            }
        }
        // Group GUIDs are numbered from the top down, well clear of the
        // leaves' own numbering, and each its own: numbered by position
        // among its siblings, the first group in a top had the top's.
        let guid = synthetic_guid(top, usize::MAX - *group);
        *group += 1;
        for (i, c) in hint.children.iter().enumerate() {
            children.push(self.node(c, (top, ashift), i as u64, count, members));
        }
        VdevNode {
            kind: hint.kind.clone(),
            id,
            guid,
            path: None,
            ashift: Some(ashift),
            asize: None,
            metaslab_array: None,
            metaslab_shift: None,
            nparity: hint.nparity,
            draid_ndata: hint.draid_ndata,
            draid_nspares: hint.draid_nspares,
            draid_ngroups: hint.draid_ngroups,
            is_log: false,
            indirect_object: None,
            children,
        }
    }

    /// Every member index the template refers to, in vdev order.
    pub fn devices(&self) -> Vec<usize> {
        self.tops
            .iter()
            .flat_map(|t| t.leaves().into_iter().flatten())
            .collect()
    }
}

/// Where the numbering of one top-level vdev's tree stands: the leaves
/// in vdev order, and the groups from the top down.
#[derive(Default)]
struct Count {
    leaf: usize,
    group: usize,
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
    let reader = PoolReader::new(&pool, devices.to_vec()).with_base_offsets(bases);
    // The newest TXG that reads: one with nothing behind it (a sync
    // whose MOS never reached the disk, a forged txg) is no evidence
    // about the layout either way.
    for c in &candidates {
        if let Ok(mos) = open_mos(&reader, &c.ub) {
            if let Ok(tree) = walk(&mos, &pool.name) {
                trial.datasets = Some(tree.datasets.len());
                break;
            }
        }
    }
    trial.mismatches = reader.mismatches();
    trial
}

/// Every ordering of the members of one top-level vdev, as layouts.
fn permutations(layout: &LayoutHints, group: &[usize]) -> Vec<LayoutHints> {
    let Some(members) = group_at(layout, group).map(|g| g.members.clone()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut order: Vec<usize> = (0..members.len()).collect();
    permute(&mut order, 0, &mut |o| {
        let mut l = layout.clone();
        if let Some(g) = group_at_mut(&mut l, group) {
            g.members = o.iter().map(|&i| members[i]).collect();
        }
        out.push(l);
    });
    out
}

/// The group a path names: a top-level vdev by its index, then a child
/// of it by its index, and so on — `[0]` the first top, `[0, 1]` the
/// second group inside it, as a raidz under a mirror is.
pub fn group_at<'l>(layout: &'l LayoutHints, group: &[usize]) -> Option<&'l TopHint> {
    let (first, rest) = group.split_first()?;
    rest.iter()
        .try_fold(layout.tops.get(*first)?, |g, &i| g.children.get(i))
}

fn group_at_mut<'l>(layout: &'l mut LayoutHints, group: &[usize]) -> Option<&'l mut TopHint> {
    let (first, rest) = group.split_first()?;
    rest.iter()
        .try_fold(layout.tops.get_mut(*first)?, |g, &i| g.children.get_mut(i))
}

/// Every group whose member order a layout leaves open: each raidz or
/// draid of two members or more, at the top or inside a mirror, by its
/// path (see [`group_at`]).
pub fn ordered_groups(layout: &LayoutHints) -> Vec<Vec<usize>> {
    fn walk(g: &TopHint, path: Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if matches!(g.kind.as_str(), "raidz" | "draid") && g.members.len() >= 2 {
            out.push(path.clone());
        }
        for (i, c) in g.children.iter().enumerate() {
            let mut p = path.clone();
            p.push(i);
            walk(c, p, out);
        }
    }
    let mut out = Vec::new();
    for (i, t) in layout.tops.iter().enumerate() {
        walk(t, vec![i], &mut out);
    }
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
    group: &[usize],
    scans: &[Option<DeviceScan>],
    devices: &[Option<&dyn BlockSource>],
    bases: &[u64],
) -> Result<Vec<Trial>, String> {
    let n = group_at(layout, group).map_or(0, |t| t.members.len());
    if n > MAX_SEARCHED_MEMBERS {
        return Err(format!(
            "{n} members is {}! orderings — name the order in the layout, or split the search",
            n
        ));
    }
    let mut trials: Vec<Trial> = permutations(layout, group)
        .iter()
        .map(|l| {
            let t = try_layout(l, scans, devices, bases);
            trace!(
                "pool",
                "order {:?}: {} datasets, {} mismatch(es)",
                group_at(l, group).map(|g| &g.members),
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
    let tree = tree_nvlist(&t.tree, Some((layout.ashift_of(top), asize)));
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
        ("vdev_tree", Value::List(tree)),
    ])
}

/// What only the MOS's copy of a vdev's configuration carries, and no
/// label does: the per-vdev ZAP objects.
const MOS_ONLY: [&str; 3] = [
    "com.delphix:vdev_zap_leaf",
    "com.delphix:vdev_zap_top",
    "com.delphix:vdev_root_zap",
];

/// The label of one member as the pool itself wrote it (SPEC F-67).
///
/// `config` is the pool's own configuration, from its MOS
/// ([`crate::dsl::pool_config`]). A label is that configuration with
/// the member's top-level vdev in place of the whole tree, the two
/// GUIDs that say whose label it is, and without what only the MOS's
/// copy has. So the label is the pool's in everything a reader checks:
/// the GUIDs of the pool and of every vdev, whose sum each uberblock
/// records; `asize` and the metaslab array, without which the vdev's
/// space cannot be opened; and `features_for_read`, without which
/// OpenZFS takes no label at all. A template has none of them
/// ([`label_nvlist`]).
///
/// The layout says where the member is — leaf `leaf`, in vdev order, of
/// top-level vdev `top`, which has `leaves` of them — and the
/// configuration which vdev that is. `name` is the pool's name as the
/// run reads it, where that is not the configuration's.
///
/// An error says why the configuration cannot tell: it does not hold
/// that vdev, or holds it in another shape than the layout does.
pub fn label_from_config(
    config: &NvList,
    name: Option<&str>,
    top: usize,
    leaf: usize,
    leaves: usize,
) -> Result<NvList, String> {
    fn leaf_guids(node: &NvList, out: &mut Vec<Option<u64>>) {
        match node.list_array("children") {
            Some(children) if !children.is_empty() => {
                children.iter().for_each(|c| leaf_guids(c, out))
            }
            _ => out.push(node.u64("guid")),
        }
    }
    fn as_a_label_has_it(node: &NvList) -> NvList {
        NvList {
            version: node.version,
            flags: node.flags,
            pairs: node
                .pairs
                .iter()
                .filter(|(key, _)| !MOS_ONLY.contains(&key.as_str()))
                .map(|(key, value)| {
                    let value = match value {
                        Value::ListArray(children) if key == "children" => {
                            Value::ListArray(children.iter().map(as_a_label_has_it).collect())
                        }
                        other => other.clone(),
                    };
                    (key.clone(), value)
                })
                .collect(),
        }
    }
    /// A value of a type the parser keeps no bytes of cannot be
    /// written back.
    fn unwritable(list: &NvList) -> Option<&str> {
        list.pairs.iter().find_map(|(key, value)| match value {
            Value::Unknown { .. } => Some(key.as_str()),
            Value::List(inner) => unwritable(inner),
            Value::ListArray(inner) => inner.iter().find_map(unwritable),
            _ => None,
        })
    }

    let tops = config
        .list("vdev_tree")
        .and_then(|root| root.list_array("children"))
        .ok_or("the pool's configuration has no vdev tree")?;
    let tree = tops.get(top).ok_or_else(|| {
        format!(
            "the pool's configuration has {} top-level vdev(s), and the layout places the member in #{top}",
            tops.len()
        )
    })?;
    let kind = tree.str("type").unwrap_or("?");
    if matches!(kind, "hole" | "indirect" | "missing") {
        return Err(format!(
            "top-level vdev #{top} is {kind:?} in the pool's configuration: no member is in it"
        ));
    }
    let mut guids = Vec::new();
    leaf_guids(tree, &mut guids);
    if guids.len() != leaves {
        return Err(format!(
            "top-level vdev #{top} has {} member(s) in the pool's configuration and {leaves} in the layout",
            guids.len()
        ));
    }
    let (Some(guid), Some(top_guid)) = (guids.get(leaf).copied().flatten(), tree.u64("guid"))
    else {
        return Err(format!(
            "the pool's configuration gives no GUID for member {leaf} of top-level vdev #{top}"
        ));
    };

    let mut label = NvList {
        version: config.version,
        flags: config.flags,
        pairs: Vec::with_capacity(config.pairs.len() + 2),
    };
    let mut whose = Some([
        ("top_guid".to_string(), Value::Uint64(top_guid)),
        ("guid".to_string(), Value::Uint64(guid)),
    ]);
    for (key, value) in &config.pairs {
        let value = match key.as_str() {
            // The MOS's own word that it keeps per-vdev ZAPs; and a
            // label's two GUIDs, which this one gets below.
            "com.delphix:has_per_vdev_zaps" | "top_guid" | "guid" => continue,
            "vdev_tree" => Value::List(as_a_label_has_it(tree)),
            "name" => Value::String(name.or(config.str("name")).unwrap_or("?").to_string()),
            _ => value.clone(),
        };
        // Where a label has them: ahead of the vdev count and the tree.
        if matches!(key.as_str(), "vdev_children" | "vdev_tree") {
            label.pairs.extend(whose.take().into_iter().flatten());
        }
        label.pairs.push((key.clone(), value));
    }
    if let Some(key) = unwritable(&label) {
        return Err(format!(
            "the pool's configuration holds {key:?} in a type this does not write"
        ));
    }
    Ok(label)
}

/// One node of a `vdev_tree` as a label carries it, with everything under
/// it. `top` holds what only the top-level vdev records (`ashift`,
/// `asize`). Every group keeps its parity and, for dRAID, the three
/// numbers its geometry is computed from: a label without them describes
/// a dRAID no reader can lay out. A group nested in another is written as
/// nested, so a member of a raidz inside a mirror gets the tree it is in.
fn tree_nvlist(node: &VdevNode, top: Option<(u64, Option<u64>)>) -> NvList {
    let leaf = node.children.is_empty();
    let kind = if leaf && top.is_none() {
        "disk".to_string()
    } else {
        node.kind.clone()
    };
    let mut pairs = vec![
        ("type", Value::String(kind)),
        ("id", Value::Uint64(node.id)),
        ("guid", Value::Uint64(node.guid)),
    ];
    if let Some((ashift, asize)) = top {
        pairs.push(("ashift", Value::Uint64(ashift)));
        if let Some(a) = asize {
            pairs.push(("asize", Value::Uint64(a)));
        }
    }
    pairs.push(("create_txg", Value::Uint64(4)));
    if leaf {
        pairs.push(("whole_disk", Value::Uint64(0)));
        return encode::list(pairs);
    }
    for (key, value) in [
        ("nparity", node.nparity),
        ("draid_ndata", node.draid_ndata),
        ("draid_nspares", node.draid_nspares),
        ("draid_ngroups", node.draid_ngroups),
    ] {
        if let Some(v) = value {
            pairs.push((key, Value::Uint64(v)));
        }
    }
    let children = node.children.iter().map(|c| tree_nvlist(c, None)).collect();
    pairs.push(("children", Value::ListArray(children)));
    encode::list(pairs)
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
                ashift: None,
                members: order.iter().map(|&i| Some(i)).collect(),
                children: Vec::new(),
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

    /// A dRAID label carries the three numbers its layout is computed
    /// from, and a member of a group nested in the top gets the tree it is
    /// in. Without them a relabelled dRAID read as nothing (exit 3), and a
    /// nested layout had "0 member(s)" to emit a label for.
    #[test]
    fn an_emitted_label_keeps_draid_geometry_and_nesting() {
        let leaf = |i| TopHint {
            kind: "disk".into(),
            nparity: None,
            draid_ndata: None,
            draid_nspares: None,
            draid_ngroups: None,
            ashift: None,
            members: vec![Some(i)],
            children: Vec::new(),
        };
        let mut spare = leaf(5);
        spare.kind = "spare".into();
        spare.members = vec![Some(5), None];
        let l = LayoutHints {
            name: Some("tank".into()),
            guid: None,
            ashift: 12,
            tops: vec![TopHint {
                kind: "draid".into(),
                nparity: Some(1),
                draid_ndata: Some(4),
                draid_nspares: Some(1),
                draid_ngroups: Some(1),
                ashift: None,
                members: Vec::new(),
                children: vec![leaf(0), leaf(1), leaf(2), leaf(3), leaf(4), spare],
            }],
        };
        let nv = label_nvlist(&l, 0, 5, 107, None);
        let tree = nv.list("vdev_tree").expect("vdev_tree");
        assert_eq!(tree.str("type"), Some("draid"));
        assert_eq!(tree.u64("draid_ndata"), Some(4));
        assert_eq!(tree.u64("draid_nspares"), Some(1));
        assert_eq!(tree.u64("draid_ngroups"), Some(1));
        let node = VdevNode::from_nvlist(tree);
        assert_eq!(node.children.len(), 6);
        let spare = &node.children[5];
        assert_eq!(spare.kind, "spare");
        assert_eq!(spare.children.len(), 2);
        // The sixth leaf in vdev order is the first under the spare.
        assert_eq!(nv.u64("guid"), Some(spare.children[0].guid));
        assert_eq!(node.children[0].kind, "disk");
        assert!(node.children[0].children.is_empty());
    }

    /// Each top-level vdev's label says which of the pool's vdevs it is.
    /// Every tree was written with id 0: placed, the labels of a pool
    /// of three vdevs described three vdevs #0, the reader kept one and
    /// set the members of the others aside as superseded, and the pool
    /// the layout had read whole was "top-level vdev #1: MISSING".
    #[test]
    fn an_emitted_label_says_which_top_level_vdev_it_is_of() {
        let group = |kind: &str, nparity, members: &[usize]| TopHint {
            kind: kind.into(),
            nparity,
            draid_ndata: None,
            draid_nspares: None,
            draid_ngroups: None,
            ashift: None,
            members: members.iter().map(|&i| Some(i)).collect(),
            children: Vec::new(),
        };
        let mut nested = group("mirror", None, &[]);
        nested.children = vec![
            group("raidz", Some(1), &[6, 7, 8]),
            group("raidz", Some(1), &[9, 10, 11]),
        ];
        let l = LayoutHints {
            name: Some("tank".into()),
            guid: Some(0x7070),
            ashift: 12,
            tops: vec![
                group("mirror", None, &[0, 1]),
                group("raidz", Some(2), &[2, 3, 4, 5]),
                nested,
            ],
        };
        let mut tops = Vec::new();
        for top in 0..3 {
            let nv = label_nvlist(&l, top, 0, 100, None);
            assert_eq!(nv.u64("vdev_children"), Some(3));
            let tree = nv.list("vdev_tree").expect("vdev_tree");
            assert_eq!(tree.u64("id"), Some(top as u64), "top {top}");
            assert_eq!(tree.u64("guid"), nv.u64("top_guid"));
            tops.push(VdevNode::from_nvlist(tree));
        }
        // What is inside a top is numbered within it, as before.
        assert_eq!(
            tops[1].children.iter().map(|c| c.id).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        // No two vdevs of the pool share a GUID: the first group inside
        // a top had the top's own.
        fn guids(n: &VdevNode, out: &mut Vec<u64>) {
            out.push(n.guid);
            n.children.iter().for_each(|c| guids(c, out));
        }
        let mut all = Vec::new();
        tops.iter().for_each(|t| guids(t, &mut all));
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n, "a GUID is given twice");
        // And the assembly numbers them the same way.
        let assembly = l.assemble();
        for (i, t) in assembly.tops.iter().enumerate() {
            assert_eq!((t.id, t.tree.id), (i as u64, i as u64));
        }
    }

    /// A top-level vdev that gives its own `ashift` is assembled, and
    /// labelled, with it; the others have the pool's.
    #[test]
    fn a_top_level_vdev_has_its_own_ashift_or_the_pools() {
        let mut l = layout(&[0, 1, 2, 3]);
        let mut second = l.tops[0].clone();
        second.members = vec![Some(4), Some(5), Some(6), Some(7)];
        second.ashift = Some(9);
        l.tops.push(second);
        assert_eq!((l.ashift_of(0), l.ashift_of(1)), (12, 9));
        let assembly = l.assemble();
        assert_eq!(
            assembly.tops.iter().map(|t| t.ashift).collect::<Vec<_>>(),
            vec![Some(12), Some(9)]
        );
        for (top, ashift) in [(0, 12), (1, 9)] {
            let nv = label_nvlist(&l, top, 0, 100, None);
            let tree = nv.list("vdev_tree").expect("vdev_tree");
            assert_eq!(tree.u64("ashift"), Some(ashift), "top {top}");
        }
    }

    /// The label made from the pool's own configuration is the label
    /// the pool wrote for that member, pair for pair: the GUIDs, the
    /// metaslab array, the features — and none of what only the MOS's
    /// copy carries. What the configuration cannot tell is said, and
    /// is no label.
    #[test]
    fn a_label_from_the_pools_configuration_is_the_one_the_pool_wrote() {
        use crate::fixture::{configured_two_top_members, mos_config};

        let (tops, _) = configured_two_top_members("tank", 0x7070, 12, [2, 3], &[(100, 1)], SIZE);
        let config = mos_config(&tops);
        assert!(config.flag("com.delphix:has_per_vdev_zaps"));
        for (top, leaves) in [(0usize, 2usize), (1, 3)] {
            for leaf in 0..leaves {
                let label = label_from_config(&config, None, top, leaf, leaves).expect("a label");
                assert_eq!(label, tops[top].config(leaf), "top {top} leaf {leaf}");
            }
        }
        // The pool as the run names it, where that is not the name the
        // configuration has.
        let renamed = label_from_config(&config, Some("rescued"), 1, 0, 3).expect("a label");
        assert_eq!(renamed.str("name"), Some("rescued"));
        assert_eq!(renamed.u64("pool_guid"), Some(0x7070));

        // A vdev the configuration does not have, or has in another
        // shape than the layout.
        let beyond = label_from_config(&config, None, 2, 0, 2).unwrap_err();
        assert!(beyond.contains("2 top-level vdev(s)"), "{beyond}");
        let shape = label_from_config(&config, None, 1, 0, 2).unwrap_err();
        assert!(
            shape.contains("3 member(s) in the pool's configuration and 2 in the layout"),
            "{shape}"
        );
        // A vdev that was removed has no member to label.
        let mut removed = config.clone();
        for (key, value) in removed.pairs.iter_mut() {
            if let ("vdev_tree", Value::List(root)) = (key.as_str(), value) {
                for (key, value) in root.pairs.iter_mut() {
                    if let ("children", Value::ListArray(tops)) = (key.as_str(), value) {
                        tops[1] = encode::list(vec![
                            ("type", Value::String("indirect".into())),
                            ("id", Value::Uint64(1)),
                            ("guid", Value::Uint64(0x1de)),
                        ]);
                    }
                }
            }
        }
        let gone = label_from_config(&removed, None, 1, 0, 3).unwrap_err();
        assert!(gone.contains("is \"indirect\""), "{gone}");
        // The vdev beside it is still labelled, and still one of two.
        let kept = label_from_config(&removed, None, 0, 1, 2).expect("a label");
        assert_eq!(kept.u64("vdev_children"), Some(2));
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

        let trials = search_order(&layout(&[0, 2, 1, 3]), &[0], &scans, &devices, &bases)
            .expect("4 members is a small search");
        let best = trials.first().expect("some order reads");
        assert_eq!(best.mismatches, 0);
        assert_eq!(
            best.layout.tops[0].members,
            vec![Some(0), Some(1), Some(2), Some(3)]
        );
        assert_eq!(trials.iter().filter(|t| t.mismatches == 0).count(), 1);

        // The same group under a mirror, as ztest lays raidz groups out:
        // only the top-level vdevs were searched, and this one was read
        // in the order written. It is a group of its own now.
        let mut nested = layout(&[0, 2, 1, 3]);
        let group = nested.tops.remove(0);
        nested.tops.push(TopHint {
            kind: "mirror".into(),
            nparity: None,
            draid_ndata: None,
            draid_nspares: None,
            draid_ngroups: None,
            ashift: None,
            members: Vec::new(),
            children: vec![group],
        });
        assert_eq!(ordered_groups(&nested), vec![vec![0, 0]]);
        let trials = search_order(&nested, &[0, 0], &scans, &devices, &bases).expect("search");
        let best = trials.first().expect("some order reads");
        assert_eq!(best.mismatches, 0);
        assert_eq!(
            group_at(&best.layout, &[0, 0]).map(|g| g.members.clone()),
            Some(vec![Some(0), Some(1), Some(2), Some(3)])
        );
    }
}
