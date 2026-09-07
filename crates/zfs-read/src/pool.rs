//! Assemble scanned members into pools and report their topology.

use std::collections::BTreeMap;

use zfs_ondisk::checksum::ChecksumStatus;
use zfs_ondisk::label::{LabelConfig, VdevNode};
use zfs_ondisk::uberblock::Uberblock;

use crate::vdev::DeviceScan;
use zvolrescue_io::trace;

/// A leaf vdev of a top-level vdev and whether it was among the scanned devices.
#[derive(Debug, Clone)]
pub struct Member {
    /// Leaf vdev GUID.
    pub guid: u64,
    /// `path` recorded in the configuration, if any.
    pub path: Option<String>,
    /// Index into the scanned device list when present.
    pub present: Option<usize>,
}

/// A top-level vdev reconstructed from the labels that describe it.
#[derive(Debug, Clone)]
pub struct TopVdev {
    /// `id` among top-level vdevs.
    pub id: u64,
    /// GUID.
    pub guid: u64,
    /// `mirror-0`, `raidz2-1`, or the leaf path for a single-disk top.
    pub name: String,
    /// `type`.
    pub kind: String,
    /// `nparity` for raidz/draid.
    pub nparity: Option<u64>,
    /// `ashift`.
    pub ashift: Option<u64>,
    /// Leaves in configuration order.
    pub members: Vec<Member>,
    /// The full vdev subtree (mirrors and raidz may nest, as ztest pools do).
    pub tree: VdevNode,
}

impl TopVdev {
    /// Whether enough leaves are present to read this vdev.
    pub fn readable(&self) -> bool {
        node_readable(&self.tree, &self.members)
    }
}

/// Recursive readability: a leaf must be present, a mirror needs one
/// readable child, raidz/draid tolerate up to `nparity` unreadable ones.
pub fn node_readable(node: &VdevNode, members: &[Member]) -> bool {
    if node.children.is_empty() {
        return members
            .iter()
            .any(|m| m.guid == node.guid && m.present.is_some());
    }
    let readable = node
        .children
        .iter()
        .filter(|c| node_readable(c, members))
        .count();
    let missing = node.children.len() - readable;
    match node.kind.as_str() {
        "mirror" => readable >= 1,
        "raidz" | "draid" => missing as u64 <= node.nparity.unwrap_or(0),
        _ => missing == 0,
    }
}

/// A pool seen across the scanned devices.
#[derive(Debug, Clone)]
pub struct PoolAssembly {
    /// Pool name from the newest label.
    pub name: String,
    /// Pool GUID.
    pub guid: u64,
    /// `state` from the newest label.
    pub state: Option<u64>,
    /// Highest label `txg` seen.
    pub txg: Option<u64>,
    /// Number of top-level vdevs the pool has according to its labels.
    pub vdev_children: Option<u64>,
    /// Top-level vdevs for which at least one member was scanned.
    pub tops: Vec<TopVdev>,
    /// Distinct `(hostid, hostname)` pairs seen in labels.
    pub hosts: Vec<(Option<u64>, Option<String>)>,
    /// Indices of scanned devices that belong to this pool.
    pub devices: Vec<usize>,
    /// Scanned devices carrying this pool's GUID whose label does not
    /// describe part of the committed configuration: `txg 0` labels of a
    /// device that was being attached or replaced, or a top-level vdev
    /// superseded by a newer label with the same id. Reads never use them.
    pub stale: Vec<StaleMember>,
}

/// A scanned device excluded from the assembled topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleMember {
    /// Index into the scanned device list.
    pub device: usize,
    /// Leaf vdev GUID from its label.
    pub guid: Option<u64>,
    /// Label `txg`.
    pub txg: Option<u64>,
    /// Why it was set aside.
    pub reason: String,
}

impl PoolAssembly {
    /// Top-level vdev ids that no scanned device described.
    pub fn missing_tops(&self) -> Vec<u64> {
        let Some(n) = self.vdev_children else {
            return Vec::new();
        };
        (0..n)
            .filter(|id| !self.tops.iter().any(|t| t.id == *id))
            .collect()
    }

    /// True when every top-level vdev is known and readable.
    pub fn readable(&self) -> bool {
        self.missing_tops().is_empty() && self.tops.iter().all(TopVdev::readable)
    }
}

/// Group scanned devices by pool GUID and rebuild each pool's topology.
///
/// `scans[i]` is `None` for devices that could not be read; they are
/// simply absent from every pool.
pub fn assemble(scans: &[Option<DeviceScan>]) -> Vec<PoolAssembly> {
    let configs: Vec<(usize, LabelConfig)> = scans
        .iter()
        .enumerate()
        .filter_map(|(i, s)| s.as_ref().and_then(DeviceScan::config).map(|c| (i, c)))
        .filter(|(_, c)| c.pool_guid.is_some())
        .collect();

    let mut by_pool: BTreeMap<u64, Vec<&(usize, LabelConfig)>> = BTreeMap::new();
    for entry in &configs {
        by_pool
            .entry(entry.1.pool_guid.unwrap_or(0))
            .or_default()
            .push(entry);
    }

    let mut pools = Vec::new();
    for (guid, entries) in by_pool {
        // Newest label wins for pool-level facts.
        let newest = entries
            .iter()
            .max_by_key(|(_, c)| c.txg.unwrap_or(0))
            .map(|(_, c)| c)
            .expect("non-empty group");

        // Top-level vdevs: keyed by top guid, described by the newest label
        // that carries that tree. A label with txg 0 was written by
        // vdev_label_init for a device being attached, replaced or added
        // as a spare and never committed: it describes nothing.
        let mut stale = Vec::new();
        let mut tops: BTreeMap<u64, (u64, &VdevNode)> = BTreeMap::new();
        for (i, c) in &entries {
            let txg = c.txg.unwrap_or(0);
            if txg == 0 {
                stale.push(StaleMember {
                    device: *i,
                    guid: c.guid,
                    txg: c.txg,
                    reason: "label txg 0: device was being attached/replaced, never part of a committed configuration".into(),
                });
                continue;
            }
            if let Some(tree) = &c.tree {
                let e = tops.entry(tree.guid).or_insert((txg, tree));
                if txg > e.0 {
                    *e = (txg, tree);
                }
            }
        }
        // Two tops with the same id: the older one was replaced or removed.
        let mut by_id: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
        for (guid, (txg, tree)) in &tops {
            let e = by_id.entry(tree.id).or_insert((*txg, *guid));
            if *txg > e.0 {
                *e = (*txg, *guid);
            }
        }
        let superseded: Vec<u64> = tops
            .iter()
            .filter(|(guid, (_, tree))| by_id[&tree.id].1 != **guid)
            .map(|(guid, _)| *guid)
            .collect();
        for guid in superseded {
            let (txg, tree) = tops.remove(&guid).expect("present");
            for (i, c) in &entries {
                if c.top_guid == Some(guid) {
                    stale.push(StaleMember {
                        device: *i,
                        guid: c.guid,
                        txg: c.txg,
                        reason: format!(
                            "label txg {txg} describes top-level vdev #{} (guid {guid:#x}) superseded by a newer label",
                            tree.id
                        ),
                    });
                }
            }
        }
        let leaf_owner = |leaf_guid: u64| -> Option<usize> {
            entries
                .iter()
                .filter(|(i, _)| !stale.iter().any(|m| m.device == *i))
                .find(|(_, c)| c.guid == Some(leaf_guid))
                .map(|(i, _)| *i)
        };
        let mut tops: Vec<TopVdev> = tops
            .into_values()
            .map(|(_, tree)| TopVdev {
                id: tree.id,
                guid: tree.guid,
                name: tree.display_name(),
                kind: tree.kind.clone(),
                nparity: tree.nparity,
                ashift: tree.ashift,
                members: tree
                    .leaves()
                    .into_iter()
                    .map(|leaf| Member {
                        guid: leaf.guid,
                        path: leaf.path.clone(),
                        present: leaf_owner(leaf.guid),
                    })
                    .collect(),
                tree: tree.clone(),
            })
            .collect();
        tops.sort_by_key(|t| t.id);

        let mut hosts: Vec<(Option<u64>, Option<String>)> = Vec::new();
        for (_, c) in &entries {
            let h = (c.hostid, c.hostname.clone());
            if !hosts.contains(&h) {
                hosts.push(h);
            }
        }

        trace!(
            "pool",
            "pool {:?} guid {guid:#x}: {} member(s) scanned, {} top-level vdev(s) described of {:?}",
            newest.name.as_deref().unwrap_or("?"),
            entries.len(),
            tops.len(),
            newest.vdev_children
        );
        for t in &tops {
            for m in &t.members {
                trace!(
                    "pool",
                    "  {} leaf {:#x} {:?}: {}",
                    t.name,
                    m.guid,
                    m.path,
                    match m.present {
                        Some(i) => format!("device #{i}"),
                        None => "MISSING".to_string(),
                    }
                );
            }
        }
        pools.push(PoolAssembly {
            name: newest.name.clone().unwrap_or_default(),
            guid,
            state: newest.state,
            txg: entries.iter().filter_map(|(_, c)| c.txg).max(),
            vdev_children: newest.vdev_children,
            tops,
            hosts,
            devices: entries.iter().map(|(i, _)| *i).collect(),
            stale,
        });
    }
    pools
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::Pool;
    use crate::vdev::scan_device;
    use zfs_ondisk::label::LABEL_SIZE;
    use zvolrescue_io::MemSource;

    fn scan(img: Vec<u8>) -> Option<DeviceScan> {
        scan_device(&MemSource::new(img)).ok()
    }

    #[test]
    fn mirror_with_one_member_missing() {
        let pool = Pool::mirror("tank", 0x1000, 12).txgs(&[(100, 1)]);
        let scans = vec![scan(pool.member_image(0, 8 * LABEL_SIZE)), None];
        let pools = assemble(&scans);
        assert_eq!(pools.len(), 1);
        let p = &pools[0];
        assert_eq!(p.name, "tank");
        assert_eq!(p.tops.len(), 1);
        assert_eq!(p.tops[0].name, "mirror-0");
        assert_eq!(p.tops[0].members.len(), 2);
        assert_eq!(p.tops[0].members[0].present, Some(0));
        assert_eq!(p.tops[0].members[1].present, None);
        assert!(p.tops[0].readable());
        assert!(p.readable());
    }

    #[test]
    fn txg_zero_label_is_stale_not_a_top() {
        // A device that was being attached: same pool GUID, label txg 0,
        // no verified uberblocks (what vdev_label_init leaves behind).
        let pool = Pool::mirror("tank", 0x1000, 12).txgs(&[(100, 1)]);
        let mut attaching = Pool::mirror("tank", 0x1000, 12);
        attaching.members[0].guid = 0xdead_0001;
        attaching.members[1].guid = 0xdead_0002;
        let scans = vec![
            scan(attaching.member_image(0, 8 * LABEL_SIZE)),
            scan(pool.member_image(0, 8 * LABEL_SIZE)),
            scan(pool.member_image(1, 8 * LABEL_SIZE)),
        ];
        let pools = assemble(&scans);
        assert_eq!(pools.len(), 1);
        let p = &pools[0];
        assert_eq!(p.tops.len(), 1);
        assert_eq!(p.tops[0].members.len(), 2);
        assert_eq!(p.tops[0].members[0].present, Some(1));
        assert_eq!(p.tops[0].members[1].present, Some(2));
        assert_eq!(p.stale.len(), 1);
        assert_eq!(p.stale[0].device, 0);
        assert_eq!(p.stale[0].txg, Some(0));
        assert!(p.stale[0].reason.contains("txg 0"));
        assert_eq!(p.devices.len(), 3);
    }

    #[test]
    fn two_pools_and_a_missing_top() {
        let a = Pool::mirror("a", 0x1, 12).txgs(&[(5, 1)]);
        let mut b = Pool::mirror("b", 0x2, 9).txgs(&[(9, 1)]);
        b.vdev_children = 2;
        let scans = vec![
            scan(a.member_image(1, 8 * LABEL_SIZE)),
            scan(b.member_image(0, 8 * LABEL_SIZE)),
            scan(a.member_image(0, 8 * LABEL_SIZE)),
        ];
        let pools = assemble(&scans);
        assert_eq!(pools.len(), 2);
        assert_eq!(pools[0].name, "a");
        assert_eq!(pools[0].devices, vec![0, 2]);
        assert!(pools[0].readable());
        assert_eq!(pools[1].name, "b");
        assert_eq!(pools[1].missing_tops(), vec![1]);
        assert!(!pools[1].readable());
    }
}

/// How to pick the TXG to read a pool at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxgSelect {
    /// Highest verified TXG.
    Newest,
    /// Exactly this TXG.
    Exact(u64),
    /// Highest TXG whose uberblock timestamp is at or before this Unix time.
    Before(u64),
}

/// A verified uberblock available for a pool, with where it was found.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// The uberblock.
    pub ub: Uberblock,
    /// Scanned device index.
    pub device: usize,
    /// Label index on that device.
    pub label: usize,
}

/// Every checksum-verified uberblock of `pool` across its scanned members,
/// one per TXG (first occurrence kept), newest first.
pub fn uberblock_candidates(scans: &[Option<DeviceScan>], pool: &PoolAssembly) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    for &dev in &pool.devices {
        let Some(scan) = scans.get(dev).and_then(|s| s.as_ref()) else {
            continue;
        };
        for label in &scan.labels {
            for slot in &label.uberblocks {
                if slot.checksum != ChecksumStatus::Ok || slot.ub.txg == 0 {
                    continue;
                }
                if out.iter().any(|c| c.ub.txg == slot.ub.txg) {
                    continue;
                }
                out.push(Candidate {
                    ub: slot.ub.clone(),
                    device: dev,
                    label: label.index,
                });
            }
        }
    }
    out.sort_by_key(|c| std::cmp::Reverse(c.ub.txg));
    trace!(
        "txg",
        "verified uberblocks: {}",
        out.iter()
            .map(|c| format!("{}@dev{}/L{}", c.ub.txg, c.device, c.label))
            .collect::<Vec<_>>()
            .join(" ")
    );
    out
}

/// Choose among `candidates` (newest first) per `sel`.
pub fn select_uberblock(candidates: &[Candidate], sel: TxgSelect) -> Option<&Candidate> {
    match sel {
        TxgSelect::Newest => candidates.first(),
        TxgSelect::Exact(txg) => candidates.iter().find(|c| c.ub.txg == txg),
        TxgSelect::Before(ts) => candidates.iter().find(|c| c.ub.timestamp <= ts),
    }
}
