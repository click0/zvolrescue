//! Assemble scanned members into pools and report their topology.

use std::collections::BTreeMap;

use zfs_ondisk::label::{LabelConfig, VdevNode};

use crate::vdev::DeviceScan;

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
}

impl TopVdev {
    /// Whether enough leaves are present to read this vdev.
    pub fn readable(&self) -> bool {
        let present = self.members.iter().filter(|m| m.present.is_some()).count();
        let missing = self.members.len() - present;
        match self.kind.as_str() {
            "mirror" => present >= 1,
            "raidz" | "draid" => missing as u64 <= self.nparity.unwrap_or(0),
            _ => missing == 0,
        }
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
        // that carries that tree.
        let mut tops: BTreeMap<u64, (u64, &VdevNode)> = BTreeMap::new();
        for (_, c) in &entries {
            if let Some(tree) = &c.tree {
                let txg = c.txg.unwrap_or(0);
                let e = tops.entry(tree.guid).or_insert((txg, tree));
                if txg > e.0 {
                    *e = (txg, tree);
                }
            }
        }
        let leaf_owner = |leaf_guid: u64| -> Option<usize> {
            entries
                .iter()
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

        pools.push(PoolAssembly {
            name: newest.name.clone().unwrap_or_default(),
            guid,
            state: newest.state,
            txg: entries.iter().filter_map(|(_, c)| c.txg).max(),
            vdev_children: newest.vdev_children,
            tops,
            hosts,
            devices: entries.iter().map(|(i, _)| *i).collect(),
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
