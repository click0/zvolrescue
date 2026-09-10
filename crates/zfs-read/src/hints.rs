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
