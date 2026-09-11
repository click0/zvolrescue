//! What the allocator has given out, read from the pool (COMPANIONS
//! C-06).
//!
//! A carved candidate's dnode says where its blocks were. The space maps
//! say whether that space is still spoken for. The two answers are
//! different things and both matter:
//!
//! * *free* — the space was released; the blocks are very likely still
//!   there and readable, and will stay so until something else is
//!   written over them. This is the case a recovery is racing.
//! * *allocated* — the space is spoken for. Either the candidate is
//!   still live at some transaction group, or the space was handed to
//!   something else and what is there now is not what was there then.
//!
//! Neither is a verdict on the data: the checksum is. This only says
//! which way the wind is blowing, and it costs one pass over the
//! metaslab logs rather than a read of every block.

use std::collections::BTreeMap;

use zfs_ondisk::dmu::DnodePhys;
use zfs_ondisk::label::VdevNode;
use zfs_ondisk::spacemap::{entries, Ranges, SpaceMapPhys};
use zvolrescue_io::trace;

use crate::dmu::DnodeArray;
use crate::pool::PoolAssembly;
use crate::zio::{PoolReader, ReadError};

/// The allocated space of one top-level vdev.
#[derive(Debug, Clone)]
pub struct VdevSpace {
    /// Which top-level vdev this is.
    pub vdev: u64,
    /// Ranges the metaslab logs say are in use, in vdev-relative bytes.
    pub allocated: Ranges,
    /// Metaslabs whose space map was read.
    pub metaslabs: usize,
    /// Metaslabs whose space map could not be read, and whose space is
    /// therefore unknown rather than free.
    pub unreadable: usize,
    /// Sum of `smp_alloc` over the maps that were read: what ZFS itself
    /// says it has given out, and what replaying the logs must come to.
    pub declared_bytes: i64,
}

impl VdevSpace {
    /// Whether replaying the logs agrees with what the maps declare.
    ///
    /// It has to, on a map that was read whole: `smp_alloc` is
    /// maintained by the same code that appends the entries. A
    /// disagreement means the decoder is wrong, not the pool.
    pub fn consistent(&self) -> bool {
        self.unreadable == 0 && self.allocated.bytes() as i64 == self.declared_bytes
    }
}

/// What the space maps of a pool say (C-06).
#[derive(Debug, Clone, Default)]
pub struct Space {
    /// Allocated ranges per top-level vdev.
    pub vdevs: BTreeMap<u64, VdevSpace>,
    /// Why a vdev is missing from the map, when one is.
    pub skipped: Vec<String>,
    /// The pool keeps recent allocations in log space maps that have not
    /// been flushed into the metaslabs yet, so what is here lags. Space
    /// allocated in the last few transaction groups can still read as
    /// free.
    pub may_lag: bool,
}

impl Space {
    /// Whether `[offset, offset + len)` of `vdev` is spoken for.
    ///
    /// `None` when nothing is known about that vdev — which is not the
    /// same as free, and is reported as its own answer rather than
    /// folded into one.
    pub fn allocated(&self, vdev: u64, offset: u64, len: u64) -> Option<bool> {
        let v = self.vdevs.get(&vdev)?;
        if v.unreadable > 0 && !v.allocated.intersects(offset, len) {
            // Some of this vdev's space is unaccounted for, so "not in
            // the ranges we read" cannot be called free.
            return None;
        }
        Some(v.allocated.intersects(offset, len))
    }

    /// Vdevs whose logs were read whole and agree with themselves.
    pub fn trustworthy(&self) -> usize {
        self.vdevs.values().filter(|v| v.consistent()).count()
    }
}

/// The top-level vdev nodes of an assembly, by id.
fn tops(pool: &PoolAssembly) -> Vec<(u64, &VdevNode)> {
    pool.tops.iter().map(|t| (t.id, &t.tree)).collect()
}

/// Read the space maps of every top-level vdev.
///
/// `mos` is the MOS at the transaction group being asked about. A vdev
/// whose configuration does not say where its metaslabs are — a layout
/// given by hand, a label too damaged to carry it — is skipped by name
/// rather than guessed at.
pub fn read(reader: &PoolReader<'_>, pool: &PoolAssembly, mos: &DnodeArray<'_, '_>) -> Space {
    let mut out = Space {
        may_lag: true,
        ..Space::default()
    };
    let _ = reader;
    for (id, node) in tops(pool) {
        let (Some(array), Some(shift), Some(ashift)) =
            (node.metaslab_array, node.metaslab_shift, node.ashift)
        else {
            out.skipped.push(format!(
                "vdev {id}: the configuration does not say where its metaslabs are"
            ));
            continue;
        };
        // The array object is allocated in blocks and can be longer
        // than the vdev has metaslabs; only the first `asize >> shift`
        // entries are metaslabs at all.
        let count = node.asize.map(|a| (a >> shift) as usize).filter(|n| *n > 0);
        let objects = match metaslab_objects(mos, array) {
            Ok(v) => v,
            Err(e) => {
                out.skipped
                    .push(format!("vdev {id}: metaslab array {array}: {e}"));
                continue;
            }
        };
        let mut space = VdevSpace {
            vdev: id,
            allocated: Ranges::new(),
            metaslabs: 0,
            unreadable: 0,
            declared_bytes: 0,
        };
        let objects = match count {
            Some(n) => &objects[..n.min(objects.len())],
            None => &objects[..],
        };
        for (i, obj) in objects.iter().enumerate() {
            let base = (i as u64) << shift;
            if *obj == 0 {
                // A metaslab that has never been written has no space
                // map and no allocated space: nothing to read, and
                // nothing missing either.
                space.metaslabs += 1;
                continue;
            }
            match read_one(mos, *obj, ashift as u32) {
                Ok((phys, es)) => {
                    space.allocated.replay(&es, base);
                    space.declared_bytes = space.declared_bytes.saturating_add(phys.alloc);
                    space.metaslabs += 1;
                }
                Err(e) => {
                    trace!("spacemap", "vdev {id} metaslab {i} object {obj}: {e}");
                    space.unreadable += 1;
                }
            }
        }
        trace!(
            "spacemap",
            "vdev {id}: {} metaslab(s), {} range(s), {} byte(s) allocated, declared {}",
            space.metaslabs,
            space.allocated.len(),
            space.allocated.bytes(),
            space.declared_bytes
        );
        out.vdevs.insert(id, space);
    }
    out
}

/// The space map object of each metaslab, in order.
fn metaslab_objects(mos: &DnodeArray<'_, '_>, array: u64) -> Result<Vec<u64>, ReadError> {
    let obj = mos.object(array)?;
    let len = obj.logical_size() as usize;
    let raw = obj.read_range(0, len)?;
    let endian = obj.endian();
    Ok(raw
        .chunks_exact(8)
        .map(|c| {
            let b: [u8; 8] = c.try_into().expect("8 bytes");
            match endian {
                zfs_ondisk::Endian::Little => u64::from_le_bytes(b),
                zfs_ondisk::Endian::Big => u64::from_be_bytes(b),
            }
        })
        .collect())
}

/// One metaslab's space map: its header and its entries.
fn read_one(
    mos: &DnodeArray<'_, '_>,
    object: u64,
    ashift: u32,
) -> Result<(SpaceMapPhys, Vec<zfs_ondisk::spacemap::Entry>), ReadError> {
    let dnode: DnodePhys = mos.get(object)?;
    let phys = SpaceMapPhys::parse(&dnode.bonus, mos.endian())?;
    if phys.length == 0 {
        return Ok((phys, Vec::new()));
    }
    let obj = mos.object(object)?;
    // The object can be longer than the log: everything past smp_length
    // is space the map has grown into but not written.
    let want = phys.length.min(obj.logical_size()) as usize;
    let raw = obj.read_range(0, want)?;
    Ok((phys, entries(&raw, ashift, mos.endian())))
}
