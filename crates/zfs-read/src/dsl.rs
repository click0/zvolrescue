//! Walking the Meta Object Set into a dataset tree.
//!
//! Path: uberblock root pointer → MOS objset → dnode array → object 1
//! (the object directory ZAP) → `root_dataset` → DSL directory → children
//! ZAP and head dataset → recurse. Each head dataset's objset block gives
//! its type (filesystem / volume) and each dataset's `snapnames` ZAP gives
//! its snapshots.

use std::collections::BTreeSet;

use zfs_ondisk::dmu::{ObjsetPhys, ObjsetType};
use zfs_ondisk::dsl::{DslDatasetPhys, DslDirPhys};
use zfs_ondisk::uberblock::Uberblock;
use zfs_ondisk::zap::Value;
use zfs_ondisk::Endian;

use crate::dmu::{DnodeArray, ObjectReader};
use crate::zap::read_zap;
use crate::zio::{PoolReader, ReadError};

/// MOS object number of the object directory.
pub const OBJECT_DIRECTORY: u64 = 1;
/// Object number of the data object inside a zvol objset (`ZVOL_OBJ`).
pub const ZVOL_OBJ: u64 = 1;
/// Object number of the properties ZAP inside a zvol objset (`ZVOL_ZAP_OBJ`).
pub const ZVOL_ZAP_OBJ: u64 = 2;
/// Recursion bound on DSL directory depth.
pub const MAX_DEPTH: usize = 64;

/// A dataset as seen at one TXG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dataset {
    /// Full name, e.g. `tank/vm/disk0` or `tank/vm/disk0@snap`.
    pub name: String,
    /// MOS object number of the `DMU_OT_DSL_DATASET` dnode.
    pub object: u64,
    /// MOS object number of the owning DSL directory.
    pub dir_object: u64,
    /// `ds_guid`.
    pub guid: u64,
    /// Objset type, or `None` when the objset block could not be read.
    pub kind: Option<ObjsetType>,
    /// Snapshot rather than head dataset.
    pub snapshot: bool,
    /// `ds_creation_txg`.
    pub creation_txg: u64,
    /// `ds_creation_time` (Unix seconds).
    pub creation_time: u64,
    /// `ds_referenced_bytes`.
    pub referenced_bytes: u64,
    /// `ds_prev_snap_obj`.
    pub prev_snap_obj: u64,
    /// `dd_origin_obj` of the directory: the clone origin snapshot, if any.
    pub origin_obj: u64,
    /// MOS object of the directory's properties ZAP.
    pub props_zapobj: u64,
    /// `volsize` for volumes, from the zvol objset's properties ZAP.
    pub volsize: Option<u64>,
    /// `volblocksize` for volumes: the data object's block size.
    pub volblocksize: Option<u64>,
    /// The dataset's own `dsl_dataset_phys_t`.
    pub phys: DslDatasetPhys,
    /// Problems met while describing this dataset (never fatal).
    pub warnings: Vec<String>,
}

/// Everything found in one MOS walk.
#[derive(Debug, Clone, Default)]
pub struct DatasetTree {
    /// Pool name (the root directory's name).
    pub pool_name: String,
    /// Datasets and snapshots in traversal order (parents before children,
    /// heads before their snapshots).
    pub datasets: Vec<Dataset>,
    /// Directories or datasets that could not be read, with the reason.
    pub errors: Vec<String>,
}

impl DatasetTree {
    /// Find by full name.
    pub fn get(&self, name: &str) -> Option<&Dataset> {
        self.datasets.iter().find(|d| d.name == name)
    }
}

/// Open the MOS behind `ub` and return its dnode array.
pub fn open_mos<'r, 'a>(
    reader: &'r PoolReader<'a>,
    ub: &Uberblock,
) -> Result<DnodeArray<'r, 'a>, ReadError> {
    let rootbp = zfs_ondisk::blkptr::BlkPtr::parse(&ub.rootbp, ub.endian)?;
    let block = reader.read_block(&rootbp, false)?;
    let os = ObjsetPhys::parse(&block.data, rootbp.endian)?;
    if os.os_type != ObjsetType::Meta {
        return Err(ReadError::Io(format!(
            "root objset is {} not meta",
            os.os_type.name()
        )));
    }
    Ok(DnodeArray::new(reader, os.meta_dnode, rootbp.endian))
}

/// Read the object directory of the MOS as `(name, object)` pairs.
pub fn object_directory(mos: &DnodeArray<'_, '_>) -> Result<Vec<(String, u64)>, ReadError> {
    let obj = mos.object(OBJECT_DIRECTORY)?;
    Ok(read_zap(&obj)?
        .into_iter()
        .filter_map(|e| e.value.as_u64().map(|v| (e.name, v)))
        .collect())
}

/// Walk the whole dataset tree of the pool named `pool_name` from its MOS.
pub fn walk(mos: &DnodeArray<'_, '_>, pool_name: &str) -> Result<DatasetTree, ReadError> {
    let dir = object_directory(mos)?;
    let root = dir
        .iter()
        .find(|(n, _)| n == "root_dataset")
        .map(|(_, v)| *v)
        .ok_or_else(|| ReadError::Io("object directory has no root_dataset".into()))?;
    let mut tree = DatasetTree {
        pool_name: pool_name.to_string(),
        ..Default::default()
    };
    let mut seen = BTreeSet::new();
    walk_dir(mos, root, pool_name, 0, &mut tree, &mut seen);
    Ok(tree)
}

fn walk_dir(
    mos: &DnodeArray<'_, '_>,
    dir_obj: u64,
    name: &str,
    depth: usize,
    tree: &mut DatasetTree,
    seen: &mut BTreeSet<u64>,
) {
    if depth > MAX_DEPTH || !seen.insert(dir_obj) {
        tree.errors
            .push(format!("{name}: directory {dir_obj} revisited or too deep"));
        return;
    }
    let dir = match read_dir(mos, dir_obj) {
        Ok(d) => d,
        Err(e) => {
            tree.errors
                .push(format!("{name}: DSL directory {dir_obj}: {e}"));
            return;
        }
    };
    if dir.head_dataset_obj != 0 {
        match describe(mos, dir.head_dataset_obj, name, &dir) {
            Ok(mut head) => {
                let snaps = snapshots(mos, &head, name);
                tree.datasets.push(head.clone());
                for s in snaps {
                    tree.datasets.push(s);
                }
                head.warnings.clear();
            }
            Err(e) => tree
                .errors
                .push(format!("{name}: dataset {}: {e}", dir.head_dataset_obj)),
        }
    }
    if dir.child_dir_zapobj == 0 {
        return;
    }
    let children = match mos.object(dir.child_dir_zapobj).and_then(|o| read_zap(&o)) {
        Ok(c) => c,
        Err(e) => {
            tree.errors.push(format!(
                "{name}: children ZAP {}: {e}",
                dir.child_dir_zapobj
            ));
            return;
        }
    };
    for child in children {
        let Value::U64(obj) = child.value else {
            continue;
        };
        // The MOS bookkeeping directories are not datasets.
        if child.name.starts_with('$') {
            continue;
        }
        let child_name = format!("{name}/{}", child.name);
        walk_dir(mos, obj, &child_name, depth + 1, tree, seen);
    }
}

/// Read a `dsl_dir_phys_t` from MOS object `obj`.
pub fn read_dir(mos: &DnodeArray<'_, '_>, obj: u64) -> Result<DslDirPhys, ReadError> {
    let d = mos.get(obj)?;
    Ok(DslDirPhys::parse(&d.bonus, mos.endian())?)
}

/// Read a `dsl_dataset_phys_t` from MOS object `obj`.
pub fn read_dataset(mos: &DnodeArray<'_, '_>, obj: u64) -> Result<DslDatasetPhys, ReadError> {
    let d = mos.get(obj)?;
    Ok(DslDatasetPhys::parse(&d.bonus, mos.endian())?)
}

fn describe(
    mos: &DnodeArray<'_, '_>,
    obj: u64,
    name: &str,
    dir: &DslDirPhys,
) -> Result<Dataset, ReadError> {
    let phys = read_dataset(mos, obj)?;
    let mut warnings = Vec::new();
    let mut volsize = None;
    let mut volblocksize = None;
    let kind = if phys.bp.is_hole() {
        None
    } else {
        match mos.reader().read_block(&phys.bp, false) {
            Ok(b) => match ObjsetPhys::parse(&b.data, phys.bp.endian) {
                Ok(os) => {
                    if os.os_type == ObjsetType::Zvol {
                        let objs =
                            DnodeArray::new(mos.reader(), os.meta_dnode.clone(), phys.bp.endian);
                        match objs.get(ZVOL_OBJ) {
                            Ok(d) if !d.is_free() => volblocksize = Some(d.datablksz()),
                            Ok(_) => warnings.push("zvol data object is free".into()),
                            Err(e) => warnings.push(format!("zvol data object: {e}")),
                        }
                        match objs.object(ZVOL_ZAP_OBJ).and_then(|o| read_zap(&o)) {
                            Ok(entries) => {
                                volsize = entries
                                    .iter()
                                    .find(|e| e.name == "size")
                                    .and_then(|e| e.value.as_u64());
                                if volsize.is_none() {
                                    warnings.push("zvol properties have no size".into());
                                }
                            }
                            Err(e) => warnings.push(format!("zvol properties: {e}")),
                        }
                    }
                    Some(os.os_type)
                }
                Err(e) => {
                    warnings.push(format!("objset header: {e}"));
                    None
                }
            },
            Err(e) => {
                warnings.push(format!("objset block: {e}"));
                None
            }
        }
    };
    Ok(Dataset {
        name: name.to_string(),
        object: obj,
        dir_object: phys.dir_obj,
        guid: phys.guid,
        kind,
        snapshot: phys.is_snapshot(),
        creation_txg: phys.creation_txg,
        creation_time: phys.creation_time,
        referenced_bytes: phys.referenced_bytes,
        prev_snap_obj: phys.prev_snap_obj,
        origin_obj: dir.origin_obj,
        props_zapobj: dir.props_zapobj,
        volsize,
        volblocksize,
        phys,
        warnings,
    })
}

fn snapshots(mos: &DnodeArray<'_, '_>, head: &Dataset, name: &str) -> Vec<Dataset> {
    let mut out = Vec::new();
    if head.phys.snapnames_zapobj == 0 {
        return out;
    }
    let entries = match mos
        .object(head.phys.snapnames_zapobj)
        .and_then(|o| read_zap(&o))
    {
        Ok(e) => e,
        Err(_) => return out,
    };
    let dir = DslDirPhys {
        origin_obj: head.origin_obj,
        props_zapobj: head.props_zapobj,
        ..Default::default()
    };
    for e in entries {
        let Value::U64(obj) = e.value else { continue };
        let snap_name = format!("{name}@{}", e.name);
        if let Ok(mut d) = describe(mos, obj, &snap_name, &dir) {
            d.snapshot = true;
            out.push(d);
        }
    }
    out.sort_by_key(|d| d.creation_txg);
    out
}

/// Byte order and reader access needed by the walk.
impl<'r, 'a> DnodeArray<'r, 'a> {
    /// The pool reader this array reads through.
    pub fn reader(&self) -> &'r PoolReader<'a> {
        self.meta_reader()
    }
}

/// Convenience: an [`ObjectReader`] for a MOS object by number.
pub fn mos_object<'r, 'a>(
    mos: &DnodeArray<'r, 'a>,
    obj: u64,
) -> Result<ObjectReader<'r, 'a>, ReadError> {
    mos.object(obj)
}

/// Byte order of MOS structures.
pub fn mos_endian(mos: &DnodeArray<'_, '_>) -> Endian {
    mos.endian()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{build_sample_mos, Alloc, Pool};
    use crate::pool::assemble;
    use crate::vdev::scan_device;
    use zfs_ondisk::blkptr;
    use zfs_ondisk::label::LABEL_SIZE;
    use zvolrescue_io::{BlockSource, MemSource};

    const SIZE: u64 = 64 * LABEL_SIZE;

    /// A pool whose MOS describes: tank (fs), tank/vm (fs), tank/vm/disk0
    /// (zvol) with snapshot @before, and a $MOS bookkeeping dir.
    fn build() -> (Vec<MemSource>, crate::pool::PoolAssembly, Uberblock) {
        let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
        let mut members = vec![vec![0u8; SIZE as usize]];
        let mut a = Alloc::new(0x20_0000);
        build_sample_mos(&mut pool, &mut members, &mut a);
        pool.write_labels(0, &mut members[0]);
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
        let ub = scans[0].as_ref().unwrap().labels[0]
            .best()
            .unwrap()
            .ub
            .clone();
        let assembly = assemble(&scans).into_iter().next().unwrap();
        (sources, assembly, ub)
    }

    #[test]
    fn walks_the_dataset_tree() {
        let (s, a, ub) = build();
        let dyns: Vec<Option<&dyn BlockSource>> =
            s.iter().map(|x| Some(x as &dyn BlockSource)).collect();
        let reader = PoolReader::new(&a, dyns);
        let mos = open_mos(&reader, &ub).unwrap();
        let dir = object_directory(&mos).unwrap();
        assert!(dir.contains(&("root_dataset".to_string(), 2)));
        let tree = walk(&mos, "tank").unwrap();
        assert!(tree.errors.is_empty(), "{:?}", tree.errors);
        let names: Vec<&str> = tree.datasets.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["tank", "tank/vm", "tank/vm/disk0", "tank/vm/disk0@before"]
        );
        let disk0 = tree.get("tank/vm/disk0").unwrap();
        assert_eq!(disk0.kind, Some(ObjsetType::Zvol));
        assert_eq!(disk0.creation_txg, 30);
        assert_eq!(disk0.guid, 0xa3);
        assert!(!disk0.snapshot);
        assert_eq!(disk0.volsize, Some(32 << 20));
        assert_eq!(disk0.volblocksize, Some(8192));
        assert_eq!(tree.get("tank/vm").unwrap().volsize, None);
        let snap = tree.get("tank/vm/disk0@before").unwrap();
        assert!(snap.snapshot);
        assert_eq!(snap.creation_txg, 25);
        assert_eq!(tree.get("tank").unwrap().kind, Some(ObjsetType::Zfs));
        assert!(tree.datasets.iter().all(|d| d.warnings.is_empty()));
    }

    fn reader_for<'a>(s: &'a MemSource, a: &crate::pool::PoolAssembly) -> PoolReader<'a> {
        PoolReader::new(a, vec![Some(s as &dyn BlockSource)])
    }

    #[test]
    fn damaged_objset_blocks_leave_datasets_untyped() {
        let (s, a, ub) = build();
        // The first allocation is the filesystem objset block shared by
        // tank and tank/vm; the zvol's objset comes later and stays intact.
        let mut img = s[0].clone();
        let off = (blkptr::LABEL_START_SIZE + 0x20_0000) as usize;
        for b in img.bytes_mut()[off..off + 4096].iter_mut() {
            *b ^= 0x55;
        }
        let reader = reader_for(&img, &a);
        let mos = open_mos(&reader, &ub).unwrap();
        let tree = walk(&mos, "tank").unwrap();
        assert_eq!(tree.datasets.len(), 4);
        for name in ["tank", "tank/vm"] {
            let d = tree.get(name).unwrap();
            assert!(d.kind.is_none());
            assert!(d.warnings.iter().any(|w| w.contains("objset block")));
        }
        assert_eq!(
            tree.get("tank/vm/disk0").unwrap().kind,
            Some(ObjsetType::Zvol)
        );
    }

    #[test]
    fn damaged_dnode_block_fails_the_walk_not_the_process() {
        let (s, a, ub) = build();
        let reader = reader_for(&s[0], &a);
        // Find the MOS dnode block through the root pointer.
        let rootbp = blkptr::BlkPtr::parse(&ub.rootbp, ub.endian).unwrap();
        let os = ObjsetPhys::parse(
            &reader.read_block(&rootbp, false).unwrap().data,
            rootbp.endian,
        )
        .unwrap();
        let dnode_off = os.meta_dnode.blkptr[0].dva[0].offset;
        let mut img = s[0].clone();
        let off = (blkptr::LABEL_START_SIZE + dnode_off) as usize;
        img.bytes_mut()[off + 100] ^= 0xff;
        let reader = reader_for(&img, &a);
        let mos = open_mos(&reader, &ub).unwrap();
        assert_eq!(walk(&mos, "tank").unwrap_err(), ReadError::AllCopiesBad);
    }
}
