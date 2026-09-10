//! Walking the Meta Object Set into a dataset tree.
//!
//! Path: uberblock root pointer → MOS objset → dnode array → object 1
//! (the object directory ZAP) → `root_dataset` → DSL directory → children
//! ZAP and head dataset → recurse. Each head dataset's objset block gives
//! its type (filesystem / volume) and each dataset's `snapnames` ZAP gives
//! its snapshots.

use std::collections::BTreeSet;

use zfs_ondisk::dmu::{ObjsetPhys, ObjsetType, OT_NEWTYPE};
use zfs_ondisk::dsl::{DslDatasetPhys, DslDirPhys};
use zfs_ondisk::uberblock::Uberblock;
use zfs_ondisk::zap::Value;
use zfs_ondisk::Endian;

use crate::dmu::{DnodeArray, ObjectReader};
use crate::zap::read_zap;
use crate::zio::{PoolReader, ReadError};
use zvolrescue_io::trace;

/// MOS object number of the object directory.
pub const OBJECT_DIRECTORY: u64 = 1;
/// Object-directory entry holding the pool checksum salt (`DMU_POOL_CHECKSUM_SALT`).
pub const CHECKSUM_SALT: &str = "org.illumos:checksum_salt";
/// Object number of the data object inside a zvol objset (`ZVOL_OBJ`).
pub const ZVOL_OBJ: u64 = 1;
/// Object number of the properties ZAP inside a zvol objset (`ZVOL_ZAP_OBJ`).
pub const ZVOL_ZAP_OBJ: u64 = 2;
/// Recursion bound on DSL directory depth.
pub const MAX_DEPTH: usize = 64;

/// ZAP attribute of a zapified DSL directory naming its DSL crypto key
/// object (`DD_FIELD_CRYPTO_KEY_OBJ`).
pub const CRYPTO_KEY_OBJ: &str = "com.datto:crypto_key_obj";

/// What an encrypted dataset's on-disk metadata says about its key,
/// read without any key: the DSL crypto key ZAP (`dsl_crypt.h`) of the
/// dataset's directory plus the key properties of its encryption root.
/// Wrapped keys, IV and MAC are kept for the unwrap step of phase 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encryption {
    /// MOS object of the DSL crypto key ZAP.
    pub crypto_key_obj: u64,
    /// `DSL_CRYPTO_SUITE`: `ZIO_CRYPT_*` code (3..=5 AES-CCM, 6..=8 AES-GCM).
    pub suite: u64,
    /// `DSL_CRYPTO_GUID`: identifies the key (shared by clones).
    pub key_guid: u64,
    /// `DSL_CRYPTO_VERSION` (absent on the initial on-disk format = 0).
    pub key_version: u64,
    /// `DSL_CRYPTO_ROOT_DDOBJ`: directory of the encryption root, which
    /// holds the key properties below.
    pub root_ddobj: u64,
    /// `keyformat`, stored in the crypto key ZAP: 1 raw, 2 hex, 3 passphrase.
    pub keyformat: Option<u64>,
    /// `keylocation` property of the encryption root (`prompt` or a
    /// `file://` URI); the one value that lives in the directory's props ZAP.
    pub keylocation: Option<String>,
    /// `pbkdf2iters` (passphrase keys), from the crypto key ZAP.
    pub pbkdf2_iters: Option<u64>,
    /// `pbkdf2salt` (passphrase keys), the 64-bit salt as stored in the
    /// crypto key ZAP.
    pub pbkdf2_salt: Option<u64>,
    /// `DSL_CRYPTO_IV` (12 bytes) used to wrap the keys.
    pub iv: Vec<u8>,
    /// `DSL_CRYPTO_MAC` (16 bytes) of the wrapped keys.
    pub mac: Vec<u8>,
    /// `DSL_CRYPTO_MASTER_KEY_1`: the wrapped master key.
    pub wrapped_master_key: Vec<u8>,
    /// `DSL_CRYPTO_HMAC_KEY_1`: the wrapped HMAC key (64 bytes).
    pub wrapped_hmac_key: Vec<u8>,
}

impl Encryption {
    /// `zio_crypt_table` name of the suite.
    pub fn suite_name(&self) -> String {
        match self.suite {
            3 => "aes-128-ccm".into(),
            4 => "aes-192-ccm".into(),
            5 => "aes-256-ccm".into(),
            6 => "aes-128-gcm".into(),
            7 => "aes-192-gcm".into(),
            8 => "aes-256-gcm".into(),
            other => format!("suite-{other}"),
        }
    }

    /// `keyformat` property name.
    pub fn keyformat_name(&self) -> String {
        match self.keyformat {
            Some(1) => "raw".into(),
            Some(2) => "hex".into(),
            Some(3) => "passphrase".into(),
            Some(other) => format!("keyformat-{other}"),
            None => "?".into(),
        }
    }
}

/// Read the encryption facts of DSL directory `dir_obj`, or `None` when
/// the directory is not zapified or carries no crypto key object (an
/// unencrypted dataset).
pub fn read_encryption(
    mos: &DnodeArray<'_, '_>,
    dir_obj: u64,
) -> Result<Option<Encryption>, ReadError> {
    let dn = mos.get(dir_obj)?;
    // dmu_object_zapify() turns the directory dnode into a ZAP of type
    // DMU_OTN_ZAP_METADATA; a plain DMU_OT_DSL_DIR has no attributes.
    if dn.object_type & OT_NEWTYPE == 0 || dn.object_type & 0x1f != 4 {
        return Ok(None);
    }
    let attrs = read_zap(&mos.object(dir_obj)?)?;
    let Some(key_obj) = attrs
        .iter()
        .find(|e| e.name == CRYPTO_KEY_OBJ)
        .and_then(|e| e.value.as_u64())
    else {
        return Ok(None);
    };
    let entries = read_zap(&mos.object(key_obj)?)?;
    let u64_of = |name: &str| {
        entries
            .iter()
            .find(|e| e.name == name)
            .and_then(|e| e.value.as_u64())
    };
    let bytes_of = |name: &str| -> Vec<u8> {
        match entries.iter().find(|e| e.name == name).map(|e| &e.value) {
            Some(Value::Bytes(b)) => b.clone(),
            Some(Value::Ints { raw, .. }) => raw.clone(),
            _ => Vec::new(),
        }
    };
    let root_ddobj = u64_of("DSL_CRYPTO_ROOT_DDOBJ").unwrap_or(dir_obj);
    let mut enc = Encryption {
        crypto_key_obj: key_obj,
        suite: u64_of("DSL_CRYPTO_SUITE").unwrap_or(0),
        key_guid: u64_of("DSL_CRYPTO_GUID").unwrap_or(0),
        key_version: u64_of("DSL_CRYPTO_VERSION").unwrap_or(0),
        root_ddobj,
        keyformat: u64_of("keyformat"),
        keylocation: None,
        pbkdf2_iters: u64_of("pbkdf2iters"),
        pbkdf2_salt: u64_of("pbkdf2salt"),
        iv: bytes_of("DSL_CRYPTO_IV"),
        mac: bytes_of("DSL_CRYPTO_MAC"),
        wrapped_master_key: bytes_of("DSL_CRYPTO_MASTER_KEY_1"),
        wrapped_hmac_key: bytes_of("DSL_CRYPTO_HMAC_KEY_1"),
    };
    // keylocation is an ordinary property of the encryption root.
    let root = read_dir(mos, root_ddobj)?;
    if root.props_zapobj != 0 {
        let props = read_zap(&mos.object(root.props_zapobj)?)?;
        enc.keylocation = props
            .iter()
            .find(|e| e.name == "keylocation")
            .and_then(|e| e.value.as_str());
    }
    trace!(
        "dsl",
        "dir {dir_obj}: encrypted, crypto key obj {key_obj} suite {} ({}) guid {:#x} version {} root dir {root_ddobj} keyformat {} keylocation {:?} pbkdf2iters {:?}",
        enc.suite,
        enc.suite_name(),
        enc.key_guid,
        enc.key_version,
        enc.keyformat_name(),
        enc.keylocation,
        enc.pbkdf2_iters
    );
    Ok(Some(enc))
}

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
    /// `dd_origin_obj` of the directory: the origin snapshot, if any.
    pub origin_obj: u64,
    /// A clone: the origin is a snapshot of some other dataset.
    ///
    /// Not the same as `origin_obj != 0`. OpenZFS gives every ordinary
    /// dataset an origin as well — the pool's own hidden `$ORIGIN`
    /// snapshot — so what makes a dataset a clone is an origin that is
    /// *not* that one (`dsl_dir_is_clone`).
    pub clone: bool,
    /// MOS object of the directory's properties ZAP.
    pub props_zapobj: u64,
    /// `volsize` for volumes, from the zvol objset's properties ZAP.
    pub volsize: Option<u64>,
    /// `volblocksize` for volumes: the data object's block size.
    pub volblocksize: Option<u64>,
    /// Encryption facts when the dataset is encrypted (no key needed).
    pub encryption: Option<Encryption>,
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
    trace!(
        "dsl",
        "open MOS at txg {}: rootbp lsize {} psize {} {} {} birth {} dva0 vdev {} off {:#x}",
        ub.txg,
        rootbp.lsize,
        rootbp.psize,
        rootbp.compression.name(),
        rootbp.checksum.name(),
        rootbp.birth,
        rootbp.dva[0].vdev,
        rootbp.dva[0].offset
    );
    let block = reader.read_block(&rootbp, false)?;
    let os = ObjsetPhys::parse(&block.data, rootbp.endian)?;
    trace!(
        "dsl",
        "MOS objset: type {} meta-dnode datablksz {} nlevels {} maxblkid {}",
        os.os_type.name(),
        os.meta_dnode.datablksz(),
        os.meta_dnode.nlevels,
        os.meta_dnode.maxblkid
    );
    if os.os_type != ObjsetType::Meta {
        return Err(ReadError::Io(format!(
            "root objset is {} not meta",
            os.os_type.name()
        )));
    }
    let mos = DnodeArray::new(reader, os.meta_dnode, rootbp.endian);
    // The salt lives in the object directory, which is never itself
    // salted-checksummed; load it before anything else is read.
    match mos.object(OBJECT_DIRECTORY).and_then(|o| read_zap(&o)) {
        Ok(entries) => {
            let salt = entries
                .iter()
                .find(|e| e.name == CHECKSUM_SALT)
                .and_then(|e| match &e.value {
                    Value::Bytes(b) if b.len() == 32 => {
                        let mut s = [0u8; 32];
                        s.copy_from_slice(b);
                        Some(s)
                    }
                    _ => None,
                });
            trace!(
                "dsl",
                "checksum salt: {}",
                if salt.is_some() { "present" } else { "absent" }
            );
            reader.set_salt(salt);
        }
        Err(e) => trace!(
            "dsl",
            "object directory unreadable while looking for the checksum salt: {e}"
        ),
    }
    Ok(mos)
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
    trace!(
        "dsl",
        "object directory: {}",
        dir.iter()
            .map(|(n, v)| format!("{n}={v}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let root = dir
        .iter()
        .find(|(n, _)| n == "root_dataset")
        .map(|(_, v)| *v)
        .ok_or_else(|| ReadError::Io("object directory has no root_dataset".into()))?;
    let mut tree = DatasetTree {
        pool_name: pool_name.to_string(),
        ..Default::default()
    };
    let origin_snap = origin_snapshot(mos, root);
    trace!("dsl", "$ORIGIN snapshot object: {origin_snap}");
    let mut seen = BTreeSet::new();
    walk_dir(mos, root, pool_name, 0, origin_snap, &mut tree, &mut seen);
    Ok(tree)
}

/// The object of `$ORIGIN@$ORIGIN`, the snapshot every dataset that is
/// not a clone descends from, or 0 when the pool has none.
///
/// It lives in a directory the walk skips (`$`-prefixed names are MOS
/// bookkeeping, not datasets), but its object number is what separates a
/// clone from an ordinary dataset, so it is looked up once per walk. A
/// pool that predates the mechanism simply has no `$ORIGIN`; then every
/// non-zero origin is a real one.
fn origin_snapshot(mos: &DnodeArray<'_, '_>, root_dir_obj: u64) -> u64 {
    let Ok(root) = read_dir(mos, root_dir_obj) else {
        return 0;
    };
    if root.child_dir_zapobj == 0 {
        return 0;
    }
    let Ok(children) = mos.object(root.child_dir_zapobj).and_then(|o| read_zap(&o)) else {
        return 0;
    };
    let Some(dir_obj) = children
        .iter()
        .find(|e| e.name == "$ORIGIN")
        .and_then(|e| e.value.as_u64())
    else {
        return 0;
    };
    let Ok(dir) = read_dir(mos, dir_obj) else {
        return 0;
    };
    if dir.head_dataset_obj == 0 {
        return 0;
    }
    read_dataset(mos, dir.head_dataset_obj).map_or(0, |d| d.prev_snap_obj)
}

fn walk_dir(
    mos: &DnodeArray<'_, '_>,
    dir_obj: u64,
    name: &str,
    depth: usize,
    origin_snap: u64,
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
            trace!("dsl", "dir {dir_obj} ({name}): unreadable: {e}");
            tree.errors
                .push(format!("{name}: DSL directory {dir_obj}: {e}"));
            return;
        }
    };
    trace!(
        "dsl",
        "dir {dir_obj} ({name}): head {} children zap {} props zap {} origin {} parent {}",
        dir.head_dataset_obj,
        dir.child_dir_zapobj,
        dir.props_zapobj,
        dir.origin_obj,
        dir.parent_obj
    );
    if dir.head_dataset_obj != 0 {
        match describe(mos, dir.head_dataset_obj, name, &dir, origin_snap) {
            Ok(mut head) => {
                let snaps = snapshots(mos, &head, name, origin_snap);
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
        walk_dir(mos, obj, &child_name, depth + 1, origin_snap, tree, seen);
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
    origin_snap: u64,
) -> Result<Dataset, ReadError> {
    let phys = read_dataset(mos, obj)?;
    trace!(
        "dsl",
        "dataset {obj} ({name}): guid {:#x} creation txg {} snapnames {} prev {} next {} bp {}",
        phys.guid,
        phys.creation_txg,
        phys.snapnames_zapobj,
        phys.prev_snap_obj,
        phys.next_snap_obj,
        if phys.bp.is_hole() {
            "HOLE".to_string()
        } else {
            format!(
                "vdev {} off {:#x} birth {}",
                phys.bp.dva[0].vdev, phys.bp.dva[0].offset, phys.bp.birth
            )
        }
    );
    let mut warnings = Vec::new();
    let mut volsize = None;
    let mut volblocksize = None;
    let encryption = match read_encryption(mos, phys.dir_obj) {
        Ok(e) => e,
        Err(e) => {
            warnings.push(format!("encryption metadata: {e}"));
            None
        }
    };
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
        clone: dir.origin_obj != 0 && dir.origin_obj != origin_snap,
        props_zapobj: dir.props_zapobj,
        volsize,
        volblocksize,
        encryption,
        phys,
        warnings,
    })
}

fn snapshots(
    mos: &DnodeArray<'_, '_>,
    head: &Dataset,
    name: &str,
    origin_snap: u64,
) -> Vec<Dataset> {
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
        if let Ok(mut d) = describe(mos, obj, &snap_name, &dir, origin_snap) {
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
    use crate::fixture::{build_sample_mos, destroyed_zvol_members, Alloc, Pool};
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

    #[test]
    fn destroyed_volume_is_gone_at_newest_txg_but_present_before() {
        let mut pool = Pool::mirror("tank", 0x4343, 12).txgs(&[(100, 1), (101, 2), (102, 3)]);
        let (members, destroyed_at, last_with) = destroyed_zvol_members(&mut pool, SIZE);
        assert_eq!((destroyed_at, last_with), (102, 101));
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
        let assembly = assemble(&scans).into_iter().next().unwrap();
        let candidates = crate::pool::uberblock_candidates(&scans, &assembly);
        assert_eq!(
            candidates.iter().map(|c| c.ub.txg).collect::<Vec<_>>(),
            vec![102, 101, 100]
        );
        let reader = PoolReader::new(
            &assembly,
            vec![
                Some(&sources[0] as &dyn BlockSource),
                Some(&sources[1] as &dyn BlockSource),
            ],
        );
        let at = |txg: u64| {
            let c = crate::pool::select_uberblock(&candidates, crate::pool::TxgSelect::Exact(txg))
                .unwrap();
            walk(&open_mos(&reader, &c.ub).unwrap(), "tank").unwrap()
        };
        let newest = at(102);
        assert!(newest.get("tank/vm/disk0").is_none());
        assert_eq!(newest.datasets.len(), 2);
        let older = at(101);
        assert!(older.get("tank/vm/disk0").is_some());
        assert!(older.get("tank/vm/disk0@before").is_some());
        assert_eq!(at(100).datasets.len(), 4);
    }

    #[test]
    fn salted_pool_reads_blake3_volume_after_salt_lookup() {
        use crate::zvol::{extract, open_volume, OnError};
        use zvolrescue_io::MemSink;
        let mut pool = Pool::mirror("tank", 0x5a17, 12).txgs(&[(100, 1)]);
        let mut members = vec![vec![0u8; SIZE as usize]];
        let mut a = Alloc::new(0x20_0000);
        a.salt = Some([0x42u8; 32]);
        build_sample_mos(&mut pool, &mut members, &mut a);
        pool.write_labels(0, &mut members[0]);
        let src = MemSource::new(members.remove(0));
        let scans = vec![scan_device(&src).ok()];
        let ub = scans[0].as_ref().unwrap().labels[0]
            .best()
            .unwrap()
            .ub
            .clone();
        let assembly = assemble(&scans).into_iter().next().unwrap();
        let reader = PoolReader::new(&assembly, vec![Some(&src as &dyn BlockSource)]);
        assert!(reader.salt().is_none());
        let mos = open_mos(&reader, &ub).unwrap();
        assert_eq!(reader.salt(), Some([0x42u8; 32]));
        let tree = walk(&mos, "tank").unwrap();
        let ds = tree.get("tank/vm/disk0").unwrap();
        let (obj, _) = open_volume(&reader, ds).unwrap();
        let mut sink = MemSink::default();
        let r = extract(
            &obj,
            ds.volsize.unwrap(),
            &mut sink,
            OnError::Abort,
            |_, _| {},
        )
        .unwrap();
        assert_eq!(
            r.sha256,
            "d6d58af862ec2761bf43158f7ee2b2b0f4628fa6ca8095544493f9d698d7b80d"
        );
        // Without the salt the same blocks cannot be verified.
        reader.set_salt(None);
        let mut sink = MemSink::default();
        let r = extract(
            &obj,
            ds.volsize.unwrap(),
            &mut sink,
            OnError::Abort,
            |_, _| {},
        )
        .unwrap();
        assert!(r.aborted);
        assert!(r.bad[0].reason.contains("checksum algorithm not supported"));
    }
}
