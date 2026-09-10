//! Reading a filesystem dataset as files and directories (COMPANIONS
//! Z-01…Z-03, Z-08).
//!
//! The main binary treats a filesystem dataset as an object dump at
//! most. This module knows the ZFS POSIX layer: it opens the objset,
//! reads the master node, learns how the dataset encodes system
//! attributes, and walks directories into paths.
//!
//! Everything it reads goes through `PoolReader`, so every block is
//! verified by its checksum and decrypted where a key was installed,
//! exactly as anywhere else in this workspace.

use std::collections::BTreeMap;

use zfs_ondisk::dmu::{ObjsetPhys, ObjsetType};
use zfs_ondisk::zap::Value;
use zfs_ondisk::zpl::{
    self, attr, dirent, parse_sa_header, parse_znode_phys, place_attrs, FileType, RegisteredAttr,
    Znode, MASTER_NODE_OBJ, OT_ZNODE,
};
use zfs_ondisk::Endian;
use zvolrescue_io::trace;

use crate::dmu::{DnodeArray, ObjectReader};
use crate::dsl::Dataset;

use crate::zap::read_zap;
use crate::zio::{PoolReader, ReadError};

/// How deep a directory walk will go before it decides the tree is not
/// one. ZFS allows far more; a carve of damaged metadata does not.
const MAX_DEPTH: usize = 64;

/// A dataset opened as a filesystem.
pub struct Filesystem<'r, 'a> {
    /// Every object of the dataset.
    pub objects: DnodeArray<'r, 'a>,
    /// Byte order of the objset.
    pub endian: Endian,
    /// Root directory object, from the master node.
    pub root: u64,
    /// `casesensitivity`, `normalization` and `utf8only` as the master
    /// node records them (Z-09 reports them; matching is caller's).
    pub properties: BTreeMap<String, u64>,
    /// Fixed length of each registered attribute number, 0 = variable.
    attr_length: BTreeMap<u16, u16>,
    /// Attribute number of each name this reader looks for.
    attr_num: BTreeMap<String, u16>,
    /// Ordered attribute numbers of each layout.
    layouts: BTreeMap<u16, Vec<u16>>,
}

/// One entry of a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Entry name, as stored.
    pub name: String,
    /// Object number it points at.
    pub object: u64,
    /// Type from the entry itself, which may be unknown on an old
    /// directory; the znode's mode is the authority.
    pub file_type: FileType,
}

/// Open a filesystem dataset.
pub fn open_filesystem<'r, 'a>(
    reader: &'r PoolReader<'a>,
    ds: &Dataset,
) -> Result<Filesystem<'r, 'a>, ReadError> {
    if ds.phys.bp.is_hole() {
        return Err(ReadError::Hole);
    }
    let block = reader.read_block(&ds.phys.bp, false)?;
    let os = ObjsetPhys::parse(&block.data, ds.phys.bp.endian)?;
    if os.os_type != ObjsetType::Zfs {
        return Err(ReadError::Io(format!(
            "{} is a {}, not a filesystem",
            ds.name,
            os.os_type.name()
        )));
    }
    let endian = ds.phys.bp.endian;
    let objects = DnodeArray::new(reader, os.meta_dnode, endian);

    // The master node names everything else in the dataset.
    let master = read_zap(&objects.object(MASTER_NODE_OBJ)?)?;
    let named = |n: &str| {
        master
            .iter()
            .find(|e| e.name == n)
            .and_then(|e| e.value.as_u64())
    };
    let root = named("ROOT")
        .ok_or_else(|| ReadError::Io(format!("{}: master node has no ROOT directory", ds.name)))?;
    let mut properties = BTreeMap::new();
    for p in ["VERSION", "casesensitivity", "normalization", "utf8only"] {
        if let Some(v) = named(p) {
            properties.insert(p.to_string(), v);
        }
    }
    trace!(
        "zpl",
        "{}: root directory object {root}, {} master-node entries",
        ds.name,
        master.len()
    );

    // System attributes: two ZAPs, one saying what each attribute is and
    // one saying which attributes each layout holds, in order.
    let mut attr_length = BTreeMap::new();
    let mut attr_num = BTreeMap::new();
    let mut layouts = BTreeMap::new();
    if let Some(sa) = named("SA_ATTRS") {
        match read_zap(&objects.object(sa)?) {
            Ok(entries) => {
                let sub = |n: &str| {
                    entries
                        .iter()
                        .find(|e| e.name == n)
                        .and_then(|e| e.value.as_u64())
                };
                if let Some(reg) = sub("REGISTRY") {
                    for e in read_zap(&objects.object(reg)?)?.iter() {
                        let Some(v) = e.value.as_u64() else { continue };
                        let RegisteredAttr { num, length } = zpl::registered_attr(v);
                        attr_length.insert(num, length);
                        attr_num.insert(e.name.clone(), num);
                    }
                }
                if let Some(lay) = sub("LAYOUTS") {
                    for e in read_zap(&objects.object(lay)?)?.iter() {
                        let Ok(n) = e.name.parse::<u16>() else {
                            continue;
                        };
                        layouts.insert(n, layout_numbers(&e.value));
                    }
                }
            }
            Err(e) => {
                // A dataset whose SA metadata is gone can still be read
                // through legacy znodes, so this is not fatal.
                trace!("zpl", "{}: SA_ATTRS unreadable: {e}", ds.name);
            }
        }
    }
    trace!(
        "zpl",
        "{}: {} registered attribute(s), {} layout(s)",
        ds.name,
        attr_length.len(),
        layouts.len()
    );

    Ok(Filesystem {
        objects,
        endian,
        root,
        properties,
        attr_length,
        attr_num,
        layouts,
    })
}

/// A layout ZAP entry: an array of 16-bit attribute numbers.
fn layout_numbers(value: &Value) -> Vec<u16> {
    match value {
        Value::Ints { intlen: 2, raw } => raw
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect(),
        Value::U64Array(a) => a.iter().map(|v| *v as u16).collect(),
        Value::U64(v) => vec![*v as u16],
        _ => Vec::new(),
    }
}

impl Filesystem<'_, '_> {
    /// The metadata of one object (Z-02).
    ///
    /// System attributes first, since that is what any pool made this
    /// decade writes; a legacy `znode_phys_t` bonus is read as one when
    /// the buffer does not carry the system-attribute magic.
    pub fn znode(&self, object: u64) -> Result<Znode, ReadError> {
        let d = self.objects.get(object)?;
        if d.is_free() {
            return Err(ReadError::Io(format!("object {object} is free")));
        }
        if d.bonus_type == OT_ZNODE {
            return Ok(parse_znode_phys(&d.bonus, self.endian)?);
        }
        let header = parse_sa_header(&d.bonus, self.endian)?;
        let layout = self.layouts.get(&header.layout).cloned().ok_or_else(|| {
            ReadError::Io(format!(
                "object {object}: system-attribute layout {} is not in this dataset's layouts",
                header.layout
            ))
        })?;
        let lengths = |n: u16| self.attr_length.get(&n).copied();
        let placed = place_attrs(&d.bonus, &header, &layout, &lengths, self.endian);
        let by_num: BTreeMap<u16, Vec<u8>> = placed.into_iter().collect();
        let word = |name: &str| -> u64 {
            self.attr_num
                .get(name)
                .and_then(|n| by_num.get(n))
                .and_then(|b| zpl::attr_u64(b, self.endian))
                .unwrap_or(0)
        };
        let symlink = self
            .attr_num
            .get(attr::SYMLINK)
            .and_then(|n| by_num.get(n))
            .filter(|b| !b.is_empty())
            .cloned();
        let dxattr = self
            .attr_num
            .get(attr::DXATTR)
            .and_then(|n| by_num.get(n))
            .filter(|b| !b.is_empty())
            .cloned();
        Ok(Znode {
            dxattr,
            mode: word(attr::MODE),
            size: word(attr::SIZE),
            links: word(attr::LINKS),
            uid: word(attr::UID),
            gid: word(attr::GID),
            atime: word(attr::ATIME),
            mtime: word(attr::MTIME),
            ctime: word(attr::CTIME),
            crtime: word(attr::CRTIME),
            xattr: word(attr::XATTR),
            rdev: word(attr::RDEV),
            parent: word(attr::PARENT),
            symlink,
        })
    }

    /// The entries of one directory (Z-01).
    pub fn read_dir(&self, object: u64) -> Result<Vec<DirEntry>, ReadError> {
        let entries = read_zap(&self.objects.object(object)?)?;
        let mut out: Vec<DirEntry> = entries
            .iter()
            .filter_map(|e| {
                let v = e.value.as_u64()?;
                let (obj, kind) = dirent(v);
                (obj != 0).then(|| DirEntry {
                    name: e.name.clone(),
                    object: obj,
                    file_type: kind,
                })
            })
            .collect();
        // Directory order on disk is hash order; a report reads better,
        // and compares better between runs, in name order.
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Resolve a slash-separated path from the root.
    ///
    /// An exact match always wins. Only where the dataset says names are
    /// matched without regard to case does a case-folded match count,
    /// and then only when nothing matched exactly (Z-09).
    pub fn lookup(&self, path: &str) -> Result<u64, ReadError> {
        let mut at = self.root;
        for part in path.split('/').filter(|p| !p.is_empty() && *p != ".") {
            let entries = self.read_dir(at)?;
            let found = entries
                .iter()
                .find(|e| e.name == part)
                .or_else(|| {
                    self.case_insensitive()
                        .then(|| entries.iter().find(|e| e.name.eq_ignore_ascii_case(part)))?
                })
                .ok_or_else(|| ReadError::Io(format!("{path}: no such file or directory")))?;
            at = found.object;
        }
        Ok(at)
    }

    /// An object's contents as a reader.
    pub fn object(&self, object: u64) -> Result<ObjectReader<'_, '_>, ReadError> {
        self.objects.object(object)
    }

    /// The extended attributes of one object (Z-04).
    ///
    /// Two places, and both are looked in. `xattr=sa` packs them into
    /// the system attributes as an nvlist, which is where a small
    /// attribute lives on any modern pool. `xattr=on` gives the object
    /// its own hidden directory, whose entries are the attribute names
    /// and whose objects hold the values; that form survives attributes
    /// too large for a bonus buffer.
    pub fn xattrs(&self, z: &Znode) -> Vec<(String, Vec<u8>)> {
        let mut out: Vec<(String, Vec<u8>)> = Vec::new();
        if let Some(packed) = &z.dxattr {
            match zfs_ondisk::nvlist::parse_packed(packed) {
                Ok(nv) => {
                    for (name, value) in &nv.pairs {
                        let bytes = match value {
                            zfs_ondisk::nvlist::Value::Bytes(b) => b.clone(),
                            other => format!("{other:?}").into_bytes(),
                        };
                        out.push((name.to_string(), bytes));
                    }
                }
                Err(e) => trace!("zpl", "packed xattrs unreadable: {e}"),
            }
        }
        if z.xattr != 0 {
            match self.read_dir(z.xattr) {
                Ok(entries) => {
                    for e in entries {
                        // The value is the object's contents; a large one
                        // is read whole because an attribute is small by
                        // construction.
                        let value = self
                            .znode(e.object)
                            .ok()
                            .and_then(|vz| {
                                let len = vz.size.min(64 * 1024) as usize;
                                self.objects.object(e.object).ok()?.read_range(0, len).ok()
                            })
                            .unwrap_or_default();
                        out.push((e.name, value));
                    }
                }
                Err(e) => trace!("zpl", "xattr directory {} unreadable: {e}", z.xattr),
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out.dedup_by(|a, b| a.0 == b.0);
        out
    }

    /// Whether names in this dataset are matched without regard to case.
    ///
    /// `casesensitivity` is 0 for sensitive, 1 for insensitive and 2 for
    /// mixed; mixed means both forms are stored, so an exact match still
    /// works and a case-folded one is the fallback (Z-09).
    pub fn case_insensitive(&self) -> bool {
        matches!(self.properties.get("casesensitivity"), Some(1 | 2))
    }

    /// The target of a symbolic link, wherever it is kept.
    ///
    /// A short target lives inside the system attributes; a longer one
    /// is the object's own data.
    pub fn symlink_target(&self, object: u64, z: &Znode) -> Result<Vec<u8>, ReadError> {
        if let Some(t) = &z.symlink {
            return Ok(t.clone());
        }
        let obj = self.objects.object(object)?;
        let len = z.size.min(4096) as usize;
        obj.read_range(0, len)
    }
}

/// One file met while walking (Z-01, Z-03).
#[derive(Debug, Clone)]
pub struct Entry {
    /// Path from the root of the dataset, without a leading slash.
    pub path: String,
    /// Object number.
    pub object: u64,
    /// Metadata, when it could be read.
    pub znode: Option<Znode>,
    /// Why the metadata could not be read.
    pub error: Option<String>,
}

impl Entry {
    /// What kind of file this is, from the znode when there is one.
    pub fn file_type(&self) -> Option<FileType> {
        self.znode.as_ref().map(Znode::file_type)
    }
}

/// Walk a directory tree into paths.
///
/// Depth-first and in name order, so two runs of the same evidence
/// produce the same list. An object met twice — a hard link, or a cycle
/// in damaged metadata — is reported once at each path but walked once,
/// which is what stops a loop from becoming an infinite tree.
pub fn walk(fs: &Filesystem<'_, '_>, from: u64, prefix: &str, recursive: bool) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut seen_dirs = std::collections::BTreeSet::new();
    walk_into(fs, from, prefix, recursive, 0, &mut seen_dirs, &mut out);
    out
}

fn walk_into(
    fs: &Filesystem<'_, '_>,
    object: u64,
    prefix: &str,
    recursive: bool,
    depth: usize,
    seen_dirs: &mut std::collections::BTreeSet<u64>,
    out: &mut Vec<Entry>,
) {
    if depth > MAX_DEPTH || !seen_dirs.insert(object) {
        return;
    }
    let entries = match fs.read_dir(object) {
        Ok(e) => e,
        Err(e) => {
            out.push(Entry {
                path: prefix.to_string(),
                object,
                znode: None,
                error: Some(format!("directory: {e}")),
            });
            return;
        }
    };
    for e in entries {
        let path = if prefix.is_empty() {
            e.name.clone()
        } else {
            format!("{prefix}/{}", e.name)
        };
        let (znode, error) = match fs.znode(e.object) {
            Ok(z) => (Some(z), None),
            Err(err) => (None, Some(err.to_string())),
        };
        let is_dir = znode
            .as_ref()
            .map(|z| z.file_type() == FileType::Dir)
            .unwrap_or(e.file_type == FileType::Dir);
        out.push(Entry {
            path: path.clone(),
            object: e.object,
            znode,
            error,
        });
        if is_dir && recursive {
            walk_into(fs, e.object, &path, recursive, depth + 1, seen_dirs, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{zpl_deep, zpl_hello, zpl_members, Pool};
    use crate::pool::{assemble, uberblock_candidates};
    use crate::vdev::scan_device;
    use zvolrescue_io::{BlockSource, MemSource};

    const SIZE: u64 = 64 * 1024 * 1024;

    /// Build the fixture, open `tank/fs`, and hand it to `f`.
    ///
    /// A callback rather than a return value: the filesystem borrows the
    /// reader, which borrows the sources, and none of them outlives the
    /// pool they were assembled from.
    fn with_fs(f: impl FnOnce(&Filesystem<'_, '_>)) {
        let mut pool = Pool::mirror("tank", 0x5eed_0000_0000_0003, 12)
            .txgs(&[(4816228, 1757100000), (4816229, 1757100005)]);
        let members = zpl_members(&mut pool, SIZE);
        let sources: Vec<MemSource> = members.into_iter().map(MemSource::new).collect();
        let scans: Vec<_> = sources
            .iter()
            .map(|s| Some(scan_device(s).expect("scan")))
            .collect();
        let pools = assemble(&scans);
        let pool = pools.into_iter().next().expect("a pool");
        let devices: Vec<Option<&dyn BlockSource>> = sources
            .iter()
            .map(|s| Some(s as &dyn BlockSource))
            .collect();
        let reader = PoolReader::new(&pool, devices);
        let ub = uberblock_candidates(&scans, &pool)
            .into_iter()
            .next()
            .expect("an uberblock")
            .ub;
        let mos = crate::dsl::open_mos(&reader, &ub).expect("mos");
        let tree = crate::dsl::walk(&mos, "tank").expect("walk");
        let ds = tree
            .datasets
            .iter()
            .find(|d| d.name == "tank/fs")
            .expect("tank/fs");
        f(&open_filesystem(&reader, ds).expect("open"));
    }

    /// The whole tree, read the way an operator would ask for it.
    #[test]
    fn a_filesystem_dataset_reads_as_files_and_directories() {
        with_fs(|fs| {
            assert_eq!(fs.properties.get("VERSION"), Some(&5));
            let entries = walk(fs, fs.root, "", true);
            let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
            assert_eq!(
                paths,
                ["hardlink.txt", "hello.txt", "link", "sub", "sub/deep.txt"]
            );
            assert!(entries.iter().all(|e| e.error.is_none()), "{entries:?}");

            // Z-02: the metadata comes out of the system attributes.
            let z = entries[1].znode.as_ref().expect("znode");
            assert_eq!(z.file_type(), FileType::Regular);
            assert_eq!(z.permissions(), 0o644);
            assert_eq!(z.size, zpl_hello().len() as u64);
            assert_eq!(z.links, 2);
            assert_eq!(z.mtime, 1_757_100_001);
            assert_eq!(z.parent, 3);

            let dir = entries[3].znode.as_ref().expect("znode");
            assert_eq!(dir.file_type(), FileType::Dir);
            assert_eq!(dir.permissions(), 0o755);

            // Z-03: a symlink whose target lives in the attributes.
            let link = &entries[2];
            let lz = link.znode.as_ref().expect("znode");
            assert_eq!(lz.file_type(), FileType::Symlink);
            assert_eq!(
                fs.symlink_target(link.object, lz).expect("target"),
                b"sub/deep.txt"
            );

            // Z-03: the file's own bytes, through the pool, checksums and all.
            let deep = fs.object(entries[4].object).expect("object");
            let want = zpl_deep();
            assert_eq!(deep.read_range(0, want.len()).expect("read"), want);
        });
    }

    /// A path is resolved from the root, and a missing one says so
    /// rather than returning something else.
    #[test]
    fn a_path_resolves_from_the_root() {
        with_fs(|fs| {
            assert_eq!(fs.lookup("sub/deep.txt").expect("lookup"), 9);
            assert_eq!(fs.lookup("/sub").expect("lookup"), 7);
            assert_eq!(fs.lookup("").expect("lookup"), fs.root);
            assert!(fs.lookup("sub/missing").is_err());
        });
    }

    /// Z-04: extended attributes, packed into the system attributes.
    #[test]
    fn extended_attributes_come_out_of_the_system_attributes() {
        with_fs(|fs| {
            let obj = fs.lookup("hello.txt").expect("lookup");
            let z = fs.znode(obj).expect("znode");
            let xattrs = fs.xattrs(&z);
            let names: Vec<&str> = xattrs.iter().map(|(n, _)| n.as_str()).collect();
            assert_eq!(names, ["user.case", "user.note"]);
            assert_eq!(xattrs[1].1, b"kept in the attributes");
            // A file without any says so by having none, not by failing.
            let plain = fs
                .znode(fs.lookup("sub/deep.txt").expect("lookup"))
                .expect("znode");
            assert!(fs.xattrs(&plain).is_empty());
        });
    }

    /// Z-07: two names for one object are one object.
    #[test]
    fn a_hard_link_is_the_same_object_under_two_names() {
        with_fs(|fs| {
            let a = fs.lookup("hello.txt").expect("lookup");
            let b = fs.lookup("hardlink.txt").expect("lookup");
            assert_eq!(a, b);
            assert_eq!(fs.znode(a).expect("znode").links, 2);
        });
    }

    /// Z-09: an exact match always wins; case folding only where the
    /// dataset says names are matched that way.
    #[test]
    fn case_folding_follows_the_dataset_property() {
        with_fs(|fs| {
            assert!(!fs.case_insensitive());
            assert!(fs.lookup("HELLO.TXT").is_err());
        });
    }

    /// One directory, not the whole tree, when that is what was asked.
    #[test]
    fn a_walk_that_is_not_recursive_stops_at_one_directory() {
        with_fs(|fs| {
            let paths: Vec<String> = walk(fs, fs.root, "", false)
                .into_iter()
                .map(|e| e.path)
                .collect();
            assert_eq!(paths, ["hardlink.txt", "hello.txt", "link", "sub"]);
        });
    }
}
