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

use zfs_ondisk::blkptr::BlkPtr;
use zfs_ondisk::dmu::{ot, ObjsetPhys, ObjsetType};
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
    /// Entry name as text, with anything undecodable replaced.
    pub name: String,
    /// Entry name as the bytes on disk.
    ///
    /// A dataset with `utf8only=off` can hold a name that is not UTF-8:
    /// on Linux a file name is any byte string without `/` or NUL. The
    /// name is given back from these bytes, not from [`DirEntry::name`],
    /// so a file comes out called what it was called (Z-09).
    pub raw: Vec<u8>,
    /// Object number it points at.
    pub object: u64,
    /// Type from the entry itself, which may be unknown on an old
    /// directory; the znode's mode is the authority.
    pub file_type: FileType,
}

/// A Unicode normalization a dataset matches names under (Z-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Normalization {
    /// `formD`: canonical decomposition.
    D,
    /// `formC`: canonical decomposition, then canonical composition.
    C,
    /// `formKD`: compatibility decomposition.
    KD,
    /// `formKC`: compatibility decomposition, then canonical composition.
    KC,
}

impl Normalization {
    /// Decode the `normalization` property, which is a bit set:
    /// `U8_CANON_DECOMP` 0x10, `U8_COMPAT_DECOMP` 0x20, `U8_CANON_COMP`
    /// 0x40 (`u8_textprep.h`). `None` for 0 — the property's own way of
    /// saying names are not normalized — and for any value whose bits
    /// name no form, because guessing at one would be worse than
    /// matching only what is exactly there.
    pub fn from_property(value: u64) -> Option<Normalization> {
        const CANON_DECOMP: u64 = 0x10;
        const COMPAT_DECOMP: u64 = 0x20;
        const CANON_COMP: u64 = 0x40;
        if value & CANON_DECOMP == 0 {
            return None;
        }
        Some(
            match (value & COMPAT_DECOMP != 0, value & CANON_COMP != 0) {
                (false, false) => Normalization::D,
                (false, true) => Normalization::C,
                (true, false) => Normalization::KD,
                (true, true) => Normalization::KC,
            },
        )
    }

    /// `name` in this form.
    ///
    /// The tables here are whatever version of Unicode this build was
    /// compiled against; ZFS normalizes with tables of its own, frozen
    /// long ago. For the characters anyone names a file with the two
    /// agree, and where they do not the cost is bounded by where this is
    /// used: a fallback that can turn "not found" into "found" and never
    /// a correct match into a wrong one.
    pub fn apply(self, name: &str) -> String {
        use unicode_normalization::UnicodeNormalization;
        match self {
            Normalization::D => name.nfd().collect(),
            Normalization::C => name.nfc().collect(),
            Normalization::KD => name.nfkd().collect(),
            Normalization::KC => name.nfkc().collect(),
        }
    }
}

impl DirEntry {
    /// Whether the name on disk is valid UTF-8 — that is, whether
    /// [`DirEntry::name`] gives it back exactly.
    pub fn name_is_text(&self) -> bool {
        self.name.as_bytes() == self.raw
    }
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
        let mut by_num: BTreeMap<u16, Vec<u8>> = placed.into_iter().collect();
        // Whatever did not fit the bonus buffer is in the spill block,
        // under a header and a layout of its own (Z-10).
        if d.bonus_type == ot::SA {
            if let Some(bp) = &d.spill {
                for (num, value) in self.spilled_attrs(object, bp)? {
                    by_num.entry(num).or_insert(value);
                }
            }
        }
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
        // Absent where the dataset has no `project_quota` feature, and
        // zero where it has one and nothing was set: two different
        // answers, kept apart (Z-10).
        let projid = self
            .attr_num
            .get(attr::PROJID)
            .and_then(|n| by_num.get(n))
            .and_then(|b| zpl::attr_u64(b, self.endian));
        Ok(Znode {
            dxattr,
            projid,
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

    /// The system attributes an object keeps in its spill block (Z-10).
    ///
    /// A layout that does not fit the bonus buffer is split: what fits
    /// stays in the bonus and the rest goes to the spill block, which
    /// carries a header and names a layout of its own. Usually what
    /// spills is `ZPL_DXATTR` — the one attribute large enough to push
    /// a layout over the edge — but nothing says it has to be, and a
    /// reader that looks only at the bonus loses whatever went there
    /// without noticing. That is why an unreadable spill is an error
    /// and not a warning: a file whose attributes are half-read is a
    /// wrong answer, and a refusal is not.
    fn spilled_attrs(&self, object: u64, bp: &BlkPtr) -> Result<Vec<(u16, Vec<u8>)>, ReadError> {
        if bp.is_hole() {
            return Ok(Vec::new());
        }
        let block = self
            .objects
            .meta_reader()
            .read_block(bp, false)
            .map_err(|e| ReadError::Io(format!("object {object}: spill block: {e}")))?;
        let header = parse_sa_header(&block.data, bp.endian).map_err(|e| {
            ReadError::Io(format!(
                "object {object}: its spill block is not a system-attribute buffer: {e}"
            ))
        })?;
        let layout = self.layouts.get(&header.layout).cloned().ok_or_else(|| {
            ReadError::Io(format!(
                "object {object}: spill-block layout {} is not in this dataset's layouts",
                header.layout
            ))
        })?;
        trace!(
            "zpl",
            "object {object}: spill block holds layout {} ({} attribute(s))",
            header.layout,
            layout.len()
        );
        let lengths = |n: u16| self.attr_length.get(&n).copied();
        Ok(place_attrs(
            &block.data,
            &header,
            &layout,
            &lengths,
            bp.endian,
        ))
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
                    raw: e.raw.clone(),
                    object: obj,
                    file_type: kind,
                })
            })
            .collect();
        // Directory order on disk is hash order; a report reads better,
        // and compares better between runs, in name order — by the bytes
        // rather than by the text, so two names that print alike still
        // come out in the same order every time.
        out.sort_by(|a, b| a.raw.cmp(&b.raw));
        Ok(out)
    }

    /// Resolve a slash-separated path from the root.
    pub fn lookup(&self, path: &str) -> Result<u64, ReadError> {
        self.lookup_bytes(path.as_bytes())
    }

    /// Resolve a path given as the bytes it is on disk.
    ///
    /// Three attempts, in this order, and each only when the one before
    /// it found nothing (Z-09):
    ///
    /// 1. the bytes, which always wins and is the only one that needs no
    ///    assumption about what the bytes mean;
    /// 2. case-folded, where the dataset's `casesensitivity` says names
    ///    are matched that way;
    /// 3. Unicode-normalized, where its `normalization` says so.
    ///
    /// The order is the whole design. Steps 2 and 3 read the name as
    /// text and compare it with tables — this build's tables, not the
    /// ones ZFS used — so putting either first could match the wrong
    /// entry. Behind an exact match they cannot: the worst a
    /// disagreement between the two sets of tables can do is leave a
    /// file unfound, which is what would have happened anyway.
    pub fn lookup_bytes(&self, path: &[u8]) -> Result<u64, ReadError> {
        let shown = String::from_utf8_lossy(path).into_owned();
        let mut at = self.root;
        for part in path
            .split(|&b| b == b'/')
            .filter(|p| !p.is_empty() && *p != b".")
        {
            let entries = self.read_dir(at)?;
            let found = entries
                .iter()
                .find(|e| e.raw == part)
                .or_else(|| self.matched_as_text(&entries, part))
                .ok_or_else(|| ReadError::Io(format!("{shown}: no such file or directory")))?;
            at = found.object;
        }
        Ok(at)
    }

    /// The fallbacks of [`Filesystem::lookup_bytes`]: a name read as
    /// text, folded and normalized as the dataset's properties say.
    ///
    /// Returns nothing at all for a component that is not UTF-8, because
    /// neither folding nor normalizing means anything for bytes that are
    /// not text — and such a name can only be asked for exactly.
    fn matched_as_text<'e>(&self, entries: &'e [DirEntry], part: &[u8]) -> Option<&'e DirEntry> {
        let part = std::str::from_utf8(part).ok()?;
        let fold = self.case_insensitive();
        if fold {
            let want = part.to_lowercase();
            if let Some(e) = entries.iter().find(|e| e.name.to_lowercase() == want) {
                return Some(e);
            }
        }
        let form = self.normalization()?;
        // Folding and normalizing are independent properties and a
        // dataset may have both; when it does, the last attempt applies
        // both rather than making the operator choose which one the path
        // was typed under.
        let prepare = |s: &str| {
            let s = form.apply(s);
            if fold {
                s.to_lowercase()
            } else {
                s
            }
        };
        let want = prepare(part);
        entries.iter().find(|e| prepare(&e.name) == want)
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

    /// The Unicode normalization this dataset matches names under, if
    /// any (Z-09).
    ///
    /// The property is a bit set, the one OpenZFS's `u8_textprep.h`
    /// defines: `U8_CANON_DECOMP` 0x10, `U8_COMPAT_DECOMP` 0x20,
    /// `U8_CANON_COMP` 0x40. So `formD` is 0x10, `formKD` 0x30, `formC`
    /// 0x50 and `formKC` 0x70. It is read by its bits rather than as one
    /// of four numbers, because that is how it is written.
    ///
    /// **Not verified against a pool.** `ztest` makes no dataset with
    /// `normalization` set, so nothing in this workspace's tests has
    /// ever seen one of these values on disk; the mapping comes from the
    /// header. That is the reason normalization is a *fallback* below
    /// and never the first thing tried.
    pub fn normalization(&self) -> Option<Normalization> {
        Normalization::from_property(*self.properties.get("normalization")?)
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
    /// Path from the root of the dataset, without a leading slash, as
    /// text — which is what to print, not what to write.
    pub path: String,
    /// The same path as the bytes on disk, components joined with `/`.
    ///
    /// Equal to `path` on every dataset whose names are UTF-8, and the
    /// only faithful answer on one whose names are not (Z-09).
    pub raw_path: Vec<u8>,
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

    /// Whether the path is text — whether printing it loses nothing.
    pub fn path_is_text(&self) -> bool {
        self.path.as_bytes() == self.raw_path
    }
}

/// Walk a directory tree into paths.
///
/// Depth-first and in name order, so two runs of the same evidence
/// produce the same list. An object met twice — a hard link, or a cycle
/// in damaged metadata — is reported once at each path but walked once,
/// which is what stops a loop from becoming an infinite tree.
pub fn walk(fs: &Filesystem<'_, '_>, from: u64, prefix: &str, recursive: bool) -> Vec<Entry> {
    walk_from(fs, from, prefix, prefix.as_bytes(), recursive)
}

/// Walk from a prefix whose bytes are not its text.
///
/// The two forms are carried side by side all the way down, because one
/// is what a report prints and the other is what a file is called.
pub fn walk_from(
    fs: &Filesystem<'_, '_>,
    from: u64,
    prefix: &str,
    raw_prefix: &[u8],
    recursive: bool,
) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut seen_dirs = std::collections::BTreeSet::new();
    walk_into(
        fs,
        from,
        prefix,
        raw_prefix,
        recursive,
        0,
        &mut seen_dirs,
        &mut out,
    );
    out
}

/// Join one name onto a byte path.
fn join_raw(prefix: &[u8], name: &[u8]) -> Vec<u8> {
    if prefix.is_empty() {
        return name.to_vec();
    }
    let mut out = Vec::with_capacity(prefix.len() + 1 + name.len());
    out.extend_from_slice(prefix);
    out.push(b'/');
    out.extend_from_slice(name);
    out
}

#[allow(clippy::too_many_arguments)]
fn walk_into(
    fs: &Filesystem<'_, '_>,
    object: u64,
    prefix: &str,
    raw_prefix: &[u8],
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
                raw_path: raw_prefix.to_vec(),
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
        let raw_path = join_raw(raw_prefix, &e.raw);
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
            raw_path: raw_path.clone(),
            object: e.object,
            znode,
            error,
        });
        if is_dir && recursive {
            walk_into(
                fs,
                e.object,
                &path,
                &raw_path,
                recursive,
                depth + 1,
                seen_dirs,
                out,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{
        zpl_big_dnode, zpl_big_dnode_value, zpl_deep, zpl_hello, zpl_latin1, zpl_members_with,
        zpl_spilled, zpl_spilled_value, Matching, Pool, Spill, ZPL_BIG_DNODE_TRAP,
        ZPL_BIG_DNODE_XATTR, ZPL_COMPOSED_NAME, ZPL_DECOMPOSED_NAME, ZPL_DEEP_PROJID,
        ZPL_LATIN1_NAME, ZPL_SPILLED_XATTR,
    };
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
        with_matching_fs(Matching::Exact, f);
    }

    fn with_matching_fs(matching: Matching, f: impl FnOnce(&Filesystem<'_, '_>)) {
        with_fixture(matching, Spill::Attributes, f);
    }

    fn with_fixture(matching: Matching, spill: Spill, f: impl FnOnce(&Filesystem<'_, '_>)) {
        let mut pool = Pool::mirror("tank", 0x5eed_0000_0000_0003, 12)
            .txgs(&[(4816228, 1757100000), (4816229, 1757100005)]);
        let members = zpl_members_with(&mut pool, SIZE, matching, spill);
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
            let paths: Vec<&[u8]> = entries.iter().map(|e| e.raw_path.as_slice()).collect();
            assert_eq!(
                paths,
                [
                    b"bigdnode.txt".as_slice(),
                    ZPL_LATIN1_NAME,
                    b"hardlink.txt",
                    b"hello.txt",
                    b"link",
                    b"spilled.txt",
                    b"sub",
                    b"sub/deep.txt"
                ]
            );
            assert!(entries.iter().all(|e| e.error.is_none()), "{entries:?}");
            // By name, not by position: a fixture gains files over time
            // and a test that counts from the top starts asserting about
            // whichever file happens to be there.
            let at = |path: &[u8]| {
                entries
                    .iter()
                    .find(|e| e.raw_path == path)
                    .unwrap_or_else(|| panic!("{} is in the tree", String::from_utf8_lossy(path)))
            };

            // Z-09: the one name that is not text says so, and the rest
            // do not.
            assert!(!at(ZPL_LATIN1_NAME).path_is_text());
            assert!(entries
                .iter()
                .filter(|e| e.raw_path != ZPL_LATIN1_NAME)
                .all(Entry::path_is_text));

            // Z-02: the metadata comes out of the system attributes.
            let z = at(b"hello.txt").znode.as_ref().expect("znode");
            assert_eq!(z.file_type(), FileType::Regular);
            assert_eq!(z.permissions(), 0o644);
            assert_eq!(z.size, zpl_hello().len() as u64);
            assert_eq!(z.links, 2);
            assert_eq!(z.mtime, 1_757_100_001);
            assert_eq!(z.parent, 3);

            let dir = at(b"sub").znode.as_ref().expect("znode");
            assert_eq!(dir.file_type(), FileType::Dir);
            assert_eq!(dir.permissions(), 0o755);

            // Z-03: a symlink whose target lives in the attributes.
            let link = at(b"link");
            let lz = link.znode.as_ref().expect("znode");
            assert_eq!(lz.file_type(), FileType::Symlink);
            assert_eq!(
                fs.symlink_target(link.object, lz).expect("target"),
                b"sub/deep.txt"
            );

            // Z-03: the file's own bytes, through the pool, checksums and all.
            let deep = fs.object(at(b"sub/deep.txt").object).expect("object");
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

    /// Z-09: a name that is not UTF-8 is found by its bytes, and by
    /// nothing else — the text it prints as belongs to no file.
    #[test]
    fn a_name_that_is_not_text_is_found_by_its_bytes() {
        with_fs(|fs| {
            assert_eq!(fs.lookup_bytes(ZPL_LATIN1_NAME).expect("lookup"), 10);
            let shown = String::from_utf8_lossy(ZPL_LATIN1_NAME).into_owned();
            assert!(
                fs.lookup(&shown).is_err(),
                "{shown:?} is not a name on disk"
            );
            let obj = fs.lookup_bytes(ZPL_LATIN1_NAME).expect("lookup");
            let z = fs.znode(obj).expect("znode");
            assert_eq!(z.size, zpl_latin1().len() as u64);
            let read = fs.object(obj).expect("object");
            assert_eq!(
                read.read_range(0, zpl_latin1().len()).expect("read"),
                zpl_latin1()
            );
        });
    }

    /// Z-09: a dataset that normalizes finds a composed name by its
    /// decomposed spelling, and the reverse — which is the case a macOS
    /// client and a Linux one create between them.
    #[test]
    fn a_normalizing_dataset_matches_across_the_two_spellings() {
        with_matching_fs(Matching::NormalizedFormD, |fs| {
            assert_eq!(fs.normalization(), Some(Normalization::D));
            // Exactly as stored: no normalization needed, and it wins.
            let object = fs.lookup_bytes(ZPL_COMPOSED_NAME).expect("composed");
            // The other spelling of the same name reaches the same file.
            assert_eq!(
                fs.lookup_bytes(ZPL_DECOMPOSED_NAME).expect("decomposed"),
                object
            );
            // A name that is neither is still not there.
            assert!(fs.lookup("resume.txt").is_err());
        });
    }

    /// And a dataset that does not normalize does not: the property is
    /// read, not assumed. Without this the test above would pass on a
    /// reader that normalized everything always.
    #[test]
    fn a_dataset_that_does_not_normalize_matches_only_the_bytes() {
        with_fs(|fs| {
            assert_eq!(fs.normalization(), None);
            assert_eq!(fs.lookup_bytes(ZPL_LATIN1_NAME).expect("as stored"), 10);
            // The composed fixture's name is not in this one at all, and
            // neither spelling of it may be invented.
            assert!(fs.lookup_bytes(ZPL_COMPOSED_NAME).is_err());
            assert!(fs.lookup_bytes(ZPL_DECOMPOSED_NAME).is_err());
        });
    }

    /// The property is a bit set from `u8_textprep.h`, not one of four
    /// numbers. Nothing in this workspace has seen one on a real pool,
    /// so the decoding is pinned here against the header's constants.
    #[test]
    fn the_normalization_property_is_read_by_its_bits() {
        use Normalization::*;
        for (value, want) in [
            (0x00, None),
            (0x10, Some(D)),  // U8_CANON_DECOMP
            (0x30, Some(KD)), // | U8_COMPAT_DECOMP
            (0x50, Some(C)),  // | U8_CANON_COMP
            (0x70, Some(KC)), // all three
            // No canonical decomposition bit names no form; composing
            // alone is not one of the four, and is not guessed at.
            (0x40, None),
            (0x20, None),
        ] {
            assert_eq!(Normalization::from_property(value), want, "{value:#x}");
        }
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

    /// Z-10: an attribute that did not fit the bonus buffer is in the
    /// spill block, and is read from there.
    ///
    /// The point of the fixture is that the bonus alone is a plausible
    /// answer: the ten plain attributes are all there, the file has a
    /// size and a mode and times, and nothing about it looks wrong. A
    /// reader that stops at the bonus reports a file with no extended
    /// attributes rather than a file it could not fully read.
    #[test]
    fn an_attribute_too_large_for_the_bonus_is_read_from_the_spill_block() {
        with_fs(|fs| {
            let obj = fs.lookup("spilled.txt").expect("lookup");
            let z = fs.znode(obj).expect("znode");
            // The bonus half: present, and not what is being tested.
            assert_eq!(z.size, zpl_spilled().len() as u64);
            assert_eq!(z.permissions(), 0o644);
            // The spill half.
            let xattrs = fs.xattrs(&z);
            let names: Vec<&str> = xattrs.iter().map(|(n, _)| n.as_str()).collect();
            assert_eq!(names, [ZPL_SPILLED_XATTR]);
            assert_eq!(xattrs[0].1, zpl_spilled_value());
            assert!(
                xattrs[0].1.len() > 512,
                "the value has to be one no bonus buffer could hold"
            );
        });
    }

    /// Z-10: a project id is read where the dataset keeps one, and its
    /// absence is not reported as project zero.
    #[test]
    fn a_project_id_is_read_where_there_is_one_and_not_invented_where_there_is_not() {
        with_fs(|fs| {
            let deep = fs.lookup("sub/deep.txt").expect("lookup");
            assert_eq!(fs.znode(deep).expect("znode").projid, Some(ZPL_DEEP_PROJID));
            // The other files are in a layout that has no project id.
            // A dataset without the feature has none either, and zero is
            // a project a file can really be in — so the two must not be
            // reported as the same thing.
            let plain = fs.lookup("hello.txt").expect("lookup");
            assert_eq!(fs.znode(plain).expect("znode").projid, None);
        });
    }

    /// Z-10: a spill block that cannot be read says so, rather than
    /// handing back the half of the attributes that survived.
    ///
    /// The distinction this test exists for: the file's bonus is
    /// intact, so a reader could return a perfectly plausible znode
    /// with no extended attributes at all. The dnode says an attribute
    /// lives in the spill block; unreadable is not absent.
    #[test]
    fn a_spill_block_that_is_not_attributes_is_refused_not_ignored() {
        with_fixture(Matching::Exact, Spill::Unreadable, |fs| {
            let obj = fs.lookup("spilled.txt").expect("lookup");
            let e = fs
                .znode(obj)
                .expect_err("a half-read object is not an answer");
            let said = e.to_string();
            assert!(said.contains("spill block"), "{said}");
            // The file that spills is the only one affected: everything
            // else in the dataset still reads.
            let other = fs.lookup("hello.txt").expect("lookup");
            assert_eq!(
                fs.znode(other).expect("znode").size,
                zpl_hello().len() as u64
            );
        });
    }

    /// Z-10: a dnode that owns two slots is read across both of them.
    #[test]
    fn a_large_dnode_is_read_across_the_slots_it_owns() {
        with_fs(|fs| {
            let obj = fs.lookup("bigdnode.txt").expect("lookup");
            let d = fs.objects.get(obj).expect("dnode");
            assert_eq!(d.extra_slots, 1, "the fixture object is two slots wide");
            assert!(
                d.bonus.len() > 512 - 64 - 128,
                "its bonus does not fit one slot"
            );
            let z = fs.znode(obj).expect("znode");
            assert_eq!(z.size, zpl_big_dnode().len() as u64);
            let xattrs = fs.xattrs(&z);
            assert_eq!(
                xattrs.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
                [ZPL_BIG_DNODE_XATTR]
            );
            assert_eq!(xattrs[0].1.len(), zpl_big_dnode_value().len());
            assert!(
                xattrs[0]
                    .1
                    .windows(ZPL_BIG_DNODE_TRAP.len())
                    .any(|w| w == ZPL_BIG_DNODE_TRAP),
                "the attribute carries the bytes planted in the second slot"
            );
            // And the slot it swallowed is not an object of its own.
            // This one parses as a dnode — those bytes are part of the
            // attribute above — so a walk that stepped by one would not
            // fail, it would report an object that was never there.
            let planted = fs.objects.get(obj + 1).expect("the trap parses");
            assert!(!planted.is_free(), "and looks like a live object");
            assert_eq!(fs.objects.next_object(obj), obj + 2);
            let plain = fs.lookup("hello.txt").expect("lookup");
            assert_eq!(fs.objects.next_object(plain), plain + 1);
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
            assert_eq!(
                paths,
                [
                    "bigdnode.txt",
                    "caf\u{fffd}.txt",
                    "hardlink.txt",
                    "hello.txt",
                    "link",
                    "spilled.txt",
                    "sub"
                ]
            );
        });
    }
}
