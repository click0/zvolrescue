//! The ZFS POSIX layer: directories, znodes and system attributes
//! (COMPANIONS Z-01…Z-03).
//!
//! A filesystem dataset's objset holds one ZAP — the master node — that
//! names the root directory and the object holding the system-attribute
//! registry. Directories are ZAPs whose values pack an object number and
//! a file type. A file's metadata lives either in a legacy
//! `znode_phys_t` bonus buffer or, on any pool made this decade, in the
//! system-attribute encoding, which is a layout number plus a packed run
//! of values whose meaning comes from two ZAPs in the dataset.
//!
//! Nothing here does I/O: these are the decoders, and the walk that uses
//! them lives in `zfs-read`.

use crate::error::ParseError;
use crate::Endian;

/// Object number of the master node in a ZPL objset.
pub const MASTER_NODE_OBJ: u64 = 1;

/// `SA_MAGIC`, at the start of a system-attribute bonus buffer.
pub const SA_MAGIC: u32 = 0x002f_505a;

/// Bonus type of a legacy `znode_phys_t` (`DMU_OT_ZNODE`).
pub const OT_ZNODE: u8 = 17;

/// What a directory entry points at, from the top four bits of its value.
///
/// These are the POSIX `DT_*` values, which is how ZFS stores them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// A directory.
    Dir,
    /// A regular file.
    Regular,
    /// A symbolic link.
    Symlink,
    /// A character device.
    CharDevice,
    /// A block device.
    BlockDevice,
    /// A FIFO.
    Fifo,
    /// A socket.
    Socket,
    /// Anything else, or a directory whose entries carry no type.
    Other(u8),
}

impl FileType {
    /// From the `DT_*` value in a directory entry.
    pub fn from_dt(dt: u8) -> FileType {
        match dt {
            1 => FileType::Fifo,
            2 => FileType::CharDevice,
            4 => FileType::Dir,
            6 => FileType::BlockDevice,
            8 => FileType::Regular,
            10 => FileType::Symlink,
            12 => FileType::Socket,
            other => FileType::Other(other),
        }
    }

    /// From the file-type bits of a mode word (`S_IFMT`).
    pub fn from_mode(mode: u64) -> FileType {
        match (mode >> 12) & 0xf {
            0x1 => FileType::Fifo,
            0x2 => FileType::CharDevice,
            0x4 => FileType::Dir,
            0x6 => FileType::BlockDevice,
            0x8 => FileType::Regular,
            0xa => FileType::Symlink,
            0xc => FileType::Socket,
            other => FileType::Other(other as u8),
        }
    }

    /// Single-letter name, as `ls -l` writes it.
    pub fn as_char(self) -> char {
        match self {
            FileType::Dir => 'd',
            FileType::Regular => '-',
            FileType::Symlink => 'l',
            FileType::CharDevice => 'c',
            FileType::BlockDevice => 'b',
            FileType::Fifo => 'p',
            FileType::Socket => 's',
            FileType::Other(_) => '?',
        }
    }
}

/// Object number and file type packed into a directory entry's value.
///
/// `ZFS_DIRENT_OBJ` is the low 48 bits and `ZFS_DIRENT_TYPE` the top
/// four. A directory made before the type was recorded stores the bare
/// object number, which reads as type 0 and is reported as unknown
/// rather than guessed at.
pub fn dirent(value: u64) -> (u64, FileType) {
    (
        value & 0x0000_ffff_ffff_ffff,
        FileType::from_dt((value >> 60) as u8),
    )
}

/// The metadata of one file, however it was stored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Znode {
    /// `mode`, including the file-type bits.
    pub mode: u64,
    /// Size in bytes: the file's length, or the entry count of a
    /// directory.
    pub size: u64,
    /// Hard-link count.
    pub links: u64,
    /// Owner and group.
    pub uid: u64,
    /// Group.
    pub gid: u64,
    /// Access time.
    pub atime: Time,
    /// Modification time.
    pub mtime: Time,
    /// Change time.
    pub ctime: Time,
    /// Creation time.
    pub crtime: Time,
    /// Object holding the extended attributes, when there is one.
    pub xattr: u64,
    /// Device number for a device node.
    pub rdev: u64,
    /// Parent directory's object number.
    pub parent: u64,
    /// Target of a symbolic link stored inside the attributes.
    pub symlink: Option<Vec<u8>>,
    /// Extended attributes packed into the system attributes
    /// (`xattr=sa`), as the nvlist they are stored as.
    pub dxattr: Option<Vec<u8>>,
    /// Project id, where the dataset keeps one (Z-10).
    ///
    /// `None` and `Some(0)` are different answers and are kept apart:
    /// a dataset made before the `project_quota` feature has no such
    /// attribute at all, while one made after it puts every file in
    /// project 0 unless told otherwise. Reporting the first as zero
    /// would invent a project that was never set.
    pub projid: Option<u64>,
    /// Why the spill block could not be read, when it could not (Z-10).
    ///
    /// What did not fit the bonus — an extended attribute too large for
    /// it, as a rule, or an ACL, or a long link target — is in the spill
    /// block, and from the bonus alone nothing says which. The rest of
    /// the object is as read; whatever reads its attributes says this.
    pub spill_error: Option<String>,
}

/// One timestamp of a file: seconds either side of the epoch and the
/// nanoseconds into that second, as OpenZFS keeps them — two 64-bit
/// words, the first a `time_t` (`ZFS_TIME_DECODE`).
///
/// Read as one unsigned count of seconds, a time before 1970 came out
/// in the year 584 554 051 223 and the nanoseconds were dropped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Time {
    /// Seconds since the epoch; negative before it.
    pub secs: i64,
    /// Nanoseconds into the second, below 10^9.
    pub nanos: u32,
}

impl Time {
    /// From the two words on disk. A nanosecond count of a second or
    /// more is not one, and is read as none rather than carried.
    pub fn from_words(secs: u64, nanos: u64) -> Time {
        Time {
            secs: secs as i64,
            nanos: u32::try_from(nanos)
                .ok()
                .filter(|n| *n < 1_000_000_000)
                .unwrap_or(0),
        }
    }

    /// From a 16-byte attribute; `None` when it is shorter.
    pub fn from_attr(bytes: &[u8], endian: Endian) -> Option<Time> {
        Some(Time::from_words(
            endian.u64_at(bytes, 0)?,
            endian.u64_at(bytes, 8)?,
        ))
    }
}

impl Znode {
    /// What kind of file this is.
    pub fn file_type(&self) -> FileType {
        FileType::from_mode(self.mode)
    }

    /// Permission bits alone.
    pub fn permissions(&self) -> u32 {
        (self.mode & 0o7777) as u32
    }
}

/// How long a legacy `znode_phys_t` is (`ZFS_OLD_ZNODE_PHYS_SIZE`): the
/// fields, three spare words and the ACL. A short symbolic link keeps
/// its target in the bonus right after it.
pub const OLD_ZNODE_PHYS_SIZE: usize = 264;

/// Parse a legacy `znode_phys_t` bonus buffer (Z-02's fallback).
///
/// The layout is fixed (`zfs_znode.h`): four 16-byte timestamps, then
/// generation, mode, size, parent, links, xattr, rdev, flags, uid and
/// gid as 64-bit words, at 64, 72, 80 … 136. The offsets were read one
/// word off from 72 on — size where mode is, mode where the flags are —
/// and no file of a pool made before system attributes came out right.
///
/// A symbolic link whose target fits the bonus keeps it after the
/// structure (`zfs_sa_symlink`); a longer one is the object's data.
pub fn parse_znode_phys(bonus: &[u8], endian: Endian) -> Result<Znode, ParseError> {
    const NEEDED: usize = 144;
    if bonus.len() < NEEDED {
        return Err(ParseError::Truncated {
            needed: NEEDED,
            got: bonus.len(),
        });
    }
    let at = |o: usize| endian.u64_at(bonus, o).expect("length checked");
    let time = |o: usize| Time::from_words(at(o), at(o + 8));
    let mode = at(72);
    let size = at(80);
    let symlink = (FileType::from_mode(mode) == FileType::Symlink)
        .then(|| {
            let end = OLD_ZNODE_PHYS_SIZE.checked_add(usize::try_from(size).ok()?)?;
            bonus.get(OLD_ZNODE_PHYS_SIZE..end).map(<[u8]>::to_vec)
        })
        .flatten();
    Ok(Znode {
        atime: time(0),
        mtime: time(16),
        ctime: time(32),
        crtime: time(48),
        mode,
        size,
        parent: at(88),
        links: at(96),
        xattr: at(104),
        rdev: at(112),
        uid: at(128),
        gid: at(136),
        symlink,
        dxattr: None,
        // A legacy `znode_phys_t` predates the feature by a decade.
        projid: None,
        spill_error: None,
    })
}

/// The system attributes this reader knows how to place.
///
/// The numbers are not fixed on disk — the registry in the dataset says
/// which number each name has — so these are the names, and the
/// registry is what maps them.
pub mod attr {
    /// Access time, two 64-bit words.
    pub const ATIME: &str = "ZPL_ATIME";
    /// Modification time.
    pub const MTIME: &str = "ZPL_MTIME";
    /// Change time.
    pub const CTIME: &str = "ZPL_CTIME";
    /// Creation time.
    pub const CRTIME: &str = "ZPL_CRTIME";
    /// `mode`.
    pub const MODE: &str = "ZPL_MODE";
    /// Size in bytes.
    pub const SIZE: &str = "ZPL_SIZE";
    /// Parent directory object.
    pub const PARENT: &str = "ZPL_PARENT";
    /// Hard-link count.
    pub const LINKS: &str = "ZPL_LINKS";
    /// Extended-attribute directory object.
    pub const XATTR: &str = "ZPL_XATTR";
    /// Device number.
    pub const RDEV: &str = "ZPL_RDEV";
    /// Owner.
    pub const UID: &str = "ZPL_UID";
    /// Group.
    pub const GID: &str = "ZPL_GID";
    /// Symbolic-link target, stored inside the attributes.
    pub const SYMLINK: &str = "ZPL_SYMLINK";
    /// System-attribute extended attributes (`xattr=sa`).
    pub const DXATTR: &str = "ZPL_DXATTR";
    /// Project id, where the dataset has the `project_quota` feature.
    pub const PROJID: &str = "ZPL_PROJID";
}

/// One attribute as the registry describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredAttr {
    /// Attribute number, as layouts refer to it.
    pub num: u16,
    /// Fixed length in bytes, or 0 when the attribute is variable-length.
    pub length: u16,
}

/// Decode one entry of the SA registry ZAP.
///
/// The value packs the attribute number in bits 0–15, the byteswap
/// function in 16–23 and the length in 24–39 (`sa_impl.h`: `ATTR_NUM`,
/// `ATTR_BSWAP`, `ATTR_LENGTH`); only the number and the length matter
/// to a reader that already knows the byte order of the block it is
/// looking at. The number was read from bits 8–23 — the byteswap
/// function and half of nothing — and every attribute of a real pool
/// came out as number 0: no file had a mode, a size or an owner.
pub fn registered_attr(value: u64) -> RegisteredAttr {
    RegisteredAttr {
        num: (value & 0xffff) as u16,
        length: ((value >> 24) & 0xffff) as u16,
    }
}

/// The header at the start of a system-attribute buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaHeader {
    /// Which layout the values that follow are in.
    pub layout: u16,
    /// Bytes of header, including the variable-length sizes.
    pub hdrsize: usize,
    /// Sizes of the variable-length attributes, in layout order.
    pub lengths_at: usize,
    /// How many variable-length sizes the header carries.
    pub lengths: usize,
}

/// Parse the header of a system-attribute buffer.
///
/// `sa_layout_info` packs the layout number in its low ten bits and the
/// header size, in eight-byte units, in the six above them. Anything
/// without the magic is not a system-attribute buffer — most often a
/// legacy `znode_phys_t`, which the caller should try instead.
pub fn parse_sa_header(buf: &[u8], endian: Endian) -> Result<SaHeader, ParseError> {
    if buf.len() < 8 {
        return Err(ParseError::Truncated {
            needed: 8,
            got: buf.len(),
        });
    }
    let magic = match endian {
        Endian::Little => u32::from_le_bytes(buf[0..4].try_into().expect("4 bytes")),
        Endian::Big => u32::from_be_bytes(buf[0..4].try_into().expect("4 bytes")),
    };
    if magic != SA_MAGIC {
        return Err(ParseError::Malformed {
            what: "not a system-attribute buffer (bad SA magic)",
            at: 0,
        });
    }
    let info = match endian {
        Endian::Little => u16::from_le_bytes(buf[4..6].try_into().expect("2 bytes")),
        Endian::Big => u16::from_be_bytes(buf[4..6].try_into().expect("2 bytes")),
    };
    let layout = info & 0x3ff;
    let hdrsize = ((info >> 10) & 0x3f) as usize * 8;
    if hdrsize < 8 || hdrsize > buf.len() {
        return Err(ParseError::Malformed {
            what: "system-attribute header size outside the buffer",
            at: 4,
        });
    }
    Ok(SaHeader {
        layout,
        hdrsize,
        lengths_at: 6,
        // The header is the magic, the layout info, then one 16-bit size
        // per variable-length attribute, padded to eight bytes.
        lengths: (hdrsize - 6) / 2,
    })
}

/// Place the attributes of one system-attribute buffer.
///
/// `layout` is the ordered list of attribute numbers the layout ZAP
/// gives, and `lengths` maps an attribute number to its fixed length, 0
/// meaning variable. Returns each attribute's bytes in layout order.
///
/// Variable-length attributes take their size from the header, in the
/// order they appear in the layout; everything else is exactly as long
/// as the registry says. Each one starts on an eight-byte boundary
/// (`sa_attr_iter`: `P2ROUNDUP(length, 8)`): a variable-length one —
/// an ACL, a link target — is padded, and what follows it was read
/// from inside the padding. A layout that runs past the end of the
/// buffer stops there rather than reading whatever follows.
pub fn place_attrs(
    buf: &[u8],
    header: &SaHeader,
    layout: &[u16],
    lengths: &dyn Fn(u16) -> Option<u16>,
    endian: Endian,
) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::with_capacity(layout.len());
    let mut variable = 0usize;
    let mut at = header.hdrsize;
    for num in layout {
        let fixed = lengths(*num).unwrap_or(0);
        let len = if fixed != 0 {
            fixed as usize
        } else {
            let o = header.lengths_at + variable * 2;
            variable += 1;
            let Some(bytes) = buf.get(o..o + 2) else {
                break;
            };
            let v = match endian {
                Endian::Little => u16::from_le_bytes(bytes.try_into().expect("2 bytes")),
                Endian::Big => u16::from_be_bytes(bytes.try_into().expect("2 bytes")),
            };
            v as usize
        };
        let Some(value) = buf.get(at..at + len) else {
            break;
        };
        out.push((*num, value.to_vec()));
        at += len.next_multiple_of(8);
    }
    out
}

/// A 64-bit attribute value, or `None` when it is the wrong size.
pub fn attr_u64(bytes: &[u8], endian: Endian) -> Option<u64> {
    endian.u64_at(bytes, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry value as OpenZFS writes it (`ATTR_ENCODE`): the
    /// number in the low sixteen bits. `ZPL_MODE` on a real pool is
    /// 0x8000005 — eight bytes, an array of 64-bit words, number 5 —
    /// and `ZPL_DACL_ACES` 0x40013: no fixed length, byteswapped as an
    /// ACL, number 0x13.
    #[test]
    fn a_registry_entry_is_read_as_openzfs_encodes_it() {
        assert_eq!(
            registered_attr(0x800_0005),
            RegisteredAttr { num: 5, length: 8 }
        );
        assert_eq!(
            registered_attr(0x4_0013),
            RegisteredAttr {
                num: 0x13,
                length: 0
            }
        );
    }

    /// Every attribute starts on an eight-byte boundary: what follows a
    /// five-byte variable-length value is three bytes further on.
    #[test]
    fn attributes_are_placed_on_eight_byte_boundaries() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&SA_MAGIC.to_le_bytes());
        // Layout 2, a 16-byte header: two variable lengths, 5 and 3.
        buf.extend_from_slice(&(2u16 | (2 << 10)).to_le_bytes());
        buf.extend_from_slice(&5u16.to_le_bytes());
        buf.extend_from_slice(&3u16.to_le_bytes());
        buf.resize(16, 0);
        buf.extend_from_slice(b"abcde\0\0\0");
        buf.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        buf.extend_from_slice(b"xyz\0\0\0\0\0");
        let header = parse_sa_header(&buf, Endian::Little).unwrap();
        let lengths = |n: u16| Some(if n == 2 { 8 } else { 0 });
        let placed = place_attrs(&buf, &header, &[1, 2, 3], &lengths, Endian::Little);
        assert_eq!(
            placed,
            vec![
                (1, b"abcde".to_vec()),
                (2, 0x1122_3344_5566_7788u64.to_le_bytes().to_vec()),
                (3, b"xyz".to_vec()),
            ]
        );
    }

    /// `znode_phys_t` as `zfs_znode.h` lays it out — mode at 72, size
    /// at 80, parent 88, links 96, flags 120, uid 128, gid 136 — and a
    /// short link's target after its 264 bytes.
    #[test]
    fn a_legacy_znode_is_read_at_its_offsets() {
        let mut b = vec![0u8; OLD_ZNODE_PHYS_SIZE];
        let mut put = |o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
        put(16, 1_243_919_918); // mtime
        put(64, 7); // generation
        put(72, 0o120777); // mode
        put(80, 5); // size
        put(88, 3); // parent
        put(96, 1); // links
        put(120, 0x2_0000_0000); // flags
        put(128, 1001); // uid
        put(136, 1002); // gid
        b.extend_from_slice(b"abcde");
        let z = parse_znode_phys(&b, Endian::Little).unwrap();
        assert_eq!(
            (z.mode, z.size, z.parent, z.links, z.uid, z.gid),
            (0o120777, 5, 3, 1, 1001, 1002)
        );
        assert_eq!(z.mtime.secs, 1_243_919_918);
        assert_eq!(z.symlink.as_deref(), Some(&b"abcde"[..]));
        // A target that is not in the bonus is the object's data.
        b.truncate(OLD_ZNODE_PHYS_SIZE);
        assert_eq!(parse_znode_phys(&b, Endian::Little).unwrap().symlink, None);
    }
}
