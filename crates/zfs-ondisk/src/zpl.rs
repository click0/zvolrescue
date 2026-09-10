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
    /// Access, modification, change and creation times, seconds only.
    pub atime: u64,
    /// Modification time.
    pub mtime: u64,
    /// Change time.
    pub ctime: u64,
    /// Creation time.
    pub crtime: u64,
    /// Object holding the extended attributes, when there is one.
    pub xattr: u64,
    /// Device number for a device node.
    pub rdev: u64,
    /// Parent directory's object number.
    pub parent: u64,
    /// Target of a symbolic link stored inside the attributes.
    pub symlink: Option<Vec<u8>>,
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

/// Parse a legacy `znode_phys_t` bonus buffer (Z-02's fallback).
///
/// The layout is fixed: four 16-byte timestamps, then generation, size,
/// parent, links, xattr, rdev, mode, uid and gid as 64-bit words.
pub fn parse_znode_phys(bonus: &[u8], endian: Endian) -> Result<Znode, ParseError> {
    const NEEDED: usize = 168;
    if bonus.len() < NEEDED {
        return Err(ParseError::Truncated {
            needed: NEEDED,
            got: bonus.len(),
        });
    }
    let at = |o: usize| endian.u64_at(bonus, o).expect("length checked");
    Ok(Znode {
        atime: at(0),
        mtime: at(16),
        ctime: at(32),
        crtime: at(48),
        size: at(72),
        parent: at(80),
        links: at(88),
        xattr: at(104),
        rdev: at(112),
        mode: at(120),
        uid: at(128),
        gid: at(136),
        symlink: None,
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
/// The value packs the byteswap function, the attribute number and the
/// length; only the last two matter to a reader that already knows the
/// byte order of the block it is looking at.
pub fn registered_attr(value: u64) -> RegisteredAttr {
    RegisteredAttr {
        num: ((value >> 8) & 0xffff) as u16,
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
/// as the registry says. A layout that runs past the end of the buffer
/// stops there rather than reading whatever follows.
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
        at += len;
    }
    out
}

/// A 64-bit attribute value, or `None` when it is the wrong size.
pub fn attr_u64(bytes: &[u8], endian: Endian) -> Option<u64> {
    endian.u64_at(bytes, 0)
}
