//! What a volume's contents say they are (SPEC F-43, COMPANIONS C-12).
//!
//! A carved volume's dnode says how many blocks it has, which is not the
//! same as how large it was: a volume whose tail was never written looks
//! smaller, and one whose metadata is gone says nothing at all. What is
//! *inside* it usually does say. Nearly every filesystem writes a
//! superblock at a fixed offset near the front, and that superblock
//! carries the size it was made for.
//!
//! So the first megabyte of a candidate is worth a look before anyone
//! spends hours extracting it: it says whether this is an ext4 root
//! filesystem of 40 GB, a swap area, an NTFS disk, or nothing
//! recognisable at all.
//!
//! Nothing here does I/O — the caller passes a closure that reads a
//! range — and nothing here is trusted: a signature bounds a guess, it
//! does not replace a checksum.

use std::fmt;

/// What was recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// ext2, ext3 or ext4 — the magic does not distinguish them.
    Ext,
    /// A Linux swap area.
    Swap,
    /// XFS.
    Xfs,
    /// btrfs.
    Btrfs,
    /// NTFS.
    Ntfs,
    /// FAT32.
    Fat32,
    /// A FreeBSD UFS2 filesystem.
    Ufs2,
    /// A LUKS container: encrypted, and its size is inside.
    Luks,
    /// A GPT partition table — the volume holds partitions, not a
    /// filesystem.
    Gpt,
    /// A ZFS vdev label: a pool inside a volume.
    ZfsLabel,
}

impl Kind {
    /// Stable name, as printed and as written to JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Ext => "ext2/3/4",
            Kind::Swap => "swap",
            Kind::Xfs => "xfs",
            Kind::Btrfs => "btrfs",
            Kind::Ntfs => "ntfs",
            Kind::Fat32 => "fat32",
            Kind::Ufs2 => "ufs2",
            Kind::Luks => "luks",
            Kind::Gpt => "gpt",
            Kind::ZfsLabel => "zfs",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One thing recognised inside a volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// What it is.
    pub kind: Kind,
    /// Where the signature was, in bytes from the start of the volume.
    pub at: u64,
    /// The size the signature says the volume was made for, when it
    /// says. This is the number a carved volume otherwise has no way of
    /// knowing.
    pub size: Option<u64>,
    /// The volume label, where the format keeps one.
    pub label: Option<String>,
}

/// Reads `len` bytes at `at`, or `None` when they cannot be read.
pub type Reader<'a> = dyn Fn(u64, usize) -> Option<Vec<u8>> + 'a;

fn le16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn le32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

fn le64(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

fn be32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

fn be64(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

/// A NUL-padded name as a label, or `None` when it is empty.
fn label(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let s = String::from_utf8_lossy(&bytes[..end]).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Everything recognisable near the front of a volume.
///
/// The offsets are where each format puts its superblock, and they do
/// not collide, so a volume can only match more than one by accident —
/// which is itself worth reporting rather than hiding.
pub fn identify(read: &Reader<'_>) -> Vec<Found> {
    let mut out = Vec::new();
    out.extend(ext(read));
    out.extend(swap(read));
    out.extend(xfs(read));
    out.extend(btrfs(read));
    out.extend(ntfs(read));
    out.extend(fat32(read));
    out.extend(ufs2(read));
    out.extend(luks(read));
    out.extend(gpt(read));
    out.extend(zfs_label(read));
    out
}

/// ext2/3/4: the superblock is at 1024 and says how many blocks of what
/// size the filesystem was made with.
fn ext(read: &Reader<'_>) -> Option<Found> {
    let sb = read(1024, 0x160)?;
    if le16(&sb, 0x38)? != 0xef53 {
        return None;
    }
    let log_block_size = le32(&sb, 0x18)?;
    // A block is 1024 << s_log_block_size; anything past 64 KiB is not a
    // filesystem this magic belongs to.
    if log_block_size > 6 {
        return None;
    }
    let block = 1024u64 << log_block_size;
    let blocks = u64::from(le32(&sb, 0x04)?) | (u64::from(le32(&sb, 0x150)?) << 32);
    Some(Found {
        kind: Kind::Ext,
        at: 1024,
        size: blocks.checked_mul(block).filter(|n| *n > 0),
        label: label(sb.get(0x78..0x88)?),
    })
}

/// A Linux swap area: the magic is at the end of the first page and the
/// header at 1024 says how many pages there are.
fn swap(read: &Reader<'_>) -> Option<Found> {
    // The page size is whatever the machine that made it used; 4 KiB is
    // what every amd64 and arm64 host writes.
    for page in [4096u64, 8192, 16384, 65536] {
        let Some(tail) = read(page - 10, 10) else {
            continue;
        };
        if tail != b"SWAPSPACE2" {
            continue;
        }
        let info = read(1024, 44)?;
        let last_page = u64::from(le32(&info, 4)?);
        return Some(Found {
            kind: Kind::Swap,
            at: page - 10,
            // last_page is the highest usable page, and page 0 is the
            // header itself.
            size: last_page.checked_add(1)?.checked_mul(page),
            label: label(info.get(28..44)?),
        });
    }
    None
}

/// XFS: everything at the front, and big-endian.
fn xfs(read: &Reader<'_>) -> Option<Found> {
    let sb = read(0, 128)?;
    if sb.get(0..4)? != b"XFSB" {
        return None;
    }
    let block = u64::from(be32(&sb, 4)?);
    let blocks = be64(&sb, 8)?;
    Some(Found {
        kind: Kind::Xfs,
        at: 0,
        size: blocks.checked_mul(block).filter(|n| *n > 0),
        label: label(sb.get(0x6c..0x78)?),
    })
}

/// btrfs: the superblock is at 64 KiB and the magic 64 bytes into it.
fn btrfs(read: &Reader<'_>) -> Option<Found> {
    // The label is 256 bytes at 0x12b, so the whole superblock has to be
    // read, not just its head.
    let sb = read(0x1_0000, 0x1000)?;
    if sb.get(0x40..0x48)? != b"_BHRfS_M" {
        return None;
    }
    Some(Found {
        kind: Kind::Btrfs,
        at: 0x1_0040,
        size: le64(&sb, 0x70).filter(|n| *n > 0),
        label: label(sb.get(0x12b..0x22b)?),
    })
}

/// NTFS: the boot sector names itself, and the sector count excludes the
/// backup sector at the end.
fn ntfs(read: &Reader<'_>) -> Option<Found> {
    let boot = read(0, 0x40)?;
    if boot.get(3..11)? != b"NTFS    " {
        return None;
    }
    let bytes_per_sector = u64::from(le16(&boot, 0x0b)?);
    if !(512..=4096).contains(&bytes_per_sector) {
        return None;
    }
    let sectors = le64(&boot, 0x28)?;
    Some(Found {
        kind: Kind::Ntfs,
        at: 0,
        size: sectors
            .checked_add(1)
            .and_then(|s| s.checked_mul(bytes_per_sector))
            .filter(|n| *n > 0),
        label: None,
    })
}

/// FAT32: the type string is at 0x52 and the 32-bit sector count at 0x20.
fn fat32(read: &Reader<'_>) -> Option<Found> {
    let boot = read(0, 0x5a)?;
    if boot.get(0x52..0x5a)? != b"FAT32   " {
        return None;
    }
    let bytes_per_sector = u64::from(le16(&boot, 0x0b)?);
    if !(512..=4096).contains(&bytes_per_sector) {
        return None;
    }
    let sectors = u64::from(le32(&boot, 0x20)?);
    Some(Found {
        kind: Kind::Fat32,
        at: 0,
        size: sectors.checked_mul(bytes_per_sector).filter(|n| *n > 0),
        label: label(boot.get(0x47..0x52)?),
    })
}

/// UFS2, as FreeBSD writes it: the superblock is at 64 KiB and its magic
/// 1372 bytes in.
///
/// The size is not read: UFS keeps it in fragments whose size is itself
/// in the superblock, and getting that wrong would put a number on a
/// guess. The kind is what matters here.
fn ufs2(read: &Reader<'_>) -> Option<Found> {
    let sb = read(65536, 1376)?;
    if le32(&sb, 1372)? != 0x1954_0119 {
        return None;
    }
    Some(Found {
        kind: Kind::Ufs2,
        at: 65536 + 1372,
        size: None,
        label: None,
    })
}

/// LUKS: encrypted, so nothing inside can be read, but knowing that is
/// itself the answer to "why does this look like noise?".
fn luks(read: &Reader<'_>) -> Option<Found> {
    let head = read(0, 8)?;
    if head.get(0..6)? != b"LUKS\xba\xbe" {
        return None;
    }
    Some(Found {
        kind: Kind::Luks,
        at: 0,
        size: None,
        label: None,
    })
}

/// A GPT header in the second sector: the volume holds partitions.
fn gpt(read: &Reader<'_>) -> Option<Found> {
    for sector in [512u64, 4096] {
        if read(sector, 8).as_deref() == Some(b"EFI PART") {
            return Some(Found {
                kind: Kind::Gpt,
                at: sector,
                size: None,
                label: None,
            });
        }
    }
    None
}

/// A ZFS vdev label: a pool inside a volume, which happens more often
/// than it sounds — a zvol handed to a guest that made a pool on it.
///
/// The configuration nvlist at 16 KiB is XDR-encoded and big-endian,
/// which is those first two bytes.
fn zfs_label(read: &Reader<'_>) -> Option<Found> {
    let head = read(16384, 4)?;
    if head.get(0..4)? != [1, 1, 0, 0] {
        return None;
    }
    Some(Found {
        kind: Kind::ZfsLabel,
        at: 16384,
        size: None,
        label: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader over one buffer, as a volume's first bytes would be.
    fn over(buf: Vec<u8>) -> impl Fn(u64, usize) -> Option<Vec<u8>> {
        move |at: u64, len: usize| {
            let start = usize::try_from(at).ok()?;
            buf.get(start..start + len).map(<[u8]>::to_vec)
        }
    }

    fn blank(len: usize) -> Vec<u8> {
        vec![0u8; len]
    }

    fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
        buf[at..at + bytes.len()].copy_from_slice(bytes);
    }

    #[test]
    fn nothing_in_zeros() {
        assert!(identify(&over(blank(1 << 20))).is_empty());
    }

    /// The fields are the ones a real `mkfs.ext4 -L zvoltest` on a 64 MiB
    /// image writes: 16384 blocks of 1024 << 2 bytes.
    #[test]
    fn an_ext4_superblock_says_how_large_it_was_made() {
        let mut b = blank(1 << 20);
        put(&mut b, 1024 + 0x38, &0xef53u16.to_le_bytes());
        put(&mut b, 1024 + 0x18, &2u32.to_le_bytes());
        put(&mut b, 1024 + 0x04, &16384u32.to_le_bytes());
        put(&mut b, 1024 + 0x78, b"zvoltest");
        let found = identify(&over(b));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, Kind::Ext);
        assert_eq!(found[0].size, Some(64 << 20));
        assert_eq!(found[0].label.as_deref(), Some("zvoltest"));
    }

    /// A filesystem larger than 4 GiB keeps the top half of its block
    /// count elsewhere; reading only the low half would report 32 GiB as
    /// nothing at all.
    #[test]
    fn a_large_ext4_uses_both_halves_of_its_block_count() {
        let mut b = blank(1 << 20);
        put(&mut b, 1024 + 0x38, &0xef53u16.to_le_bytes());
        put(&mut b, 1024 + 0x18, &2u32.to_le_bytes());
        put(&mut b, 1024 + 0x04, &0u32.to_le_bytes());
        put(&mut b, 1024 + 0x150, &2u32.to_le_bytes());
        let found = identify(&over(b));
        assert_eq!(found[0].size, Some((2u64 << 32) * 4096));
    }

    #[test]
    fn a_block_size_that_could_not_be_one_is_not_a_filesystem() {
        let mut b = blank(1 << 20);
        put(&mut b, 1024 + 0x38, &0xef53u16.to_le_bytes());
        put(&mut b, 1024 + 0x18, &9u32.to_le_bytes());
        put(&mut b, 1024 + 0x04, &16384u32.to_le_bytes());
        assert!(identify(&over(b)).is_empty());
    }

    /// The fields `mkswap -L swaptest` writes on a 16 MiB image.
    #[test]
    fn a_swap_area_says_how_many_pages_it_has() {
        let mut b = blank(1 << 20);
        put(&mut b, 4096 - 10, b"SWAPSPACE2");
        put(&mut b, 1024 + 4, &4095u32.to_le_bytes());
        put(&mut b, 1024 + 28, b"swaptest");
        let found = identify(&over(b));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, Kind::Swap);
        assert_eq!(found[0].size, Some(16 << 20));
        assert_eq!(found[0].label.as_deref(), Some("swaptest"));
    }

    #[test]
    fn xfs_is_big_endian() {
        let mut b = blank(1 << 20);
        put(&mut b, 0, b"XFSB");
        put(&mut b, 4, &4096u32.to_be_bytes());
        put(&mut b, 8, &(1u64 << 20).to_be_bytes());
        put(&mut b, 0x6c, b"data");
        let found = identify(&over(b));
        assert_eq!(found[0].kind, Kind::Xfs);
        assert_eq!(found[0].size, Some(4096 * (1 << 20)));
        assert_eq!(found[0].label.as_deref(), Some("data"));
    }

    #[test]
    fn btrfs_keeps_its_superblock_at_64_kib() {
        let mut b = blank(1 << 20);
        put(&mut b, 0x1_0040, b"_BHRfS_M");
        put(&mut b, 0x1_0070, &(40u64 << 30).to_le_bytes());
        let found = identify(&over(b));
        assert_eq!(found[0].kind, Kind::Btrfs);
        assert_eq!(found[0].at, 0x1_0040);
        assert_eq!(found[0].size, Some(40 << 30));
    }

    /// NTFS counts every sector but the backup boot sector at the end.
    #[test]
    fn ntfs_counts_one_more_sector_than_it_says() {
        let mut b = blank(1 << 20);
        put(&mut b, 3, b"NTFS    ");
        put(&mut b, 0x0b, &512u16.to_le_bytes());
        put(&mut b, 0x28, &1023u64.to_le_bytes());
        let found = identify(&over(b));
        assert_eq!(found[0].kind, Kind::Ntfs);
        assert_eq!(found[0].size, Some(1024 * 512));
    }

    #[test]
    fn fat32_names_itself_at_0x52() {
        let mut b = blank(1 << 20);
        put(&mut b, 0x52, b"FAT32   ");
        put(&mut b, 0x0b, &512u16.to_le_bytes());
        put(&mut b, 0x20, &2048u32.to_le_bytes());
        put(&mut b, 0x47, b"ESP        ");
        let found = identify(&over(b));
        assert_eq!(found[0].kind, Kind::Fat32);
        assert_eq!(found[0].size, Some(2048 * 512));
        assert_eq!(found[0].label.as_deref(), Some("ESP"));
    }

    /// Some formats are recognised without a size, and saying so is the
    /// point: a guess with no number is honest, a made-up number is not.
    #[test]
    fn what_cannot_be_sized_is_reported_without_a_size() {
        for (at, magic, kind) in [
            (65536 + 1372, &0x1954_0119u32.to_le_bytes()[..], Kind::Ufs2),
            (0, &b"LUKS\xba\xbe"[..], Kind::Luks),
            (512, &b"EFI PART"[..], Kind::Gpt),
            (16384, &[1u8, 1, 0, 0][..], Kind::ZfsLabel),
        ] {
            let mut b = blank(1 << 20);
            put(&mut b, at, magic);
            let found = identify(&over(b));
            assert_eq!(found.len(), 1, "{kind}");
            assert_eq!(found[0].kind, kind);
            assert_eq!(found[0].size, None, "{kind}");
        }
    }

    /// A volume shorter than a signature's offset is not a volume with
    /// that signature: the reader says no and nothing is invented.
    #[test]
    fn a_short_volume_reads_as_nothing() {
        assert!(identify(&over(blank(512))).is_empty());
    }

    /// Noise must not look like a filesystem; a carve looks at a great
    /// deal of it.
    #[test]
    fn noise_is_not_a_filesystem() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..200 {
            let mut b = vec![0u8; 1 << 17];
            for chunk in b.chunks_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
            }
            assert!(identify(&over(b)).is_empty());
        }
    }
}
