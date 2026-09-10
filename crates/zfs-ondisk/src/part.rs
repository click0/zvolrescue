//! Partition tables, as a source of *candidate* vdev starts (F-06, F-60).
//!
//! A ZFS member is usually a partition, and an image of a whole disk holds
//! the table that says where it began. That table is a hint and nothing
//! more: it may have been rewritten with different bounds, which is one of
//! the ways a pool stops importing in the first place. Every candidate it
//! yields is confirmed the same way as any other — by a checksum that only
//! verifies at the right offset (D-5).

/// A partition as the table describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// 1-based index in the table.
    pub index: usize,
    /// First byte.
    pub start: u64,
    /// Length in bytes.
    pub length: u64,
    /// GPT type GUID, formatted, or the MBR type byte as `0x..`.
    pub kind: String,
    /// GPT partition name, when it has one.
    pub name: Option<String>,
    /// Whether the type is one ZFS is normally found in.
    pub zfs: bool,
}

/// What was found on a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionTable {
    /// `gpt`, `gpt-backup` or `mbr`.
    pub scheme: &'static str,
    /// Logical sector size the table was read with.
    pub sector: u64,
    /// The partitions, in table order.
    pub partitions: Vec<Partition>,
}

impl PartitionTable {
    /// Starts of the partitions ZFS is normally found in, then of every
    /// other partition: candidate vdev bases, in the order worth trying.
    pub fn candidate_bases(&self) -> Vec<u64> {
        let mut out: Vec<u64> = self
            .partitions
            .iter()
            .filter(|p| p.zfs)
            .map(|p| p.start)
            .collect();
        out.extend(self.partitions.iter().filter(|p| !p.zfs).map(|p| p.start));
        out
    }
}

/// `6a898cc3-1dd2-11b2-99a6-080020736631`: Solaris/illumos/FreeBSD ZFS.
const GPT_ZFS: &str = "6a898cc3-1dd2-11b2-99a6-080020736631";
/// `516e7cba-6ecf-11d6-8ff8-00022d09712b`: FreeBSD ZFS (`freebsd-zfs`).
const GPT_FREEBSD_ZFS: &str = "516e7cba-6ecf-11d6-8ff8-00022d09712b";
/// Linux filesystem data. Not a ZFS type — a member is sometimes found
/// in one anyway, so it stays a candidate, just not a likely one.
pub const GPT_LINUX_DATA: &str = "0fc63daf-8483-4772-8e79-3d69d8477de4";

const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

/// Format a 16-byte GPT GUID the way `gpart`/`sgdisk` print it: the first
/// three fields little-endian, the rest big-endian.
pub fn format_guid(b: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32le(b, 0),
        u16le(b, 4),
        u16le(b, 6),
        b[8],
        b[9],
        b[10..16]
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    )
}

fn utf16_name(b: &[u8]) -> Option<String> {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    if units.is_empty() {
        return None;
    }
    String::from_utf16(&units).ok()
}

/// Parse a GPT whose header sits in `header` (one sector) with the entry
/// array in `entries`.
///
/// `sector` is the logical sector size the offsets are counted in.
pub fn parse_gpt(
    header: &[u8],
    entries: &[u8],
    sector: u64,
    backup: bool,
) -> Option<PartitionTable> {
    if header.len() < 92 || &header[..8] != GPT_SIGNATURE {
        return None;
    }
    let count = u32le(header, 80) as usize;
    let size = u32le(header, 84) as usize;
    if size < 128 || count == 0 || count > 4096 {
        return None;
    }
    let mut partitions = Vec::new();
    for i in 0..count {
        let at = i * size;
        if at + 128 > entries.len() {
            break;
        }
        let e = &entries[at..at + size.min(entries.len() - at)];
        if e[..16].iter().all(|&b| b == 0) {
            continue; // unused slot
        }
        let kind = format_guid(&e[..16]);
        let first = u64le(e, 32);
        let last = u64le(e, 40);
        if last < first {
            continue;
        }
        partitions.push(Partition {
            index: i + 1,
            start: first * sector,
            length: (last - first + 1) * sector,
            zfs: matches!(kind.as_str(), GPT_ZFS | GPT_FREEBSD_ZFS),
            kind,
            name: e.get(56..128).and_then(utf16_name),
        });
    }
    Some(PartitionTable {
        scheme: if backup { "gpt-backup" } else { "gpt" },
        sector,
        partitions,
    })
}

/// Parse an MBR from the first sector.
///
/// A protective MBR (one entry of type 0xee covering the disk) is not a
/// table: GPT is, and this returns `None` so the caller keeps looking.
pub fn parse_mbr(sector0: &[u8], sector: u64) -> Option<PartitionTable> {
    if sector0.len() < 512 || sector0[510] != 0x55 || sector0[511] != 0xaa {
        return None;
    }
    let mut partitions = Vec::new();
    for i in 0..4 {
        let e = &sector0[446 + i * 16..446 + (i + 1) * 16];
        let kind = e[4];
        let first = u32le(e, 8) as u64;
        let sectors = u32le(e, 12) as u64;
        if kind == 0 || sectors == 0 {
            continue;
        }
        if kind == 0xee {
            return None; // protective MBR: the real table is the GPT
        }
        partitions.push(Partition {
            index: i + 1,
            start: first * sector,
            length: sectors * sector,
            // 0xbf: Solaris/ZFS. 0xa5: a FreeBSD slice, which holds its
            // own disklabel — ZFS lives inside it, not at its start.
            zfs: kind == 0xbf,
            kind: format!("{kind:#04x}"),
            name: None,
        });
    }
    if partitions.is_empty() {
        return None;
    }
    Some(PartitionTable {
        scheme: "mbr",
        sector,
        partitions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gpt_header(entry_count: u32, entry_size: u32) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..8].copy_from_slice(GPT_SIGNATURE);
        h[80..84].copy_from_slice(&entry_count.to_le_bytes());
        h[84..88].copy_from_slice(&entry_size.to_le_bytes());
        h
    }

    fn gpt_entry(kind: &str, first: u64, last: u64, name: &str) -> Vec<u8> {
        let mut e = vec![0u8; 128];
        // Write the GUID back in the on-disk byte order.
        let hex: Vec<u8> = kind
            .chars()
            .filter(|c| *c != '-')
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|c| u8::from_str_radix(&c.iter().collect::<String>(), 16).expect("hex"))
            .collect();
        e[0..4].copy_from_slice(&u32::from_be_bytes(hex[0..4].try_into().unwrap()).to_le_bytes());
        e[4..6].copy_from_slice(&u16::from_be_bytes(hex[4..6].try_into().unwrap()).to_le_bytes());
        e[6..8].copy_from_slice(&u16::from_be_bytes(hex[6..8].try_into().unwrap()).to_le_bytes());
        e[8..16].copy_from_slice(&hex[8..16]);
        e[16..32].copy_from_slice(&[0x11; 16]);
        e[32..40].copy_from_slice(&first.to_le_bytes());
        e[40..48].copy_from_slice(&last.to_le_bytes());
        for (i, u) in name.encode_utf16().enumerate() {
            e[56 + i * 2..58 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        e
    }

    #[test]
    fn a_gpt_yields_the_zfs_partition_first() {
        let header = gpt_header(3, 128);
        let mut entries = Vec::new();
        entries.extend(gpt_entry(GPT_LINUX_DATA, 2048, 4095, "boot"));
        entries.extend(gpt_entry(GPT_FREEBSD_ZFS, 4096, 20_479, "zfs0"));
        entries.extend(vec![0u8; 128]); // an unused slot in the middle
        let t = parse_gpt(&header, &entries, 512, false).expect("a GPT");
        assert_eq!(t.scheme, "gpt");
        assert_eq!(t.partitions.len(), 2);
        assert_eq!(t.partitions[1].start, 4096 * 512);
        assert_eq!(t.partitions[1].length, 16_384 * 512);
        assert_eq!(t.partitions[1].name.as_deref(), Some("zfs0"));
        assert_eq!(t.partitions[1].kind, GPT_FREEBSD_ZFS);
        assert!(t.partitions[1].zfs);
        // The ZFS partition is the first candidate, the rest follow.
        assert_eq!(t.candidate_bases(), vec![4096 * 512, 2048 * 512]);
        assert!(
            !t.partitions[0].zfs,
            "linux data is a candidate, not a likely one"
        );
    }

    #[test]
    fn a_4k_sector_table_measures_in_4k() {
        let header = gpt_header(1, 128);
        let entries = gpt_entry(GPT_ZFS, 256, 1279, "");
        let t = parse_gpt(&header, &entries, 4096, false).expect("a GPT");
        assert_eq!(t.sector, 4096);
        assert_eq!(t.partitions[0].start, 256 * 4096);
        assert_eq!(t.partitions[0].name, None);
    }

    #[test]
    fn an_mbr_is_read_and_a_protective_one_is_not_a_table() {
        let mut s = vec![0u8; 512];
        s[510] = 0x55;
        s[511] = 0xaa;
        s[446 + 4] = 0xbf; // Solaris/ZFS
        s[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
        s[446 + 12..446 + 16].copy_from_slice(&100_000u32.to_le_bytes());
        s[462 + 4] = 0x83; // Linux
        s[462 + 8..462 + 12].copy_from_slice(&200_000u32.to_le_bytes());
        s[462 + 12..462 + 16].copy_from_slice(&1000u32.to_le_bytes());
        let t = parse_mbr(&s, 512).expect("an MBR");
        assert_eq!(t.scheme, "mbr");
        assert_eq!(t.partitions.len(), 2);
        assert!(t.partitions[0].zfs);
        assert_eq!(t.partitions[0].start, 2048 * 512);
        assert_eq!(t.candidate_bases(), vec![2048 * 512, 200_000 * 512]);

        let mut prot = vec![0u8; 512];
        prot[510] = 0x55;
        prot[511] = 0xaa;
        prot[446 + 4] = 0xee;
        prot[446 + 12..446 + 16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(parse_mbr(&prot, 512), None);
    }

    #[test]
    fn garbage_is_not_a_table() {
        assert_eq!(parse_gpt(&[0u8; 512], &[0u8; 128], 512, false), None);
        assert_eq!(parse_mbr(&[0u8; 512], 512), None);
        assert_eq!(parse_mbr(&[0xa5u8; 16], 512), None);
        // A GPT header claiming an absurd entry array is not trusted.
        let mut h = gpt_header(1 << 20, 128);
        h[..8].copy_from_slice(GPT_SIGNATURE);
        assert_eq!(parse_gpt(&h, &[0u8; 128], 512, false), None);
    }
}
