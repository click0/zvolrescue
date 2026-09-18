//! Write fixture member images for smoke tests.
//!
//! `cargo run -p zfs-read --example mkfixture -- DIR [mirror|mirror3|raidz2|striped] [ashift] [carved|zpl|removed|dedup]`
//! writes `DIR/member0.img`, `DIR/member1.img`, … with sealed labels,
//! three uberblocks each and, for mirrors, a small MOS with four datasets
//! at the older TXGs and the volume destroyed at the newest one.
//!
//! With `removed`, the volume's data blocks are addressed on a top-level
//! vdev the pool has since had removed, and the MOS carries the mapping
//! that says where those bytes went (SPEC F-69). With `dedup`, the
//! volume's data pointers carry the dedup bit and sha256 checksums, and
//! `dedup=sha256,verify` is set on it (SPEC F-28).
//!
//! With `carved` as the fourth argument, no uberblock mentions the volume
//! at all, though its blocks are still on the member: the pool a carve
//! has to find something in when a walk cannot (COMPANIONS §3.4). With
//! `zpl`, the pool holds one filesystem dataset with a small POSIX tree
//! instead of a volume (COMPANIONS §5.4). A fifth argument names one more
//! active read-incompatible feature for the labels to claim, so a refusal
//! can be seen (SPEC F-70).
//!
//! `mirror3` is a three-way mirror, the shape `zpool attach` leaves.
//! `striped` is a pool of two top-level mirrors, two and three leaves
//! wide, with the MOS on the first and the volume's data on the second:
//! members `member0`…`member4`, one transaction group, the volume
//! present. It takes no mode.

use std::path::PathBuf;

use zfs_read::fixture::{
    carved_zvol_members, dedup_zvol_members, dense_volume_members, destroyed_zvol_members,
    removed_vdev_members, two_top_mirror_members, zpl_members, Dense, Pool,
};

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(
        args.next()
            .expect("usage: mkfixture DIR [mirror|raidz2] [ashift]"),
    );
    let kind = args.next().unwrap_or_else(|| "mirror".into());
    let ashift: u32 = args
        .next()
        .map(|a| a.parse().expect("ashift"))
        .unwrap_or(12);
    let mode = args.next().unwrap_or_default();
    let feature = args.next();
    let carved = mode == "carved";
    let zpl = mode == "zpl";
    let removed = mode == "removed";
    let dedup = mode == "dedup";
    // `bench` and `bench-raidz2`: a dense volume for measurements (SPEC
    // N-03, N-08). The fourth argument is the size in MiB, the fifth the
    // compression: off (the default), lz4, or gzip.
    if kind == "bench" || kind == "bench-raidz2" {
        let mib: u64 = mode
            .parse()
            .expect("bench: size in MiB as the fourth argument");
        let compression = match feature.as_deref().unwrap_or("off") {
            "off" => zfs_ondisk::blkptr::Compression::Off,
            "lz4" => zfs_ondisk::blkptr::Compression::Lz4,
            "gzip" => zfs_ondisk::blkptr::Compression::Gzip(6),
            other => panic!("bench: unknown compression {other}"),
        };
        let mut pool = if kind == "bench" {
            Pool::mirror("tank", 0x5eed_0000_0000_0001, ashift)
        } else {
            Pool::raidz("tank", 0x5eed_0000_0000_0002, ashift, 4, 2)
        }
        .txgs(&[(4816229, 1757100005)]);
        let dense = Dense {
            bytes: mib << 20,
            blocksize: 128 << 10,
            compression,
        };
        let (members, sha256) = dense_volume_members(&mut pool, dense);
        std::fs::create_dir_all(&dir).expect("mkdir");
        println!(
            "tank/vm/disk0 is {mib} MiB, dense, 128 KiB blocks, compression {}",
            compression.name()
        );
        println!("sha256 {sha256}");
        for (i, img) in members.iter().enumerate() {
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, img).expect("write");
            println!("{}", p.display());
        }
        return;
    }
    if kind == "striped" {
        assert!(mode.is_empty(), "striped takes no mode");
        let (_, members) = two_top_mirror_members(
            "tank",
            0x5eed_0000_0000_0003,
            ashift,
            [2, 3],
            &[(4816229, 1757100005)],
            64 * 1024 * 1024,
        );
        std::fs::create_dir_all(&dir).expect("mkdir");
        println!("tank/vm/disk0's data is on mirror-1 (members 2..5); the MOS is on mirror-0 (members 0..2)");
        for (i, img) in members.iter().enumerate() {
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, img).expect("write");
            println!("{}", p.display());
        }
        return;
    }
    let mut pool = match kind.as_str() {
        "mirror" => Pool::mirror("tank", 0x5eed_0000_0000_0001, ashift),
        "mirror3" => Pool::mirror_of("tank", 0x5eed_0000_0000_0001, ashift, 3),
        "raidz2" => Pool::raidz("tank", 0x5eed_0000_0000_0002, ashift, 4, 2),
        other => panic!("unknown kind {other}"),
    }
    .txgs(&[
        (4816228, 1757100000),
        (4816229, 1757100005),
        (4816230, 1757100010),
    ]);
    if let Some(f) = &feature {
        println!("the labels claim {f} is active");
        pool = pool.with_feature(f);
    }
    std::fs::create_dir_all(&dir).expect("mkdir");
    let n = pool.members.len();
    let size = 64 * 1024 * 1024u64;
    // A MOS in which tank/vm/disk0 exists at the older TXGs and is
    // destroyed at the newest; laid out as a mirror or with RAIDZ parity.
    let members = if removed {
        println!(
            "tank/vm/disk0 lives at addresses on top-level vdev 1, which the pool had removed"
        );
        removed_vdev_members(&mut pool, size)
    } else if zpl {
        println!("tank/fs is a filesystem dataset with a small POSIX tree");
        zpl_members(&mut pool, size)
    } else if carved {
        println!("tank/vm/disk0 is on the members, and no uberblock leads to it");
        carved_zvol_members(&mut pool, size)
    } else if dedup {
        let (members, destroyed_at, last_with) = dedup_zvol_members(&mut pool, size);
        println!(
            "tank/vm/disk0 is deduplicated (dedup=sha256,verify), destroyed at txg {destroyed_at}, last present at txg {last_with}"
        );
        members
    } else {
        let (members, destroyed_at, last_with) = destroyed_zvol_members(&mut pool, size);
        println!("tank/vm/disk0 destroyed at txg {destroyed_at}, last present at txg {last_with}");
        members
    };
    let _ = n;
    for (i, img) in members.iter().enumerate() {
        let p = dir.join(format!("member{i}.img"));
        std::fs::write(&p, img).expect("write");
        println!("{}", p.display());
    }
}
