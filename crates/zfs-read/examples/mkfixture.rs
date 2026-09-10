//! Write fixture member images for smoke tests.
//!
//! `cargo run -p zfs-read --example mkfixture -- DIR [mirror|raidz2] [ashift] [carved|zpl]`
//! writes `DIR/member0.img`, `DIR/member1.img`, … with sealed labels,
//! three uberblocks each and, for mirrors, a small MOS with four datasets
//! at the older TXGs and the volume destroyed at the newest one.
//!
//! With `carved` as the fourth argument, no uberblock mentions the volume
//! at all, though its blocks are still on the member: the pool a carve
//! has to find something in when a walk cannot (COMPANIONS §3.4). With
//! `zpl`, the pool holds one filesystem dataset with a small POSIX tree
//! instead of a volume (COMPANIONS §5.4).

use std::path::PathBuf;

use zfs_read::fixture::{carved_zvol_members, destroyed_zvol_members, zpl_members, Pool};

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
    let carved = mode == "carved";
    let zpl = mode == "zpl";
    let mut pool = match kind.as_str() {
        "mirror" => Pool::mirror("tank", 0x5eed_0000_0000_0001, ashift),
        "raidz2" => Pool::raidz("tank", 0x5eed_0000_0000_0002, ashift, 4, 2),
        other => panic!("unknown kind {other}"),
    }
    .txgs(&[
        (4816228, 1757100000),
        (4816229, 1757100005),
        (4816230, 1757100010),
    ]);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let n = pool.members.len();
    let size = 64 * 1024 * 1024u64;
    // A MOS in which tank/vm/disk0 exists at the older TXGs and is
    // destroyed at the newest; laid out as a mirror or with RAIDZ parity.
    let members = if zpl {
        println!("tank/fs is a filesystem dataset with a small POSIX tree");
        zpl_members(&mut pool, size)
    } else if carved {
        println!("tank/vm/disk0 is on the members, and no uberblock leads to it");
        carved_zvol_members(&mut pool, size)
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
