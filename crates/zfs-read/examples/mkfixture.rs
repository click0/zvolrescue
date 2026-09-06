//! Write fixture member images for smoke tests.
//!
//! `cargo run -p zfs-read --example mkfixture -- DIR [mirror|raidz2] [ashift]`
//! writes `DIR/member0.img`, `DIR/member1.img`, … with sealed labels,
//! three uberblocks each and, for mirrors, a small MOS with four datasets
//! at the older TXGs and the volume destroyed at the newest one.

use std::path::PathBuf;

use zfs_read::fixture::{destroyed_zvol_members, Pool};

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
    let members: Vec<Vec<u8>> = if kind == "mirror" {
        // Mirror members carry the same blocks; give them a MOS in which
        // tank/vm/disk0 exists at the older TXGs and is destroyed at the
        // newest. RAIDZ data layout is phase 2.
        let (m, destroyed_at, last_with) = destroyed_zvol_members(&mut pool, size);
        println!("tank/vm/disk0 destroyed at txg {destroyed_at}, last present at txg {last_with}");
        m
    } else {
        let mut m: Vec<Vec<u8>> = (0..n).map(|_| vec![0u8; size as usize]).collect();
        for (i, img) in m.iter_mut().enumerate() {
            pool.write_labels(i, img);
        }
        m
    };
    for (i, img) in members.iter().enumerate() {
        let p = dir.join(format!("member{i}.img"));
        std::fs::write(&p, img).expect("write");
        println!("{}", p.display());
    }
}
