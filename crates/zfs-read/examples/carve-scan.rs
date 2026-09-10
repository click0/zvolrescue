//! Scan a member for dnodes nothing points at any more.
//!
//! `cargo run -p zfs-read --example carve-scan -- MEMBER [ashift] [type]`

use std::path::PathBuf;

use zfs_ondisk::carve::Profile;
use zfs_read::carve::{scan_member, score, Options};
use zvolrescue_io::FileSource;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = PathBuf::from(
        args.next()
            .expect("usage: carve-scan MEMBER [ashift] [type]"),
    );
    let ashift: u32 = args.next().map_or(12, |a| a.parse().expect("ashift"));
    let dnode_type: Option<u8> = args.next().map(|t| t.parse().expect("type"));
    let src = FileSource::open(&path).expect("open");
    let opts = Options {
        profile: Profile {
            dnode_type,
            ..Profile::default()
        },
        ..Options::default()
    };
    let scan = scan_member(&src, 0, ashift, &opts).expect("scan");
    println!(
        "{}: {} bytes read, {} slots, {} hit(s)",
        path.display(),
        scan.bytes_read,
        scan.slots_examined,
        scan.hits.len()
    );
    let mut by_type = std::collections::BTreeMap::new();
    for h in &scan.hits {
        *by_type.entry(h.dnode.type_name()).or_insert(0u64) += 1;
    }
    let lz4 = scan
        .hits
        .iter()
        .filter(|h| h.found == zfs_read::carve::Found::Lz4)
        .count();
    println!("  {} plaintext, {lz4} from lz4", scan.hits.len() - lz4);
    for (t, n) in &by_type {
        println!("  {n:>6} {t}");
    }
    for (r, n) in scan.counts.ranked().iter().take(8) {
        println!("  rejected {n:>10} by {}", r.as_str());
    }
    let mut best: Vec<_> = scan.hits.iter().map(|h| (score(h), h)).collect();
    best.sort_by(|a, b| b.0.partial_cmp(&a.0).expect("finite"));
    for (s, h) in best.iter().take(5) {
        println!(
            "  score {s:.2} {} at {:#x}+{} datablksz {} nlevels {} maxblkid {} ({})",
            h.dnode.type_name(),
            h.offset,
            h.slot,
            h.dnode.datablksz(),
            h.dnode.nlevels,
            h.dnode.maxblkid,
            h.found.as_str()
        );
    }
}
