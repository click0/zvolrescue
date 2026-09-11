//! What the space maps of a pool say is allocated.
//!
//! `cargo run -p zfs-read --example space -- MEMBER...`

use zfs_read::dsl::open_mos;
use zfs_read::pool::{assemble, uberblock_candidates};
use zfs_read::spacemap;
use zfs_read::vdev::scan_device;
use zfs_read::zio::PoolReader;
use zvolrescue_io::{BlockSource, FileSource};

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    let sources: Vec<FileSource> = paths
        .iter()
        .map(|p| FileSource::open(p).expect("open"))
        .collect();
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
    let mos = open_mos(&reader, &ub).expect("mos");
    let space = spacemap::read(&reader, &pool, &mos);
    for w in &space.skipped {
        println!("skipped {w}");
    }
    for (id, v) in &space.vdevs {
        println!(
            "vdev {id}: {} metaslab(s), {} unreadable, {} range(s), replayed {} byte(s), declared {} byte(s){}",
            v.metaslabs,
            v.unreadable,
            v.allocated.len(),
            v.allocated.bytes(),
            v.declared_bytes,
            if v.consistent() { " — agree" } else { " — DISAGREE" }
        );
    }
}
