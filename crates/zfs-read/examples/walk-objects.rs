//! Read every block of every object of every dataset in a pool and report
//! what was met: checksum outcomes per algorithm, compression codes,
//! encrypted/gang/embedded pointers. A self-consistency check for
//! zio/dmu on real pools (for example ones created by ztest).
//!
//! `cargo run -p zfs-read --example walk-objects -- MEMBER...`

use std::collections::BTreeMap;
use std::path::PathBuf;

use zfs_ondisk::dmu::ObjsetPhys;
use zfs_read::dmu::DnodeArray;
use zfs_read::dsl::{open_mos, walk};
use zfs_read::pool::{assemble, select_uberblock, uberblock_candidates, TxgSelect};
use zfs_read::vdev::scan_device;
use zfs_read::zio::{PoolReader, ReadError};
use zvolrescue_io::{BlockSource, FileSource};

fn main() {
    let paths: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    let sources: Vec<FileSource> = paths
        .iter()
        .map(|p| FileSource::open(p).expect("open"))
        .collect();
    let scans: Vec<_> = sources.iter().map(|s| scan_device(s).ok()).collect();
    let pool = assemble(&scans).into_iter().next().expect("a pool");
    let candidates = uberblock_candidates(&scans, &pool);
    let ub = select_uberblock(&candidates, TxgSelect::Newest).expect("uberblock");
    let devices: Vec<Option<&dyn BlockSource>> = sources
        .iter()
        .map(|s| Some(s as &dyn BlockSource))
        .collect();
    let reader = PoolReader::new(&pool, devices);
    let mos = open_mos(&reader, &ub.ub).expect("mos");
    let tree = walk(&mos, &pool.name).expect("walk");

    let mut outcomes: BTreeMap<String, u64> = BTreeMap::new();
    let mut compress: BTreeMap<String, u64> = BTreeMap::new();
    let mut objects = 0u64;
    let mut blocks = 0u64;
    let bump = |m: &mut BTreeMap<String, u64>, k: String| *m.entry(k).or_insert(0) += 1;
    if std::env::var_os("ZR_DEBUG").is_some() {
        zvolrescue_io::trace::enable(None);
    }
    let detail = std::env::var_os("ZR_DETAIL").is_some();

    let mut objsets: Vec<(String, zfs_ondisk::blkptr::BlkPtr)> = tree
        .datasets
        .iter()
        .map(|d| (d.name.clone(), d.phys.bp.clone()))
        .collect();
    // The MOS itself, through the uberblock's root pointer.
    objsets.push((
        "<mos>".into(),
        zfs_ondisk::blkptr::BlkPtr::parse(&ub.ub.rootbp, ub.ub.endian).unwrap(),
    ));
    for (name, bp) in objsets {
        if bp.is_hole() {
            continue;
        }
        let block = match reader.read_block(&bp, false) {
            Ok(b) => b,
            Err(e) => {
                bump(&mut outcomes, format!("objset {name}: {e}"));
                continue;
            }
        };
        let os = match ObjsetPhys::parse(&block.data, bp.endian) {
            Ok(o) => o,
            Err(e) => {
                bump(&mut outcomes, format!("objset {name}: parse {e}"));
                continue;
            }
        };
        let array = DnodeArray::new(&reader, os.meta_dnode, bp.endian);
        let max = array.max_object();
        let mut objnum = 0u64;
        while objnum < max {
            let this = objnum;
            objnum += 1;
            let dn = match array.get(this) {
                Ok(d) => d,
                Err(e) => {
                    bump(&mut outcomes, format!("dnode: {e}"));
                    if detail && e.to_string().contains("parse") {
                        // Show the raw slot so the failure can be understood.
                        let per = array.slots_per_block();
                        if let Ok(block) = array.meta_object().read_blkid(this / per) {
                            let at = ((this % per) * 512) as usize;
                            eprintln!(
                                "dataset {name} object {this}: {e}\n{}",
                                zvolrescue_io::trace::hexdump(&block[at..at + 64], at as u64, 64)
                            );
                        }
                    }
                    continue;
                }
            };
            if dn.is_free() {
                continue;
            }
            // A large dnode owns the following extra_slots slots: they are
            // its bonus buffer, not objects.
            objnum += u64::from(dn.extra_slots);
            objects += 1;
            let obj = array.object(this).unwrap();
            let nblocks = dn.maxblkid + 1;
            for blkid in 0..nblocks.min(4096) {
                match obj.locate(blkid) {
                    Ok(None) => continue,
                    Ok(Some(bp)) => {
                        blocks += 1;
                        bump(
                            &mut compress,
                            format!(
                                "{}{}",
                                bp.compression.name(),
                                if bp.encrypted { "+encrypted" } else { "" }
                            ),
                        );
                        let key = format!(
                            "{}{}{}",
                            bp.checksum.name(),
                            if bp.encrypted { " encrypted" } else { "" },
                            if bp.dvas().any(|d| d.gang) {
                                " gang"
                            } else {
                                ""
                            }
                        );
                        match reader.read_block(&bp, false) {
                            Ok(b) => bump(&mut outcomes, format!("{key}: {:?}", b.verify)),
                            Err(ReadError::ChecksumUnsupported) => {
                                bump(&mut outcomes, format!("{key}: unsupported"))
                            }
                            Err(ReadError::Encrypted) => {
                                bump(&mut outcomes, format!("{key}: Ok, ciphertext (no key)"))
                            }
                            Err(e) => {
                                bump(&mut outcomes, format!("{key}: ERROR {e}"));
                                if detail {
                                    eprintln!("dataset {name} object {this} ({}) blkid {blkid} level {} type {} {} psize {} lsize {} encrypted {}: {e}", dn.type_name(), bp.level, bp.object_type, bp.compression.name(), bp.psize, bp.lsize, bp.encrypted);
                                    if let Some(payload) = bp.embedded_payload() {
                                        eprintln!(
                                            "{}",
                                            zvolrescue_io::trace::hexdump(&payload, 0, 128)
                                        );
                                    } else if let Ok((raw, _)) =
                                        reader.read_dva(&bp.dva[0], bp.psize as usize)
                                    {
                                        eprintln!("{}", zvolrescue_io::trace::hexdump(&raw, 0, 48));
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => bump(&mut outcomes, format!("locate: ERROR {e}")),
                }
            }
        }
    }
    println!(
        "datasets {} objects {objects} blocks {blocks}",
        tree.datasets.len()
    );
    println!("checksum outcomes:");
    for (k, v) in &outcomes {
        println!("  {v:>7}  {k}");
    }
    println!("compression:");
    for (k, v) in &compress {
        println!("  {v:>7}  {k}");
    }
    let bad = outcomes
        .iter()
        .filter(|(k, _)| k.contains("ERROR") || k.contains("Mismatch"))
        .map(|(_, v)| v)
        .sum::<u64>();
    std::process::exit(if bad > 0 { 1 } else { 0 });
}
