//! Try a key against every encrypted dataset of a pool: derive the wrapping
//! key and unwrap the master/HMAC keys, printing one line per encryption
//! root. Nothing is decrypted beyond the key material.
//!
//! `cargo run -p zfs-read --example unwrap-key -- KEYSPEC MEMBER...`
//! where KEYSPEC is `raw:FILE`, `hex:HEX|@FILE` or `passphrase:TEXT|@FILE`.
//! Exit status is 1 when any encryption root refuses the key.

use std::collections::BTreeSet;
use std::path::PathBuf;

use zfs_read::crypt::{unwrap_keys, wrapping_key, KeyMaterial};
use zfs_read::dsl::{open_mos, walk};
use zfs_read::pool::{assemble, select_uberblock, uberblock_candidates, TxgSelect};
use zfs_read::vdev::scan_device;
use zfs_read::zio::PoolReader;
use zvolrescue_io::{BlockSource, FileSource};

fn main() {
    let mut args = std::env::args().skip(1);
    let spec = args.next().expect("KEYSPEC");
    let material = KeyMaterial::from_spec(&spec).expect("key spec");
    let paths: Vec<PathBuf> = args.map(PathBuf::from).collect();
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

    let mut seen = BTreeSet::new();
    let mut failed = 0;
    for d in &tree.datasets {
        let Some(enc) = &d.encryption else { continue };
        if !seen.insert(enc.crypto_key_obj) {
            continue;
        }
        let result = wrapping_key(&material, enc).and_then(|w| unwrap_keys(enc, &w));
        match result {
            Ok(keys) => println!(
                "{} crypto obj {} {} key guid {:#x} v{}: OK, master key {} bytes",
                d.name,
                enc.crypto_key_obj,
                enc.suite_name(),
                keys.key_guid,
                keys.version,
                keys.master.len()
            ),
            Err(e) => {
                failed += 1;
                println!(
                    "{} crypto obj {} {}: FAILED: {e}",
                    d.name,
                    enc.crypto_key_obj,
                    enc.suite_name()
                );
            }
        }
    }
    if seen.is_empty() {
        println!("no encrypted datasets");
    }
    std::process::exit(if failed > 0 { 1 } else { 0 });
}
