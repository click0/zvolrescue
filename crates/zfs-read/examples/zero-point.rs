//! Find the vdev base of members whose labels are damaged, using nothing
//! but surviving uberblocks (F-61).
//!
//! `cargo run -p zfs-read --example zero-point -- [--psize BYTES] MEMBER...`
//!
//! Prints one line per confirmed base, with the number of anchors, the
//! newest TXG they carry and the labels they came from. Exit status is 1
//! when a member yields no anchor at all.

use std::path::PathBuf;

use zfs_read::zeropoint::{find, Search};
use zvolrescue_io::{BlockSource, FileSource};

fn main() {
    let mut opts = Search::default();
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--psize" => {
                let v = args.next().expect("--psize BYTES");
                opts.psize_hints.push(v.parse().expect("psize"));
            }
            "--whole" => opts.windows = vec![(0, u64::MAX)],
            _ => paths.push(PathBuf::from(a)),
        }
    }
    let mut failed = false;
    for path in &paths {
        let dev = FileSource::open(path).expect("open member");
        let found = find(&dev, &opts).expect("search");
        if found.is_empty() {
            println!("{}: no uberblock anchor found", path.display());
            failed = true;
            continue;
        }
        for z in &found {
            let mut labels: Vec<String> = z
                .anchors
                .iter()
                .map(|a| match a.label {
                    Some(l) => format!("L{l}"),
                    None => "L?".to_string(),
                })
                .collect();
            labels.dedup();
            println!(
                "{}: base {} ({} bytes into a {}-byte member), {} anchors {}, newest txg {}, psize {}",
                path.display(),
                z.base,
                z.base,
                dev.size(),
                z.anchors.len(),
                labels.join(","),
                z.newest_txg(),
                z.implied_psize()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "unknown".into()),
            );
        }
    }
    if failed {
        std::process::exit(1);
    }
}
