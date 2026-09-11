//! `zvolcarve list` — the candidates a scan found.

use std::path::Path;

use zvol_common::{exit, Format, Global};

use crate::model::{load_index, Index};

fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes}B")
    } else {
        format!("{v:.1}{}", UNITS[i])
    }
}

/// Print an index the way `scan` and `list` both do.
pub fn print(index: &Index) {
    println!(
        "{} candidate(s) from {} slot(s) in {} bytes of {}",
        index.candidates.len(),
        index.slots_examined,
        index.bytes_read,
        index.pool
    );
    // C-14: an empty list has to say whether the filter rejected
    // everything or there was nothing to reject.
    if index.candidates.is_empty() && index.rejected_by_profile > 0 {
        println!(
            "  none matched the profile: {} candidate(s) were rejected by it",
            index.rejected_by_profile
        );
    }
    // C-06: what the allocator says about the space, which is about
    // what happens next rather than about what is there now.
    if let Some(sp) = &index.space {
        if sp.vdevs_read > 0 {
            println!(
                "  space maps: {} vdev(s) read, {} byte(s) still given out{}",
                sp.vdevs_read,
                sp.allocated_bytes,
                if sp.may_lag {
                    " (recent allocations may not be in them yet)"
                } else {
                    ""
                }
            );
        }
        for w in &sp.skipped {
            println!("  space maps: {w}");
        }
    }
    if index.datasets_met > 0 {
        println!(
            "  {} dataset dnode(s) met, which is what can name a candidate",
            index.datasets_met
        );
    }
    for r in index.rejected.iter().take(10) {
        println!(
            "  rejected {:>12} by {}{}",
            r.count,
            r.reason,
            if r.profile { " (profile)" } else { "" }
        );
    }
    // C-19: what is actually on the disk, so a profile can be picked
    // from it. Printed before the candidates, because with a sample the
    // candidates are the raw material of the histograms, not an answer.
    if let Some(h) = &index.histograms {
        println!();
        println!("what {} sampled hit(s) look like:", h.sampled);
        let bars = |title: &str, buckets: &[crate::model::Bucket]| {
            if buckets.is_empty() {
                return;
            }
            println!("  {title}");
            let widest = buckets.iter().map(|b| b.count).max().unwrap_or(1).max(1);
            for b in buckets.iter().take(8) {
                let bar = (b.count * 40).div_ceil(widest) as usize;
                println!(
                    "    {:>16} {:>8}  {}",
                    b.value,
                    b.count,
                    "#".repeat(bar.max(1))
                );
            }
            if buckets.len() > 8 {
                println!("    {:>16} {} more", "…", buckets.len() - 8);
            }
        };
        bars("object type", &h.dnode_type);
        bars("block size", &h.volblocksize);
        bars("tree depth", &h.levels);
        bars("birth txg", &h.txg);
        println!();
        println!(
            "Pick a profile from these, then scan again with --volblocksize / --levels / --txg."
        );
        return;
    }
    if index.candidates.is_empty() {
        return;
    }
    println!();
    println!(
        "{:<8} {:>6} {:<20} {:>9} {:>6} {:>10} {:>12} {:>9} WHERE",
        "ID", "SCORE", "TYPE", "BLOCKSIZE", "LEVELS", "SIZE", "BIRTH", "VERIFIED"
    );
    for c in &index.candidates {
        let verified = match &c.assessment {
            None => "—".to_string(),
            Some(a) => format!("{:.0}%", a.agreement * 100.0),
        };
        println!(
            "{:<8} {:>6.2} {:<20} {:>9} {:>6} {:>10} {:>12} {:>9} {}:{:#x}+{} {}",
            c.id,
            c.score,
            c.dnode_type,
            c.volblocksize,
            c.levels,
            size(c.implied_size),
            c.birth,
            verified,
            c.device,
            c.offset,
            c.slot,
            c.found
        );
        if let Some(a) = &c.assessment {
            if a.blocks_allocated + a.blocks_free + a.blocks_unknown > 0 {
                println!(
                    "         space: {} block(s) still given out, {} released{}",
                    a.blocks_allocated,
                    a.blocks_free,
                    if a.blocks_unknown > 0 {
                        format!(", {} unaccounted for", a.blocks_unknown)
                    } else {
                        String::new()
                    }
                );
            }
        }
        if let Some(g) = &c.dataset_guid {
            println!(
                "         belonged to dataset {g}{}",
                c.dataset_creation_txg
                    .map_or(String::new(), |t| format!(" (created at txg {t})"))
            );
        }
        if !c.profile_misses.is_empty() {
            println!("         did not match: {}", c.profile_misses.join(", "));
        }
    }
    println!();
    println!(
        "Extract one with: zvolcarve dump DIR {} MEMBER... -o out.img",
        index.candidates[0].id
    );
}

/// Run `list`.
pub fn run(g: &Global, dir: &Path) -> u8 {
    let index = match load_index(dir) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("zvolcarve: {e}");
            return exit::EVIDENCE;
        }
    };
    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&index).expect("serialisable")
        ),
        Format::Text => print(&index),
    }
    0
}
