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
    for r in index.rejected.iter().take(10) {
        println!(
            "  rejected {:>12} by {}{}",
            r.count,
            r.reason,
            if r.profile { " (profile)" } else { "" }
        );
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
