//! `zvolcarve list` — the candidates a scan found.

use std::path::Path;
use zvol_common::text::{shown, shown_path};
use zvol_common::{errln, outln};

use zfs_ondisk::dmu::DnodePhys;
use zfs_ondisk::Endian;
use zfs_read::carve::{Found, Hit};
use zvol_common::{exit, Format, Global};

use crate::model::{
    from_hex, load_index, AssessmentOut, Candidate, Index, Progress, State, INDEX, STATE,
};
use crate::roots::Names;

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

/// The share of a walk that agreed, as the list shows it: 100% is said
/// of a candidate no block of which failed, and of no other. Rounded,
/// one failed block in 640 was "100%", and so were 4999 in a million.
fn verified(a: &AssessmentOut) -> String {
    let percent = (a.agreement * 100.0 + 1e-9).floor() as u64;
    let percent = if a.blocks_failed > 0 {
        percent.min(99)
    } else {
        percent
    };
    format!("{percent}%")
}

/// Why a candidate has the score it has (C-05), for `-v`: the profile
/// decides which half of the range it is in, and its structure and its
/// walk where in that half ([`zfs_read::carve::rank`]).
fn explain(c: &Candidate) {
    // What the dnode's own shape scores is not in the index; the dnode
    // is, and it is scored again as the scan scored it.
    let structure = from_hex(&c.dnode_hex)
        .ok()
        .and_then(|b| DnodePhys::parse(&b, Endian::Little).ok())
        .map(|dnode| {
            zfs_read::carve::score(&Hit {
                device: c.device,
                offset: c.offset,
                slot: c.slot,
                found: Found::Plaintext,
                dnode,
                misses: Vec::new(),
            })
        });
    let band = if c.profile_misses.is_empty() {
        "0.55 for matching the profile, and 0.45 of"
    } else {
        "below every candidate that matched the profile: 0.45 of"
    };
    let structure = structure.map_or("?".to_string(), |s| format!("{s:.2}"));
    match &c.assessment {
        Some(a) => {
            outln!(
                "         score {:.4}: {band} the mean of its structure ({structure}) and its walk ({:.4})",
                c.score,
                a.agreement
            );
            let looked = a.blocks_verified + a.blocks_holes + a.blocks_failed;
            outln!(
                "         walk: of {looked} block(s) looked at{}, {} verified, {} hole(s), {} failed",
                if a.sampled {
                    format!(
                        " (a sample of {}; --full-assess reads every one)",
                        a.blocks_total
                    )
                } else {
                    String::new()
                },
                a.blocks_verified,
                a.blocks_holes,
                a.blocks_failed
            );
        }
        None => outln!(
            "         score {:.4}: {band} its structure ({structure}); not walked, with no pool to read it through",
            c.score
        ),
    }
}

/// Print an index the way `scan` and `list` both do, its candidates
/// named by what `roots` found in the same workspace.
pub fn print(index: &Index, names: &Names, verbose: bool) {
    outln!(
        "{} candidate(s) from {} slot(s) in {} bytes of {}",
        index.candidates.len(),
        index.slots_examined,
        index.bytes_read,
        shown(&index.pool)
    );
    // A list from a scan that stopped part of the way is the list of
    // that part, and has to say so: handed on, it read as the answer
    // about the whole disk. A sample stops where it has enough, and
    // says what it is further down.
    if let Some(p) = index
        .progress
        .as_ref()
        .filter(|p| !p.complete && index.histograms.is_none())
    {
        outln!(
            "  NOT FINISHED: the scan stopped before the end of what it was to read, and this is what the part it read holds; `zvolcarve scan --resume` goes on"
        );
        for (i, reached) in p.reached.iter().enumerate() {
            let member = index
                .members
                .get(i)
                .map_or_else(|| format!("member {i}"), |m| shown_path(m));
            match p.member_bytes.get(i).copied() {
                None => outln!("    {member}: read to byte {reached}"),
                // A member that did not open was not there to read.
                Some(0) => {}
                Some(size) => {
                    let end = p.range.map_or(size, |[_, end]| end.min(size));
                    if *reached < end {
                        outln!("    {member}: read to byte {reached} of {end}");
                    }
                }
            }
        }
    }
    // C-14: an empty list has to say whether the filter rejected
    // everything or there was nothing to reject.
    if index.candidates.is_empty() && index.rejected_by_profile > 0 {
        outln!(
            "  none matched the profile: {} candidate(s) were rejected by it",
            index.rejected_by_profile
        );
    }
    // C-06: what the allocator says about the space, which is about
    // what happens next rather than about what is there now.
    if let Some(sp) = &index.space {
        if sp.vdevs_read > 0 {
            outln!(
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
            outln!("  space maps: {w}");
        }
    }
    if index.datasets_met > 0 {
        outln!(
            "  {} dataset dnode(s) met, which is what can name a candidate",
            index.datasets_met
        );
    }
    for r in index.rejected.iter().take(10) {
        outln!(
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
        outln!();
        outln!("what {} sampled hit(s) look like:", h.sampled);
        let bars = |title: &str, buckets: &[crate::model::Bucket]| {
            if buckets.is_empty() {
                return;
            }
            outln!("  {title}");
            let widest = buckets.iter().map(|b| b.count).max().unwrap_or(1).max(1);
            for b in buckets.iter().take(8) {
                let bar = (b.count * 40).div_ceil(widest) as usize;
                outln!(
                    "    {:>16} {:>8}  {}",
                    b.value,
                    b.count,
                    "#".repeat(bar.max(1))
                );
            }
            if buckets.len() > 8 {
                outln!("    {:>16} {} more", "…", buckets.len() - 8);
            }
        };
        bars("object type", &h.dnode_type);
        bars("block size", &h.volblocksize);
        bars("tree depth", &h.levels);
        bars("birth txg", &h.txg);
        outln!();
        outln!(
            "Pick a profile from these, then scan again with --volblocksize / --levels / --txg."
        );
        return;
    }
    if index.candidates.is_empty() {
        return;
    }
    outln!();
    outln!(
        "{:<8} {:>6} {:<20} {:>9} {:>6} {:>10} {:>12} {:>9} WHERE",
        "ID",
        "SCORE",
        "TYPE",
        "BLOCKSIZE",
        "LEVELS",
        "SIZE",
        "BIRTH",
        "VERIFIED"
    );
    for c in &index.candidates {
        let verified = c
            .assessment
            .as_ref()
            .map_or_else(|| "—".to_string(), verified);
        outln!(
            "{:<8} {:>6.2} {:<20} {:>9} {:>6} {:>10} {:>12} {:>9} {}:{:#x}+{} {}",
            c.id,
            // Down, not to the nearest: 1.00 is a candidate with nothing
            // against it, and 0.9997 was shown as one.
            (c.score * 100.0 + 1e-9).floor() / 100.0,
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
        for f in &c.contents {
            outln!(
                "         holds {}{}{}",
                f.kind,
                f.size
                    .map_or(String::new(), |s| format!(", made for {}", size(s))),
                f.label
                    .as_ref()
                    .map_or(String::new(), |l| format!(", label {l:?}"))
            );
        }
        if let Some(a) = &c.assessment {
            if a.blocks_allocated + a.blocks_free + a.blocks_unknown > 0 {
                outln!(
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
            let created = c
                .dataset_creation_txg
                .map_or(String::new(), |t| format!("created at txg {t}"));
            match names.of(g) {
                // The GUID is the dataset's own; the name is what a MOS
                // header found by `roots` calls it.
                Some(n) => outln!(
                    "         belonged to dataset {} ({g}{}{created}){}{}",
                    shown(&n.name),
                    if created.is_empty() { "" } else { ", " },
                    n.volsize
                        .map_or(String::new(), |v| format!(": a volume made {}", size(v))),
                    match names.newest() {
                        Some(newest) if n.last_txg >= newest =>
                            format!("; the pool's newest root (txg {newest}) names it"),
                        _ => format!(
                            "; last named by the root of txg {}, and not by the newest",
                            n.last_txg
                        ),
                    }
                ),
                None => outln!(
                    "         belonged to dataset {g}{}",
                    if created.is_empty() {
                        String::new()
                    } else {
                        format!(" ({created})")
                    }
                ),
            }
        }
        if !c.profile_misses.is_empty() {
            outln!("         did not match: {}", c.profile_misses.join(", "));
        }
        if verbose {
            explain(c);
        }
    }
    outln!();
    outln!(
        "Extract one with: zvolcarve dump DIR {} MEMBER... -o out.img",
        index.candidates[0].id
    );
}

/// Run `list`.
pub fn run(g: &Global, dir: &Path) -> u8 {
    let mut index = match load_index(dir) {
        Ok(i) => i,
        Err(e) => {
            errln!("zvolcarve: {e}");
            return exit::EVIDENCE;
        }
    };
    // An index written before it recorded how far its scan got has the
    // scan's state beside it, which says.
    if index.progress.is_none() {
        index.progress = std::fs::read_to_string(dir.join(STATE))
            .ok()
            .and_then(|t| serde_json::from_str::<State>(&t).ok())
            .map(|s| Progress {
                complete: s.complete,
                range: s.range,
                reached: s.reached,
                member_bytes: Vec::new(),
            });
    }
    // The candidates' datasets, by the names `roots` found them under,
    // when it has been run into this workspace.
    let names = Names::load_or_say(dir);
    for c in &mut index.candidates {
        if let Some(n) = c.dataset_guid.as_deref().and_then(|g| names.of(g)) {
            c.dataset_name = Some(n.name.clone());
            c.dataset_volsize = n.volsize;
            c.dataset_last_txg = Some(n.last_txg);
        }
    }
    match g.format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&index).expect("serialisable")
        ),
        Format::Text => print(&index, &names, g.verbose > 0),
    }
    // On the record like every other run: `--evidence-log` was taken,
    // the file created, and nothing written to it. What was shown is the
    // index, which the record names as what the run read; the list
    // itself is in that file, not copied here.
    let shown = serde_json::json!({
        "workspace": dir,
        "pool": index.pool,
        "pool_guid": index.pool_guid,
        "candidates": index.candidates.len(),
        "named": index
            .candidates
            .iter()
            .filter(|c| c.dataset_name.is_some())
            .count(),
        "complete": index.progress.as_ref().map(|p| p.complete),
    });
    // And `roots.json`, where the names came from it.
    let mut read = vec![dir.join(INDEX)];
    if index.candidates.iter().any(|c| c.dataset_name.is_some()) {
        read.push(dir.join(crate::roots::ROOTS));
    }
    g.log_evidence("zvolcarve", &shown, 0, &read, Vec::new())
}
