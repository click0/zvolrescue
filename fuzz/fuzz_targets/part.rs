//! What surrounds a member: a GPT header and its entries, an MBR, and a
//! GEOM metadata sector.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zfs_ondisk::{geom, part};

fuzz_target!(|data: &[u8]| {
    let _ = geom::parse(data).map(|m| (m.inner_size(), m.device_name()));
    let _ = part::parse_mbr(data, 512).map(|t| t.candidate_bases());
    let head = data.len().min(512);
    for backup in [false, true] {
        if let Some(t) = part::parse_gpt(&data[..head], &data[head..], 512, backup) {
            let _ = t.candidate_bases();
            for p in &t.partitions {
                let _ = p.device_names();
            }
        }
    }
});
