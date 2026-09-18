//! Every structure that lives in a dnode's bonus buffer or a metadata
//! block: space maps, indirect mappings, DSL directories and datasets,
//! bpobjs, deadlists, znodes and system-attribute headers.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zfs_ondisk::{dsl, indirect, spacemap, zpl, Endian};

fuzz_target!(|data: &[u8]| {
    for endian in [Endian::Little, Endian::Big] {
        let _ = spacemap::SpaceMapPhys::parse(data, endian);
        let _ = spacemap::entries(data, (data.first().copied().unwrap_or(9) % 32) as u32, endian);
        let _ = indirect::MappingPhys::parse(data, endian);
        let _ = indirect::Entry::parse(data, endian);
        if let Ok(m) = indirect::Mapping::parse(data, (data.len() / 16) as u64, endian) {
            let _ = m.remap(0, 4096);
            let _ = m.mapped_bytes();
        }
        let _ = dsl::DslDirPhys::parse(data, endian);
        let _ = dsl::DslDatasetPhys::parse(data, endian).map(|d| d.is_snapshot());
        let _ = dsl::BpobjPhys::parse(data, endian);
        let _ = dsl::DeadlistPhys::parse(data, endian);
        let _ = zpl::parse_znode_phys(data, endian).map(|z| (z.file_type(), z.permissions()));
        let _ = zpl::parse_sa_header(data, endian);
    }
});
