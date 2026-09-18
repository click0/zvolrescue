//! Seeds for the fuzz targets (fuzz/): one well-formed instance of each
//! structure, built with the same encoders the unit tests use, so that
//! the fuzzer starts from something the parser accepts rather than from
//! noise it rejects in the first byte.
//!
//!     cargo run -p zfs-ondisk --example fuzz-seeds -- fuzz/seeds
//!
//! The output is committed; regenerate it when an encoder changes.

use std::fs;
use std::path::Path;

use zfs_ondisk::blkptr::encode::Builder;
use zfs_ondisk::dmu::encode::DnodeSpec;
use zfs_ondisk::nvlist::encode::{list, pack};
use zfs_ondisk::nvlist::Value;
use zfs_ondisk::{dmu, dsl, uberblock, zap};

fn put(dir: &Path, target: &str, name: &str, bytes: &[u8]) {
    let d = dir.join(target);
    fs::create_dir_all(&d).unwrap();
    fs::write(d.join(name), bytes).unwrap();
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "fuzz/seeds".into());
    let out = Path::new(&out);

    // A label's configuration: the shape `scan` reads on every member.
    let leaf = |id: u64, path: &str| {
        list(vec![
            ("type", Value::String("disk".into())),
            ("id", Value::Uint64(id)),
            ("guid", Value::Uint64(0x1234_5678_0000 + id)),
            ("path", Value::String(path.into())),
        ])
    };
    let tree = list(vec![
        ("type", Value::String("mirror".into())),
        ("id", Value::Uint64(0)),
        ("guid", Value::Uint64(0xfeed_face)),
        ("ashift", Value::Uint64(12)),
        ("asize", Value::Uint64(1 << 30)),
        (
            "children",
            Value::ListArray(vec![leaf(0, "/dev/gpt/a"), leaf(1, "/dev/gpt/b")]),
        ),
    ]);
    let config = list(vec![
        ("version", Value::Uint64(5000)),
        ("name", Value::String("tank".into())),
        ("state", Value::Uint64(0)),
        ("txg", Value::Uint64(4816229)),
        ("pool_guid", Value::Uint64(0xdead_beef)),
        ("top_guid", Value::Uint64(0xfeed_face)),
        ("guid", Value::Uint64(0x1234_5678_0000)),
        ("vdev_children", Value::Uint64(1)),
        ("vdev_tree", Value::List(tree)),
        (
            "features_for_read",
            Value::List(list(vec![("com.delphix:hole_birth", Value::Boolean)])),
        ),
    ]);
    put(out, "nvlist", "label-config", &pack(&config));

    // A block pointer with two DVAs, and one embedded.
    let bp = Builder::new()
        .dva(0, 0, 0x4000, 0x2000, false)
        .dva(1, 0, 0x8000, 0x2000, false)
        .sizes(0x4000, 0x2000)
        .props(15, 7, dmu::ot::OBJSET, 0)
        .births(3, 3, 1)
        .cksum([1, 2, 3, 4]);
    put(
        out,
        "blkptr",
        "two-dvas",
        &bp.0
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<_>>(),
    );
    let emb = Builder::new().embedded(b"hello, embedded", 15, 2, dmu::ot::PLAIN_FILE_CONTENTS);
    put(
        out,
        "blkptr",
        "embedded",
        &emb.0
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<_>>(),
    );

    // A dnode with one block pointer and a bonus, and an objset header.
    let spec = DnodeSpec {
        object_type: dmu::ot::PLAIN_FILE_CONTENTS,
        indblkshift: 17,
        nlevels: 1,
        datablksz: 0x20000,
        maxblkid: 0,
        blkptrs: vec![bp
            .0
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()],
        bonus_type: 17, // DMU_OT_ZNODE
        bonus: vec![0u8; 64],
        ..Default::default()
    };
    let dnode = spec.build();
    put(out, "dnode", "plain-file", &dnode);
    put(out, "dnode", "objset", &dmu::encode::objset(&dnode, 1));

    // A microzap, a fat ZAP header and a leaf.
    put(
        out,
        "zap",
        "micro",
        &zap::encode::micro(512, &[("root_dataset", 2), ("config", 1)]),
    );
    put(
        out,
        "zap",
        "fat-header",
        &zap::encode::fat_header(4096, 1, 2),
    );
    put(
        out,
        "zap",
        "leaf",
        &zap::encode::leaf(
            4096,
            &[
                ("a", 8, 1u64.to_le_bytes().to_vec()),
                ("bb", 1, b"x".to_vec()),
            ],
        ),
    );

    // An uberblock slot: magic, version, txg, guid sum, timestamp, root bp.
    let mut ub = vec![0u8; 1024];
    ub[..8].copy_from_slice(&uberblock::MAGIC.to_le_bytes());
    ub[8..16].copy_from_slice(&5000u64.to_le_bytes());
    ub[16..24].copy_from_slice(&4816229u64.to_le_bytes());
    ub[24..32].copy_from_slice(&0xdead_beefu64.to_le_bytes());
    ub[32..40].copy_from_slice(&1_700_000_000u64.to_le_bytes());
    for (i, w) in bp.0.iter().enumerate() {
        ub[40 + i * 8..48 + i * 8].copy_from_slice(&w.to_le_bytes());
    }
    put(out, "uberblock", "slot", &ub);

    // Bonus buffers.
    put(
        out,
        "bonus",
        "dsl-dir",
        &dsl::encode::dsl_dir(&dsl::DslDirPhys::default()),
    );
    put(out, "bonus", "znode", &vec![0u8; 264]);

    // Compressed blocks: lz4 (15) in ZFS's framing — a big-endian
    // length, then the block — and zle (14): one byte above 64 is that
    // many minus 64 zeros.
    let plain = b"abababababababababababababababab".repeat(4);
    let block = lz4_flex::block::compress(&plain);
    let mut lz4 = vec![15, plain.len() as u8, (plain.len() >> 8) as u8, 0];
    lz4.extend_from_slice(&(block.len() as u32).to_be_bytes());
    lz4.extend_from_slice(&block);
    put(out, "compress", "lz4", &lz4);
    let zle = vec![14, 66, 0, 0, 0x81];
    put(out, "compress", "zle", &zle);

    // A GPT header alone, and a GEOM label sector.
    let mut gpt = vec![0u8; 512];
    gpt[..8].copy_from_slice(b"EFI PART");
    gpt[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    gpt[12..16].copy_from_slice(&92u32.to_le_bytes());
    gpt[24..32].copy_from_slice(&1u64.to_le_bytes());
    gpt[72..80].copy_from_slice(&2u64.to_le_bytes());
    gpt[80..84].copy_from_slice(&128u32.to_le_bytes());
    gpt[84..88].copy_from_slice(&128u32.to_le_bytes());
    put(out, "part", "gpt-header", &gpt);
    let mut glabel = vec![0u8; 512];
    glabel[..12].copy_from_slice(b"GEOM::LABEL\0");
    glabel[16..20].copy_from_slice(&2u32.to_le_bytes());
    glabel[20..24].copy_from_slice(b"tank");
    glabel[36..44].copy_from_slice(&((64u64 << 20) + 512).to_le_bytes());
    put(out, "part", "glabel", &glabel);

    // A seed the parser rejects is a seed wasted, so each is read back
    // by the parser its target calls before it is written.
    use zfs_ondisk::{compress, geom, nvlist, Endian};
    assert!(nvlist::parse_packed(&pack(&config)).is_ok(), "nvlist seed");
    let bp_bytes: Vec<u8> = bp.0.iter().flat_map(|w| w.to_le_bytes()).collect();
    assert!(
        zfs_ondisk::blkptr::BlkPtr::parse(&bp_bytes, Endian::Little).is_ok(),
        "blkptr seed"
    );
    assert!(
        dmu::DnodePhys::parse(&dnode, Endian::Little).is_ok(),
        "dnode seed"
    );
    assert!(
        dmu::ObjsetPhys::parse(&dmu::encode::objset(&dnode, 1), Endian::Little).is_ok(),
        "objset seed"
    );
    assert!(
        zap::parse_micro(&zap::encode::micro(512, &[("a", 1)]), Endian::Little).is_ok(),
        "microzap seed"
    );
    assert!(
        zap::parse_fat_header(&zap::encode::fat_header(4096, 1, 2), Endian::Little).is_ok(),
        "fat seed"
    );
    assert!(uberblock::Uberblock::parse(&ub).is_ok(), "uberblock seed");
    assert!(
        dsl::DslDirPhys::parse(
            &dsl::encode::dsl_dir(&dsl::DslDirPhys::default()),
            Endian::Little
        )
        .is_ok(),
        "dsl seed"
    );
    assert_eq!(
        compress::lz4(&lz4[4..], plain.len()).as_deref(),
        Ok(&plain[..]),
        "lz4 seed"
    );
    assert_eq!(
        compress::zle(&zle[4..], 66).map(|v| v.len()),
        Ok(66),
        "zle seed"
    );
    assert!(geom::parse(&glabel).is_some(), "glabel seed");
    eprintln!("seeds written to {} and read back", out.display());
}
