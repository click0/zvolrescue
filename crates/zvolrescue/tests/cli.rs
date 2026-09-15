//! The command line, end to end, on fixture members written to disk:
//! what `scan`, `list` and `dump` print and exit with is the contract a
//! script relies on, and until now only CI steps held it.

use std::path::{Path, PathBuf};
use std::process::Command;

use zfs_ondisk::blkptr::LABEL_START_SIZE;
use zfs_ondisk::label::LABEL_SIZE;
use zfs_read::fixture::{
    build_sample_mos, removed_vdev_members, Alloc, Pool, SAMPLE_ZVOL_BLOCK0_OFFSET,
};
use zfs_read::hash::{Digests, Extra};

const SIZE: u64 = 64 * LABEL_SIZE;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zvolrescue-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A two-way mirror with the sample MOS at one txg, the volume present.
fn plain_members() -> Vec<Vec<u8>> {
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let mut members = vec![vec![0u8; SIZE as usize], vec![0u8; SIZE as usize]];
    let mut a = Alloc::new(0x20_0000);
    build_sample_mos(&mut pool, &mut members, &mut a);
    for (i, m) in members.iter_mut().enumerate() {
        pool.write_labels(i, m);
    }
    members
}

fn write_members(dir: &Path, members: &[Vec<u8>]) -> Vec<String> {
    members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, m).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect()
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_zvolrescue"))
        .args(args)
        .output()
        .expect("run zvolrescue");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).unwrap_or_else(|e| panic!("not JSON ({e}): {stdout}"))
}

#[test]
fn scan_tells_a_removed_vdev_from_a_missing_one() {
    let dir = scratch("scan-removed");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let members = write_members(&dir, &removed_vdev_members(&mut pool, SIZE));

    let (code, out, _) = run(&["-q", "-f", "json", "scan", &members[0], &members[1]]);
    assert_eq!(code, 0);
    let pool = &json(&out)["pools"][0];
    assert_eq!(pool["readable"], true, "{pool}");
    assert_eq!(pool["removed_tops"], serde_json::json!([1]), "{pool}");
    assert_eq!(pool["missing_tops"], serde_json::json!([]), "{pool}");
    assert_eq!(pool["device_removal"], true, "{pool}");

    let (_, text, _) = run(&["-q", "scan", &members[0], &members[1]]);
    assert!(text.contains("READABLE from scanned members"), "{text}");
    assert!(
        text.contains("top-level vdev #1: removed; its blocks live on the vdevs that remain"),
        "{text}"
    );
    assert!(!text.contains("MISSING"), "{text}");
}

#[test]
fn scan_of_a_healthy_pool_says_nothing_about_removal() {
    let dir = scratch("scan-plain");
    let members = write_members(&dir, &plain_members());
    let (code, out, _) = run(&["-q", "-f", "json", "scan", &members[0], &members[1]]);
    assert_eq!(code, 0);
    let pool = &json(&out)["pools"][0];
    assert_eq!(pool["readable"], true);
    assert_eq!(pool["removed_tops"], serde_json::json!([]));
    assert_eq!(pool["device_removal"], false);
}

#[test]
fn list_reports_properties_only_when_asked() {
    let dir = scratch("list-props");
    let members = write_members(&dir, &plain_members());

    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "list",
        "-r",
        "-p",
        &members[0],
        &members[1],
    ]);
    assert_eq!(code, 0);
    let by_name: std::collections::BTreeMap<String, serde_json::Value> = json(&out)["datasets"]
        .as_array()
        .expect("datasets")
        .iter()
        .map(|d| (d["name"].as_str().unwrap().to_string(), d.clone()))
        .collect();
    assert_eq!(
        by_name["tank/vm/disk0"]["properties"],
        serde_json::json!([
            {"name": "compression", "value": 15, "means": "lz4"},
            {"name": "checksum", "value": 12, "means": "skein"},
            {"name": "org.example:ticket", "value": "RT-4471"},
        ])
    );
    // Set nothing: an empty list, not an absent key.
    assert_eq!(by_name["tank/vm"]["properties"], serde_json::json!([]));

    let (_, text, _) = run(&["-q", "list", "-r", "-p", &members[0]]);
    assert!(text.contains("property: compression = 15 (lz4)"), "{text}");
    assert!(
        text.contains("property: org.example:ticket = RT-4471"),
        "{text}"
    );

    // Not asked: not read, and not in the output at all.
    let (_, out, _) = run(&["-q", "-f", "json", "list", "-r", &members[0]]);
    for d in json(&out)["datasets"].as_array().expect("datasets") {
        assert!(d.get("properties").is_none(), "{d}");
    }
}

#[test]
fn dump_takes_the_legacy_digests_in_the_same_pass_and_only_when_asked() {
    let dir = scratch("dump-hash");
    let members = write_members(&dir, &plain_members());
    let out_img = dir.join("vol.img");
    let out_s = out_img.to_string_lossy().into_owned();

    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &members[0],
        &members[1],
        "--hash",
        "md5,sha1",
        "-o",
        &out_s,
    ]);
    assert_eq!(code, 0);
    let v = &json(&out)["volumes"][0];
    // What was printed is what the written file hashes to.
    let mut d = Digests::new(Extra {
        md5: true,
        sha1: true,
    });
    d.update(&std::fs::read(&out_img).expect("image"));
    let got = d.finish();
    assert_eq!(v["sha256"], got.sha256);
    assert_eq!(v["sha1"], got.sha1.expect("sha1"));
    assert_eq!(v["md5"], got.md5.expect("md5"));

    let plain = dir.join("plain.img");
    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &members[0],
        "-o",
        &plain.to_string_lossy(),
    ]);
    assert_eq!(code, 0);
    let v = &json(&out)["volumes"][0];
    assert!(v.get("sha1").is_none() && v.get("md5").is_none(), "{v}");

    let (code, _, err) = run(&[
        "-q",
        "dump",
        "tank/vm/disk0",
        &members[0],
        "--hash",
        "crc32",
        "-o",
        &dir.join("x.img").to_string_lossy(),
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("unknown digest \"crc32\""), "{err}");
}

#[test]
fn an_image_with_zeroed_blocks_exits_4_and_a_healed_one_exits_0() {
    let dir = scratch("dump-zeroed");
    let mut members = plain_members();
    let at = (LABEL_START_SIZE + SAMPLE_ZVOL_BLOCK0_OFFSET) as usize;
    let intact = members[1].clone();
    // Both copies of block 0 damaged: nothing to heal from.
    members[0][at + 5] ^= 0xff;
    members[1][at + 5] ^= 0xff;
    let paths = write_members(&dir, &members);
    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "-o",
        &dir.join("zeroed.img").to_string_lossy(),
    ]);
    assert_eq!(code, 4, "{out}");
    let v = &json(&out)["volumes"][0];
    assert_eq!(v["blocks_zeroed"], 1, "{v}");
    assert_eq!(v["aborted"], false);
    let zeroed_hash = v["sha256"].clone();

    // One copy intact: healed from it, nothing zeroed, exit 0.
    let good = dir.join("member1-intact.img");
    std::fs::write(&good, &intact).expect("write");
    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &good.to_string_lossy(),
        "-o",
        &dir.join("healed.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}");
    let v = &json(&out)["volumes"][0];
    assert_eq!(v["blocks_zeroed"], 0, "{v}");
    assert_ne!(v["sha256"], zeroed_hash, "a zeroed block changes the image");

    // --strict on the damaged pair: aborted, and still 4.
    let (code, out, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &paths[0],
        &paths[1],
        "--strict",
        "-o",
        &dir.join("strict.img").to_string_lossy(),
    ]);
    assert_eq!(code, 4, "{out}");
    assert_eq!(json(&out)["volumes"][0]["aborted"], true);
}
