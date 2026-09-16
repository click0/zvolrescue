//! The command line, end to end, on fixture members written to disk:
//! what `scan`, `list` and `dump` print and exit with is the contract a
//! script relies on, and until now only CI steps held it.

use std::path::{Path, PathBuf};
use std::process::Command;

use zfs_ondisk::blkptr::LABEL_START_SIZE;
use zfs_ondisk::label::LABEL_SIZE;
use zfs_read::fixture::{
    build_sample_mos, destroyed_zvol_members, removed_vdev_members, Alloc, Pool,
    SAMPLE_ZVOL_BLOCK0_OFFSET,
};
use zfs_read::hash::{Digests, Extra};

const SIZE: u64 = 64 * LABEL_SIZE;

fn scratch(name: &str) -> PathBuf {
    let tmp = std::env::temp_dir();
    // What an earlier run left under this name: each test writes tens
    // of megabytes, and a directory per process id adds up.
    if let Ok(entries) = std::fs::read_dir(&tmp) {
        for e in entries.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("zvolrescue-cli-") && n.ends_with(&format!("-{name}")) {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    let dir = tmp.join(format!("zvolrescue-cli-{}-{name}", std::process::id()));
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
    assert_eq!(
        v["blocks_salvaged"], 0,
        "a checksum mismatch names no sector: {v}"
    );
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

/// `--diff` names what one transaction group has that the other does
/// not, by guid: the destroyed volume and its snapshot, with the
/// command that gets each back.
#[test]
fn list_diff_names_what_the_newest_txg_no_longer_has() {
    let dir = scratch("list-diff");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1), (200, 2)]);
    let (members, newest, previous) = destroyed_zvol_members(&mut pool, SIZE);
    assert_eq!((newest, previous), (200, 100));
    let paths = write_members(&dir, &members);

    let (code, out, _) = run(&[
        "-q", "-f", "json", "list", "-r", "--diff", "100", &paths[0], &paths[1],
    ]);
    assert_eq!(code, 0, "{out}");
    let v = json(&out);
    assert_eq!(v["txg"], 200);
    let diff = &v["diff"];
    assert_eq!(diff["txg"], 100);
    assert_eq!(diff["created_since"], serde_json::json!([]));
    let gone: Vec<&str> = diff["destroyed_since"]
        .as_array()
        .expect("destroyed_since")
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        gone,
        vec!["tank/vm/disk0", "tank/vm/disk0@before"],
        "{diff}"
    );
    // Nothing that reads properties runs here, so none are reported.
    assert!(diff["destroyed_since"][0].get("properties").is_none());

    let (_, text, _) = run(&["-q", "list", "-r", "--diff", "100", &paths[0]]);
    assert!(text.contains("compared with txg 100"), "{text}");
    assert!(
        text.contains("destroyed  tank/vm/disk0 ") && text.contains("--txg 100"),
        "{text}"
    );

    // A transaction group no uberblock verifies at is an error, not an
    // empty diff.
    let (code, _, err) = run(&["-q", "list", "-r", "--diff", "150", &paths[0]]);
    assert_eq!(code, 3);
    assert!(
        err.contains("--diff txg 150 has no verified uberblock"),
        "{err}"
    );
}

/// `--resume` believes a state file only as far as the output backs it
/// up: a state that names another dataset, or claims more bytes than
/// the file holds, is set aside and the extraction starts over, and
/// the image and its digests come out the same either way.
#[test]
fn a_resume_state_the_output_does_not_back_up_is_set_aside() {
    let dir = scratch("dump-resume");
    let members = write_members(&dir, &plain_members());
    let img = dir.join("vol.img");
    let img_s = img.to_string_lossy().into_owned();
    let state_path = dir.join("vol.img.resume.json");
    let dump = |extra: &[&str]| {
        let mut args = vec![
            "-q",
            "-f",
            "json",
            "dump",
            "tank/vm/disk0",
            &members[0],
            "--hash",
            "md5",
            "-o",
            &img_s,
        ];
        args.extend_from_slice(extra);
        let (code, out, err) = run(&args);
        assert_eq!(code, 0, "{out}{err}");
        (json(&out)["volumes"][0].clone(), err)
    };
    let (first, _) = dump(&[]);
    assert_eq!(first["resumed_from_block"], 0);
    assert!(!state_path.exists(), "a finished dump leaves no state");
    let want = (first["sha256"].clone(), first["md5"].clone());
    let state = |dataset: &str, blocks_done: u64| {
        serde_json::json!({
            "version": 1,
            "dataset": dataset,
            "dataset_guid": first["dataset_guid"],
            "txg": first["txg"],
            "volsize": first["volsize"],
            "blocksize": first["blocksize"],
            "blocks_done": blocks_done,
        })
        .to_string()
    };

    // An honest state: the first two blocks are in the file, and they
    // are hashed back before the rest is read.
    std::fs::write(&state_path, state("tank/vm/disk0", 2)).unwrap();
    let (v, err) = dump(&["--resume"]);
    assert_eq!(v["resumed_from_block"], 2, "{err}");
    assert_eq!((v["sha256"].clone(), v["md5"].clone()), want);
    assert_eq!(v["blocks_read"], 1, "only block 2 is read now; 3 is a hole");

    // A state for some other dataset.
    std::fs::write(&state_path, state("tank/other", 2)).unwrap();
    let (v, err) = dump(&["--resume"]);
    assert!(
        err.contains("describes a different dataset/txg/size"),
        "{err}"
    );
    assert_eq!(v["resumed_from_block"], 0);
    assert_eq!((v["sha256"].clone(), v["md5"].clone()), want);

    // A state that claims two blocks are done when the file holds less
    // than one.
    std::fs::write(&state_path, state("tank/vm/disk0", 2)).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&img)
        .unwrap()
        .set_len(4096)
        .unwrap();
    let (v, err) = dump(&["--resume"]);
    assert!(
        err.contains("shorter than the 16384 bytes the resume state claims; starting over"),
        "{err}"
    );
    assert_eq!(v["resumed_from_block"], 0);
    assert_eq!((v["sha256"].clone(), v["md5"].clone()), want);
    assert_eq!(std::fs::metadata(&img).unwrap().len(), 32 << 20);
}

/// The text report prints each legacy digest on its own line, and only
/// those that were taken.
#[test]
fn the_text_report_prints_the_legacy_digests_that_were_taken() {
    let dir = scratch("dump-text");
    let members = write_members(&dir, &plain_members());
    let img = dir.join("vol.img");
    let (code, text, _) = run(&[
        "-q",
        "dump",
        "tank/vm/disk0",
        &members[0],
        "--hash",
        "sha1",
        "-o",
        &img.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{text}");
    let mut d = Digests::new(Extra {
        md5: false,
        sha1: true,
    });
    d.update(&std::fs::read(&img).unwrap());
    let got = d.finish();
    assert!(
        text.contains(&format!("  sha256: {}", got.sha256)),
        "{text}"
    );
    assert!(
        text.contains(&format!("  sha1:   {}", got.sha1.unwrap())),
        "{text}"
    );
    assert!(!text.contains("  md5:"), "{text}");
}

/// A member that cannot be opened is reported as such, per device, and
/// the scan exits 2: evidence was missing, nothing was refused.
#[test]
fn scan_reports_a_member_it_cannot_open_and_exits_2() {
    let dir = scratch("scan-missing");
    let missing = dir.join("nothing-here.img");
    let missing_s = missing.to_string_lossy().into_owned();
    let (code, out, _) = run(&["-q", "-f", "json", "scan", &missing_s]);
    assert_eq!(code, 2, "{out}");
    let v = json(&out);
    assert_eq!(v["pools"], serde_json::json!([]));
    let dev = &v["devices"][0];
    assert_eq!(dev["path"], missing_s);
    assert_eq!(dev["size"], 0);
    assert!(
        dev["error"].as_str().unwrap().contains("No such file"),
        "{dev}"
    );

    let (code, text, _) = run(&["-q", "scan", &missing_s]);
    assert_eq!(code, 2);
    assert!(text.contains("error: No such file"), "{text}");
}

/// A whole-disk image: protective MBR, a GPT whose one partition is
/// named and has a unique GUID, and `member` inside it.
fn gpt_wrap(member: &[u8], start: u64, name: &str, guid_bytes: [u8; 16]) -> Vec<u8> {
    let sector = 512usize;
    let mut disk = vec![0u8; start as usize + member.len() + 64 * sector];
    disk[510] = 0x55;
    disk[511] = 0xaa;
    disk[446 + 4] = 0xee;
    disk[446 + 12..446 + 16].copy_from_slice(&u32::MAX.to_le_bytes());
    disk[sector..sector + 8].copy_from_slice(b"EFI PART");
    disk[sector + 80..sector + 84].copy_from_slice(&1u32.to_le_bytes());
    disk[sector + 84..sector + 88].copy_from_slice(&128u32.to_le_bytes());
    let mut e = vec![0u8; 128];
    // freebsd-zfs, 516e7cba-6ecf-11d6-8ff8-00022d09712b, on-disk order.
    e[..16].copy_from_slice(&[
        0xba, 0x7c, 0x6e, 0x51, 0xcf, 0x6e, 0xd6, 0x11, 0x8f, 0xf8, 0x00, 0x02, 0x2d, 0x09, 0x71,
        0x2b,
    ]);
    e[16..32].copy_from_slice(&guid_bytes);
    let first = start / sector as u64;
    let last = first + (member.len() / sector) as u64 - 1;
    e[32..40].copy_from_slice(&first.to_le_bytes());
    e[40..48].copy_from_slice(&last.to_le_bytes());
    for (i, u) in name.encode_utf16().enumerate() {
        e[56 + i * 2..58 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    disk[sector * 2..sector * 2 + 128].copy_from_slice(&e);
    disk[start as usize..start as usize + member.len()].copy_from_slice(member);
    disk
}

/// Zero every label's configuration, leaving the uberblock rings.
fn wipe_configs(img: &mut [u8]) {
    let (phys_off, phys) = (16 * 1024usize, 112 * 1024usize);
    let label = LABEL_SIZE as usize;
    let aligned = img.len() & !(label - 1);
    for off in [0, label, aligned - 2 * label, aligned - label] {
        img[off + phys_off..off + phys_off + phys].fill(0);
    }
}

/// A member whose labels are gone is tied to the leaf its siblings
/// describe by the name its own disk gives it (SPEC F-71): the GPT
/// label matches the `path` the pool recorded, `scan` says which leaf
/// that is and how to bind it, and the binding reads.
#[test]
fn a_bare_member_is_named_by_its_gpt_label_and_the_pool_says_which_leaf() {
    let dir = scratch("gpt-name");
    let members = plain_members();
    let good = dir.join("member0.img");
    std::fs::write(&good, &members[0]).unwrap();
    let mut bare = members[1].clone();
    wipe_configs(&mut bare);
    let disk = dir.join("disk1.img");
    std::fs::write(&disk, gpt_wrap(&bare, 1 << 20, "tank-d1", [0x33; 16])).unwrap();
    let (good_s, disk_s) = (
        good.to_string_lossy().into_owned(),
        disk.to_string_lossy().into_owned(),
    );

    let (code, out, _) = run(&["-q", "-f", "json", "scan", &good_s, &disk_s]);
    assert_eq!(code, 0, "{out}");
    let v = json(&out);
    let d = &v["devices"][1];
    let part = &d["partitions"]["partitions"][0];
    assert_eq!(part["name"], "tank-d1");
    assert_eq!(part["guid"], "33333333-3333-3333-3333-333333333333");
    assert_eq!(
        d["names"],
        serde_json::json!([
            "/dev/gpt/tank-d1",
            "/dev/disk/by-partlabel/tank-d1",
            "/dev/gptid/33333333-3333-3333-3333-333333333333",
            "/dev/disk/by-partuuid/33333333-3333-3333-3333-333333333333",
        ])
    );
    assert!(
        d["config"].is_null(),
        "no label configuration survives: {d}"
    );
    let members = &v["pools"][0]["tops"][0]["members"];
    assert_eq!(members[0]["present"], good_s);
    assert!(members[1]["present"].is_null());
    assert_eq!(members[1]["path"], "/dev/gpt/tank-d1");
    assert_eq!(members[1]["named_by"], disk_s, "{members}");
    assert!(members[0].get("named_by").is_none());
    assert!(
        v["pools"][0].get("name_hints").is_none(),
        "matched, so not a mere hint"
    );
    let guid = members[1]["guid"].as_str().unwrap().to_owned();

    let (_, text, _) = run(&["-q", "scan", &good_s, &disk_s]);
    assert!(text.contains("named: /dev/gpt/tank-d1"), "{text}");
    assert!(
        text.contains(&format!(
            "MISSING; {disk_s} is named /dev/gpt/tank-d1 on its own disk (SPEC F-71) — bind it with --assume-member {disk_s}={guid}"
        )),
        "{text}"
    );

    // The binding the scan spelled out is accepted: a sibling with its
    // labels describes the pool (F-62), the bare disk takes the vacant
    // leaf, and the volume comes out.
    let img = dir.join("bound.img");
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &good_s,
        &disk_s,
        "--assume-member",
        &format!("{disk_s}={guid}"),
        "-o",
        &img.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}{err}");
    let (_, whole, _) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &good_s,
        "-o",
        &dir.join("whole.img").to_string_lossy(),
    ]);
    assert_eq!(
        json(&out)["volumes"][0]["sha256"],
        json(&whole)["volumes"][0]["sha256"]
    );
}

/// A name that only contains the pool's name is reported as a hint and
/// binds nothing; a name no pool recorded is just listed.
#[test]
fn a_name_that_merely_contains_the_pool_name_is_a_hint_not_a_binding() {
    let dir = scratch("gpt-hint");
    let members = plain_members();
    let good = dir.join("member0.img");
    std::fs::write(&good, &members[0]).unwrap();
    let mut bare = members[1].clone();
    wipe_configs(&mut bare);
    let disk = dir.join("disk-x.img");
    std::fs::write(&disk, gpt_wrap(&bare, 1 << 20, "tank-spare", [0x44; 16])).unwrap();
    let (good_s, disk_s) = (
        good.to_string_lossy().into_owned(),
        disk.to_string_lossy().into_owned(),
    );
    let (code, out, _) = run(&["-q", "-f", "json", "scan", &good_s, &disk_s]);
    assert_eq!(code, 0, "{out}");
    let v = json(&out);
    let members = &v["pools"][0]["tops"][0]["members"];
    assert!(members[1].get("named_by").is_none(), "{members}");
    assert_eq!(
        v["pools"][0]["name_hints"],
        serde_json::json!([
            {"device": disk_s, "name": "/dev/gpt/tank-spare"},
            {"device": disk_s, "name": "/dev/disk/by-partlabel/tank-spare"},
        ])
    );
    let (_, text, _) = run(&["-q", "scan", &good_s, &disk_s]);
    assert!(
        text.contains("hint: ") && text.contains("nothing binds on it"),
        "{text}"
    );
    assert!(text.contains(" MISSING\n"), "{text}");
}

/// `glabel`: the name is in the last sector and the provider ZFS saw
/// ends there, so the rear labels are read where the metadata says and
/// the device answers to `/dev/label/NAME`.
#[test]
fn a_glabel_names_the_member_and_says_how_long_its_provider_was() {
    let dir = scratch("glabel");
    // A member 512 bytes short of a 256 KiB boundary, so that the one
    // sector the metadata occupies moves the rear labels.
    let psize = SIZE - 512;
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let mut members = vec![vec![0u8; psize as usize], vec![0u8; psize as usize]];
    let mut a = Alloc::new(0x20_0000);
    build_sample_mos(&mut pool, &mut members, &mut a);
    for (i, m) in members.iter_mut().enumerate() {
        pool.write_labels(i, m);
    }
    let mut tail = vec![0u8; 512];
    tail[..11].copy_from_slice(b"GEOM::LABEL");
    tail[16..20].copy_from_slice(&2u32.to_le_bytes());
    tail[20..27].copy_from_slice(b"tank-d0");
    // As glabel writes it: the size of the provider it was put on, the
    // metadata sector included.
    tail[36..44].copy_from_slice(&SIZE.to_le_bytes());
    let mut labelled = members[0].clone();
    labelled.extend_from_slice(&tail);
    let img = dir.join("label0.img");
    std::fs::write(&img, &labelled).unwrap();
    let img_s = img.to_string_lossy().into_owned();

    let (code, out, _) = run(&["-q", "-f", "json", "scan", &img_s]);
    assert_eq!(code, 0, "{out}");
    let d = &json(&out)["devices"][0];
    assert_eq!(d["size"], SIZE);
    assert_eq!(d["vdev_size"], psize);
    assert_eq!(d["vdev_base_from"], "GEOM metadata");
    assert_eq!(d["geom"]["class"], "label");
    assert_eq!(d["geom"]["name"], "tank-d0");
    assert_eq!(d["geom"]["provsize"], SIZE);
    assert_eq!(d["names"], serde_json::json!(["/dev/label/tank-d0"]));
    let ok = d["labels"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["config_checksum"] == "ok")
        .count();
    assert_eq!(ok, 4, "{}", d["labels"]);

    let (_, text, _) = run(&["-q", "scan", &img_s]);
    assert!(
        text.contains(&format!(
            "GEOM::LABEL v2 in the last sector: this was /dev/label/tank-d0, provider {SIZE} bytes; the vdev is {psize} bytes and its rear labels were read there"
        )),
        "{text}"
    );

    // And the pool reads through it.
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        "tank/vm/disk0",
        &img_s,
        "-o",
        &dir.join("out.img").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(json(&out)["volumes"][0]["blocks_zeroed"], 0);
}

/// `geli` is named for what it is: nothing under it is readable, and the
/// scan says so instead of reporting a disk with no ZFS on it.
#[test]
fn a_geli_provider_is_reported_as_encrypted() {
    let dir = scratch("geli");
    let mut img = vec![0u8; SIZE as usize];
    let at = img.len() - 512;
    img[at..at + 9].copy_from_slice(b"GEOM::ELI");
    img[at + 16..at + 20].copy_from_slice(&7u32.to_le_bytes());
    let p = dir.join("eli.img");
    std::fs::write(&p, &img).unwrap();
    let p_s = p.to_string_lossy().into_owned();
    let (_, out, _) = run(&["-q", "-f", "json", "scan", &p_s]);
    let d = &json(&out)["devices"][0];
    assert_eq!(d["geom"]["class"], "eli");
    assert!(d.get("names").is_none(), "{d}");
    let (_, text, _) = run(&["-q", "scan", &p_s]);
    assert!(
        text.contains("GEOM::ELI v7 in the last sector; the member is geli-encrypted"),
        "{text}"
    );
}
