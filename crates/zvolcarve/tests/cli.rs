//! `zvolcarve` end to end on a pool whose volume nothing points at:
//! the scan finds it, the dump gets it out, and the legacy digests are
//! taken in the same pass, only when asked (SPEC F-53).

use std::path::PathBuf;
use std::process::Command;

use zfs_ondisk::label::LABEL_SIZE;
use zfs_read::fixture::{carved_zvol_members, Pool};
use zfs_read::hash::{Digests, Extra};

const SIZE: u64 = 64 * LABEL_SIZE;

/// What the 32 MiB fixture volume comes to; the same number the CI
/// cross-check holds `zvolrescue dump` and `zvolcarve dump` to.
const FIXTURE_SHA256: &str = "febfe0108392728dbde89ee63f9f25419a0192ac04420db3ad88b0032a088585";

fn scratch(name: &str) -> PathBuf {
    let tmp = std::env::temp_dir();
    // What an earlier run left under this name: each test writes tens
    // of megabytes, and a directory per process id adds up.
    if let Ok(entries) = std::fs::read_dir(&tmp) {
        for e in entries.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("zvolcarve-cli-") && n.ends_with(&format!("-{name}")) {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    let dir = tmp.join(format!("zvolcarve-cli-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_zvolcarve"))
        .args(args)
        .output()
        .expect("run zvolcarve");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).unwrap_or_else(|e| panic!("not JSON ({e}): {stdout}"))
}

/// One sector an imager could not read costs that sector, not the 4 MiB
/// chunk around it: the scan finds what it finds without the map, says
/// how many bytes it could not search, and exits 4 rather than 0.
#[test]
fn an_unreadable_sector_costs_a_sector_not_a_chunk() {
    let dir = scratch("map-sector");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let members: Vec<String> = carved_zvol_members(&mut pool, SIZE)
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, m).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect();
    let count = |ws: &str| -> usize {
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(format!("{ws}/candidates.json")).unwrap())
                .unwrap();
        assert!(index["unreadable_bytes"].is_u64(), "{index}");
        index["candidates"].as_array().unwrap().len()
    };
    let plain = dir.join("plain").to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "scan", &members[0], &members[1], "-o", &plain]);
    assert_eq!(code, 0, "{err}");
    let want = count(&plain);
    assert!(want > 0);

    let map = dir.join("m0.map");
    std::fs::write(
        &map,
        format!(
            "0x0 +\n0x0 0x800000 +\n0x800000 0x200 -\n0x800200 {:#x} +\n",
            SIZE - 0x800200
        ),
    )
    .unwrap();
    let mapped = dir.join("mapped").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &members[0],
        &members[1],
        "--map",
        &format!("{}={}", members[0], map.display()),
        "-o",
        &mapped,
    ]);
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("512 byte(s) could not be read"), "{err}");
    assert_eq!(count(&mapped), want);
}

/// Nothing a carve writes lands on what it reads: a member lying in the
/// workspace as `candidates.json` was replaced by the index, and
/// `dump -o` naming the index replaced the index with the image.
#[test]
fn a_carve_writes_nothing_over_what_it_reads() {
    let dir = scratch("over-inputs");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let carve = dir.join("carve");
    std::fs::create_dir_all(&carve).unwrap();
    let names = [carve.join("candidates.json"), dir.join("member1.img")];
    let members: Vec<String> = carved_zvol_members(&mut pool, SIZE)
        .iter()
        .zip(&names)
        .map(|(m, p)| {
            std::fs::write(p, m).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect();
    let before = std::fs::read(&members[0]).unwrap();
    let carve_s = carve.to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "scan", &members[0], &members[1], "-o", &carve_s]);
    assert_eq!(code, 5, "{err}");
    assert_eq!(
        std::fs::read(&members[0]).unwrap(),
        before,
        "the member was written"
    );

    // A proper workspace, then a dump told to write over its index.
    let ws = dir.join("ws").to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "scan", &members[0], &members[1], "-o", &ws]);
    assert_eq!(code, 0, "{err}");
    let index_path = dir.join("ws/candidates.json");
    let index = std::fs::read(&index_path).unwrap();
    let id = serde_json::from_slice::<serde_json::Value>(&index).unwrap()["candidates"][0]["id"]
        .as_str()
        .expect("a candidate")
        .to_owned();
    let index_s = index_path.to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "dump",
        &ws,
        &id,
        &members[0],
        &members[1],
        "-o",
        &index_s,
    ]);
    assert_eq!(code, 5, "{err}");
    assert_eq!(
        std::fs::read(&index_path).unwrap(),
        index,
        "the index was written"
    );
    // A candidate asked for by its number is pointed at its name: it
    // was "no candidate 1", and nothing said to type c0001.
    let number = id.trim_start_matches(['c', '0']);
    let out = dir.join("n.img").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "dump",
        &ws,
        number,
        &members[0],
        &members[1],
        "-o",
        &out,
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains(&format!("did you mean {id}?")), "{err}");

    // Nor do the logs, which no word of the command line ties to the
    // index: a debug log there was created over it at the start — then
    // the run refused — and an evidence log was appended to it.
    let out = dir.join("c.img").to_string_lossy().into_owned();
    for (log, cmd) in [
        (
            "--debug-log",
            vec!["dump", &ws, &id, &members[0], &members[1], "-o", &out],
        ),
        (
            "--evidence-log",
            vec!["dump", &ws, &id, &members[0], &members[1], "-o", &out],
        ),
        (
            "--debug-log",
            vec!["scan", "--resume", &members[0], &members[1], "-o", &ws],
        ),
        ("--evidence-log", vec!["list", &ws]),
    ] {
        let mut args = vec!["-q", log, &index_s];
        args.extend(cmd.iter().copied());
        let (code, _, err) = run(&args);
        assert_eq!(code, 5, "{log} {cmd:?}: {err}");
        assert_eq!(
            std::fs::read(&index_path).unwrap(),
            index,
            "{log} {cmd:?} wrote the index"
        );
    }
    // A workspace that does not exist yet is no exception.
    let fresh = dir.join("fresh");
    let fresh_s = fresh.to_string_lossy().into_owned();
    let fresh_index = fresh.join("candidates.json").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "--evidence-log",
        &fresh_index,
        "scan",
        &members[0],
        &members[1],
        "-o",
        &fresh_s,
    ]);
    assert_eq!(code, 5, "{err}");
}

#[test]
fn a_carved_volume_is_hashed_in_the_same_pass_and_only_when_asked() {
    let dir = scratch("hash");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let members: Vec<String> = carved_zvol_members(&mut pool, SIZE)
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, m).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect();
    let carve = dir.join("carve");
    let carve_s = carve.to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "scan", &members[0], &members[1], "-o", &carve_s]);
    assert_eq!(code, 0, "{err}");
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(carve.join("candidates.json")).expect("candidates.json"),
    )
    .expect("index");
    let best = &index["candidates"][0];
    assert_eq!(best["dnode_type_code"], 23, "{best}"); // DMU_OT_ZVOL
    let id = best["id"].as_str().expect("id").to_owned();

    let img = dir.join("carved.img");
    let img_s = img.to_string_lossy().into_owned();
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        &carve_s,
        &id,
        &members[0],
        &members[1],
        "--hash",
        "md5,sha1",
        "-o",
        &img_s,
    ]);
    assert_eq!(code, 0, "{out}{err}");
    let v = json(&out);
    assert_eq!(v["candidate"], id);
    assert_eq!(v["size"], 32 << 20);
    assert_eq!(v["blocks_zeroed"], 0);
    let mut d = Digests::new(Extra {
        md5: true,
        sha1: true,
    });
    d.update(&std::fs::read(&img).expect("image"));
    let got = d.finish();
    assert_eq!(got.sha256, FIXTURE_SHA256);
    assert_eq!(v["sha256"], got.sha256);
    assert_eq!(v["sha1"], got.sha1.clone().expect("sha1"));
    assert_eq!(v["md5"], got.md5.clone().expect("md5"));

    // Not asked for: present as null, so a script sees the key and
    // knows the digest was not taken rather than lost.
    let plain = dir.join("plain.img");
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        &carve_s,
        &id,
        &members[0],
        "-o",
        &plain.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}{err}");
    let v = json(&out);
    assert_eq!(v["sha256"], FIXTURE_SHA256);
    assert!(v["sha1"].is_null() && v["md5"].is_null(), "{v}");

    // Text: one line per digest taken.
    let text_img = dir.join("text.img");
    let (code, text, _) = run(&[
        "-q",
        "dump",
        &carve_s,
        &id,
        &members[0],
        "--hash",
        "sha1",
        "-o",
        &text_img.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{text}");
    assert!(
        text.contains(&format!("  sha256: {FIXTURE_SHA256}")),
        "{text}"
    );
    assert!(
        text.contains(&format!("  sha1:   {}", got.sha1.unwrap())),
        "{text}"
    );
    assert!(!text.contains("  md5:"), "{text}");

    // A digest this build does not have is a usage error before any
    // byte is read.
    let (code, _, err) = run(&[
        "-q",
        "dump",
        &carve_s,
        &id,
        &members[0],
        "--hash",
        "crc32",
        "-o",
        &dir.join("never.img").to_string_lossy(),
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("--hash: unknown digest \"crc32\""), "{err}");
}

/// C-07, SPEC F-32: `dump --resume` takes up the state file `zvolrescue
/// dump` would have written — the same shape, the candidate id where
/// the dataset name goes — hashes the prefix already there, and ends
/// with the hash of a straight run; a state that names another
/// candidate starts over and says so.
#[test]
fn a_carved_dump_resumes_from_its_state_file() {
    let dir = scratch("resume");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let members: Vec<String> = carved_zvol_members(&mut pool, SIZE)
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, m).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect();
    let carve = dir.join("carve");
    let carve_s = carve.to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "scan", &members[0], &members[1], "-o", &carve_s]);
    assert_eq!(code, 0, "{err}");
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(carve.join("candidates.json")).expect("candidates.json"),
    )
    .expect("index");
    let id = index["candidates"][0]["id"]
        .as_str()
        .expect("id")
        .to_owned();

    // A straight run, for the image and its hash.
    let whole = dir.join("whole.img");
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        &carve_s,
        &id,
        &members[0],
        &members[1],
        "-o",
        &whole.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{out}{err}");
    let v = json(&out);
    assert_eq!(v["resumed_from_block"], 0, "{v}");
    assert!(v["interrupted_at"].is_null(), "{v}");
    let blocksize = v["blocksize"].as_u64().expect("blocksize");
    assert!(!dir.join("whole.img.resume.json").exists());
    let image = std::fs::read(&whole).expect("image");

    // A run that stopped after two blocks: its prefix, and a state
    // file in the shared shape saying so.
    let cut = dir.join("cut.img");
    std::fs::write(&cut, &image[..2 * blocksize as usize]).expect("prefix");
    let state = serde_json::json!({
        "version": 1, "dataset": id, "dataset_guid": "candidate", "txg": 0,
        "volsize": 32 << 20, "blocksize": blocksize, "blocks_done": 2,
    });
    std::fs::write(dir.join("cut.img.resume.json"), state.to_string()).expect("state");
    let (code, out, err) = run(&[
        "-f",
        "json",
        "dump",
        &carve_s,
        &id,
        &members[0],
        &members[1],
        "-o",
        &cut.to_string_lossy(),
        "--resume",
    ]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(err.contains(&format!("resuming {id} at block 2")), "{err}");
    let v = json(&out);
    assert_eq!(v["resumed_from_block"], 2, "{v}");
    assert_eq!(v["sha256"], FIXTURE_SHA256, "{v}");
    assert_eq!(std::fs::read(&cut).expect("image"), image);
    assert!(!dir.join("cut.img.resume.json").exists());

    // The same state against another candidate id starts over.
    let state = serde_json::json!({
        "version": 1, "dataset": "c9999", "dataset_guid": "candidate", "txg": 0,
        "volsize": 32 << 20, "blocksize": blocksize, "blocks_done": 2,
    });
    std::fs::write(dir.join("cut.img.resume.json"), state.to_string()).expect("state");
    let (code, out, err) = run(&[
        "-f",
        "json",
        "dump",
        &carve_s,
        &id,
        &members[0],
        "-o",
        &cut.to_string_lossy(),
        "--resume",
    ]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        err.contains("describes a different dataset/txg/size"),
        "{err}"
    );
    assert_eq!(json(&out)["resumed_from_block"], 0);
}

/// The refusal follows what the path resolves to: a symlink to a
/// device — the `/dev/mapper/NAME` and `/dev/disk/by-id/…` names an
/// operator types — is refused like the device itself (SPEC N-10).
#[cfg(unix)]
#[test]
fn a_symlink_to_a_device_is_not_carved_without_leave() {
    if !std::path::Path::new("/dev/null").exists() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("zvolcarve-symlink-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let link = dir.join("disk");
    std::os::unix::fs::symlink("/dev/null", &link).unwrap();
    let link = link.to_string_lossy().into_owned();
    let (code, _out, err) = run(&["scan", &link, "-o", "/nonexistent/carve"]);
    assert_eq!(code, 5, "{err}");
    assert!(
        err.contains("a block device is not scanned (SPEC N-10)"),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Carving is a surface scan, and a block device is refused one
/// before it is even opened (SPEC N-10): exit 5 and the reason.
#[test]
fn a_block_device_is_not_carved_without_leave() {
    if !std::path::Path::new("/dev/null").exists() {
        return;
    }
    let (code, _out, err) = run(&["scan", "/dev/null", "-o", "/nonexistent/carve"]);
    assert_eq!(code, 5, "{err}");
    assert!(
        err.contains("a block device is not scanned (SPEC N-10)"),
        "{err}"
    );
    assert!(err.contains("--surface-scan-on-device"), "{err}");
    let (code, _out, err) = run(&[
        "scan",
        "/dev/null",
        "-o",
        "/nonexistent/carve",
        "--surface-scan-on-device",
    ]);
    assert_ne!(code, 5, "{err}");
}

/// The scan's contract as the manual states it: a mirror's leaves are
/// copies and each candidate is listed once (C-09); a scan that finds
/// nothing is exit 3; a range that starts between two slots finds what
/// the slot-aligned one does; and `--dnode-type` given on the command
/// line wins over the profile's, while a profile that names no type
/// looks for volumes.
#[test]
fn the_scan_does_what_the_manual_says() {
    let dir = scratch("contract");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let members: Vec<String> = carved_zvol_members(&mut pool, SIZE)
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, m).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect();
    let index = |ws: &str| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(format!("{ws}/candidates.json")).unwrap()).unwrap()
    };
    let ws = |n: &str| dir.join(n).to_string_lossy().into_owned();

    let both = ws("both");
    let (code, _, err) = run(&["-q", "scan", &members[0], &members[1], "-o", &both]);
    assert_eq!(code, 0, "{err}");
    let one = ws("one");
    let (code, _, err) = run(&["-q", "scan", &members[0], "-o", &one]);
    assert_eq!(code, 0, "{err}");
    let (b, o) = (index(&both), index(&one));
    assert_eq!(
        b["candidates"].as_array().unwrap().len(),
        o["candidates"].as_array().unwrap().len()
    );
    assert!(b["mirror_duplicates"].as_u64().unwrap() > 0, "{b}");

    let off = ws("off");
    let range = format!("1000-{SIZE}");
    let (code, _, err) = run(&["-q", "scan", &members[0], "--range", &range, "-o", &off]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(index(&off)["candidates"], o["candidates"]);

    let none = ws("none");
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &members[0],
        "-o",
        &none,
        "--volblocksize",
        "1048576",
        "--strict-profile",
    ]);
    assert_eq!(code, 3, "{err}");

    let profile = dir.join("p.json");
    std::fs::write(&profile, r#"{"dnode_type": "file"}"#).unwrap();
    let p = profile.to_string_lossy().into_owned();
    let pw = ws("profile");
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &members[0],
        "-o",
        &pw,
        "--profile",
        &p,
        "--dnode-type",
        "zvol",
    ]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(index(&pw)["profile"]["dnode_type"], "zvol object");
    std::fs::write(&profile, r#"{"volblocksize": 8192}"#).unwrap();
    let pv = ws("profile-vbs");
    let (code, _, err) = run(&["-q", "scan", &members[0], "-o", &pv, "--profile", &p]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(index(&pv)["profile"]["dnode_type"], "zvol object");
}

/// Members written to `dir`, from a pool of this guid.
fn carved_members(dir: &std::path::Path, guid: u64, tag: &str) -> Vec<String> {
    let mut pool = Pool::mirror("tank", guid, 12).txgs(&[(100, 1)]);
    carved_zvol_members(&mut pool, SIZE)
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let p = dir.join(format!("{tag}{i}.img"));
            std::fs::write(&p, m).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect()
}

/// A carve's extraction is on the record in the shape `zvolrescue dump`
/// gives one — `volumes`, with the pool it came from — so a report
/// built from the log has it; it had none. And a candidate read
/// through another pool's members, which only gave zeros and exit 4,
/// is refused.
#[test]
fn a_carved_dump_is_a_volume_of_the_pool_it_was_found_in() {
    let dir = scratch("dump-record");
    let members = carved_members(&dir, 0x4242, "member");
    let carve = dir.join("carve").to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "scan", &members[0], &members[1], "-o", &carve]);
    assert_eq!(code, 0, "{err}");
    let img = dir.join("carved.img").to_string_lossy().into_owned();
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "dump",
        &carve,
        "c0001",
        &members[0],
        &members[1],
        "-o",
        &img,
    ]);
    assert_eq!(code, 0, "{err}");
    let v = json(&out);
    assert_eq!(v["pool_guid"], "0x0000000000004242");
    let vol = &v["volumes"][0];
    assert_eq!(vol["dataset"], "c0001");
    assert_eq!(vol["output"], img.as_str());
    assert_eq!(vol["volsize"], 32 << 20);
    assert_eq!(vol["sha256"], FIXTURE_SHA256);
    assert_eq!(vol["blocks_zeroed"], 0);
    assert_eq!(vol["aborted"], false);

    let other = carved_members(&dir, 0x5151, "other");
    let (code, _, err) = run(&[
        "-q",
        "dump",
        &carve,
        "c0001",
        &other[0],
        &other[1],
        "-o",
        &dir.join("never.img").to_string_lossy(),
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("give the members that scan read"), "{err}");
    assert!(!dir.join("never.img").exists());
}

/// `--resume` goes on with the scan that was started, or refuses: with
/// another pool's members it skipped as many bytes of theirs as the
/// first run had read of its own, and a range past the end of every
/// member is a usage error, not "nothing found".
#[test]
fn a_resume_is_of_the_same_scan() {
    let dir = scratch("resume-same");
    let members = carved_members(&dir, 0x4242, "member");
    let other = carved_members(&dir, 0x5151, "other");
    let carve = dir.join("carve").to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "scan", &members[0], &members[1], "-o", &carve]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = run(&["-q", "scan", &other[0], &other[1], "-o", &carve, "--resume"]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("a scan of something else"), "{err}");
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &members[0],
        &members[1],
        "-o",
        &carve,
        "--resume",
    ]);
    assert_eq!(code, 0, "{err}");
    // A scan of the second half, resumed: the same half, not the
    // whole member from where the first one stopped; and a resume over
    // a range that starts elsewhere is refused.
    let half = dir.join("half").to_string_lossy().into_owned();
    let second = format!("{}-{}", SIZE / 2, SIZE);
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &members[0],
        &members[1],
        "-o",
        &half,
        "--range",
        &second,
    ]);
    assert!(code == 0 || code == 3, "{err}");
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("half/state.json")).unwrap()).unwrap();
    assert_eq!(
        state["range"],
        serde_json::json!([SIZE / 2, SIZE]),
        "{state}"
    );
    let whole = format!("0-{SIZE}");
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &members[0],
        &members[1],
        "-o",
        &half,
        "--resume",
        "--range",
        &whole,
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("the scan began at byte"), "{err}");
    let past = format!("{}-{}", SIZE * 2, SIZE * 3);
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &members[0],
        "-o",
        &dir.join("past").to_string_lossy(),
        "--range",
        &past,
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("past the end of every member"), "{err}");
}

/// `roots` and `zeropoint` are on the evidence record like every other
/// run, with what they wrote; and `roots` lists a header the two sides
/// of a mirror both hold once.
#[test]
fn roots_and_zeropoint_are_on_the_record() {
    let dir = scratch("roots-record");
    let members = carved_members(&dir, 0x4242, "member");
    let log = dir.join("case.jsonl").to_string_lossy().into_owned();
    let roots = dir.join("roots");
    let (code, _, err) = run(&[
        "-q",
        "--evidence-log",
        &log,
        "roots",
        &members[0],
        &members[1],
        "-o",
        &roots.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(roots.join("roots.json")).unwrap()).unwrap();
    let listed = doc["roots"].as_array().unwrap();
    assert!(!listed.is_empty());
    assert!(
        listed
            .iter()
            .all(|r| r["member"] == members[0].as_str() && r["also_on"][0] == members[1].as_str()),
        "{doc}"
    );
    let (code, _, err) = run(&[
        "-q",
        "--evidence-log",
        &log,
        "zeropoint",
        &members[0],
        "-o",
        &dir.join("zp").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    let records: Vec<serde_json::Value> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let wrote: Vec<String> = records
        .iter()
        .map(|r| {
            r["outputs"][0]["path"]
                .as_str()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(wrote, ["roots.json", "zeropoint.json"]);
}

/// The scan's state is kept from the logs and the image like its index,
/// and a state that does not read stops a resume rather than letting it
/// begin again from nothing over the record of where it had got to.
#[test]
fn the_scan_state_is_kept_and_a_bad_one_stops_a_resume() {
    let dir = scratch("state-kept");
    let members = carved_members(&dir, 0x4242, "member");
    let carve = dir.join("carve");
    let c = carve.to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "scan", &members[0], &members[1], "-o", &c]);
    assert_eq!(code, 0, "{err}");
    let state = carve.join("state.json");
    let before = std::fs::read(&state).unwrap();
    let s = state.to_string_lossy().into_owned();
    for args in [
        vec![
            "-q",
            "--debug-log",
            &s,
            "dump",
            &c,
            "c0001",
            &members[0],
            "-o",
        ],
        vec!["-q", "--evidence-log", &s, "list", &c],
    ] {
        let mut args = args.clone();
        let img = dir.join("c.img").to_string_lossy().into_owned();
        if args.last() == Some(&"-o") {
            args.push(&img);
            let (code, _, err) = run(&args);
            assert_eq!(code, 5, "{err}");
        } else {
            let (code, _, err) = run(&args);
            assert_eq!(code, 5, "{err}");
        }
    }
    let (code, _, err) = run(&["-q", "dump", &c, "c0001", &members[0], "-o", &s]);
    assert_eq!(code, 5, "{err}");
    assert_eq!(std::fs::read(&state).unwrap(), before);

    let mut bad = before.clone();
    bad.extend_from_slice(b"garbage\n");
    std::fs::write(&state, &bad).unwrap();
    let (code, _, err) = run(&["-q", "scan", &members[0], &members[1], "-o", &c, "--resume"]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("not a scan state"), "{err}");
    assert_eq!(std::fs::read(&state).unwrap(), bad);
}

/// A member no label places is searched for its start by its block
/// pointers, as `zeropoint` does, and the compressed pass steps from
/// there: a vdev on a partition at sector 63 had none of its blocks
/// tried, and `--compressed lz4` found nothing without a word. The start
/// is said and recorded; a member that starts at 0 gets neither.
#[test]
fn a_member_no_label_places_is_placed_by_its_pointers() {
    let dir = scratch("by-pointers");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let mut bare = carved_zvol_members(&mut pool, SIZE).swap_remove(0);
    let (n, labels) = (bare.len(), 2 * LABEL_SIZE as usize);
    bare[..labels].fill(0);
    bare[n - labels..].fill(0);
    let mut shifted = vec![0u8; 63 * 512];
    shifted.extend_from_slice(&bare);
    for (name, bytes, start) in [("shifted", &shifted, Some(32256)), ("bare", &bare, None)] {
        let img = dir.join(format!("{name}.img"));
        std::fs::write(&img, bytes).unwrap();
        let ws = dir.join(format!("ws-{name}"));
        let (code, _, err) = run(&[
            "-q",
            "scan",
            img.to_str().unwrap(),
            "-o",
            ws.to_str().unwrap(),
        ]);
        assert_eq!(code, 0, "{name}: {err}");
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(ws.join("candidates.json")).unwrap()).unwrap();
        let recorded = index["starts_by_pointers"][0]["base"].as_u64();
        assert_eq!(recorded, start, "{name}: {err}");
        assert_eq!(
            err.contains("its block pointers put it at byte 32256"),
            start.is_some(),
            "{name}: {err}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
