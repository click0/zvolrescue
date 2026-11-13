//! `zvolcarve` end to end on a pool whose volume nothing points at:
//! the scan finds it, the dump gets it out, and the legacy digests are
//! taken in the same pass, only when asked (SPEC F-53).

use std::path::Path;
use std::process::Command;

use zfs_ondisk::label::LABEL_SIZE;
use zfs_read::fixture::{carved_zvol_members, Pool};
use zfs_read::hash::{Digests, Extra};
use zvol_common::scratch::Scratch;

const SIZE: u64 = 64 * LABEL_SIZE;

/// What the 32 MiB fixture volume comes to; the same number the CI
/// cross-check holds `zvolrescue dump` and `zvolcarve dump` to.
const FIXTURE_SHA256: &str = "febfe0108392728dbde89ee63f9f25419a0192ac04420db3ad88b0032a088585";

/// A directory for one test, removed when the test ends.
fn scratch(name: &str) -> Scratch {
    Scratch::new("zvolcarve-cli", name)
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
    let log = dir.join("case.jsonl");
    let (code, _, err) = run(&[
        "-q",
        "--evidence-log",
        &log.to_string_lossy(),
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
    // The map is evidence the run read, on its record like the members
    // (SPEC F-72); a carve's record had the members only.
    let text = std::fs::read_to_string(&log).unwrap();
    let rec: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    let inputs: Vec<String> = rec["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["path"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        inputs.contains(&map.to_string_lossy().into_owned()),
        "{inputs:?}"
    );
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

/// An output that will not take a block — here a file-size limit, as a
/// full disk would — stops a carved dump there as a signal does: exit 6,
/// a state at that block, and `--resume` finishes the image once there
/// is room. It ended as exit 3, with no state to resume from.
#[cfg(unix)]
#[test]
fn a_carved_dump_into_a_full_output_resumes_once_there_is_room() {
    let dir = scratch("dump-full");
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
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(carve.join("candidates.json")).unwrap()).unwrap();
    let id = index["candidates"][0]["id"].as_str().unwrap().to_owned();
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
    assert_eq!(code, 0, "{err}");
    let v = json(&out);
    let bs = v["blocksize"].as_u64().unwrap() as usize;
    let image = std::fs::read(&whole).unwrap();
    // Room for every block before the second that holds data.
    let k = (1..image.len() / bs)
        .find(|&b| image[b * bs..(b + 1) * bs].iter().any(|&x| x != 0))
        .expect("a second block with data");

    let img = dir.join("cut.img");
    let script = format!(
        "trap '' XFSZ; ulimit -f {}; exec \"$0\" -q -f json dump '{}' '{}' '{}' '{}' -o '{}'",
        k * bs / 512,
        carve_s,
        id,
        members[0],
        members[1],
        img.display()
    );
    let out = Command::new("/bin/sh")
        .args(["-c", &script, env!("CARGO_BIN_EXE_zvolcarve")])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(6), "{err}");
    assert!(
        err.contains(&format!("the output refused block {k}, at byte {}", k * bs))
            && err.contains("and --resume continues there once the output has room (exit 6)"),
        "{err}"
    );
    let v = json(&String::from_utf8_lossy(&out.stdout));
    assert_eq!(v["interrupted_at"], k as u64, "{v}");
    assert_eq!(v["resume_at"], k as u64, "{v}");
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("cut.img.resume.json")).unwrap()).unwrap();
    assert_eq!(state["blocks_done"], k as u64, "{state}");

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
        &img.to_string_lossy(),
        "--resume",
    ]);
    assert_eq!(code, 0, "{err}");
    let v = json(&out);
    assert_eq!(v["resumed_from_block"], k as u64, "{v}");
    assert_eq!(std::fs::read(&img).unwrap(), image);
    assert!(!dir.join("cut.img.resume.json").exists());
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
    // A candidate is known by its dnode, which is the volume; its id
    // is only its place in one scan's list.
    let dnode: Vec<u8> = {
        let hex = index["candidates"][0]["dnode_hex"].as_str().expect("dnode");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    };
    let known_as = format!(
        "candidate, dnode sha256 {}",
        zvol_common::evidence::sha256_hex(&dnode)
    );
    let state = serde_json::json!({
        "version": 1, "dataset": id, "dataset_guid": known_as, "txg": 0,
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

    // A state that says the blocks before it lost one, written as zeros:
    // the run that finishes the image reports it with its own, exit 4,
    // as zvolrescue's does. It used to end 0 with no range listed.
    std::fs::write(&cut, &image[..2 * blocksize as usize]).expect("prefix");
    let lost = serde_json::json!({
        "bad": [{"blkid": 1, "offset": blocksize, "len": blocksize,
                 "reason": "checksum mismatch, before the interruption"}],
        "blocks_zeroed": 1,
    });
    let mut with_lost = state.clone();
    with_lost["lost"] = lost.clone();
    std::fs::write(dir.join("cut.img.resume.json"), with_lost.to_string()).expect("state");
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
        &cut.to_string_lossy(),
        "--resume",
    ]);
    assert_eq!(code, 4, "{out}{err}");
    let v = json(&out);
    assert_eq!(v["resumed_from_block"], 2, "{v}");
    assert_eq!(v["blocks_zeroed"], 1, "{v}");
    assert_eq!(v["bad"], lost["bad"], "{v}");
    assert_eq!(v["volumes"][0]["bad"], lost["bad"], "{v}");
    assert!(!dir.join("cut.img.resume.json").exists());

    // The same state against another candidate id starts over; so does
    // one of the same id and size whose dnode is another — `c0001` of
    // another scan.
    for (other_id, other_dnode) in [
        ("c9999", known_as.as_str()),
        (id.as_str(), "candidate, dnode sha256 00"),
        (id.as_str(), "candidate"),
    ] {
        let state = serde_json::json!({
            "version": 1, "dataset": other_id, "dataset_guid": other_dnode, "txg": 0,
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
            "{other_id} {other_dnode}: {err}"
        );
        assert_eq!(json(&out)["resumed_from_block"], 0);
    }
}

/// A carve dump's `-o` that is the run's own standard output is refused
/// before anything is read: the summary went into the file over the
/// image's first bytes. The pool given twice — a member and a copy of
/// it — is refused as it is for zvolrescue, and the record of a dump
/// read through an imager's map names the map.
#[cfg(unix)]
#[test]
fn a_carved_dump_is_held_to_what_zvolrescue_dump_is() {
    let dir = scratch("dump-like-rescue");
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
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(carve.join("candidates.json")).expect("index"))
            .expect("index");
    let id = index["candidates"][0]["id"]
        .as_str()
        .expect("id")
        .to_owned();

    let img = dir.join("vol.img");
    let mut names = vec![img.to_string_lossy().into_owned()];
    if Path::new("/dev/stdout").exists() {
        names.push("/dev/stdout".into());
    }
    for name in &names {
        let sink = std::fs::File::create(&img).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_zvolcarve"))
            .args([
                "-q",
                "dump",
                &carve_s,
                &id,
                &members[0],
                &members[1],
                "-o",
                name,
            ])
            .stdout(sink)
            .output()
            .expect("run zvolcarve");
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{name}: {err}");
        assert!(err.contains("standard output of the run"), "{name}: {err}");
        assert_eq!(std::fs::metadata(&img).unwrap().len(), 0, "{name}");
    }

    let copy = dir.join("member0-copy.img");
    std::fs::copy(&members[0], &copy).unwrap();
    let copy = copy.to_string_lossy().into_owned();
    let o = dir.join("twin.img").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "dump",
        &carve_s,
        &id,
        &members[0],
        &copy,
        &members[1],
        "-o",
        &o,
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("are the same disk of pool tank"), "{err}");
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &members[0],
        &copy,
        "-o",
        &dir.join("c2").to_string_lossy(),
    ]);
    assert_eq!(code, 1, "{err}");

    let map = dir.join("m0.map");
    std::fs::write(&map, format!("0x0 +\n0x0 {SIZE:#x} +\n")).unwrap();
    let log = dir.join("case.jsonl");
    let o = dir.join("mapped.img").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "--evidence-log",
        &log.to_string_lossy(),
        "dump",
        &carve_s,
        &id,
        &members[0],
        &members[1],
        "--map",
        &format!("{}={}", members[0], map.display()),
        "-o",
        &o,
    ]);
    assert_eq!(code, 0, "{err}");
    let text = std::fs::read_to_string(&log).unwrap();
    let rec: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    let inputs: Vec<&str> = rec["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["path"].as_str().unwrap())
        .collect();
    assert!(
        inputs.contains(&map.to_string_lossy().as_ref()),
        "{inputs:?}"
    );
}

/// `-o` cannot name a member the scan read, as its index names it, even
/// when this run is given the members by other names.
#[cfg(unix)]
#[test]
fn a_carved_image_is_not_written_over_a_member_the_scan_read() {
    let dir = scratch("dump-over-member");
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
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(carve.join("candidates.json")).expect("index"))
            .expect("index");
    let id = index["candidates"][0]["id"]
        .as_str()
        .expect("id")
        .to_owned();
    // The same pool, copied: the dump reads the copies.
    let copies: Vec<String> = members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let p = dir.join(format!("copy{i}.img"));
            std::fs::copy(m, &p).expect("copy");
            p.to_string_lossy().into_owned()
        })
        .collect();
    let before = std::fs::read(&members[1]).expect("member");
    let (code, _, err) = run(&[
        "-q",
        "dump",
        &carve_s,
        &id,
        &copies[0],
        &copies[1],
        "-o",
        &members[1],
    ]);
    assert_eq!(code, 5, "{err}");
    assert_eq!(std::fs::read(&members[1]).expect("member"), before);
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
        // A resume goes on with the start the scan found: it was looked
        // for again, over the whole member, on every resume.
        let (code, _, err) = run(&[
            "-q",
            "scan",
            img.to_str().unwrap(),
            "-o",
            ws.to_str().unwrap(),
            "--resume",
        ]);
        assert_eq!(code, 0, "{name}: {err}");
        assert!(!err.contains("its block pointers put it"), "{name}: {err}");
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(ws.join("candidates.json")).unwrap()).unwrap();
        assert_eq!(index["starts_by_pointers"][0]["base"].as_u64(), start);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `--max-hits` ends a member's scan after the chunk it was reached in,
/// says so, and exits 6; `--resume` with the same limit goes on from the
/// first hit not listed, and a scan resumed to its end lists what one
/// pass does. The resume went on from the chunk's start, met the same
/// hits and the same limit, and never got further; nothing said why the
/// run ended 6. A sample that reached its size did what it was asked,
/// exit 0, and a limit of 0 is refused.
#[test]
fn a_limited_scan_resumes_to_the_scan_in_one_pass() {
    let dir = scratch("limited");
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
    let one = dir.join("one").to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "scan", &members[0], "-o", &one, "--dnode-type", "any"]);
    assert_eq!(code, 0, "{err}");
    let keys = |ws: &str| {
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(Path::new(ws).join("candidates.json")).unwrap())
                .unwrap();
        let mut k: Vec<(u64, u64)> = index["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| (c["offset"].as_u64().unwrap(), c["slot"].as_u64().unwrap()))
            .collect();
        k.sort();
        (
            k,
            index["slots_examined"].clone(),
            index["rejected"].clone(),
        )
    };
    let want = keys(&one);
    assert!(want.0.len() > 2, "{:?}", want.0);

    let parts = dir.join("parts").to_string_lossy().into_owned();
    let mut runs = 0;
    loop {
        let mut args = vec![
            "-q",
            "scan",
            &members[0],
            "-o",
            &parts,
            "--dnode-type",
            "any",
            "--max-hits",
            "1",
        ];
        if runs > 0 {
            args.push("--resume");
        }
        let (code, _, err) = run(&args);
        runs += 1;
        if code == 0 {
            break;
        }
        assert_eq!(code, 6, "{err}");
        assert!(err.contains("the --max-hits limit"), "{err}");
        assert!(runs <= want.0.len() + 1, "no progress after {runs} runs");
    }
    assert_eq!(keys(&parts), want);
    assert!(runs > 2, "the limit was reached: {runs} run(s)");

    let sample = dir.join("sample").to_string_lossy().into_owned();
    let (code, out, err) = run(&[
        "-f",
        "json",
        "scan",
        &members[0],
        "-o",
        &sample,
        "--sample",
        "2",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("a sample of the first 2 hit(s)"), "{err}");
    assert_eq!(json(&out)["histograms"]["sampled"], 2, "{out}");

    for (cmd, flag) in [
        ("scan", "--max-hits"),
        ("scan", "--sample"),
        ("roots", "--max-roots"),
    ] {
        let ws = dir.join("zero").to_string_lossy().into_owned();
        let (code, _, err) = run(&["-q", cmd, &members[0], "-o", &ws, flag, "0"]);
        assert_eq!(code, 1, "{flag}: {err}");
        assert!(err.contains(&format!("{flag} 0 keeps nothing")), "{err}");
        assert!(!Path::new(&ws).exists());
    }
}

/// A member that did not open is said, and the exit code says it too
/// (2), as `zvolrescue` says it; a scan of the members that did was
/// exit 0. A member given twice is searched once: every candidate on it
/// was listed twice, without a word.
#[test]
fn a_member_missing_or_twice_is_said() {
    let dir = scratch("members-said");
    let m = carved_members(&dir, 0x4242, "member");
    let once = dir.join("once");
    let (code, _, err) = run(&["-q", "scan", &m[0], &m[1], "-o", &once.to_string_lossy()]);
    assert_eq!(code, 0, "{err}");
    let count = |d: &Path| {
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(d.join("candidates.json")).unwrap()).unwrap();
        index["candidates"].as_array().unwrap().len()
    };
    let twice = dir.join("twice");
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &m[0],
        &m[1],
        &m[0],
        "-o",
        &twice.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("again; read once"), "{err}");
    assert_eq!(count(&twice), count(&once));

    let gone = dir.join("gone.img").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &m[0],
        &m[1],
        &gone,
        "-o",
        &dir.join("gone").to_string_lossy(),
    ]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("gone.img"), "{err}");
}

/// A search profile is held to its keys and its ranges: a misspelt key
/// searched as though it were absent, and a range whose start is past
/// its end found nothing, exit 3, as if nothing were there.
#[test]
fn a_profile_says_only_what_it_can() {
    let dir = scratch("profile");
    let m = carved_members(&dir, 0x4242, "member");
    for (profile, want) in [
        (
            serde_json::json!({"volblocksise": 8192}),
            "unknown field `volblocksise`",
        ),
        (
            serde_json::json!({"size": [33554432, 1048576]}),
            "size [33554432, 1048576]: the range is empty",
        ),
        (
            serde_json::json!({"txg": [200, 100]}),
            "txg [200, 100]: the range is empty",
        ),
    ] {
        let file = dir.join("profile.json");
        std::fs::write(&file, profile.to_string()).unwrap();
        let (code, _, err) = run(&[
            "-q",
            "scan",
            &m[0],
            &m[1],
            "-o",
            &dir.join("out").to_string_lossy(),
            "--profile",
            &file.to_string_lossy(),
        ]);
        assert_eq!(code, 1, "{profile}: {err}");
        assert!(err.contains(want), "{want}: {err}");
    }
}
