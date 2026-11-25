//! `zvolcarve` end to end on a pool whose volume nothing points at:
//! the scan finds it, the dump gets it out, and the legacy digests are
//! taken in the same pass, only when asked (SPEC F-53).

use std::path::Path;
use std::process::Command;

use zfs_ondisk::blkptr::Compression;
use zfs_ondisk::dmu::ot;
use zfs_ondisk::label::LABEL_SIZE;
use zfs_read::fixture::{
    build_sample_mos, build_sample_mos_variant, carved_zvol_members, Alloc, Pool,
};
use zfs_read::hash::{Digests, Extra};
use zvol_common::scratch::Scratch;

const SIZE: u64 = 64 * LABEL_SIZE;

/// What the 32 MiB fixture volume comes to; the same number the CI
/// cross-check holds `zvolrescue dump` and `zvolcarve dump` to.
const FIXTURE_SHA256: &str = "febfe0108392728dbde89ee63f9f25419a0192ac04420db3ad88b0032a088585";

/// Where a dnode was found: `(offset, slot)` each.
type Places = Vec<(u64, u64)>;

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
    // And by what its blocks came to: a state that does not say is
    // taken up on nothing.
    let state = serde_json::json!({
        "version": 1, "dataset": id, "dataset_guid": known_as, "txg": 0,
        "volsize": 32 << 20, "blocksize": blocksize, "blocks_done": 2,
        "prefix_sha256": zvol_common::evidence::sha256_hex(&image[..2 * blocksize as usize]),
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
    // "To the end, wherever that is": the largest end there is was
    // rounded up past it, to 0, and the scan read nothing, found nothing
    // (exit 3) and wrote that it was complete.
    let far = ws("far");
    let range = format!("0-{}", u64::MAX);
    let (code, _, err) = run(&["-q", "scan", &members[0], "--range", &range, "-o", &far]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(index(&far)["candidates"], o["candidates"]);
    assert_eq!(index(&far)["bytes_read"], o["bytes_read"]);

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

/// `--size` is the volume's size when the dnode cannot say it, and a
/// size no file or device can hold is not one: it was taken, and the
/// run hashed the zeros after the last block — 2^64 bytes of them, with
/// nothing to say it would not end. It is refused before anything is
/// opened to write.
#[test]
fn a_size_no_image_can_have_is_refused() {
    let dir = scratch("dump-size");
    let members = carved_members(&dir, 0x4242, "member");
    let carve = dir.join("carve").to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "scan", &members[0], &members[1], "-o", &carve]);
    assert_eq!(code, 0, "{err}");
    let img = dir.join("carved.img");
    for size in ["18446744073709551615", "9223372036854775808"] {
        let (code, _, err) = run(&[
            "-q",
            "dump",
            &carve,
            "c0001",
            &members[0],
            &members[1],
            "-o",
            img.to_str().unwrap(),
            "--size",
            size,
        ]);
        assert_eq!(code, 1, "{err}");
        assert!(
            err.contains(&format!(
                "c0001: {size} bytes (as asked) is more than a file or a device can hold"
            )),
            "{err}"
        );
        assert!(!img.exists(), "an image was opened for --size {size}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
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

    // A scan made before the pool's GUID was known recorded none: its
    // work directory is not another pool's, for a run that reads one.
    let index = Path::new(&carve).join("candidates.json");
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&index).unwrap()).unwrap();
    v["pool_guid"] = "0x0000000000000000".into();
    std::fs::write(&index, v.to_string()).unwrap();
    let again = dir.join("again.img").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "dump",
        &carve,
        "c0001",
        &members[0],
        &members[1],
        "-o",
        &again,
    ]);
    assert_eq!(code, 0, "{err}");
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
    // What is tried decides what is found, as the profile does: a resume
    // with other compressions wrote the index of no scan there is. The
    // index says which it was made with.
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("carve/candidates.json")).unwrap()).unwrap();
    assert_eq!(
        index["compressed"],
        serde_json::json!(["lz4", "lzjb", "gzip", "zstd"])
    );
    for other in ["none", "lz4", "zstd,gzip,lzjb,lz4"] {
        let (code, _, err) = run(&[
            "-q",
            "scan",
            &members[0],
            &members[1],
            "-o",
            &carve,
            "--resume",
            "--compressed",
            other,
        ]);
        assert_eq!(code, 1, "{other}: {err}");
        assert!(
            err.contains(&format!(
                "--compressed lz4,lzjb,gzip,zstd there, {other} here"
            )),
            "{other}: {err}"
        );
    }
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

/// `roots` lists a header once, wherever its copies are, says when
/// `--max-roots` cut the list, and names the newest header a pool walks
/// out of whatever its rank. The ranking puts first what yields most of
/// a pool, so once a dataset has been destroyed the pool's last state is
/// last of all: cut to the cap, the list of the command that finds the
/// MOS did not hold the pool's last one, and `truncated` said false.
#[test]
fn roots_names_the_newest_and_says_what_it_cut() {
    let dir = scratch("roots-newest");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(300, 1)]);
    let mut images: Vec<Vec<u8>> = (0..2).map(|_| vec![0u8; SIZE as usize]).collect();
    let mut alloc = Alloc::new(0x20_0000);
    // Four states of the pool with the volume in it, then the one after
    // it was destroyed, which is the state the pool is in.
    for txg in 100..104 {
        alloc.born = Some(txg);
        build_sample_mos_variant(&mut images, &mut alloc, true);
    }
    alloc.born = Some(200);
    pool.rootbp = Some(build_sample_mos_variant(&mut images, &mut alloc, false));
    let write = |images: &[Vec<u8>]| -> Vec<String> {
        images
            .iter()
            .enumerate()
            .map(|(i, img)| {
                let mut img = img.clone();
                pool.write_labels(i, &mut img);
                let p = dir.join(format!("member{i}.img"));
                std::fs::write(&p, img).expect("write member");
                p.to_string_lossy().into_owned()
            })
            .collect()
    };
    let m = write(&images);
    let roots = |name: &str, more: &[&str]| {
        let out = dir.join(name);
        let mut args = vec!["-q", "roots", m[0].as_str(), m[1].as_str(), "-o"];
        let o = out.to_string_lossy().into_owned();
        args.push(&o);
        args.extend(more);
        let (code, text, err) = run(&args);
        assert_eq!(code, 0, "{err}");
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("roots.json")).unwrap()).unwrap();
        (doc, text)
    };
    let (all, text) = roots("all", &[]);
    let listed = all["roots"].as_array().unwrap();
    let births: Vec<u64> = listed
        .iter()
        .map(|r| r["birth"].as_u64().unwrap())
        .collect();
    assert_eq!(births, [103, 102, 101, 100, 200], "{all}");
    assert_eq!(all["found"], 5, "{all}");
    assert_eq!(all["truncated"], false, "{all}");
    assert_eq!(all["newest"]["id"], 4, "{all}");
    assert_eq!(all["newest"]["birth"], 200, "{all}");
    assert!(
        listed[4]["datasets"].as_u64() < listed[0]["datasets"].as_u64(),
        "{all}"
    );
    assert!(
        text.contains("the newest a pool walks out of is [4]:"),
        "{text}"
    );

    let (cut, text) = roots("cut", &["--max-roots", "2"]);
    assert_eq!(cut["roots"].as_array().unwrap().len(), 2, "{cut}");
    assert_eq!(cut["found"], 5, "{cut}");
    assert_eq!(cut["truncated"], true, "{cut}");
    assert_eq!(cut["newest"], all["newest"], "{cut}");
    assert!(
        text.starts_with("5 object-set header(s)")
            && text.contains("the first 2 by rank are listed and 3 are not")
            && text.contains("is [4], past where the list was cut:"),
        "{text}"
    );

    // The same header a second time on one member — the MOS is written
    // three times over — is that header, not another.
    let at = listed[0]["offset"].as_u64().unwrap() as usize;
    let (spare, mut again) = (14usize << 20, images.clone());
    let header = again[0][at..at + 4096].to_vec();
    assert!(again[0][spare..spare + 4096].iter().all(|b| *b == 0));
    again[0][spare..spare + 4096].copy_from_slice(&header);
    let m = write(&again);
    let out = dir.join("copy");
    let (code, text, err) = run(&["-q", "roots", &m[0], &m[1], "-o", &out.to_string_lossy()]);
    assert_eq!(code, 0, "{err}");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("roots.json")).unwrap()).unwrap();
    assert_eq!(doc["found"], 5, "{doc}");
    assert_eq!(
        doc["roots"][0]["copies"],
        serde_json::json!([{"member": m[0], "offset": spare}]),
        "{doc}"
    );
    assert_eq!(doc["roots"][0]["also_on"], serde_json::json!([m[1]]));
    assert!(
        text.contains(&format!("the same header also at {spare:#x} ({})", m[0])),
        "{text}"
    );
}

/// A candidate is named by what `roots` found: the scan knows the GUID
/// of the dataset whose object set pointed at a carved dnode, a MOS
/// header says what that GUID was called and how large the volume was
/// made, and `list`, the text of `scan` and `dump` put the two together
/// when both are in the workspace. The volume here was destroyed: the
/// pool's newest root does not name it, the roots from before do, and
/// the list said `0x…a3` of every one of its candidates.
#[test]
fn a_candidate_is_named_by_what_roots_found() {
    let dir = scratch("named");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(300, 1)]);
    let mut images: Vec<Vec<u8>> = (0..2).map(|_| vec![0u8; SIZE as usize]).collect();
    let mut alloc = Alloc::new(0x20_0000);
    for txg in 100..104 {
        alloc.born = Some(txg);
        build_sample_mos_variant(&mut images, &mut alloc, true);
    }
    alloc.born = Some(200);
    pool.rootbp = Some(build_sample_mos_variant(&mut images, &mut alloc, false));
    let m: Vec<String> = images
        .iter_mut()
        .enumerate()
        .map(|(i, img)| {
            pool.write_labels(i, img);
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, img).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect();
    let ws = dir.join("carve");
    let w = ws.to_string_lossy().into_owned();

    // Without `roots` a candidate has the GUID alone.
    let (code, out, err) = run(&["-q", "scan", &m[0], &m[1], "-o", &w]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("belonged to dataset 0x"), "{out}");
    assert!(!out.contains("tank/vm/disk0"), "{out}");

    let (code, out, err) = run(&["-q", "roots", &m[0], &m[1], "-o", &w]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("dataset name(s) the headers give are not in the newest (txg 200):")
            && out.contains("tank/vm/disk0 (0x"),
        "{out}"
    );
    let roots: serde_json::Value =
        serde_json::from_slice(&std::fs::read(ws.join("roots.json")).unwrap()).unwrap();
    let table = roots["datasets"].as_array().unwrap();
    let of = |name: &str| {
        table
            .iter()
            .find(|d| d["name"] == name)
            .unwrap_or_else(|| panic!("{name} is not in {table:?}"))
    };
    assert_eq!(of("tank")["last_txg"], 200);
    assert_eq!(of("tank")["first_txg"], 100);
    assert_eq!(of("tank")["kind"], "filesystem");
    let disk = of("tank/vm/disk0");
    assert_eq!(
        (&disk["first_txg"], &disk["last_txg"], &disk["kind"]),
        (&100.into(), &103.into(), &"volume".into()),
        "{disk}"
    );
    assert_eq!(disk["volsize"], 32 << 20, "{disk}");
    assert_eq!(disk["volblocksize"], 8192, "{disk}");
    assert_eq!(of("tank/vm/disk0@before")["snapshot"], true);

    let (code, out, err) = run(&["-f", "json", "list", &w]);
    assert_eq!(code, 0, "{err}");
    let listed = json(&out);
    let named: Vec<&serde_json::Value> = listed["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c.get("dataset_name").is_some())
        .collect();
    assert!(!named.is_empty(), "{listed}");
    for c in &named {
        let name = c["dataset_name"].as_str().unwrap();
        assert!(name.starts_with("tank/vm/disk0"), "{c}");
        assert_eq!(c["dataset_guid"], of(name)["guid"], "{c}");
        assert_eq!(c["dataset_last_txg"], 103, "{c}");
        assert_eq!(c["dataset_volsize"], 32 << 20, "{c}");
    }
    // The index is what the scan found, whatever has been said since.
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(ws.join("candidates.json")).unwrap()).unwrap();
    assert!(
        index["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c.get("dataset_name").is_none()),
        "{index}"
    );
    let (code, out, err) = run(&["list", &w]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("belonged to dataset tank/vm/disk0")
            && out.contains(
                ": a volume made 32.0MiB; last named by the root of txg 103, and not by the newest"
            ),
        "{out}"
    );

    // And the image is on the record as that volume.
    let id = named[0]["id"].as_str().unwrap();
    let img = dir.join("disk0.img").to_string_lossy().into_owned();
    let (code, out, err) = run(&["-q", "-f", "json", "dump", &w, id, &m[0], &m[1], "-o", &img]);
    assert_eq!(code, 0, "{err}");
    let volume = json(&out)["volumes"][0].clone();
    assert_eq!(volume["dataset"], id, "{volume}");
    assert_eq!(volume["dataset_name"], named[0]["dataset_name"], "{volume}");
    assert_eq!(volume["dataset_guid"], named[0]["dataset_guid"], "{volume}");
    assert_eq!(volume["dataset_volsize"], 32 << 20, "{volume}");

    // A `roots.json` that does not read costs the names, not the list.
    std::fs::write(ws.join("roots.json"), b"{ not json").unwrap();
    let (code, out, err) = run(&["list", &w]);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("roots.json") && err.contains("candidates are not named from it"),
        "{err}"
    );
    assert!(
        out.contains("belonged to dataset 0x") && !out.contains("tank/vm/disk0"),
        "{out}"
    );
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

    // One that reads is not yet the state of this scan: of another
    // version, of one member where two are given, or with a place past
    // the end of a member, it was taken as it stood and the scan ended
    // "complete".
    let index = carve.join("candidates.json");
    let index_before = std::fs::read(&index).unwrap();
    for (bad, why) in [
        (
            serde_json::json!({"index_version": 99, "reached": [0, 0], "complete": false}),
            "state version 99",
        ),
        (
            serde_json::json!({"index_version": 1, "reached": [4096], "complete": false}),
            "its `reached` is of 1 member(s), and 2 are given",
        ),
        (
            serde_json::json!({"index_version": 1, "reached": [0, 0], "complete": false,
                "counted": [0]}),
            "its `counted` is of 1 member(s)",
        ),
        (
            serde_json::json!({"index_version": 1, "reached": [u64::MAX, 0], "complete": false}),
            "past its end",
        ),
        (
            serde_json::json!({"index_version": 1, "reached": [0, 0], "complete": false,
                "cut": [[SIZE + 512, 0], null]}),
            "its `cut` puts the scan",
        ),
        (
            serde_json::json!({"index_version": 1, "reached": [0, 0], "complete": false,
                "range": [4096, 4096]}),
            "its range, 4096-4096, is empty",
        ),
    ] {
        let bad = bad.to_string().into_bytes();
        std::fs::write(&state, &bad).unwrap();
        let (code, _, err) = run(&["-q", "scan", &members[0], &members[1], "-o", &c, "--resume"]);
        assert_eq!(code, 1, "{why}: {err}");
        assert!(err.contains(why), "{why}: {err}");
        assert_eq!(std::fs::read(&state).unwrap(), bad);
        assert_eq!(std::fs::read(&index).unwrap(), index_before);
    }
    // The state of a scan that had read something, and no index of what
    // it found: gone on with, that part was in no index.
    std::fs::write(&state, &before).unwrap();
    std::fs::rename(&index, dir.join("index.kept")).unwrap();
    let (code, _, err) = run(&["-q", "scan", &members[0], &members[1], "-o", &c, "--resume"]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("that goes with it is not there"), "{err}");
    // And an index with no state is replaced by the scan that starts
    // over, as it says it does: added to, every slot was counted twice.
    std::fs::rename(dir.join("index.kept"), &index).unwrap();
    std::fs::remove_file(&state).unwrap();
    let (code, _, err) = run(&["scan", &members[0], &members[1], "-o", &c, "--resume"]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("scanning from the start"), "{err}");
    let again: serde_json::Value = serde_json::from_slice(&std::fs::read(&index).unwrap()).unwrap();
    let first: serde_json::Value = serde_json::from_slice(&index_before).unwrap();
    assert_eq!(again, first);
}

/// `list` says what its index is the list of. From a scan that stopped
/// part of the way it is the list of that part, and said nothing of it,
/// in text or in JSON: handed on, it read as the answer about the whole
/// disk. An index written before it recorded how far the scan got is
/// read with the state beside it.
#[test]
fn a_list_of_part_of_a_scan_says_so() {
    let dir = scratch("list-part");
    let members = carved_members(&dir, 0x4242, "member");
    let carve = dir.join("carve");
    let c = carve.to_string_lossy().into_owned();
    let scan = |more: &[&str]| {
        let mut args = vec!["-q", "scan", members[0].as_str(), "-o", c.as_str()];
        args.extend(["--dnode-type", "any"]);
        args.extend(more);
        run(&args)
    };
    let (code, out, err) = scan(&["--max-hits", "1"]);
    assert_eq!(code, 6, "{err}");
    assert!(out.contains("NOT FINISHED"), "{out}");
    let (code, out, err) = run(&["list", &c]);
    assert_eq!(code, 0, "{err}");
    let reached = format!("{}: read to byte ", members[0]);
    assert!(
        out.contains("NOT FINISHED") && out.contains(&reached),
        "{out}"
    );
    assert!(out.contains(&format!(" of {SIZE}\n")), "{out}");
    let (code, out, err) = run(&["-f", "json", "list", &c]);
    assert_eq!(code, 0, "{err}");
    let progress = json(&out)["progress"].clone();
    assert_eq!(progress["complete"], false, "{progress}");
    assert_eq!(progress["member_bytes"], serde_json::json!([SIZE]));
    assert!(
        progress["reached"][0].as_u64().unwrap() < SIZE,
        "{progress}"
    );

    // An index of before: the state beside it says.
    let index = carve.join("candidates.json");
    let mut old: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&index).unwrap()).unwrap();
    old.as_object_mut().unwrap().remove("progress");
    let kept = std::fs::read(&index).unwrap();
    std::fs::write(&index, old.to_string()).unwrap();
    let (code, out, err) = run(&["list", &c]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("NOT FINISHED") && out.contains(&reached),
        "{out}"
    );
    std::fs::write(&index, kept).unwrap();

    let (code, out, err) = scan(&["--resume"]);
    assert_eq!(code, 0, "{err}");
    assert!(!out.contains("NOT FINISHED"), "{out}");
    let (code, out, err) = run(&["-f", "json", "list", &c]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        json(&out)["progress"],
        serde_json::json!({"complete": true, "reached": [SIZE], "member_bytes": [SIZE]})
    );
    let (_, out, _) = run(&["list", &c]);
    assert!(!out.contains("NOT FINISHED"), "{out}");
}

/// What `list` shows is what the index says, no rounder: a candidate
/// with a block that failed its checksum is not "100%" verified, nor
/// 1.00 — one failed block in 640 was both — and `-v` says what the
/// score is made of and how the walk went (C-05). A name the pool gave
/// is shown as text, not sent to the terminal, and the run is on the
/// evidence record: the log was created and nothing written to it.
#[test]
fn a_list_shows_what_the_index_says() {
    let dir = scratch("list-says");
    let members = carved_members(&dir, 0x4242, "member");
    let carve = dir.join("carve");
    let c = carve.to_string_lossy().into_owned();
    let (code, _, err) = run(&["-q", "scan", &members[0], &members[1], "-o", &c]);
    assert_eq!(code, 0, "{err}");
    let (code, plain, err) = run(&["list", &c]);
    assert_eq!(code, 0, "{err}");
    let (code, wordy, err) = run(&["-v", "list", &c]);
    assert_eq!(code, 0, "{err}");
    assert!(
        !plain.contains("score ") && !plain.contains("walk: "),
        "{plain}"
    );
    assert!(
        wordy.contains("0.55 for matching the profile, and 0.45 of the mean of its structure (")
            && wordy.contains(" failed"),
        "{wordy}"
    );

    let index = carve.join("candidates.json");
    let mut doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&index).unwrap()).unwrap();
    doc["pool"] = "ta\u{1b}cnk".into();
    {
        let first = &mut doc["candidates"][0];
        let total = first["assessment"]["blocks_total"].as_u64().unwrap();
        assert!(total > 0, "{first}");
        // 4999 failed in a million, and a score just short of the top.
        first["assessment"]["blocks_verified"] = 995_001.into();
        first["assessment"]["blocks_holes"] = 0.into();
        first["assessment"]["blocks_failed"] = 4999.into();
        first["assessment"]["agreement"] = 0.995001.into();
        first["score"] = 0.9997.into();
    }
    std::fs::write(&index, doc.to_string()).unwrap();
    let log = dir.join("case.jsonl");
    let (code, out, err) = run(&["-v", "--evidence-log", &log.to_string_lossy(), "list", &c]);
    assert_eq!(code, 0, "{err}");
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert!(
        out.lines().next().unwrap().ends_with("of ta\\u{1b}cnk"),
        "{out}"
    );
    let row = out
        .lines()
        .find(|l| l.starts_with("c0001 "))
        .expect("the first candidate");
    assert!(row.contains("  0.99 ") && row.contains(" 99% "), "{row}");
    assert!(!row.contains("100%") && !row.contains("1.00"), "{row}");
    assert!(
        out.contains("walk: of 1000000 block(s) looked at")
            && out.contains("995001 verified, 0 hole(s), 4999 failed"),
        "{out}"
    );
    let records: Vec<serde_json::Value> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(records.len(), 1, "{records:?}");
    let r = &records[0];
    assert_eq!(r["status"], 0, "{r}");
    assert_eq!(
        r["result"]["candidates"],
        doc["candidates"].as_array().unwrap().len()
    );
    assert_eq!(r["result"]["complete"], true, "{r}");
    assert!(
        r["inputs"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with("carve/candidates.json"),
        "{r}"
    );
}

/// The names `roots` lists are what the pool's own MOS says, and are
/// shown as text; so is the pool's name in the line `scan` ends with.
#[test]
fn names_from_the_pool_are_shown_as_text() {
    let dir = scratch("names");
    let mut pool = Pool::mirror("ta\u{1b}cnk", 0x4242, 12).txgs(&[(100, 1)]);
    let members: Vec<String> = carved_zvol_members(&mut pool, SIZE)
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, m).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect();
    let (code, out, err) = run(&[
        "-q",
        "scan",
        &members[0],
        &members[1],
        "-o",
        &dir.join("carve").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert!(
        out.lines().next().unwrap().ends_with("of ta\\u{1b}cnk"),
        "{out}"
    );
    let (code, out, err) = run(&[
        "-q",
        "roots",
        &members[0],
        &members[1],
        "-o",
        &dir.join("roots").to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert!(out.contains("ta\\u{1b}cnk, ta\\u{1b}cnk/vm"), "{out}");
    // In JSON a name is a string, and is the pool's own.
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("roots/roots.json")).unwrap()).unwrap();
    assert_eq!(doc["roots"][0]["sample"][0], "ta\u{1b}cnk");
}

/// A workspace that holds a scan which did not finish is not written
/// over by a scan without `--resume`: the hours of reading and the place
/// to go on from were replaced without a word. A finished scan, or a
/// sample, is replaced, and said to be.
#[test]
fn an_unfinished_scan_is_not_written_over() {
    let dir = scratch("unfinished");
    let members = carved_members(&dir, 0x4242, "member");
    let carve = dir.join("carve");
    let c = carve.to_string_lossy().into_owned();
    let any = ["--dnode-type", "any"];
    let scan = |more: &[&str]| {
        let mut args = vec!["scan", members[0].as_str(), "-o", c.as_str()];
        args.extend(any);
        args.extend(more);
        run(&args)
    };
    let (code, _, err) = scan(&["--max-hits", "1"]);
    assert_eq!(code, 6, "{err}");
    let kept = (
        std::fs::read(carve.join("state.json")).unwrap(),
        std::fs::read(carve.join("candidates.json")).unwrap(),
    );
    let (code, _, err) = scan(&[]);
    assert_eq!(code, 1, "{err}");
    assert!(
        err.contains("it holds a scan that did not finish") && err.contains("--resume"),
        "{err}"
    );
    assert_eq!(std::fs::read(carve.join("state.json")).unwrap(), kept.0);
    assert_eq!(
        std::fs::read(carve.join("candidates.json")).unwrap(),
        kept.1
    );
    let (code, _, err) = scan(&["--resume"]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = scan(&[]);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("the index of an earlier scan is there") && err.contains("it is replaced"),
        "{err}"
    );
    // A sample stops where it has enough, and is not a scan left half
    // done: the scan it was a look for goes into the same workspace.
    let (code, _, err) = scan(&["--sample", "1"]);
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = scan(&[]);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("the index of an earlier sample is there"),
        "{err}"
    );
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
        // One compression, here and in the test after this one: what is
        // tested is where blocks are looked for, not with what, and with
        // all four tried at every sector an unoptimised build took over
        // a minute for each of the two.
        let (code, _, err) = run(&[
            "-q",
            "scan",
            img.to_str().unwrap(),
            "-o",
            ws.to_str().unwrap(),
            "--compressed",
            "lz4",
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
            "--compressed",
            "lz4",
        ]);
        assert_eq!(code, 0, "{name}: {err}");
        assert!(!err.contains("its block pointers put it"), "{name}: {err}");
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(ws.join("candidates.json")).unwrap()).unwrap();
        assert_eq!(index["starts_by_pointers"][0]["base"].as_u64(), start);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// With no label and no hints nothing says what the pool's ashift was,
/// and compressed blocks are looked for at every sector, which no block
/// is finer than. They were looked for every 4 KiB: of a pool of ashift
/// 9 with its labels gone — what a carve is for — seven blocks in eight
/// were never tried, and the scan said it was complete. And two starts
/// the block pointers do not choose between are said, not passed over.
/// One dnode found at two places is one candidate: a block of dnodes is
/// metadata, and the pool writes it two or three times over. Each copy
/// was a candidate of its own — the same volume twice in the list,
/// walked twice, and a choice between the two that is no choice. It is
/// listed once, with where else it is, and the index counts the copies
/// it folded (`ditto_copies`).
#[test]
fn a_dnode_found_twice_is_one_candidate() {
    let dir = scratch("ditto");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let mut whole = carved_zvol_members(&mut pool, SIZE).swap_remove(0);
    let plain = whole
        .chunks(512)
        .position(|slot| slot[0] == ot::ZVOL && slot[1] == 17)
        .expect("the volume's dnode")
        * 512;
    // Another copy of it, in space nothing else uses.
    let copy = 12 << 20;
    assert!(whole[copy..copy + 512].iter().all(|b| *b == 0));
    let dnode = whole[plain..plain + 512].to_vec();
    whole[copy..copy + 512].copy_from_slice(&dnode);
    let img = dir.join("member.img").to_string_lossy().into_owned();
    std::fs::write(&img, &whole).unwrap();
    let ws = dir.join("ws").to_string_lossy().into_owned();
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &img,
        "-o",
        &ws,
        "--dnode-type",
        "any",
        "--compressed",
        "none",
    ]);
    assert_eq!(code, 0, "{err}");
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("ws/candidates.json")).unwrap()).unwrap();
    let hex: String = dnode.iter().map(|b| format!("{b:02x}")).collect();
    let of_it: Vec<&serde_json::Value> = index["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["dnode_hex"] == hex.as_str())
        .collect();
    assert_eq!(of_it.len(), 1, "{index}");
    let c = of_it[0];
    assert_eq!(
        c["offset"], plain as u64,
        "the first one met is the candidate"
    );
    assert_eq!(
        c["copies"],
        serde_json::json!([{"device": 0, "path": img, "offset": copy, "slot": 0, "found": "plaintext"}]),
        "{c}"
    );
    assert!(index["ditto_copies"].as_u64().unwrap() >= 1, "{index}");
    let (code, text, err) = run(&["list", &ws]);
    assert_eq!(code, 0, "{err}");
    assert!(
        text.contains(&format!("the same dnode also at 0:{copy:#x}+0 plaintext")),
        "{text}"
    );
}

#[test]
fn a_member_with_no_label_is_searched_at_every_sector() {
    let dir = scratch("no-label-ashift9");
    let mut pool = Pool::mirror("tank", 0x4242, 9).txgs(&[(100, 1)]);
    let mut whole = carved_zvol_members(&mut pool, SIZE).swap_remove(0);
    // A block of dnodes as a pool of ashift 9 writes one: compressed,
    // and on a sector that is no 4 KiB boundary. The dnode in it is the
    // fixture's own volume, found where the fixture wrote it plain.
    let plain = whole
        .chunks(512)
        .position(|slot| slot[0] == ot::ZVOL && slot[1] == 17)
        .expect("the volume's dnode")
        * 512;
    let mut block = vec![0u8; 16384];
    for slot in [0, 3, 7] {
        block[slot * 512..(slot + 1) * 512].copy_from_slice(&whole[plain..plain + 512]);
    }
    let odd = (9 << 20) + 512;
    Alloc::new(odd).put_compressed(
        std::slice::from_mut(&mut whole),
        &block,
        Compression::Lz4,
        ot::DNODE,
        0,
        100,
    );
    let mut bare = whole.clone();
    let (n, labels) = (bare.len(), 2 * LABEL_SIZE as usize);
    bare[..labels].fill(0);
    bare[n - labels..].fill(0);
    let found = |name: &str, bytes: &[u8]| {
        let img = dir.join(format!("{name}.img"));
        std::fs::write(&img, bytes).unwrap();
        let ws = dir.join(format!("ws-{name}"));
        let (code, _, err) = run(&[
            "scan",
            img.to_str().unwrap(),
            "-o",
            ws.to_str().unwrap(),
            "--dnode-type",
            "any",
            "--compressed",
            "lz4",
        ]);
        assert_eq!(code, 0, "{name}: {err}");
        let index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(ws.join("candidates.json")).unwrap()).unwrap();
        // Every place a dnode was found at: a candidate's, and those of
        // the copies of it the scan folded into it — the three planted
        // here are one dnode, which is also where the fixture wrote it.
        let mut at: Vec<(u64, u64, String)> = index["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|c| std::iter::once(c).chain(c["copies"].as_array().into_iter().flatten()))
            .map(|c| {
                (
                    c["offset"].as_u64().unwrap(),
                    c["slot"].as_u64().unwrap(),
                    c["found"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        at.sort();
        (at, err)
    };
    let (labelled, _) = found("whole", &whole);
    let (unlabelled, err) = found("bare", &bare);
    let off_boundary = labelled
        .iter()
        .filter(|(o, _, f)| f == "lz4" && o % 4096 != 0)
        .count();
    assert_eq!(off_boundary, 3, "{labelled:?}");
    assert_eq!(unlabelled, labelled);
    assert!(!err.contains("do not settle"), "{err}");

    let mut twice = bare.clone();
    twice.extend_from_slice(&bare);
    let (both, err) = found("twice", &twice);
    assert_eq!(both.len(), 2 * labelled.len());
    assert!(
        err.contains("its block pointers do not settle it (byte 0: ")
            && err.contains("looked for at every sector"),
        "{err}"
    );
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
        // Each candidate with the copies folded into it: a scan in
        // parts folds them as one in one pass does.
        let mut k: Vec<(u64, u64, Places)> = index["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                let place = |c: &serde_json::Value| {
                    (c["offset"].as_u64().unwrap(), c["slot"].as_u64().unwrap())
                };
                let (offset, slot) = place(c);
                let mut copies: Vec<(u64, u64)> = c["copies"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(place)
                    .collect();
                copies.sort();
                (offset, slot, copies)
            })
            .collect();
        k.sort();
        (
            k,
            index["slots_examined"].clone(),
            index["rejected"].clone(),
            index["ditto_copies"].clone(),
        )
    };
    let want = keys(&one);
    assert!(want.0.len() > 2, "{:?}", want.0);
    // A run takes one hit, a copy as well as a candidate.
    let hits = want.0.iter().map(|(_, _, c)| 1 + c.len()).sum::<usize>();

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
        assert!(runs <= hits + 1, "no progress after {runs} runs");
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
    // And to what a dnode can be: a value none has searched, found
    // nothing and exited 3, as though nothing were there.
    let out = dir.join("none").to_string_lossy().into_owned();
    for (args, want) in [
        (vec!["--levels", "0"], "levels 0"),
        (vec!["--levels", "8"], "levels 8"),
        (vec!["--volblocksize", "0"], "volblocksize 0"),
        (vec!["--volblocksize", "1000"], "volblocksize 1000"),
        (vec!["--dnode-type", "0"], "dnode type 0"),
        (vec!["--dnode-type", "100"], "dnode type 100"),
        (vec!["--size", "..100"], "size up to 100"),
    ] {
        let mut argv = vec!["-q", "scan", m[0].as_str(), m[1].as_str(), "-o", &out];
        argv.extend(args.iter());
        let (code, _, err) = run(&argv);
        assert_eq!(code, 1, "{args:?}: {err}");
        assert!(
            err.contains("the profile can match nothing") && err.contains(want),
            "{args:?}: {err}"
        );
    }
    let file = dir.join("profile.json");
    std::fs::write(&file, r#"{"levels": 0}"#).unwrap();
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &m[0],
        &m[1],
        "-o",
        &out,
        "--profile",
        &file.to_string_lossy(),
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("levels 0"), "{err}");
    assert!(
        !dir.join("none").exists(),
        "a refused scan made a workspace"
    );
}

/// What `roots` finds is what the other programs read the pool by
/// (SPEC F-64): it says how, the file it wrote is one they take, and
/// `scan --like` reads a sibling's numbers at a header where no
/// uberblock is left to lead to it.
#[test]
fn what_roots_finds_is_what_a_pool_with_no_uberblock_is_read_by() {
    use zfs_read::fixture::zero_uberblock_rings;
    let dir = scratch("roots-read");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let mut images: Vec<Vec<u8>> = (0..2).map(|_| vec![0u8; SIZE as usize]).collect();
    let mut alloc = Alloc::new(0x20_0000);
    build_sample_mos(&mut pool, &mut images, &mut alloc);
    let m: Vec<String> = images
        .iter_mut()
        .enumerate()
        .map(|(i, img)| {
            pool.write_labels(i, img);
            zero_uberblock_rings(img);
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, img).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect();
    let like = |ws: &str, more: &[&str]| {
        let mut args = vec![
            "-q",
            "-f",
            "json",
            "scan",
            m[0].as_str(),
            m[1].as_str(),
            "-o",
            ws,
            "--like",
            "tank/vm/disk0",
            "--compressed",
            "none",
        ];
        args.extend(more);
        run(&args)
    };
    let (code, _, err) = like(&dir.join("none").to_string_lossy(), &[]);
    assert_eq!(code, 1, "{err}");
    assert!(
        err.contains("--like tank/vm/disk0: no verified uberblock"),
        "{err}"
    );

    let found = dir.join("found").to_string_lossy().into_owned();
    let (code, text, err) = run(&[
        "-q",
        "roots",
        &m[0],
        &m[1],
        "-o",
        &found,
        "--compressed",
        "none",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(
        text.contains(&format!(
            "to read the pool at them: zvolrescue list {} {} --roots {found}",
            m[0], m[1]
        )),
        "{text}"
    );
    let (code, out, err) = like(&dir.join("with").to_string_lossy(), &["--roots", &found]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(json(&out)["profile"]["volblocksize"], 8192, "{out}");
    // It is read, and never written over by the run that reads it.
    let (code, _, err) = run(&[
        "-q",
        "roots",
        &m[0],
        &m[1],
        "-o",
        &found,
        "--roots",
        &found,
        "--compressed",
        "none",
    ]);
    assert_eq!(code, 5, "{err}");
}

/// `--like` is a volume made like the lost one, and what it knows is
/// how that one was made: its block size, and the size it was given —
/// which is the most a dnode can imply, not what it does. A dnode is
/// measured by the highest block written, so the sibling's exact size
/// turned away the very volume made like it, tail unwritten as a VM's
/// disk is; here the volume named is itself the candidate, 32 MiB with
/// four blocks written, and was not found by its own numbers. A
/// filesystem has none of them, and is said to be one.
#[test]
fn like_takes_what_a_sibling_knows_of_the_lost_volume() {
    let dir = scratch("like");
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let mut images: Vec<Vec<u8>> = (0..2).map(|_| vec![0u8; SIZE as usize]).collect();
    let mut alloc = Alloc::new(0x20_0000);
    build_sample_mos(&mut pool, &mut images, &mut alloc);
    let m: Vec<String> = images
        .iter_mut()
        .enumerate()
        .map(|(i, img)| {
            pool.write_labels(i, img);
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, img).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect();
    let ws = dir.join("carve").to_string_lossy().into_owned();
    let (code, out, err) = run(&[
        "-q",
        "-f",
        "json",
        "scan",
        &m[0],
        &m[1],
        "-o",
        &ws,
        "--like",
        "tank/vm/disk0",
        "--strict-profile",
    ]);
    assert_eq!(code, 0, "{err}");
    let index = json(&out);
    assert_eq!(
        index["profile"],
        serde_json::json!({
            "dnode_type": "zvol object",
            "volblocksize": 8192,
            "size": [0, 32 << 20],
            "strict": true,
        })
    );
    let found = index["candidates"].as_array().unwrap();
    assert!(!found.is_empty(), "{index}");
    for c in found {
        assert_eq!(c["volblocksize"], 8192, "{c}");
        assert!(c["implied_size"].as_u64().unwrap() < 32 << 20, "{c}");
        assert!(c.get("profile_misses").is_none(), "{c}");
    }
    let (code, _, err) = run(&[
        "-q",
        "scan",
        &m[0],
        &m[1],
        "-o",
        &dir.join("fs").to_string_lossy(),
        "--like",
        "tank/vm",
    ]);
    assert_eq!(code, 1, "{err}");
    assert!(
        err.contains("--like tank/vm: it is a filesystem, not a volume"),
        "{err}"
    );
    assert!(!err.contains("I/O error"), "{err}");
}
