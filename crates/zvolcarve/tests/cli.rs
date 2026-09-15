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
    let dir = std::env::temp_dir().join(format!("zvolcarve-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
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
