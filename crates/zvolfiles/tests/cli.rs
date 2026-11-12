//! The command line, end to end, on fixture members written to disk.

use std::path::{Path, PathBuf};
use std::process::Command;

use zfs_read::fixture::{zpl_members, zpl_members_with, zpl_spilled, Matching, Pool, Spill};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zvolfiles-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// The fixture's two mirror members, written to `dir` under `names`.
fn members(dir: &Path, names: [&str; 2]) -> Vec<String> {
    let mut pool = Pool::mirror("tank", 0x5eed_0000_0000_0004, 12)
        .txgs(&[(4816228, 1757100000), (4816229, 1757100005)]);
    zpl_members(&mut pool, 64 * 1024 * 1024)
        .iter()
        .zip(names)
        .map(|(m, name)| {
            let p = dir.join(name);
            std::fs::write(&p, m).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect()
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_zvolfiles"))
        .args(args)
        .output()
        .expect("run zvolfiles");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// What is already in the output directory is never written through: a
/// symbolic link to a member, or to a directory outside the tree, is
/// replaced and what it pointed at is untouched. A member lying there
/// under the name of a file in the dataset is refused (exit 5) rather
/// than truncated to that file. A second run over the same tree works.
#[test]
fn extract_never_writes_through_what_is_in_its_way() {
    let dir = scratch("in-the-way");
    let m = members(&dir, ["member0.img", "member1.img"]);
    let before = std::fs::read(&m[1]).unwrap();
    let out = dir.join("out");
    let outside = dir.join("outside");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&m[1], out.join("spilled.txt")).unwrap();
    std::os::unix::fs::symlink(&outside, out.join("sub")).unwrap();
    let o = out.to_string_lossy().into_owned();
    for _ in 0..2 {
        let (code, err) = run(&["-q", "extract", "tank/fs", &m[0], &m[1], "-o", &o]);
        assert_eq!(code, 0, "{err}");
    }
    assert_eq!(
        std::fs::read(&m[1]).unwrap(),
        before,
        "a member was written"
    );
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);

    // A member in the output directory, named like a file of the dataset.
    let named = dir.join("hello.txt");
    std::fs::copy(&m[1], &named).unwrap();
    let named = named.to_string_lossy().into_owned();
    let d = dir.to_string_lossy().into_owned();
    let (code, err) = run(&["-q", "extract", "tank/fs", &m[0], &named, "-o", &d]);
    assert_eq!(code, 5, "{err}");
    assert!(err.contains("refused"), "{err}");
    assert_eq!(
        std::fs::read(&named).unwrap(),
        before,
        "the member was written"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `objects` writes into its directory by the same rules.
#[test]
fn objects_never_writes_through_what_is_in_its_way() {
    let dir = scratch("objects");
    let m = members(&dir, ["member0.img", "member1.img"]);
    let before = std::fs::read(&m[1]).unwrap();
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::os::unix::fs::symlink(&m[1], out.join("objects.json")).unwrap();
    let o = out.to_string_lossy().into_owned();
    let (code, err) = run(&["-q", "objects", "tank/fs", &m[0], &m[1], "-o", &o]);
    assert!(code == 0 || code == 4, "{code}: {err}");
    assert_eq!(
        std::fs::read(&m[1]).unwrap(),
        before,
        "a member was written"
    );
    assert!(!std::fs::symlink_metadata(out.join("objects.json"))
        .unwrap()
        .file_type()
        .is_symlink());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `objects` is for a dataset whose POSIX metadata is gone, and it used
/// to need that metadata: a master node that no longer verified made
/// `objects` exit 3 with every file object intact. It now writes them,
/// says what was lost, and `list` — which does need the tree — still
/// says it cannot.
#[test]
fn objects_does_not_need_the_master_node() {
    let dir = scratch("no-master");
    let m = members(&dir, ["member0.img", "member1.img"]);
    // The fixture's master-node ZAP block, on both members.
    for p in &m {
        let mut b = std::fs::read(p).unwrap();
        b[0x60_0040..0x60_0048].copy_from_slice(b"JUNKJUNK");
        std::fs::write(p, b).unwrap();
    }
    let (code, err) = run(&["-q", "list", "tank/fs", &m[0], &m[1]]);
    assert_eq!(code, 3, "{err}");
    let out = dir.join("objs");
    let o = out.to_string_lossy().into_owned();
    let (code, err) = run(&["-q", "objects", "tank/fs", &m[0], &m[1], "-o", &o]);
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("master node"), "{err}");
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("objects.json")).unwrap()).unwrap();
    assert_eq!(
        index["written"],
        index["objects"].as_array().unwrap().len(),
        "{index}"
    );
    assert!(index["damaged"][0]
        .as_str()
        .unwrap()
        .contains("master node"));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Times come back as the dataset had them, a file of mostly holes takes
/// the space of its blocks only, and `--preserve` refuses what it does
/// not know rather than quietly turning the mode off.
#[test]
fn extract_puts_back_times_and_keeps_holes() {
    use std::os::unix::fs::MetadataExt;
    let dir = scratch("times-holes");
    let m = members(&dir, ["member0.img", "member1.img"]);
    let out = dir.join("out");
    let o = out.to_string_lossy().into_owned();
    let (code, err) = run(&["-q", "extract", "tank/fs", &m[0], &m[1], "-o", &o]);
    assert_eq!(code, 0, "{err}");
    let hello = std::fs::metadata(out.join("hello.txt")).unwrap();
    // The fixture's files were written at 2025-09-05T19:20:01Z.
    assert_eq!(hello.mtime(), 1_757_100_001);
    for e in std::fs::read_dir(&out).unwrap().flatten() {
        let md = e.metadata().unwrap();
        if md.is_file() {
            assert!(
                md.blocks() * 512 <= md.len().max(4096) + 4096,
                "{:?}",
                e.path()
            );
        }
    }
    let (code, err) = run(&[
        "-q",
        "extract",
        "tank/fs",
        &m[0],
        &m[1],
        "-o",
        &o,
        "--preserve",
        "bogus,owner",
    ]);
    assert_eq!(code, 1, "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `list --path` naming a file lists that file, as `extract --path`
/// takes it; it was walked as a directory, "object is not a ZAP", exit 4.
#[test]
fn list_of_a_file_is_that_file() {
    let dir = scratch("list-file");
    let m = members(&dir, ["member0.img", "member1.img"]);
    let out = Command::new(env!("CARGO_BIN_EXE_zvolfiles"))
        .args([
            "-q",
            "-f",
            "json",
            "list",
            "tank/fs",
            &m[0],
            &m[1],
            "--path",
            "hello.txt",
        ])
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let files = v["files"].as_array().unwrap();
    assert_eq!(files.len(), 1, "{v}");
    assert_eq!(files[0]["path"], "hello.txt");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A spill block that does not read loses what was kept there, not the
/// file: its contents are written, the error is on its record and the
/// run is partial (exit 4). `list --path` of it says the same; the whole
/// file was missing, and `list` said "object is not a ZAP".
#[test]
fn an_unreadable_spill_block_loses_its_attributes_not_the_file() {
    let dir = scratch("spill");
    let mut pool = Pool::mirror("tank", 0x5eed_0000_0000_0004, 12)
        .txgs(&[(4816228, 1757100000), (4816229, 1757100005)]);
    let m: Vec<String> = zpl_members_with(
        &mut pool,
        64 * 1024 * 1024,
        Matching::Exact,
        Spill::Unreadable,
    )
    .iter()
    .enumerate()
    .map(|(i, m)| {
        let p = dir.join(format!("member{i}.img"));
        std::fs::write(&p, m).expect("write member");
        p.to_string_lossy().into_owned()
    })
    .collect();
    let out = dir.join("out");
    let (code, err) = run(&[
        "-q",
        "extract",
        "tank/fs",
        &m[0],
        &m[1],
        "-o",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 4, "{err}");
    assert_eq!(
        std::fs::read(out.join("spilled.txt")).unwrap(),
        zpl_spilled()
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
    let rec = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "spilled.txt")
        .expect("its record");
    assert!(rec.get("error").is_none(), "{rec}");
    assert!(
        rec["xattr_errors"][0]
            .as_str()
            .is_some_and(|e| e.contains("spill block")),
        "{rec}"
    );
    let listed = Command::new(env!("CARGO_BIN_EXE_zvolfiles"))
        .args([
            "-q",
            "-f",
            "json",
            "list",
            "tank/fs",
            &m[0],
            &m[1],
            "--path",
            "spilled.txt",
        ])
        .output()
        .expect("run");
    assert_eq!(listed.status.code(), Some(4));
    let v: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    let files = v["files"].as_array().unwrap();
    assert_eq!(files.len(), 1, "{v}");
    assert!(
        files[0]["xattr_errors"].to_string().contains("spill block"),
        "{v}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A path is taken as the dataset spells it: `./sub` is `sub`, and the
/// directory it names is made with its own metadata (it was neither
/// recorded nor given its time). A path inside another one given is
/// written once, not refused as taken (exit 4), and one that is not
/// there says so, and that an older TXG may still have it.
#[test]
fn paths_are_taken_as_the_dataset_spells_them() {
    use std::os::unix::fs::MetadataExt;
    let dir = scratch("paths");
    let m = members(&dir, ["member0.img", "member1.img"]);
    let out = dir.join("out");
    let o = out.to_string_lossy().into_owned();
    let (code, err) = run(&[
        "-q",
        "extract",
        "tank/fs",
        &m[0],
        &m[1],
        "-o",
        &o,
        "--path",
        "./sub",
        "--path",
        "sub/deep.txt",
        "--path",
        "/hello.txt",
        "--path",
        "hello.txt",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("the same path as --path"), "{err}");
    assert_eq!(
        std::fs::read(out.join("sub/deep.txt")).unwrap(),
        zfs_read::fixture::zpl_deep()
    );
    assert_eq!(
        std::fs::metadata(out.join("sub")).unwrap().mtime(),
        1_757_100_001
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
    let paths: Vec<&str> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["sub", "sub/deep.txt", "hello.txt"], "{manifest}");
    assert_eq!(manifest["directories"], 1);
    let (code, err) = run(&[
        "-q", "extract", "tank/fs", &m[0], &m[1], "-o", &o, "--path", "nosuch",
    ]);
    assert_eq!(code, 3, "{err}");
    assert!(
        err.contains("no such file or directory at txg") && err.contains("older --txg"),
        "{err}"
    );
    // A name under a file is said as that: it was "object is not a ZAP".
    let (code, err) = run(&[
        "-q",
        "list",
        "tank/fs",
        &m[0],
        &m[1],
        "--path",
        "hello.txt/x",
    ]);
    assert_eq!(code, 3, "{err}");
    assert!(err.contains("hello.txt is not a directory"), "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Members whose first copy of `name`, on each, is flipped: the
/// directory block holding the name no longer verifies.
fn members_without(dir: &Path, name: &[u8]) -> Vec<String> {
    let m = members(dir, ["member0.img", "member1.img"]);
    for p in &m {
        let mut b = std::fs::read(p).unwrap();
        let at = b
            .windows(name.len())
            .position(|w| w == name)
            .expect("the name is on the member");
        b[at] ^= 0xff;
        std::fs::write(p, b).unwrap();
    }
    m
}

fn json_of(args: &[&str]) -> (i32, serde_json::Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_zvolfiles"))
        .args(args)
        .output()
        .expect("run zvolfiles");
    (
        out.status.code().expect("exit code"),
        serde_json::from_slice(&out.stdout).expect("json on stdout"),
    )
}

/// A directory whose contents did not read is said on its own entry,
/// with its metadata: it was listed a second time, as `?` with no mode
/// or time, and counted as one more entry. The dataset's root, which
/// nothing lists, gets an entry of its own. `extract` writes the
/// directory, records why it is empty and counts it as not read whole,
/// not as a file that could not be written.
#[test]
fn a_directory_that_did_not_read_is_said_on_its_own_entry() {
    let dir = scratch("dir-unread");
    let m = members_without(&dir, b"deep.txt");
    let (code, v) = json_of(&[
        "-q",
        "-f",
        "json",
        "list",
        "--recursive",
        "tank/fs",
        &m[0],
        &m[1],
    ]);
    assert_eq!(code, 4, "{v}");
    let subs: Vec<&serde_json::Value> = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["path"] == "sub")
        .collect();
    assert_eq!(subs.len(), 1, "{v}");
    assert_eq!(
        (subs[0]["type"].as_str(), subs[0]["mode"].as_str()),
        (Some("d"), Some("0755"))
    );
    assert!(
        subs[0]["contents_errors"][0]
            .as_str()
            .unwrap()
            .starts_with("directory: "),
        "{v}"
    );
    let out = dir.join("out");
    let (code, v) = json_of(&[
        "-q",
        "-f",
        "json",
        "extract",
        "tank/fs",
        &m[0],
        &m[1],
        "-o",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 4, "{v}");
    assert_eq!(
        (
            v["failed"].as_u64(),
            v["incomplete"].as_u64(),
            v["directories"].as_u64()
        ),
        (Some(0), Some(1), Some(1)),
        "{v}"
    );
    let sub = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "sub")
        .unwrap();
    assert!(
        sub.get("error").is_none() && sub["contents_errors"].is_array(),
        "{sub}"
    );
    assert!(out.join("sub").is_dir());
    // The summary counts what was written: the record of what did not
    // read was one more file.
    let text = Command::new(env!("CARGO_BIN_EXE_zvolfiles"))
        .args(["extract", "tank/fs", &m[0], &m[1], "-o"])
        .arg(dir.join("out2"))
        .output()
        .expect("run zvolfiles");
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains(": 6 file(s), 1 directory ->"), "{text}");
    std::fs::remove_dir_all(&dir).unwrap();

    let dir = scratch("root-unread");
    let m = members_without(&dir, b"hello.txt");
    let (code, v) = json_of(&["-q", "-f", "json", "list", "tank/fs", &m[0], &m[1]]);
    assert_eq!(code, 4, "{v}");
    let files = v["files"].as_array().unwrap();
    assert_eq!(files.len(), 1, "{v}");
    assert_eq!(
        (files[0]["path"].as_str(), files[0]["type"].as_str()),
        (Some("."), Some("d"))
    );
    assert!(files[0]["contents_errors"].is_array(), "{v}");
    let out = dir.join("out");
    let (code, v) = json_of(&[
        "-q",
        "-f",
        "json",
        "extract",
        "tank/fs",
        &m[0],
        &m[1],
        "-o",
        out.to_str().unwrap(),
    ]);
    assert_eq!(code, 4, "{v}");
    assert_eq!(
        (v["failed"].as_u64(), v["incomplete"].as_u64()),
        (Some(0), Some(1)),
        "{v}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A second run into the same directory — `--path` for what the first
/// did not finish — keeps the first run's manifest, the one record of
/// what that run wrote.
#[test]
fn a_second_run_keeps_the_first_runs_manifest() {
    let dir = scratch("two-runs");
    let m = members(&dir, ["member0.img", "member1.img"]);
    let out = dir.join("out");
    let o = out.to_string_lossy().into_owned();
    let (code, err) = run(&["-q", "extract", "tank/fs", &m[0], &m[1], "-o", &o]);
    assert_eq!(code, 0, "{err}");
    let first = std::fs::read(out.join("manifest.json")).unwrap();
    let (code, err) = run(&[
        "-q",
        "extract",
        "tank/fs",
        &m[0],
        &m[1],
        "-o",
        &o,
        "--path",
        "hello.txt",
    ]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(std::fs::read(out.join("manifest.json")).unwrap(), first);
    let second: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("manifest.1.json")).unwrap()).unwrap();
    assert_eq!(second["files"].as_array().unwrap().len(), 1, "{second}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A block that does not verify is a run of zeros the manifest names —
/// which block, which bytes, why — and `--strict` ends the run there
/// (exit 4), where it went on to the next file.
#[test]
fn zeroed_bytes_are_named_and_strict_stops() {
    let dir = scratch("strict");
    let m = members(&dir, ["member0.img", "member1.img"]);
    let deep = zfs_read::fixture::zpl_deep();
    for p in &m {
        let mut b = std::fs::read(p).unwrap();
        let at = b
            .windows(deep.len())
            .position(|w| w == deep.as_slice())
            .expect("deep.txt is on the member");
        b[at + 7] ^= 0xff;
        std::fs::write(p, b).unwrap();
    }
    let out = dir.join("out");
    let o = out.to_string_lossy().into_owned();
    let (code, err) = run(&["-q", "extract", "tank/fs", &m[0], &m[1], "-o", &o]);
    assert_eq!(code, 4, "{err}");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
    let files = manifest["files"].as_array().unwrap();
    let deep_rec = files.iter().find(|f| f["path"] == "sub/deep.txt").unwrap();
    assert_eq!(deep_rec["errors"], 1, "{deep_rec}");
    let z = &deep_rec["zeroed"][0];
    assert_eq!(
        (z["block"].as_u64(), z["offset"].as_u64()),
        (Some(0), Some(0))
    );
    assert_eq!(z["length"], 4096);
    assert!(!z["reason"].as_str().unwrap().is_empty());

    let strict = dir.join("strict");
    let s = strict.to_string_lossy().into_owned();
    let (code, err) = run(&[
        "-q", "extract", "tank/fs", &m[0], &m[1], "-o", &s, "--strict",
    ]);
    assert_eq!(code, 4, "{err}");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(strict.join("manifest.json")).unwrap()).unwrap();
    assert!(
        manifest["stopped"]
            .as_str()
            .unwrap()
            .starts_with("sub/deep.txt: block 0"),
        "{manifest}"
    );
    let last = manifest["files"].as_array().unwrap().last().unwrap();
    assert_eq!(last["path"], "sub/deep.txt", "nothing after it: {manifest}");
    assert!(last["error"].as_str().unwrap().contains("--strict"));
    std::fs::remove_dir_all(&dir).unwrap();
}
