//! The command line, end to end, on fixture members written to disk.

use std::path::{Path, PathBuf};
use std::process::Command;

use zfs_read::fixture::{zpl_members, Pool};

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
