//! The command line, end to end, on fixture members written to disk.

use std::path::PathBuf;
use std::process::Command;

use zfs_ondisk::label::LABEL_SIZE;
use zfs_read::fixture::{build_sample_mos, Alloc, Pool};

const SIZE: u64 = 64 * LABEL_SIZE;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zvoltimeline-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A two-way mirror with the sample MOS at one txg, written to `dir`.
fn members(dir: &std::path::Path) -> Vec<String> {
    let mut pool = Pool::mirror("tank", 0x4242, 12).txgs(&[(100, 1)]);
    let mut members = vec![vec![0u8; SIZE as usize], vec![0u8; SIZE as usize]];
    let mut a = Alloc::new(0x20_0000);
    build_sample_mos(&mut pool, &mut members, &mut a);
    members
        .iter_mut()
        .enumerate()
        .map(|(i, m)| {
            pool.write_labels(i, m);
            let p = dir.join(format!("member{i}.img"));
            std::fs::write(&p, &m).expect("write member");
            p.to_string_lossy().into_owned()
        })
        .collect()
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_zvoltimeline"))
        .args(args)
        .output()
        .expect("run zvoltimeline");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `-o` is never a file the run reads: naming a member replaced the
/// member with the report and exited 0. A report beside the members is
/// still written.
#[test]
fn the_report_is_never_written_over_a_member() {
    let dir = scratch("over-member");
    let m = members(&dir);
    let before = std::fs::read(&m[1]).unwrap();
    let (code, err) = run(&["-q", &m[0], &m[1], "-o", &m[1]]);
    assert_eq!(code, 5, "{err}");
    assert!(err.contains("refusing -o"), "{err}");
    assert_eq!(
        std::fs::read(&m[1]).unwrap(),
        before,
        "the member was written"
    );
    let report = dir.join("timeline.txt").to_string_lossy().into_owned();
    let (code, err) = run(&["-q", &m[0], &m[1], "-o", &report]);
    assert_eq!(code, 0, "{err}");
    assert!(std::fs::metadata(&report).unwrap().len() > 0);
    std::fs::remove_dir_all(&dir).unwrap();
}
