//! The evidence check against real loop devices. Kept out of `src`,
//! where no code may start a process: it needs `losetup` and the right
//! to use it, and says so when it skips for want of either.

use std::path::{Path, PathBuf};

use zvolrescue_io::Evidence;

/// Loops are traced both ways: a second loop over the file an input
/// loop reads is the input, and a loop over an unrelated file beside
/// it is not. Needs `losetup` and the right to use it; skipped
/// without.
#[test]
fn a_loop_over_the_file_an_input_loop_reads_is_the_input() {
    use std::process::Command;
    let dir = std::env::temp_dir().join(format!("zvolrescue-io-loops-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let member = dir.join("member1.img");
    let other = dir.join("other.img");
    std::fs::write(&member, vec![1u8; 1 << 20]).unwrap();
    std::fs::write(&other, vec![2u8; 1 << 20]).unwrap();
    let attach = |file: &Path, ro: bool| -> Option<PathBuf> {
        let mut c = Command::new("losetup");
        c.args(["-f", "--show"]);
        if ro {
            c.arg("-r");
        }
        let out = c.arg(file).output().ok()?;
        let dev = String::from_utf8(out.stdout).ok()?;
        (out.status.success() && !dev.trim().is_empty()).then(|| PathBuf::from(dev.trim()))
    };
    let Some(input) = attach(&member, true) else {
        eprintln!("skipped: no loop device to be had here");
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    };
    let second = attach(&member, false);
    let unrelated = attach(&other, false);
    let ev = Evidence::new(std::slice::from_ref(&input));
    let refused = second.as_ref().map(|d| ev.check(d).is_err());
    let allowed = unrelated.as_ref().map(|d| ev.check(d).is_ok());
    for d in [Some(input), second, unrelated].into_iter().flatten() {
        let _ = Command::new("losetup").arg("-d").arg(&d).status();
    }
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(refused, Some(true), "a second loop over the input's file");
    assert_eq!(allowed, Some(true), "a loop over another file");
}
