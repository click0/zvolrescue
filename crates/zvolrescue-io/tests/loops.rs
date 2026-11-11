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

/// A device is written densely: the holes of the volume come out as
/// zeros over whatever the device held, and no length is set on it.
#[test]
fn a_device_gets_every_byte_holes_included() {
    use std::process::Command;
    use zvolrescue_io::{BlockSink, SparseFile};
    let dir = std::env::temp_dir().join(format!("zvolrescue-io-dense-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let backing = dir.join("disk.img");
    std::fs::write(&backing, vec![0xaau8; 1 << 20]).unwrap();
    let out = Command::new("losetup")
        .args(["-f", "--show"])
        .arg(&backing)
        .output();
    let dev = match out {
        Ok(o) if o.status.success() => PathBuf::from(String::from_utf8(o.stdout).unwrap().trim()),
        _ => {
            eprintln!("skipped: no loop device to be had here");
            std::fs::remove_dir_all(&dir).unwrap();
            return;
        }
    };
    let result = (|| {
        let mut sink = SparseFile::create(&dev)?;
        sink.write_at(8192, &[7u8; 4096])?;
        sink.finish(65536)?;
        std::fs::read(&dev)
    })();
    let _ = Command::new("losetup").arg("-d").arg(&dev).status();
    std::fs::remove_dir_all(&dir).unwrap();
    let bytes = result.expect("written");
    assert!(bytes[..8192].iter().all(|&b| b == 0), "the hole before");
    assert!(bytes[8192..12288].iter().all(|&b| b == 7));
    assert!(
        bytes[12288..65536].iter().all(|&b| b == 0),
        "the hole after"
    );
    assert!(bytes[65536..].iter().all(|&b| b == 0xaa), "past the volume");
}

/// `/dev/null` takes an image and its finish, which has nothing to flush.
#[test]
fn dev_null_takes_an_image() {
    use zvolrescue_io::{BlockSink, SparseFile};
    let mut sink = SparseFile::create(Path::new("/dev/null")).unwrap();
    sink.write_at(0, &[1u8; 512]).unwrap();
    sink.finish(1 << 20).unwrap();
}
