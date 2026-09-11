//! What a file's contents say they are.
//!
//! `cargo run -p zfs-read --example signatures -- FILE...`

use zfs_ondisk::signature::identify;
use zvolrescue_io::{BlockSource, FileSource};

fn main() {
    let mut any = false;
    for path in std::env::args().skip(1) {
        let src = FileSource::open(&path).expect("open");
        let read = |at: u64, len: usize| -> Option<Vec<u8>> {
            let mut buf = vec![0u8; len];
            src.read_at(at, &mut buf).ok()?;
            Some(buf)
        };
        let found = identify(&read);
        if found.is_empty() {
            println!("{path}: nothing recognised");
        }
        for f in found {
            any = true;
            println!(
                "{path}: {} at {} ({} byte(s)){}",
                f.kind,
                f.at,
                f.size
                    .map_or("size not stated".to_string(), |s| s.to_string()),
                f.label.map_or(String::new(), |l| format!(" label {l:?}"))
            );
        }
    }
    if !any {
        std::process::exit(1);
    }
}
