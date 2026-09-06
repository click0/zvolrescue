//! Debug tracing for `--debug`: one line per decision the reader makes,
//! and a hex dump of the bytes involved whenever a decision goes wrong.
//!
//! Off by default and free when off (one relaxed atomic load per call
//! site). Output goes to stderr or to a file given to [`enable`].

use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static ENABLED: AtomicBool = AtomicBool::new(false);
static SINK: Mutex<Option<File>> = Mutex::new(None);

/// Turn tracing on, writing to `file` or, when `None`, to stderr.
pub fn enable(file: Option<File>) {
    *SINK.lock().unwrap_or_else(|p| p.into_inner()) = file;
    ENABLED.store(true, Ordering::Relaxed);
}

/// Whether tracing is on.
#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Write one trace line for `target` (a short module tag).
pub fn emit(target: &str, args: fmt::Arguments<'_>) {
    let line = format!("[{target}] {args}\n");
    let mut sink = SINK.lock().unwrap_or_else(|p| p.into_inner());
    let result = match sink.as_mut() {
        Some(f) => f.write_all(line.as_bytes()),
        None => io::stderr().write_all(line.as_bytes()),
    };
    // Tracing must never turn a recovery run into a failure.
    let _ = result;
}

/// Emit a trace line when tracing is on.
#[macro_export]
macro_rules! trace {
    ($target:expr, $($arg:tt)*) => {
        if $crate::trace::enabled() {
            $crate::trace::emit($target, format_args!($($arg)*));
        }
    };
}

/// Hex dump of up to `max` bytes of `bytes`, with offsets starting at
/// `base`, sixteen bytes per line, in the layout of `hexdump -C`.
pub fn hexdump(bytes: &[u8], base: u64, max: usize) -> String {
    let mut out = String::new();
    let shown = bytes.len().min(max);
    for (i, row) in bytes[..shown].chunks(16).enumerate() {
        let off = base + (i * 16) as u64;
        out.push_str(&format!("  {off:08x}  "));
        for (j, b) in row.iter().enumerate() {
            out.push_str(&format!("{b:02x} "));
            if j == 7 {
                out.push(' ');
            }
        }
        for _ in row.len()..16 {
            out.push_str("   ");
        }
        if row.len() <= 8 {
            out.push(' ');
        }
        out.push_str(" |");
        for b in row {
            out.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        out.push_str("|\n");
    }
    if shown < bytes.len() {
        out.push_str(&format!("  … {} more bytes\n", bytes.len() - shown));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::hexdump;

    #[test]
    fn hexdump_layout() {
        let d = hexdump(b"hello world, this is zfs", 0x1000, 16);
        assert!(d.starts_with(
            "  00001000  68 65 6c 6c 6f 20 77 6f  72 6c 64 2c 20 74 68 69  |hello world, thi|\n"
        ));
        assert!(d.ends_with("… 8 more bytes\n"));
        let short = hexdump(&[0u8, 255], 0, 64);
        assert!(short.starts_with("  00000000  00 ff "));
        assert!(short.ends_with(" |..|\n"));
        assert_eq!(short.lines().count(), 1);
    }
}
