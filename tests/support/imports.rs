//! What a built binary asks its platform for (SPEC §8.3 (3)).
//!
//! The tool opens evidence read-only, reads it and writes images and
//! reports. It never opens a socket, never runs another program and
//! never loads code. The source says so — no `std::process::Command`, no
//! `std::net`, every network crate banned in `deny.toml` — but the source
//! is not what runs. The binary is, and its import table is the list of
//! everything it can ask the operating system to do. A dependency that
//! grew a telemetry call, or a build that linked more than it should,
//! shows up there and nowhere else, so that is what is checked, on every
//! binary the workspace builds, on every push.
//!
//! An ELF reader small enough to be read: the file header, the section
//! headers, and the symbol tables. On a dynamic binary the undefined
//! symbols of `.dynsym` are the imports. On a static one there are none
//! and the question becomes whether the C library's own `socket` was
//! linked *in*, which the defined symbols of `.symtab` answer, when the
//! binary was not stripped. Both tables are read where present.
//!
//! Shared between the binary crates by `#[path]`: it is test code, not
//! part of any binary, and a copy per crate would drift.

use std::fs;
use std::path::Path;

/// Symbols a binary of this workspace must never import or link in.
///
/// Sockets and name resolution, running programs, loading code. Each is
/// the libc name, which is what the import table carries on every ELF
/// platform this project builds for.
pub const BANNED: &[&str] = &[
    // sockets and names
    "socket",
    "socketpair",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "send",
    "sendto",
    "sendmsg",
    "recv",
    "recvfrom",
    "recvmsg",
    "getaddrinfo",
    "gethostbyname",
    "getnameinfo",
    // running programs
    "execve",
    "execv",
    "execvp",
    "execvpe",
    "execl",
    "execlp",
    "execle",
    "fexecve",
    "fork",
    "vfork",
    "posix_spawn",
    "posix_spawnp",
    "system",
    "popen",
    // loading code
    "dlopen",
    "dlmopen",
];

/// The names a binary imports (undefined dynamic symbols) and the names
/// it defines (from `.symtab`, when it has one).
#[derive(Debug, Default)]
pub struct Symbols {
    /// Undefined entries of `.dynsym`: what the binary asks the platform for.
    pub imported: Vec<String>,
    /// Defined entries of `.symtab`: what was linked into the binary.
    pub defined: Vec<String>,
}

const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;
const SHN_UNDEF: u16 = 0;

struct Reader<'a> {
    bytes: &'a [u8],
    little: bool,
}

impl Reader<'_> {
    fn u16(&self, at: usize) -> Option<u16> {
        let b: [u8; 2] = self.bytes.get(at..at + 2)?.try_into().ok()?;
        Some(if self.little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }
    fn u32(&self, at: usize) -> Option<u32> {
        let b: [u8; 4] = self.bytes.get(at..at + 4)?.try_into().ok()?;
        Some(if self.little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }
    fn u64(&self, at: usize) -> Option<u64> {
        let b: [u8; 8] = self.bytes.get(at..at + 8)?.try_into().ok()?;
        Some(if self.little {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }
    fn cstr(&self, at: usize) -> Option<&str> {
        let rest = self.bytes.get(at..)?;
        let end = rest.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&rest[..end]).ok()
    }
}

/// A section header: type, file offset, size, the linked section, and
/// the entry size.
struct Section {
    kind: u32,
    offset: usize,
    size: usize,
    link: usize,
    entsize: usize,
}

/// Reads the symbol tables of an ELF64 file. `None` when the file is
/// not ELF64 — a Mach-O on macOS, say — or is malformed.
pub fn symbols(bytes: &[u8]) -> Option<Symbols> {
    if bytes.get(..4)? != b"\x7fELF" || bytes[4] != 2 {
        return None;
    }
    let r = Reader {
        bytes,
        little: bytes[5] == 1,
    };
    let shoff = r.u64(0x28)? as usize;
    let shentsize = r.u16(0x3a)? as usize;
    let shnum = r.u16(0x3c)? as usize;
    let sections: Vec<Section> = (0..shnum)
        .map(|i| {
            let at = shoff + i * shentsize;
            Some(Section {
                kind: r.u32(at + 4)?,
                offset: r.u64(at + 0x18)? as usize,
                size: r.u64(at + 0x20)? as usize,
                link: r.u32(at + 0x28)? as usize,
                entsize: r.u64(at + 0x38)? as usize,
            })
        })
        .collect::<Option<_>>()?;
    let mut out = Symbols::default();
    for s in &sections {
        if s.kind != SHT_DYNSYM && s.kind != SHT_SYMTAB {
            continue;
        }
        let strtab = sections.get(s.link)?;
        let entsize = if s.entsize == 0 { 24 } else { s.entsize };
        for i in 0..s.size / entsize {
            let at = s.offset + i * entsize;
            let name = r.u32(at)? as usize;
            if name == 0 {
                continue;
            }
            let shndx = r.u16(at + 6)?;
            let name = r.cstr(strtab.offset + name)?.to_string();
            match (s.kind, shndx) {
                (SHT_DYNSYM, SHN_UNDEF) => out.imported.push(name),
                (SHT_SYMTAB, SHN_UNDEF) => {}
                (SHT_SYMTAB, _) => out.defined.push(name),
                _ => {}
            }
        }
    }
    Some(out)
}

/// The name without a version suffix: `connect@GLIBC_2.2.5` is `connect`.
fn bare(name: &str) -> &str {
    name.split('@').next().unwrap_or(name)
}

/// What the binary at `path` asks for that it must not: every banned
/// name it imports or links in, each saying which. `None` when the file
/// is not ELF64 and cannot be checked here.
pub fn violations(path: &str) -> Option<Vec<String>> {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let syms = symbols(&bytes)?;
    assert!(
        !syms.imported.is_empty() || !syms.defined.is_empty(),
        "{path}: no symbol table at all — a stripped static binary cannot be checked here"
    );
    eprintln!(
        "{}: {} imports, {} defined symbols",
        Path::new(path).display(),
        syms.imported.len(),
        syms.defined.len()
    );
    Some(
        syms.imported
            .iter()
            .map(|n| (n, "imports"))
            .chain(syms.defined.iter().map(|n| (n, "links in")))
            .filter(|(n, _)| BANNED.contains(&bare(n)))
            .map(|(n, how)| format!("{how} {n}"))
            .collect(),
    )
}

/// Fails when the binary at `path` imports, or links in, any of
/// [`BANNED`]. A binary that is not ELF64 is reported and passes: the
/// check is for the platforms this project builds for.
pub fn assert_clean(path: &str) {
    let Some(bad) = violations(path) else {
        eprintln!(
            "{}: not an ELF64 file; imports not checked",
            Path::new(path).display()
        );
        return;
    };
    assert!(
        bad.is_empty(),
        "{path} asks its platform for what this tool never does: {}",
        bad.join(", ")
    );
}
