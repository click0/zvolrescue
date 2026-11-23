//! Text from a pool or a log, shown on a terminal as text.

use std::borrow::Cow;
use std::fmt::Write;

/// `s` with every control character, and every character that is not
/// seen as itself, shown as its code — `\u{1b}` — instead of being one.
/// A name is whatever the pool says, and the pool may be forged: a file
/// name with a newline in it printed a line of its own in a listing,
/// and one with an escape sequence moved the cursor back over the FAIL
/// a `verify` had just printed.
pub fn shown(s: &str) -> Cow<'_, str> {
    if !s.chars().any(|c| c.is_control() || unseen(c)) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if c.is_control() || unseen(c) {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// A path, [`shown`].
pub fn shown_path(p: &std::path::Path) -> String {
    shown(&p.to_string_lossy()).into_owned()
}

/// A character that is not seen as itself: a line or paragraph
/// separator, a Unicode format character (bidirectional overrides and
/// isolates, zero-width spaces and joiners, the byte-order mark, tags),
/// or whitespace other than the plain space.
pub fn unseen(c: char) -> bool {
    matches!(
        c,
        '\u{ad}'
            | '\u{34f}'
            | '\u{61c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0000}'..='\u{e0fff}'
    ) || (c.is_whitespace() && c != ' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_would_move_the_cursor_or_end_the_line_is_shown_as_its_code() {
        assert_eq!(shown("tank/vm"), "tank/vm");
        assert!(matches!(shown("tank/vm"), Cow::Borrowed(_)));
        assert_eq!(shown("a\nb"), "a\\u{a}b");
        assert_eq!(shown("x\u{1b}[2K\rFAIL"), "x\\u{1b}[2K\\u{d}FAIL");
        assert_eq!(shown("ab\u{202e}cd"), "ab\\u{202e}cd");
        assert_eq!(shown("tab\there"), "tab\\u{9}here");
    }

    /// Showing twice is showing once: a print site that shows a name
    /// and then prints the line through `outln!` says the same.
    #[test]
    fn what_is_shown_is_shown_once() {
        let once = shown("a\nb\u{1b}[2K\u{202e}").into_owned();
        assert_eq!(shown(&once), once);
    }

    /// Every line of text the tools print goes through `outln!` or
    /// `errln!`, which show what is in it as text. What is printed with
    /// the standard macros is JSON, which escapes for itself, or shows
    /// what it prints itself. Names were shown as text where a print
    /// site remembered to: `zvolfiles list` did, and `extract`, which
    /// says what was lost, did not.
    #[test]
    fn print_sites() {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates/");
        // Spelled so that this file holds none of them.
        let macros = ["println", "eprintln", "print", "eprint"].map(|m| format!("{m}!("));
        let mut wrong = Vec::new();
        let mut seen = 0;
        for name in [
            "zvol-common",
            "zvolrescue",
            "zvolcarve",
            "zvolfiles",
            "zvolreport",
            "zvoltimeline",
        ] {
            let src = crates.join(name).join("src");
            for file in std::fs::read_dir(&src).expect("src/") {
                let path = file.expect("entry").path();
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("source");
                let mut line = 0;
                let mut at = 0;
                for l in text.split_inclusive('\n') {
                    line += 1;
                    let start = at;
                    at += l.len();
                    if l.trim_start().starts_with("//") {
                        continue;
                    }
                    for m in &macros {
                        let Some(col) = l.find(m.as_str()) else {
                            continue;
                        };
                        // By its whole name: `eprintln!(` holds the
                        // other three.
                        if l[..col].ends_with(|c: char| c.is_alphanumeric() || c == '_') {
                            continue;
                        }
                        seen += 1;
                        let call = call_at(&text[start + col + m.len()..]);
                        let own = name == "zvol-common" && call.contains("$crate::text::shown");
                        if !(own
                            || call.is_empty()
                            || call.contains("json")
                            || call.contains("shown("))
                        {
                            wrong.push(format!("{}:{line}", path.display()));
                        }
                    }
                }
            }
        }
        assert!(
            seen > 10,
            "the sources were not found: {seen} print site(s)"
        );
        assert!(
            wrong.is_empty(),
            "printed and not shown as text (use outln!/errln!): {wrong:#?}"
        );
    }

    /// The arguments of a macro call, from just past its `(` to the `)`
    /// that closes it.
    fn call_at(rest: &str) -> &str {
        let mut depth = 1;
        let mut quoted = false;
        let mut escaped = false;
        for (i, c) in rest.char_indices() {
            if quoted {
                match c {
                    _ if escaped => escaped = false,
                    '\\' => escaped = true,
                    '"' => quoted = false,
                    _ => {}
                }
                continue;
            }
            match c {
                '"' => quoted = true,
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return &rest[..i];
                    }
                }
                _ => {}
            }
        }
        rest
    }
}
