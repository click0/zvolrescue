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
}
