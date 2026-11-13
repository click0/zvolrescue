//! Markdown rendering of a report (R-05).
//!
//! Meant to be attached to a ticket or a case file: the same facts as
//! the JSON, in the order someone reads them — what the case is, what
//! was examined, what was run, what came out, and what to be careful
//! about.

use std::fmt::Write;

use zvol_common::text::unseen;
use zvol_common::timefmt::iso8601;

use crate::model::Report;

/// `s` with every control character — a newline above all — shown as
/// its code, `\u{a}`, instead of being one. A dataset name is whatever
/// the pool says, and the pool may be forged: a name with a newline in
/// it ended the table row and began whatever Markdown came next.
///
/// So are the characters that change how text reads without being seen
/// — a right-to-left override, a zero-width space, a space that is not
/// one — and a space at either end, which a table cell drops: `tank/vm`
/// and `tank/vm ` rendered alike, and a name with an override in it read
/// backwards.
fn visible(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let lead = s.len() - s.trim_start_matches(' ').len();
    let tail = s.len() - s.trim_end_matches(' ').len();
    for (i, c) in s.char_indices() {
        let edge = c == ' ' && (i < lead || i >= s.len() - tail);
        if edge || c.is_control() || unseen(c) {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// Text from the logs or the pool, as text: nothing in it can open a
/// heading, a link, emphasis, an HTML comment or a new table cell. A
/// forged dataset name (`…\n\n## Notes\n\nAll extractions complete and
/// verified.\n\n<!--`) rendered as a section of its own and hid every
/// warning, the Extractions table and the Provenance behind a comment.
fn cell(s: &str) -> String {
    let mut out = String::new();
    for c in visible(s).chars() {
        if matches!(
            c,
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '&' | '|' | '~' | '#' | '!'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Text from the logs or the pool, as code: a fence longer than any run
/// of backticks inside, so that none can close it, and the table's pipe
/// escaped, which a code span in a table still splits on.
fn code(s: &str) -> String {
    let v = visible(s).replace('|', "\\|");
    let mut longest = 0;
    let mut run = 0;
    for c in v.chars() {
        run = if c == '`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    let fence = "`".repeat(longest + 1);
    let pad = if v.starts_with('`') || v.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{v}{pad}{fence}")
}

fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {} ({bytes} B)", UNITS[i])
    }
}

/// Render the whole report.
pub fn render(r: &Report) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# zvolrescue evidence report");
    let _ = writeln!(s);
    if let Some(c) = &r.case {
        let _ = writeln!(s, "**Case:** {}  ", cell(c));
    }
    if let Some(e) = &r.examiner {
        let _ = writeln!(s, "**Examiner:** {}  ", cell(e));
    }
    if !r.hosts.is_empty() {
        let _ = writeln!(s, "**Host(s):** {}  ", cell(&r.hosts.join(", ")));
    }
    let _ = writeln!(
        s,
        "**Tools:** {}",
        r.tools
            .iter()
            .map(|t| code(&format!("{} {}", t.tool, t.version)))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let _ = writeln!(s);
    for n in &r.notes {
        let _ = writeln!(s, "> {}", cell(n));
        let _ = writeln!(s);
    }

    if !r.warnings.is_empty() {
        let _ = writeln!(s, "## Read this first");
        let _ = writeln!(s);
        for w in &r.warnings {
            let _ = writeln!(s, "* {}", cell(w));
        }
        let _ = writeln!(s);
    }

    let _ = writeln!(s, "## Evidence");
    let _ = writeln!(s);
    let _ = writeln!(s, "| File | Size | SHA-256 | Read by |");
    let _ = writeln!(s, "|---|---|---|---|");
    for e in &r.evidence {
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} |",
            code(&e.file.path.display().to_string()),
            size(e.file.size),
            e.file
                .sha256
                .as_deref()
                .map_or("not hashed".to_string(), code),
            cell(&e.read_by.join(", "))
        );
    }
    let _ = writeln!(s);

    if !r.pools.is_empty() {
        let _ = writeln!(s, "## Pools");
        let _ = writeln!(s);
        let _ = writeln!(s, "| Pool | GUID | State | TXG window | Readable |");
        let _ = writeln!(s, "|---|---|---|---|---|");
        for p in &r.pools {
            let _ = writeln!(
                s,
                "| {} | {} | {} | {} | {} |",
                cell(&p.name),
                code(&p.guid),
                cell(p.state.as_deref().unwrap_or("—")),
                p.txg_window
                    .map_or("—".to_string(), |w| format!("{}–{}", w[0], w[1])),
                if p.readable { "yes" } else { "no" }
            );
        }
        let _ = writeln!(s);
    }

    let _ = writeln!(s, "## Commands");
    let _ = writeln!(s);
    let _ = writeln!(s, "| Time (UTC) | Tool | Exit | Command |");
    let _ = writeln!(s, "|---|---|---|---|");
    for c in &r.commands {
        let _ = writeln!(
            s,
            "| {} | {} {} | {} | {} |",
            iso8601(c.ts),
            cell(&c.tool),
            cell(&c.version),
            c.status,
            code(&c.argv.join(" "))
        );
    }
    let _ = writeln!(s);

    if !r.extractions.is_empty() {
        let _ = writeln!(s, "## Extractions");
        let _ = writeln!(s);
        let _ = writeln!(
            s,
            "| Dataset | TXG | Output | Size | SHA-256 | Zeroed blocks | Complete |"
        );
        let _ = writeln!(s, "|---|---|---|---|---|---|---|");
        for (i, e) in r.extractions.iter().enumerate() {
            let complete = if e.complete() {
                "yes"
            } else if r.finished_later(i) {
                "no — finished by a later run"
            } else {
                "no"
            };
            let _ = writeln!(
                s,
                "| {} | {} | {} | {} | {} | {} | {} |",
                cell(&e.dataset),
                e.txg,
                code(&e.output.display().to_string()),
                size(e.size),
                e.sha256.as_deref().map_or("—".to_string(), code),
                e.errors,
                complete
            );
        }
        let _ = writeln!(s);
    }

    let _ = writeln!(s, "## Files written");
    let _ = writeln!(s);
    let _ = writeln!(s, "| File | Size | SHA-256 |");
    let _ = writeln!(s, "|---|---|---|");
    for o in &r.outputs {
        let _ = writeln!(
            s,
            "| {} | {} | {} |",
            code(&o.path.display().to_string()),
            size(o.size),
            o.sha256.as_deref().map_or("—".to_string(), code)
        );
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "## Provenance");
    let _ = writeln!(s);
    let _ = writeln!(s, "| Evidence log | Records | SHA-256 |");
    let _ = writeln!(s, "|---|---|---|");
    for l in &r.logs {
        let _ = writeln!(
            s,
            "| {} | {} | {} |",
            code(&l.path.display().to_string()),
            l.records,
            code(&l.sha256)
        );
    }
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Check this report against the files it names with `zvolreport verify`."
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What changes how a name reads without being seen is shown as its
    /// code: an override that reverses it, a space of no width, a space
    /// that is not one, and a space at either end, which a cell drops.
    #[test]
    fn what_is_not_seen_is_shown() {
        assert_eq!(visible("tank/vm"), "tank/vm");
        assert_eq!(visible("tank/vm a"), "tank/vm a");
        assert_eq!(visible(" tank/vm  "), "\\u{20}tank/vm\\u{20}\\u{20}");
        assert_eq!(visible("tank/\u{202e}gpj.exe"), "tank/\\u{202e}gpj.exe");
        assert_eq!(visible("ta\u{200b}nk"), "ta\\u{200b}nk");
        assert_eq!(visible("tank\u{a0}vm"), "tank\\u{a0}vm");
        assert_eq!(visible("\u{feff}tank"), "\\u{feff}tank");
        assert_eq!(visible("тека/том"), "тека/том");
        assert_eq!(visible("   "), "\\u{20}\\u{20}\\u{20}");
        assert_eq!(cell(" a"), "\\\\u{20}a");
    }

    /// Nothing the pool or a log says can make Markdown of its own.
    #[test]
    fn text_from_the_evidence_stays_text() {
        let forged = "tank/vm | 1 |\n\n## Notes\n\nAll extractions complete and verified.\n\n<!--";
        let c = cell(forged);
        assert!(!c.contains('\n'), "{c}");
        assert!(c.contains("\\#\\# Notes"), "{c}");
        assert!(c.contains("\\<\\!--"), "{c}");
        assert!(c.contains("\\|"), "{c}");
        assert_eq!(cell("tank/vm/disk0"), "tank/vm/disk0");
        let k = code("a`b``c|d\re");
        assert!(k.starts_with("```") && k.ends_with("```"), "{k}");
        assert!(k.contains("\\|") && k.contains("\\u{d}"), "{k}");
        assert_eq!(code("disk0.img"), "`disk0.img`");
        assert_eq!(code("`x"), "`` `x ``");
    }
}
