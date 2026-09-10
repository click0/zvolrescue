//! Markdown rendering of a report (R-05).
//!
//! Meant to be attached to a ticket or a case file: the same facts as
//! the JSON, in the order someone reads them — what the case is, what
//! was examined, what was run, what came out, and what to be careful
//! about.

use std::fmt::Write;

use zvol_common::timefmt::iso8601;

use crate::model::Report;

/// A cell that cannot break the table it is in.
fn cell(s: &str) -> String {
    s.replace('|', "\\|")
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
            .map(|t| format!("`{} {}`", t.tool, t.version))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let _ = writeln!(s);
    for n in &r.notes {
        let _ = writeln!(s, "> {n}");
        let _ = writeln!(s);
    }

    if !r.warnings.is_empty() {
        let _ = writeln!(s, "## Read this first");
        let _ = writeln!(s);
        for w in &r.warnings {
            let _ = writeln!(s, "* {w}");
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
            "| `{}` | {} | {} | {} |",
            cell(&e.file.path.display().to_string()),
            size(e.file.size),
            e.file
                .sha256
                .as_deref()
                .map_or("not hashed".to_string(), |h| format!("`{h}`")),
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
                "| {} | `{}` | {} | {} | {} |",
                cell(&p.name),
                cell(&p.guid),
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
            "| {} | {} {} | {} | `{}` |",
            iso8601(c.ts),
            cell(&c.tool),
            cell(&c.version),
            c.status,
            cell(&c.argv.join(" "))
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
        for e in &r.extractions {
            let _ = writeln!(
                s,
                "| {} | {} | `{}` | {} | {} | {} | {} |",
                cell(&e.dataset),
                e.txg,
                cell(&e.output.display().to_string()),
                size(e.size),
                e.sha256
                    .as_deref()
                    .map_or("—".to_string(), |h| format!("`{h}`")),
                e.errors,
                if e.aborted { "no" } else { "yes" }
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
            "| `{}` | {} | {} |",
            cell(&o.path.display().to_string()),
            size(o.size),
            o.sha256
                .as_deref()
                .map_or("—".to_string(), |h| format!("`{h}`"))
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
            "| `{}` | {} | `{}` |",
            cell(&l.path.display().to_string()),
            l.records,
            l.sha256
        );
    }
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "Check this report against the files it names with `zvolreport verify`."
    );
    s
}
