//! Unix time → ISO 8601 (UTC) without pulling in a date crate.

/// Format seconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ`.
///
/// Uses Howard Hinnant's civil-from-days algorithm; valid for any `u64`
/// that fits the proleptic Gregorian calendar.
pub fn iso8601(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3_600,
        (secs / 60) % 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::iso8601;

    #[test]
    fn known_instants() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso8601(4_102_444_799), "2099-12-31T23:59:59Z");
    }
}

/// Parse a timestamp given as Unix seconds or as `YYYY-MM-DD[THH:MM[:SS]][Z]`
/// (UTC; a space may separate date and time).
pub fn parse_timestamp(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    let s = s.strip_suffix('Z').unwrap_or(s);
    let (date, time) = match s.split_once(['T', ' ']) {
        Some((d, t)) => (d, Some(t)),
        None => (s, None),
    };
    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let m: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    if d.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }
    let (hh, mm, ss) = match time {
        None => (0, 0, 0),
        Some(t) => {
            let mut p = t.split(':');
            let hh: u64 = p.next()?.parse().ok()?;
            let mm: u64 = p.next()?.parse().ok()?;
            let ss: u64 = p.next().map(|s| s.parse().ok()).unwrap_or(Some(0))?;
            if hh > 23 || mm > 59 || ss > 60 {
                return None;
            }
            (hh, mm, ss)
        }
    };
    // Howard Hinnant's days-from-civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86_400 + hh * 3_600 + mm * 60 + ss)
}

#[cfg(test)]
mod parse_tests {
    use super::{iso8601, parse_timestamp};

    #[test]
    fn parses_and_roundtrips() {
        assert_eq!(parse_timestamp("0"), Some(0));
        assert_eq!(parse_timestamp("1970-01-01"), Some(0));
        assert_eq!(parse_timestamp("2023-11-14T22:13:20Z"), Some(1_700_000_000));
        assert_eq!(
            parse_timestamp("2023-11-14 22:13"),
            Some(1_700_000_000 - 20)
        );
        assert_eq!(parse_timestamp("2000-02-29"), Some(951_782_400));
        for ts in [1u64, 951_782_400, 1_700_000_000, 4_102_444_799] {
            assert_eq!(parse_timestamp(&iso8601(ts)), Some(ts));
        }
        assert_eq!(parse_timestamp("2023-13-01"), None);
        assert_eq!(parse_timestamp("yesterday"), None);
        assert_eq!(parse_timestamp("1969-12-31"), None);
    }
}
