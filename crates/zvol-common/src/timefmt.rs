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

/// Format a file's time — seconds either side of the epoch and the
/// nanoseconds into that second — as `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`,
/// the fraction left out when it is zero.
pub fn iso8601_ns(secs: i64, nanos: u32) -> String {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
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
    let fraction = if nanos == 0 {
        String::new()
    } else {
        format!(".{nanos:09}")
    };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}{fraction}Z",
        tod / 3_600,
        (tod / 60) % 60,
        tod % 60
    )
}

#[cfg(test)]
mod tests {
    use super::{iso8601, iso8601_ns};

    /// Before the epoch is before the epoch, and the nanoseconds show.
    #[test]
    fn file_times_either_side_of_the_epoch() {
        assert_eq!(iso8601_ns(0, 0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_ns(-86_400, 0), "1969-12-31T00:00:00Z");
        assert_eq!(
            iso8601_ns(-1, 500_000_000),
            "1969-12-31T23:59:59.500000000Z"
        );
        assert_eq!(
            iso8601_ns(1_700_000_000, 123_456_789),
            "2023-11-14T22:13:20.123456789Z"
        );
        // Damage is printed, not a panic.
        let _ = iso8601_ns(i64::MIN, 0);
        let _ = iso8601_ns(i64::MAX, 999_999_999);
    }

    #[test]
    fn known_instants() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso8601(4_102_444_799), "2099-12-31T23:59:59Z");
    }
}

/// Parse a timestamp: Unix seconds, or a date and time in RFC 3339's
/// form — `YYYY-MM-DD`, then optionally `T` (or `t`, or a space) and
/// `HH:MM[:SS[.fraction]]`, then optionally `Z` (or `z`) or an offset
/// `±HH:MM`.
///
/// A time without an offset is UTC, and so is a date alone (its
/// midnight). A fraction of a second is dropped: uberblock timestamps are
/// whole seconds, and "at or before 12:00:00.7" includes 12:00:00. A date
/// that does not exist — February 30th, April 31st — is refused rather
/// than rolled into the next month, where it would quietly move the TXG
/// chosen by days.
pub fn parse_timestamp(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    let (date, time) = match s.split_once(['T', 't', ' ']) {
        Some((d, t)) => (d, Some(t)),
        None => (s.strip_suffix(['Z', 'z']).unwrap_or(s), None),
    };
    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let m: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    if d.next().is_some() || !(0..=9999).contains(&y) || !(1..=12).contains(&m) {
        return None;
    }
    if day < 1 || day > days_in_month(y, m) {
        return None;
    }
    let (clock, offset) = match time {
        None => ("00:00", 0i64),
        Some(t) => {
            if let Some(c) = t.strip_suffix(['Z', 'z']) {
                (c, 0)
            } else if let Some(at) = t.rfind(['+', '-']) {
                let (c, off) = t.split_at(at);
                let sign = if off.starts_with('-') { -1 } else { 1 };
                let (oh, om) = off[1..].split_once(':')?;
                let (oh, om): (i64, i64) = (oh.parse().ok()?, om.parse().ok()?);
                if oh > 23 || om > 59 || off.len() != 6 {
                    return None;
                }
                (c, sign * (oh * 3_600 + om * 60))
            } else {
                (t, 0)
            }
        }
    };
    let mut p = clock.split(':');
    let hh: i64 = p.next()?.parse().ok()?;
    let mm: i64 = p.next()?.parse().ok()?;
    let ss: i64 = match p.next() {
        None => 0,
        Some(sec) => {
            let (whole, frac) = sec.split_once('.').unwrap_or((sec, "0"));
            if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            whole.parse().ok()?
        }
    };
    if p.next().is_some()
        || !(0..=23).contains(&hh)
        || !(0..=59).contains(&mm)
        || !(0..=60).contains(&ss)
    {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let t = days * 86_400 + hh * 3_600 + mm * 60 + ss - offset;
    u64::try_from(t).ok()
}

/// Days in month `m` (1–12) of year `y`, in the proleptic Gregorian
/// calendar.
fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
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

    /// RFC 3339 as the manual promises it: offsets, fractions, either
    /// case of `T` and `Z`; and no date that the calendar does not have.
    #[test]
    fn rfc3339_offsets_fractions_and_real_dates() {
        let t = Some(1_700_000_000);
        assert_eq!(parse_timestamp("2023-11-14T23:13:20+01:00"), t);
        assert_eq!(parse_timestamp("2023-11-14T21:13:20-01:00"), t);
        assert_eq!(parse_timestamp("2023-11-15T03:43:20+05:30"), t);
        assert_eq!(parse_timestamp("2023-11-14T22:13:20.75Z"), t);
        assert_eq!(parse_timestamp("2023-11-14t22:13:20z"), t);
        assert_eq!(parse_timestamp("2023-11-14Z"), Some(1_699_920_000));
        assert_eq!(parse_timestamp("2024-02-29"), Some(1_709_164_800));
        for bad in [
            "2026-02-29",
            "2026-02-31",
            "2023-04-31",
            "2023-11-14T22:13:20+24:00",
            "2023-11-14T22:13:20+0100",
            "2023-11-14T22:13:20.Z",
            "2023-11-14T25:00",
            "1970-01-01T00:30:00+01:00",
        ] {
            assert_eq!(parse_timestamp(bad), None, "{bad}");
        }
    }
}
