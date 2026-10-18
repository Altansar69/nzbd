//! Tiny UTC calendar helpers (no `chrono`/`time` dependency): file-name stamps and the current
//! year for the Scene year bound. Inputs are clamped, so the arithmetic cannot overflow.

/// Largest timestamp handled (year 9999-12-31T23:59:59Z).
const MAX_TS: i64 = 253_402_300_799;

/// Civil date and time of a Unix timestamp (clamped to `0..=MAX_TS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Civil {
    pub year: i64,
    pub month: i64,
    pub day: i64,
    pub hour: i64,
    pub minute: i64,
    pub second: i64,
}

/// Howard Hinnant's `civil_from_days`. All intermediates are small positive numbers after the
/// clamp, so plain arithmetic is exact.
pub(crate) fn civil(ts: i64) -> Civil {
    let ts = ts.clamp(0, MAX_TS);
    let days = ts.div_euclid(86_400);
    let rem = ts.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    Civil {
        year,
        month,
        day,
        hour: rem / 3600,
        minute: rem % 3600 / 60,
        second: rem % 60,
    }
}

/// `YYYYMMDDTHHMMSSZ`, safe in file names.
#[must_use]
pub fn utc_stamp(ts: i64) -> String {
    let c = civil(ts);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

/// Current UTC year as `u16` (saturating).
pub(crate) fn utc_year(ts: i64) -> u16 {
    u16::try_from(civil(ts).year).unwrap_or(u16::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn known_instants() {
        assert_eq!(utc_stamp(0), "19700101T000000Z");
        assert_eq!(utc_stamp(951_782_400), "20000229T000000Z");
        assert_eq!(utc_stamp(1_700_000_000), "20231114T221320Z");
        assert_eq!(utc_year(1_700_000_000), 2023);
        assert_eq!(utc_stamp(-5), "19700101T000000Z");
        assert_eq!(utc_stamp(i64::MAX), "99991231T235959Z");
    }
}
