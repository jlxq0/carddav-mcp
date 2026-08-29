//! `BDAY` parsing and the upcoming-birthday window.
//!
//! Split out from `mcp` because every interesting case here is a date case
//! rather than a `CardDAV` one, and a date case can be pinned by a fixture that
//! does not move. The live address book is an integration check and cannot be
//! the pin: measured 2026-08-29 it holds 45 birthdays across 366 cards, none of
//! them today, none on a leap day, and none unparseable, so a suite of live
//! checks is green on cases the data does not contain.

use chrono::{Datelike as _, NaiveDate};

/// A `BDAY` reduced to the parts a reminder needs.
///
/// `year` is optional because vCard 4.0 permits an omitted year (`--MM-DD`),
/// which is the correct way to record a birthday whose year is unknown. Age is
/// therefore optional too, and a caller must not infer one from its absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Birthday {
    /// The property value exactly as the card stored it.
    pub raw: String,
    pub month: u32,
    pub day: u32,
    pub year: Option<i32>,
}

/// Parse a `BDAY` value.
///
/// Accepts the ISO forms vCard 3.0 and 4.0 permit: `YYYY-MM-DD`, `YYYYMMDD`,
/// `--MM-DD` and `--MMDD`, each optionally followed by a `T` time part, which
/// is discarded, since a birthday has no time of day and keeping one would invite a
/// timezone question that has no answer.
///
/// **Returns `None` rather than erroring on anything else.** A card with a
/// free-text or partial `BDAY` is a card, not a fault, and one unparseable
/// value must not fail a query over the whole address book. Callers count what
/// they skipped instead.
#[must_use]
pub fn parse_bday(value: &str) -> Option<Birthday> {
    let raw = value.trim();
    if raw.is_empty() {
        return None;
    }
    let date_part = raw.split(['T', 't']).next().unwrap_or(raw);
    let digits: String = date_part.chars().filter(char::is_ascii_digit).collect();
    let no_year = date_part.starts_with("--");

    let (year, month, day) = if no_year {
        if digits.len() != 4 {
            return None;
        }
        (None, &digits[0..2], &digits[2..4])
    } else {
        if digits.len() != 8 {
            return None;
        }
        (
            Some(digits[0..4].parse::<i32>().ok()?),
            &digits[4..6],
            &digits[6..8],
        )
    };

    let month = month.parse::<u32>().ok()?;
    let day = day.parse::<u32>().ok()?;
    // Validate against a leap year so `02-29` survives; the non-leap-year
    // question is about *occurrences*, handled in `days_until`, not about
    // whether the value itself is meaningful.
    NaiveDate::from_ymd_opt(2024, month, day)?;
    // A year-bearing value must also be a real date on its own terms, so
    // `1997-02-29` is rejected rather than silently treated as a leap birthday.
    if let Some(y) = year {
        NaiveDate::from_ymd_opt(y, month, day)?;
    }

    Some(Birthday {
        raw: raw.to_owned(),
        month,
        day,
        year,
    })
}

/// Days from `today` to the next occurrence of this birthday, with today
/// itself returning 0.
///
/// **A 29 February birthday occurs on 1 March in a non-leap year**, not on 28
/// February. The reasoning, since either is defensible and the next reader will
/// wonder: 29 February has not happened yet when 28 February passes, so
/// advancing to the following day is the only choice that never reports a
/// birthday as past when it is still ahead. It costs a day of notice once every
/// four years and never reports one late.
///
/// **A birthday does not recur before the year it records.** With a reference
/// date earlier than the birth year, the next occurrence is the birth itself:
/// `1984-03-17` asked from `1983-03-16` is 367 days away, not 1. Found by
/// cross-engine review of this module rather than by reasoning about it, and
/// reachable because `reference_date` is a caller-supplied parameter.
#[must_use]
pub fn days_until(birthday: &Birthday, today: NaiveDate) -> u32 {
    let first = birthday
        .year
        .map_or_else(|| today.year(), |born| born.max(today.year()));
    for year in [first, first + 1] {
        let Some(occurrence) = occurrence_in(birthday, year) else {
            continue;
        };
        if occurrence >= today {
            // Both dates are civil dates in the same calendar, so the
            // difference is non-negative and fits a u32 for any window a
            // caller can ask for.
            return u32::try_from((occurrence - today).num_days()).unwrap_or(u32::MAX);
        }
    }
    u32::MAX
}

/// The date this birthday falls on in `year`, applying the leap-day rule.
fn occurrence_in(birthday: &Birthday, year: i32) -> Option<NaiveDate> {
    NaiveDate::from_ymd_opt(year, birthday.month, birthday.day).or_else(|| {
        (birthday.month == 2 && birthday.day == 29)
            .then(|| NaiveDate::from_ymd_opt(year, 3, 1))
            .flatten()
    })
}

/// The age reached at the next occurrence, or `None` when the card records no
/// year.
#[must_use]
pub fn turning(birthday: &Birthday, today: NaiveDate) -> Option<i32> {
    let born = birthday.year?;
    let next = today + chrono::Duration::days(i64::from(days_until(birthday, today)));
    Some(next.year() - born)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn day(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    #[test]
    fn parses_every_form_the_spec_permits() {
        assert_eq!(parse_bday("1984-03-17").unwrap().year, Some(1984));
        assert_eq!(parse_bday("19840317").unwrap().month, 3);
        assert_eq!(parse_bday("--03-17").unwrap().year, None);
        assert_eq!(parse_bday("--0317").unwrap().day, 17);
        // A time part is discarded rather than rejected.
        assert_eq!(parse_bday("1984-03-17T09:00:00Z").unwrap().day, 17);
        // The raw value is preserved for a caller that wants to show it.
        assert_eq!(parse_bday(" 1984-03-17 ").unwrap().raw, "1984-03-17");
    }

    /// An unparseable `BDAY` is skipped and never fails the query around it.
    /// Every one of these appears in real address books.
    #[test]
    fn unparseable_values_return_none_rather_than_erroring() {
        for value in [
            "",
            "   ",
            "unknown",
            "circa 1984",
            "1984",       // year alone: no day to report
            "1984-03",    // year and month: same
            "--13-01",    // month 13
            "--02-30",    // no February has 30 days
            "1997-02-29", // 1997 is not a leap year
        ] {
            assert!(parse_bday(value).is_none(), "{value} should not parse");
        }
    }

    /// The boundary, both sides, which is what the live address book cannot
    /// exercise: today's date is day 0 and a window of N includes day N.
    #[test]
    fn today_is_zero_and_the_window_edge_is_inclusive() {
        let today = day(2026, 8, 29);
        assert_eq!(days_until(&parse_bday("--08-29").unwrap(), today), 0);
        assert_eq!(days_until(&parse_bday("--09-12").unwrap(), today), 14);
        assert_eq!(days_until(&parse_bday("--09-13").unwrap(), today), 15);
    }

    /// Yesterday's birthday is next year's, not a negative number and not a
    /// small one.
    #[test]
    fn a_birthday_just_past_wraps_to_next_year() {
        let today = day(2026, 8, 29);
        assert_eq!(days_until(&parse_bday("--08-28").unwrap(), today), 364);
    }

    /// The window crossing a year boundary is the case an implementation that
    /// compares month-day pairs numerically gets wrong.
    #[test]
    fn the_window_crosses_the_year_boundary() {
        let today = day(2026, 12, 28);
        assert_eq!(days_until(&parse_bday("--01-03").unwrap(), today), 6);
        assert_eq!(days_until(&parse_bday("--12-31").unwrap(), today), 3);
    }

    /// 29 February occurs on 1 March in a non-leap year, and on itself in a
    /// leap year.
    #[test]
    fn a_leap_day_birthday_falls_on_the_first_of_march_in_a_common_year() {
        let leap = parse_bday("1996-02-29").unwrap();
        // 2026 is not a leap year: 28 Feb passes, the birthday is 1 March.
        assert_eq!(days_until(&leap, day(2026, 2, 28)), 1);
        assert_eq!(days_until(&leap, day(2026, 3, 1)), 0);
        // 2028 is: it falls on the day itself.
        assert_eq!(days_until(&leap, day(2028, 2, 28)), 1);
        assert_eq!(days_until(&leap, day(2028, 2, 29)), 0);
    }

    /// The live-data pair, reproduced as a fixture so the suite holds it after
    /// the calendar moves. Measured 2026-08-29 against the real address book:
    /// three birthdays inside 30 days, at offsets 15, 22 and 30, and therefore
    /// **none** inside 14.
    ///
    /// That pair is the acceptance for `upcoming_birthdays`, and the 14-day arm
    /// is a control only because the 30-day arm answers differently on the same
    /// day over the same cards. A test asserting only the empty arm would pass
    /// against a query that matches nothing.
    #[test]
    fn the_thirty_day_window_answers_where_the_fourteen_day_window_is_empty() {
        let today = day(2026, 8, 29);
        // Offsets 15, 22 and 30 from 2026-08-29, plus two well outside.
        let cards = ["--09-13", "--09-20", "--09-28", "--08-28", "1984-06-01"];
        let within = |days: u32| {
            cards
                .iter()
                .filter_map(|raw| parse_bday(raw))
                .filter(|b| days_until(b, today) <= days)
                .count()
        };
        assert_eq!(within(30), 3);
        assert_eq!(within(14), 0);
        // The boundary itself, so the two arms differ by a case rather than by
        // luck: offset 15 is the first card the 14-day window excludes.
        assert_eq!(within(15), 1);
    }

    /// A birthday does not recur before the year it records. Found by
    /// cross-engine review: the month-day was treated as recurring in every
    /// year, so a reference date one day before a 1984 birth reported the
    /// birthday as tomorrow.
    #[test]
    fn a_birthday_does_not_occur_before_the_year_it_records() {
        let born = parse_bday("1984-03-17").unwrap();
        // 1983-03-16 to 1984-03-17, through a leap February.
        assert_eq!(days_until(&born, day(1983, 3, 16)), 367);
        assert_eq!(days_until(&born, day(1984, 3, 17)), 0);
        // Turning 0 at the birth itself is the correct age, not a placeholder.
        assert_eq!(turning(&born, day(1983, 3, 16)), Some(0));
        // A card with no year keeps recurring in every year, as before.
        assert_eq!(
            days_until(&parse_bday("--03-17").unwrap(), day(1983, 3, 16)),
            1
        );
    }

    #[test]
    fn age_is_reported_only_when_the_card_records_a_year() {
        let today = day(2026, 8, 29);
        assert_eq!(turning(&parse_bday("1984-09-12").unwrap(), today), Some(42));
        // Already past this year, so the next occurrence is next year's.
        assert_eq!(turning(&parse_bday("1984-08-28").unwrap(), today), Some(43));
        assert_eq!(turning(&parse_bday("--09-12").unwrap(), today), None);
    }
}
