use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Renders `2026.810.0 (2026-08-10, commit abc123def456)`. The version is
/// calendar-based, so it says how old a build is on sight; the commit pins
/// exactly which build it is.
///
/// Both come from `build.rs`, not from `CARGO_PKG_VERSION`: the released
/// version lives in the release that publishes it and is never committed, so
/// the manifest holds a placeholder that would be a lie to print.
fn version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        format!(
            "{} ({}, commit {})",
            env!("LASTPASS_SSH_AGENT_VERSION"),
            release_date(env!("LASTPASS_SSH_AGENT_VERSION")),
            env!("LASTPASS_SSH_AGENT_COMMIT"),
        )
    })
}

/// Expand the calendar version back into a readable date. Anything that is
/// not a plausible date (a dev build, say) is reported as such rather than
/// rendered as a nonsense one.
fn release_date(version: &str) -> String {
    const UNKNOWN: &str = "unknown date";
    let mut parts = version.split('.');
    let (Some(year), Some(month_day)) = (parts.next(), parts.next()) else {
        return UNKNOWN.into();
    };
    // MMDD without a leading zero: 810 = August 10, 1225 = December 25
    let Ok(month_day) = month_day.parse::<u32>() else {
        return UNKNOWN.into();
    };
    let (month, day) = (month_day / 100, month_day % 100);
    if year.len() != 4 || !year.bytes().all(|b| b.is_ascii_digit()) || !(1..=12).contains(&month) {
        return UNKNOWN.into();
    }
    // Four ASCII digits by the check above, so this cannot overflow and
    // needs no fallible parse.
    let year_number = year
        .bytes()
        .fold(0u32, |acc, b| acc * 10 + u32::from(b - b'0'));
    // Per-month, so an impossible date is reported as one rather than
    // rendered: 2026.231.0 is not "2026-02-31".
    if !(1..=days_in_month(year_number, month)).contains(&day) {
        return UNKNOWN.into();
    }
    format!("{year}-{month:02}-{day:02}")
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        // month is 1..=12 by the time we get here, so this is February
        _ if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        _ => 28,
    }
}

#[derive(Debug, Parser)]
#[command(name = "lastpass-ssh-agent", version = version(), about)]
pub struct Cli {
    /// Config file (default: ~/.config/lastpass-ssh-agent/config.toml)
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the agent and serve the SSH agent protocol on the socket
    Start,
    /// List configured keys and their fingerprints
    List,
    /// Check the whole setup: config, lpass binary, login, items, socket dir
    Doctor {
        /// Also pop the confirmation dialog once, to verify it works
        #[arg(long)]
        test_confirm: bool,
    },
    /// Print shell commands to point SSH at the agent socket
    Env,
    /// Find SSH Key items in the `LastPass` vault (interactive helper)
    Search {
        /// Substring to match against item names; omit to list all SSH Key items
        query: Option<String>,
    },
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn calver_expands_to_a_readable_date() {
        assert_eq!(release_date("2026.810.0"), "2026-08-10");
        assert_eq!(release_date("2026.1225.3"), "2026-12-25");
        assert_eq!(release_date("2027.101.0"), "2027-01-01");
    }

    #[test]
    fn a_build_between_releases_dates_from_the_one_it_follows() {
        // what `git describe` gives a build off dev: the newest release, then
        // the distance past it. The date is that release's, which is the point
        // — it says how old the code underneath is.
        assert_eq!(release_date("2026.811.2-5-gabc123def456"), "2026-08-11");
        assert_eq!(release_date("2026.1225.0-1-g0000000"), "2026-12-25");
    }

    #[test]
    fn a_version_that_is_not_calver_says_so() {
        // the placeholder a build with neither an environment nor a tag gets
        assert_eq!(release_date("dev"), "unknown date");
        assert_eq!(release_date("0.1.0-dev"), "unknown date");
        assert_eq!(release_date("2026"), "unknown date");
        assert_eq!(release_date(""), "unknown date");
        assert_eq!(release_date("2026.abc.0"), "unknown date");
        assert_eq!(release_date("26.810.0"), "unknown date", "short year");
        assert_eq!(
            release_date("20x6.810.0"),
            "unknown date",
            "non-numeric year"
        );
        assert_eq!(release_date("2026.1310.0"), "unknown date", "month 13");
        assert_eq!(release_date("2026.832.0"), "unknown date", "day 32");
        assert_eq!(release_date("2026.800.0"), "unknown date", "day 0");
    }

    #[test]
    fn a_day_the_month_does_not_have_is_not_a_date() {
        // the whole point: 2026.231.0 must not render as "2026-02-31"
        assert_eq!(release_date("2026.231.0"), "unknown date", "February 31");
        assert_eq!(release_date("2026.431.0"), "unknown date", "April 31");
        assert_eq!(release_date("2026.430.0"), "2026-04-30");

        // February follows the leap rule, including both century cases
        assert_eq!(
            release_date("2026.229.0"),
            "unknown date",
            "not a leap year"
        );
        assert_eq!(release_date("2028.229.0"), "2028-02-29", "divisible by 4");
        assert_eq!(
            release_date("2100.229.0"),
            "unknown date",
            "century, not 400"
        );
        assert_eq!(release_date("2000.229.0"), "2000-02-29", "divisible by 400");
    }

    #[test]
    fn every_month_has_its_own_length() {
        // covers each arm of the month table rather than a sample of it
        for (month, days) in [
            (1, 31),
            (2, 28),
            (3, 31),
            (4, 30),
            (5, 31),
            (6, 30),
            (7, 31),
            (8, 31),
            (9, 30),
            (10, 31),
            (11, 30),
            (12, 31),
        ] {
            assert_eq!(days_in_month(2026, month), days, "month {month}");
            let last = format!("2026.{}.0", month * 100 + days);
            assert_eq!(release_date(&last), format!("2026-{month:02}-{days:02}"));
            let past_end = format!("2026.{}.0", month * 100 + days + 1);
            assert_eq!(release_date(&past_end), "unknown date", "month {month}");
        }
    }

    #[test]
    fn version_string_names_the_build() {
        let text = version();
        assert!(text.contains(env!("LASTPASS_SSH_AGENT_VERSION")), "{text}");
        assert!(text.contains("commit "), "{text}");
        // built twice, same answer (it is cached)
        assert_eq!(text, version());
    }

    #[test]
    fn cli_parses_every_subcommand() {
        use clap::CommandFactory as _;
        Cli::command().debug_assert();
    }
}
