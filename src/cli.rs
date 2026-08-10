use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Renders `2026.810.0 (2026-08-10, commit abc123def456)`. The version is
/// calendar-based, so it says how old a build is on sight; the commit pins
/// exactly which build it is.
fn version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        format!(
            "{} ({}, commit {})",
            env!("CARGO_PKG_VERSION"),
            release_date(env!("CARGO_PKG_VERSION")),
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
    if year.len() != 4
        || !year.bytes().all(|b| b.is_ascii_digit())
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
    {
        return UNKNOWN.into();
    }
    format!("{year}-{month:02}-{day:02}")
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
    fn a_version_that_is_not_calver_says_so() {
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
    fn version_string_names_the_build() {
        let text = version();
        assert!(text.contains(env!("CARGO_PKG_VERSION")), "{text}");
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
