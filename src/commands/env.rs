//! `env`: what a shell evaluates to reach the agent.

use std::path::Path;

use crate::config::Config;
use crate::error::Result;

pub fn run(config_path: &Path) -> Result<()> {
    let config = Config::load_or_default(config_path)?;
    print_env(&config.socket_path()?);
    Ok(())
}

fn print_env(socket: &Path) {
    println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", sh_quote(socket));
}

fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn sh_quote_survives_spaces_and_quotes() {
        assert_eq!(sh_quote(Path::new("/a b/agent.sock")), "'/a b/agent.sock'");
        assert_eq!(
            sh_quote(Path::new("/a'b/agent.sock")),
            r"'/a'\''b/agent.sock'"
        );
    }

    #[test]
    fn print_env_emits_the_export_line() {
        print_env(Path::new("/tmp/agent.sock"));
    }
}
