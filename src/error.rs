use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config file not found at {0} (create it or pass --config)")]
    ConfigMissing(PathBuf),

    #[error("failed to read config {path}: {source}")]
    ConfigRead {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse config {path}: {source}")]
    ConfigParse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },

    #[error("invalid config: {0}")]
    ConfigInvalid(String),

    /// A file this agent owns is not in the state it needs to be — the askpass
    /// wrapper, the Secure Enclave store. Deliberately unprefixed: these
    /// messages name the file, what is wrong with it and what to run, so a
    /// label in front would only push the useful part further along the line.
    /// Not `ConfigInvalid`: none of these are the user's config, and saying so
    /// sends them to edit a file that was never the problem.
    #[error("{0}")]
    State(String),

    #[error("hardening failed: {0}")]
    Harden(String),

    #[error("one or more doctor checks failed")]
    DoctorFailed,

    #[error("socket error: {0}")]
    Socket(String),

    #[error("agent terminated: {0}")]
    Agent(String),

    #[error(transparent)]
    Lpass(#[from] crate::lpass::LpassError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
