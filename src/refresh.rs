//! Keeping the remembered identities current while the agent runs.
//!
//! A scan costs a vault call per item, so it runs when a signature has just
//! proved the vault reachable, at most once an hour, and through a client that
//! cannot prompt: fed only what the agent already holds, it is silent with the
//! vault open, and with the vault shut it fails fast and nothing changes. What it produces replaces both the served set and
//! the file, and only whole — `KeyStore::load_complete` says what "whole" means.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::keystore::{self, KeyStore, Served};
use crate::lpass::LpassClient;

/// The identities change rarely, and a scan is a vault call per item.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

pub struct Refresher {
    served: Served,
    remembered_at: PathBuf,
    config: Arc<Config>,
    /// Fed only the master password the agent already holds, so nothing it
    /// does can put a prompt on screen — a shut vault fails fast instead.
    client: Arc<dyn LpassClient>,
    interval: Duration,
    /// When the last attempt began. Attempts rather than successes: a vault
    /// that stays shut would otherwise be scanned again at every signature.
    last: std::sync::Mutex<Option<Instant>>,
    /// Whether a scan is in flight. One at a time: two would race each other's
    /// writes — `files::write_private` stages under one name per process — and
    /// the older could land last.
    running: std::sync::atomic::AtomicBool,
}

impl Refresher {
    pub fn new(
        served: Served,
        remembered_at: PathBuf,
        config: Arc<Config>,
        client: Arc<dyn LpassClient>,
        interval: Duration,
    ) -> Self {
        Self {
            served,
            remembered_at,
            config,
            client,
            interval,
            last: std::sync::Mutex::new(None),
            running: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// A signature has just succeeded, so the vault is reachable: refresh in the
    /// background if one is due. The request that asked is not made to wait.
    pub fn after_signature(self: &Arc<Self>) {
        use std::sync::atomic::Ordering;
        // Looked at before the throttle is consulted, so a signature landing
        // while a scan runs does not spend the hour's one attempt on nothing.
        if self.running.load(Ordering::SeqCst) || !self.due() {
            return;
        }
        self.spawn();
    }

    /// The agent has just bound, and the vault may or may not be open. Refresh
    /// in the background if it is; if it is not, the attempt fails fast and
    /// nothing changes. Outside the throttle on purpose: a start that finds the
    /// vault shut must not spend the hour's one attempt, which the first
    /// signature will need.
    pub fn at_startup(self: &Arc<Self>) {
        self.spawn();
    }

    /// Run one scan in the background, unless one is already running.
    fn spawn(self: &Arc<Self>) {
        use std::sync::atomic::Ordering;
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        let this = Arc::clone(self);
        tokio::task::spawn(async move {
            this.refresh_now().await;
            this.running.store(false, Ordering::SeqCst);
        });
    }

    /// Whether an attempt is due, and if so, that one has now begun.
    fn due(&self) -> bool {
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.is_some_and(|began| began.elapsed() < self.interval) {
            return false;
        }
        *last = Some(Instant::now());
        true
    }

    /// Scan now. Only a complete scan replaces anything; every other outcome
    /// leaves the served set and the file exactly as they were, and says why at
    /// debug — a shut vault is routine here, not a fault.
    pub async fn refresh_now(&self) {
        let keys = match keystore::effective_keys(&self.client, &self.config).await {
            Ok(keys) => keys,
            Err(e) => {
                tracing::debug!("not refreshing the identities: {e}");
                return;
            }
        };
        let Some(store) = KeyStore::load_complete(self.client.as_ref(), &keys, &self.config).await
        else {
            return;
        };
        let remembered = store.remember();
        let count = remembered.keys.len();
        self.served.replace(store);
        crate::identities::save_best_effort(&self.remembered_at, &remembered);
        tracing::info!(keys = count, "refreshed the identities from the vault");
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::lpass::mock::MockLpass;

    use crate::testutil::fixtures::*;

    /// A served set of one key, and a refresher whose vault holds two.
    fn one_served_two_in_the_vault(
        vault: MockLpass,
        interval: Duration,
    ) -> (Arc<Refresher>, Served, PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let remembered_at = dir.path().join("agent.sock.identities");
        let config: Arc<Config> =
            Arc::new(toml::from_str("[[keys]]\nid = \"1\"\n[[keys]]\nid = \"2\"").unwrap());
        let served = Served::new(
            KeyStore::from_remembered(
                &crate::identities::Remembered {
                    keys: vec![crate::identities::RememberedKey {
                        id: "1".into(),
                        name: "one".into(),
                        public: ED25519_PUB.trim().into(),
                    }],
                },
                &config,
            )
            .store,
        );
        assert_eq!(served.current().len(), 1);
        let refresher = Arc::new(Refresher::new(
            served.clone(),
            remembered_at.clone(),
            config,
            Arc::new(vault),
            interval,
        ));
        (refresher, served, remembered_at, dir)
    }

    fn two_keys() -> MockLpass {
        MockLpass::logged_in().with_ed25519_public("1").with_field(
            "2",
            "Public Key",
            RSA_PUB.as_bytes(),
        )
    }

    #[tokio::test]
    async fn a_complete_scan_replaces_the_served_set_and_the_file() {
        let (refresher, served, remembered_at, _dir) =
            one_served_two_in_the_vault(two_keys(), REFRESH_INTERVAL);
        refresher.refresh_now().await;
        assert_eq!(served.current().len(), 2);
        let written = crate::identities::load(&remembered_at).unwrap().unwrap();
        assert_eq!(written.keys.len(), 2);
    }

    #[tokio::test]
    async fn a_shut_vault_leaves_both_as_they_were() {
        let (refresher, served, remembered_at, _dir) =
            one_served_two_in_the_vault(MockLpass::default(), REFRESH_INTERVAL);
        refresher.refresh_now().await;
        assert_eq!(served.current().len(), 1);
        assert!(!remembered_at.exists(), "nothing was written");
    }

    #[tokio::test]
    async fn a_discovery_the_vault_will_not_list_leaves_both_as_they_were() {
        // With nothing pinned the scan begins with `ls`, and a shut vault fails
        // there — before any key is looked at. Nothing changes, and it is said
        // at debug: a shut vault is routine here, not a fault.
        let dir = tempfile::tempdir().unwrap();
        let remembered_at = dir.path().join("agent.sock.identities");
        let config: Arc<Config> = Arc::new(toml::from_str("").unwrap());
        let served = Served::new(
            KeyStore::from_remembered(
                &crate::identities::Remembered {
                    keys: vec![crate::identities::RememberedKey {
                        id: "1".into(),
                        name: "one".into(),
                        public: ED25519_PUB.trim().into(),
                    }],
                },
                &config,
            )
            .store,
        );
        let refresher = Refresher::new(
            served.clone(),
            remembered_at.clone(),
            config,
            Arc::new(MockLpass::default()),
            REFRESH_INTERVAL,
        );
        refresher.refresh_now().await;
        assert_eq!(served.current().len(), 1);
        assert!(!remembered_at.exists());
    }

    #[tokio::test]
    async fn a_scan_the_vault_could_not_finish_leaves_both_as_they_were() {
        // Key 2 is there but the vault would not hand it over: an incomplete
        // scan must not replace a set, even one it would have grown.
        let vault = MockLpass::logged_in()
            .with_ed25519_public("1")
            .with_broken_item("2");
        let (refresher, served, remembered_at, _dir) =
            one_served_two_in_the_vault(vault, REFRESH_INTERVAL);
        refresher.refresh_now().await;
        assert_eq!(served.current().len(), 1);
        assert!(!remembered_at.exists());
    }

    #[tokio::test]
    async fn only_one_attempt_per_interval() {
        let (refresher, _served, _at, _dir) =
            one_served_two_in_the_vault(two_keys(), REFRESH_INTERVAL);
        assert!(refresher.due(), "the first attempt is always due");
        assert!(!refresher.due(), "and the next within the interval is not");

        let (eager, _served, _at, _dir) = one_served_two_in_the_vault(two_keys(), Duration::ZERO);
        assert!(eager.due());
        assert!(eager.due(), "a zero interval is due every time");
    }

    #[tokio::test]
    async fn a_signature_schedules_the_refresh_without_waiting_on_it() {
        let (refresher, served, _at, _dir) =
            one_served_two_in_the_vault(two_keys(), Duration::ZERO);
        refresher.after_signature();
        // scheduled, not run: the caller continues at once
        let deadline = Instant::now() + Duration::from_secs(10);
        while served.current().len() != 2 {
            assert!(Instant::now() < deadline, "the refresh never landed");
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn a_start_refreshes_when_the_vault_is_open_and_keeps_the_throttle_free() {
        let (refresher, served, _at, _dir) =
            one_served_two_in_the_vault(two_keys(), REFRESH_INTERVAL);
        refresher.at_startup();
        let deadline = Instant::now() + Duration::from_secs(10);
        while served.current().len() != 2 {
            assert!(Instant::now() < deadline, "the refresh never landed");
            tokio::task::yield_now().await;
        }
        assert!(
            refresher.due(),
            "the first signature still gets its attempt"
        );
    }

    #[tokio::test]
    async fn only_one_scan_runs_at_a_time_and_a_signature_meanwhile_keeps_its_attempt() {
        use std::sync::atomic::Ordering;
        let (refresher, served, _at, _dir) =
            one_served_two_in_the_vault(two_keys(), REFRESH_INTERVAL);
        // a scan is in flight
        refresher.running.store(true, Ordering::SeqCst);
        refresher.at_startup();
        refresher.after_signature();
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert_eq!(served.current().len(), 1, "nothing ran alongside it");
        assert!(refresher.due(), "the signature spent nothing");

        // it finishes, and the next start-style kick runs
        refresher.running.store(false, Ordering::SeqCst);
        refresher.at_startup();
        let deadline = Instant::now() + Duration::from_secs(10);
        while served.current().len() != 2 {
            assert!(Instant::now() < deadline, "the refresh never landed");
            tokio::task::yield_now().await;
        }
        while refresher.running.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn a_signature_inside_the_interval_schedules_nothing() {
        let (refresher, served, _at, _dir) =
            one_served_two_in_the_vault(two_keys(), REFRESH_INTERVAL);
        assert!(
            refresher.due(),
            "spend the one attempt this interval allows"
        );
        refresher.after_signature();
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert_eq!(served.current().len(), 1, "nothing ran");
    }
}
