//! The master password, held by the agent while the vault is unlocked.
//!
//! `lpass` is run once per vault call and fed the master password on stdin;
//! it derives the key, uses it and exits, and `LPASS_AGENT_DISABLE` keeps it
//! from starting the agent process that would otherwise hold that key for the
//! whole machine. So nothing this agent does leaves the vault open to any
//! other process: between calls, the only thing kept is the password itself,
//! here. (A vault you unlocked yourself in a shell is another matter — `lpass`
//! still reads that agent, and this one uses it as it finds it and never
//! locks it.) The secret held is the password itself, because `lpass` accepts
//! nothing else.
//!
//! It is dropped when the screen locks, when it has gone unused for the
//! configured idle time, when `lpass` reports it wrong, and when the agent
//! exits. The next call that needs it asks again — the Secure Enclave first
//! when that is configured and seeded, the prompt otherwise.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::approvals::LockEpoch;
use crate::config::MasterPassword;
use crate::master::{self, MasterPasswordStore, Source};
use crate::passphrase::PassphrasePrompt;

pub struct Unlock {
    held: tokio::sync::Mutex<Option<Held>>,
    /// Bumped whenever the password is dropped, so what should not outlive the
    /// unlock — remembered approvals — can tell.
    epoch: Arc<LockEpoch>,
    source: MasterPassword,
    store: Arc<dyn MasterPasswordStore>,
    prompt: Arc<dyn PassphrasePrompt>,
    /// How long it may go unused before it is dropped; `None` is never.
    idle: Option<Duration>,
    /// Set once `lpass` has rejected what the store supplied. The store is not
    /// asked again after that: its answer cannot change until
    /// `store-master-password` is run, and each ask costs a fingerprint.
    store_rejected: AtomicBool,
}

struct Held {
    /// Pinned in RAM for as long as it is held — see `platform::pin`. The copy
    /// handed to each call is not: it lives for that call and is wiped after.
    secret: Zeroizing<Vec<u8>>,
    from: Source,
    last_used: Instant,
}

impl Held {
    fn new(secret: Zeroizing<Vec<u8>>, from: Source) -> Self {
        crate::platform::pin(secret.as_ptr(), secret.capacity()).unwrap_or_else(could_not_pin);
        Self {
            secret,
            from,
            last_used: Instant::now(),
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        // Wiped while still pinned, so the pages never hold the password
        // between being unpinned and being zeroed.
        let (ptr, capacity) = (self.secret.as_ptr(), self.secret.capacity());
        self.secret.zeroize();
        crate::platform::unpin(ptr, capacity);
    }
}

/// The password is held all the same: what pinning adds is keeping it off
/// swap and out of dumps, and a lock limit exhausted by something else is not
/// a reason to refuse the vault. Excluded from coverage: a test cannot arrange
/// that limit. (`unwrap_or_else` dictates the by-value signature.)
#[expect(
    clippy::needless_pass_by_value,
    reason = "unwrap_or_else requires FnOnce(io::Error)"
)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn could_not_pin(e: std::io::Error) {
    tracing::warn!("cannot keep the master password out of swap and dumps: {e}");
}

impl Unlock {
    pub fn new(
        source: MasterPassword,
        store: Arc<dyn MasterPasswordStore>,
        prompt: Arc<dyn PassphrasePrompt>,
        idle: Option<Duration>,
    ) -> Self {
        Self {
            held: tokio::sync::Mutex::new(None),
            epoch: Arc::new(LockEpoch::default()),
            source,
            store,
            prompt,
            idle,
            store_rejected: AtomicBool::new(false),
        }
    }

    /// The password for one vault call: what is held, or — when `ask` allows —
    /// what the store or the prompt supplies, which is then held.
    ///
    /// `Ok(None)` only when nothing is held and asking was not allowed; a
    /// prompt that fails is an error, never an empty answer. The lock is kept
    /// across the prompt on purpose, so two calls arriving while nothing is held
    /// raise one prompt between them. Handing it out does not count as use:
    /// `touch` does, and only a signature's call says so.
    pub async fn password(&self, ask: bool) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        let mut held = self.held.lock().await;
        if let Some(current) = held.as_ref() {
            return Ok(Some(current.secret.clone()));
        }
        if !ask {
            return Ok(None);
        }
        // Having to ask means the vault is locked, whoever locked it: a vault a
        // shell had open holds nothing here and expires unseen, so this is the
        // one place that lock is learned of. Counted rather than treated as a
        // lock here, because the request asking is the one to decide what its
        // own approval is worth.
        self.epoch.unlocked();
        let (secret, from) = master::resolve(
            self.source,
            self.store.as_ref(),
            self.prompt.as_ref(),
            self.store_rejected.load(Ordering::SeqCst),
        )
        .await
        .map_err(|e| e.to_string())?;
        tracing::info!(
            source = from.name(),
            "holding the master password until the vault locks"
        );
        *held = Some(Held::new(secret.clone(), from));
        drop(held);
        Ok(Some(secret))
    }

    /// The counter of vault locks, for anything that should end with one.
    pub fn lock_epoch(&self) -> Arc<LockEpoch> {
        self.epoch.clone()
    }

    /// What is held has just been used. Nothing held is nothing to note.
    pub async fn touch(&self) {
        if let Some(current) = self.held.lock().await.as_mut() {
            current.last_used = Instant::now();
        }
    }

    /// `lpass` did not accept what it was given. Dropped, so the next call asks
    /// again — and if it came from the store, the store is not what gets asked.
    pub async fn rejected(&self) {
        let Some(was) = self.held.lock().await.take() else {
            return;
        };
        self.epoch.bump();
        if was.from == Source::Store {
            self.store_rejected.store(true, Ordering::SeqCst);
            tracing::warn!(
                "the stored master password no longer opens the vault, so the prompt is \
                 asked instead — run `lastpass-ssh-agent store-master-password` to replace it"
            );
        } else {
            tracing::info!("the master password was not accepted; asking again next time");
        }
    }

    /// Drop it. Already dropped is fine and says nothing — but counts as a
    /// lock all the same: a vault a shell opened holds nothing here, and what
    /// was approved while it was open should end with the screen too.
    pub async fn forget(&self, why: &str) {
        let was_held = self.held.lock().await.take().is_some();
        self.epoch.bump();
        if was_held {
            tracing::info!("{why}: the master password is no longer held");
        }
    }

    /// Drop it if it has gone unused for longer than the idle time.
    pub async fn expire_if_idle(&self) {
        let Some(idle) = self.idle else {
            return;
        };
        let mut held = self.held.lock().await;
        if held
            .as_ref()
            .is_some_and(|current| current.last_used.elapsed() >= idle)
        {
            held.take();
            drop(held);
            self.epoch.bump();
            tracing::info!(
                idle_secs = idle.as_secs(),
                "unused for the idle time: the master password is no longer held"
            );
        }
    }

    #[cfg(test)]
    pub async fn is_held(&self) -> bool {
        self.held.lock().await.is_some()
    }
}

/// What the lock watcher drives: the screen locking drops the password.
#[async_trait::async_trait]
impl crate::vaultlock::VaultKey for Unlock {
    async fn forget(&self) {
        self.forget("the screen locked").await;
    }
}

/// Apply the idle time for as long as the agent runs. Sampled rather than
/// timed from each use: a timer re-armed on every signature would be one
/// more thing on the signing path, for a deadline nobody notices to the
/// second.
pub async fn expire_when_idle(unlock: Arc<Unlock>, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        unlock.expire_if_idle().await;
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::passphrase::{PassphraseRequest, PromptError};

    /// Answers with a fixed secret and counts the asking.
    struct FakePrompt {
        answer: Option<&'static [u8]>,
        asked: std::sync::Mutex<usize>,
    }

    impl FakePrompt {
        fn answering(secret: &'static [u8]) -> Arc<Self> {
            Arc::new(Self {
                answer: Some(secret),
                asked: std::sync::Mutex::new(0),
            })
        }
        fn refusing() -> Arc<Self> {
            Arc::new(Self {
                answer: None,
                asked: std::sync::Mutex::new(0),
            })
        }
        fn asked(&self) -> usize {
            *self.asked.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl PassphrasePrompt for FakePrompt {
        async fn prompt(
            &self,
            _request: &PassphraseRequest,
        ) -> Result<Zeroizing<Vec<u8>>, PromptError> {
            *self.asked.lock().unwrap() += 1;
            self.answer.map_or_else(
                || Err(PromptError::Cancelled),
                |secret| Ok(Zeroizing::new(secret.to_vec())),
            )
        }
    }

    /// A store holding a fixed answer, counting the asking.
    struct FakeStore {
        secret: Option<&'static [u8]>,
        asked: std::sync::Mutex<usize>,
    }

    impl FakeStore {
        fn holding(secret: &'static [u8]) -> Arc<Self> {
            Arc::new(Self {
                secret: Some(secret),
                asked: std::sync::Mutex::new(0),
            })
        }
        fn asked(&self) -> usize {
            *self.asked.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl MasterPasswordStore for FakeStore {
        fn name(&self) -> &'static str {
            "a test store"
        }
        async fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            *self.asked.lock().unwrap() += 1;
            Ok(self.secret.map(|s| Zeroizing::new(s.to_vec())))
        }
        async fn set(&self, _secret: &[u8]) -> Result<(), String> {
            Ok(())
        }
        async fn forget(&self) -> Result<(), String> {
            Ok(())
        }
    }

    fn prompting(prompt: Arc<FakePrompt>, idle: Option<Duration>) -> Unlock {
        Unlock::new(
            MasterPassword::Prompt,
            Arc::new(master::NoStore),
            prompt,
            idle,
        )
    }

    #[tokio::test]
    async fn the_first_call_asks_and_the_second_is_served_from_what_is_held() {
        let prompt = FakePrompt::answering(b"secret");
        let unlock = prompting(prompt.clone(), None);
        assert!(!unlock.is_held().await);
        assert_eq!(&**unlock.password(true).await.unwrap().unwrap(), b"secret");
        assert_eq!(&**unlock.password(true).await.unwrap().unwrap(), b"secret");
        assert_eq!(prompt.asked(), 1, "held, so asked once");
        assert!(unlock.is_held().await);
    }

    #[tokio::test]
    async fn a_call_that_may_not_ask_gets_nothing_rather_than_a_prompt() {
        let prompt = FakePrompt::answering(b"secret");
        let unlock = prompting(prompt.clone(), None);
        assert!(unlock.password(false).await.unwrap().is_none());
        assert_eq!(prompt.asked(), 0);
        // but once something is held, it is served without asking either way
        unlock.password(true).await.unwrap();
        assert!(unlock.password(false).await.unwrap().is_some());
        assert_eq!(prompt.asked(), 1);
    }

    #[tokio::test]
    async fn a_refused_prompt_is_an_error_not_an_empty_answer() {
        let unlock = prompting(FakePrompt::refusing(), None);
        assert!(unlock.password(true).await.is_err());
        assert!(!unlock.is_held().await);
    }

    #[tokio::test]
    async fn forgetting_makes_the_next_call_ask_again() {
        let prompt = FakePrompt::answering(b"secret");
        let unlock = prompting(prompt.clone(), None);
        unlock.password(true).await.unwrap();
        unlock.forget("test").await;
        unlock.forget("test").await; // already gone is fine
        assert!(!unlock.is_held().await);
        unlock.password(true).await.unwrap();
        assert_eq!(prompt.asked(), 2);
    }

    #[tokio::test]
    async fn the_idle_time_drops_it_and_use_keeps_it() {
        let prompt = FakePrompt::answering(b"secret");
        let unlock = prompting(prompt.clone(), Some(Duration::from_millis(50)));
        unlock.password(true).await.unwrap();
        unlock.expire_if_idle().await;
        assert!(unlock.is_held().await, "just used");
        tokio::time::sleep(Duration::from_millis(40)).await;
        unlock.touch().await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        unlock.expire_if_idle().await;
        assert!(
            unlock.is_held().await,
            "used again before the idle time ran out"
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        unlock.expire_if_idle().await;
        assert!(!unlock.is_held().await, "idle for longer than allowed");
        unlock.touch().await; // nothing held: nothing to note
        assert!(!unlock.is_held().await);

        // and with no idle time it is kept indefinitely
        let forever = prompting(prompt, None);
        forever.password(true).await.unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        forever.expire_if_idle().await;
        assert!(forever.is_held().await);
    }

    #[tokio::test]
    async fn a_rejected_typed_password_is_dropped_and_asked_again() {
        let prompt = FakePrompt::answering(b"typo");
        let unlock = prompting(prompt.clone(), None);
        unlock.rejected().await; // nothing held yet: nothing to say
        unlock.password(true).await.unwrap();
        unlock.rejected().await;
        assert!(!unlock.is_held().await);
        unlock.password(true).await.unwrap();
        assert_eq!(prompt.asked(), 2);
    }

    #[tokio::test]
    async fn a_rejected_stored_password_stops_the_store_being_asked() {
        // Each ask of the store costs a fingerprint, for an answer that cannot
        // change until it is re-seeded. So after one rejection the prompt is
        // what gets asked.
        let store = FakeStore::holding(b"stale");
        let prompt = FakePrompt::answering(b"typed");
        let unlock = Unlock::new(MasterPassword::TouchId, store.clone(), prompt.clone(), None);
        assert_eq!(&**unlock.password(true).await.unwrap().unwrap(), b"stale");
        assert_eq!(prompt.asked(), 0);
        unlock.rejected().await;
        assert_eq!(&**unlock.password(true).await.unwrap().unwrap(), b"typed");
        assert_eq!(store.asked(), 1, "not asked a second time");
        assert_eq!(prompt.asked(), 1);
    }

    #[tokio::test]
    async fn every_way_of_dropping_it_counts_as_a_lock() {
        let prompt = FakePrompt::answering(b"secret");
        let unlock = prompting(prompt.clone(), Some(Duration::ZERO));
        let epoch = unlock.lock_epoch();
        assert_eq!(epoch.current(), 0);
        unlock.forget("nothing held").await;
        assert_eq!(
            epoch.current(),
            1,
            "a lock with nothing held still ends approvals"
        );
        unlock.password(true).await.unwrap();
        assert_eq!(epoch.unlocks(), 1, "having to ask is counted");
        unlock.password(true).await.unwrap();
        assert_eq!(epoch.unlocks(), 1, "served from what is held: no ask");
        assert_eq!(epoch.current(), 1, "and an ask is not itself a lock");
        unlock.forget("held").await;
        assert_eq!(epoch.current(), 2);
        unlock.password(true).await.unwrap();
        unlock.rejected().await;
        assert_eq!(epoch.current(), 3);
        unlock.password(true).await.unwrap();
        unlock.expire_if_idle().await;
        assert_eq!(epoch.current(), 4);
        unlock.rejected().await; // nothing held: not a lock
        assert_eq!(epoch.current(), 4);
        assert_eq!(epoch.unlocks(), 3);
    }

    #[tokio::test]
    async fn the_lock_watcher_drops_it() {
        let prompt = FakePrompt::answering(b"secret");
        let unlock = prompting(prompt, None);
        unlock.password(true).await.unwrap();
        crate::vaultlock::VaultKey::forget(&unlock).await;
        assert!(!unlock.is_held().await);
    }

    #[tokio::test]
    async fn the_idle_sweep_runs_on_its_own() {
        let prompt = FakePrompt::answering(b"secret");
        let unlock = Arc::new(prompting(prompt, Some(Duration::ZERO)));
        unlock.password(true).await.unwrap();
        let sweep = tokio::spawn(expire_when_idle(unlock.clone(), Duration::from_millis(1)));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !unlock.is_held().await,
            "a zero idle time expires on the first sweep"
        );
        sweep.abort();
    }
}
