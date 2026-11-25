//! The master password sealed to the Secure Enclave, kept in this process's
//! memory — and what the Enclave shim's answers mean.
//!
//! Sealed is encrypted to a key that never leaves this machine's Enclave and
//! that macOS will not use without a fingerprint. Neither the wrapped key nor
//! the ciphertext is a secret, and both stay in memory all the same, never in
//! a file: on disk, any process of the user's could load them and raise the
//! same Touch ID sheet under a name of its choosing, and one fingerprint would
//! hand it the vault. In here they are behind `platform::harden`, as the
//! password itself is, and gone when the agent exits — so the first unlock
//! after a start is typed.
//!
//! The shim itself is Swift behind a `cfg`, so only one CI job can reach it and
//! nobody without a Mac can compile it. Everything that is a *decision* lives
//! here instead: which stage of a failed call means what, what to tell the user
//! about it, and when a sealed copy is kept, replaced and dropped. All of it is
//! ordinary logic over integers and bytes, so it is tested on every platform —
//! which leaves the `cfg`-gated part with nothing in it but three calls.

// Only macOS has anything to call this, but it is compiled and tested
// everywhere on purpose — that is what keeps the `cfg`-gated adapter down to
// three foreign calls with no decisions in them.
#![cfg_attr(
    not(target_os = "macos"),
    allow(
        dead_code,
        reason = "the store this serves is macOS-only; the logic is tested on both platforms"
    )
)]

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use zeroize::Zeroizing;

use crate::master::MasterPasswordStore;

/// Where a shim call stopped, for the stages this tells apart. They mirror
/// `swift/secure_enclave.swift` and must be changed together.
///
/// The rest of the shim's stages are deliberately not named here, because
/// naming them would imply this does something with them and it does not: 1 (a
/// buffer too small), 3 (an access control that would not build), 4 (a key that
/// would not create) and 7 (a box that would not seal) are all bugs or broken
/// hardware rather than states to recover from, and are reported alike,
/// carrying whatever the system said. So is any stage a newer shim adds.
pub const STAGE_OK: i32 = 0;
pub const STAGE_UNAVAILABLE: i32 = 2;
pub const STAGE_RESTORE: i32 = 5;
pub const STAGE_AGREEMENT: i32 = 6;
pub const STAGE_MALFORMED: i32 = 8;
pub const STAGE_DECRYPT: i32 = 9;

/// `LocalAuthentication` codes that mean the prompt did not end in a
/// fingerprint. Listed rather than treated as one range because the range also
/// holds failures that are not about the person in front of the machine.
///
/// `userCancel`, `userFallback`, `systemCancel`, `appCancel`,
/// `biometryNotEnrolled`, `biometryLockout` and `notInteractive`, in that
/// order.
const NOT_AUTHENTICATED: [i32; 7] = [-2, -3, -4, -9, -7, -8, -1004];

/// What a call to the Enclave came back with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// It worked.
    Done,
    /// This machine has no Secure Enclave, so this store can never work here.
    Unavailable,
    /// Nobody proved presence — cancelled, timed out, no session to ask in.
    /// Ordinary, and never treated as a broken store.
    Refused,
    /// The sealed copy cannot be opened again, by anyone. A fingerprint added
    /// or removed since it was sealed invalidates the key by design.
    Lost,
    /// Something else went wrong. The raw code goes in the message, because
    /// this is the case where the code is the only clue.
    Failed(i32),
}

/// Turn a stage and the system's own error code into a decision.
///
/// Deliberately incomplete about one thing: a `biometryCurrentSet` key whose
/// enrolment changed fails somewhere in the agreement, and this does not claim
/// to know which code that is. Anything at that stage which is not plainly a
/// declined prompt is reported as a failure carrying its code, so the log says
/// what actually happened rather than a guess dressed up as a diagnosis.
pub fn meaning(stage: i32, os_error: i32) -> Outcome {
    match stage {
        STAGE_OK => Outcome::Done,
        STAGE_UNAVAILABLE => Outcome::Unavailable,
        // Three ways for the sealed copy to be past saving: the blob would not
        // load at all, the ciphertext is too short to be one, or it would not
        // open despite a fingerprint that worked. None of them can ever yield
        // the secret again, so all three are a copy to drop rather than a
        // fault the user could do something about.
        STAGE_RESTORE | STAGE_MALFORMED | STAGE_DECRYPT => Outcome::Lost,
        STAGE_AGREEMENT if NOT_AUTHENTICATED.contains(&os_error) => Outcome::Refused,
        _ => Outcome::Failed(os_error),
    }
}

impl Outcome {
    /// How this reads in the agent's log.
    ///
    /// Every one of these ends up in the same place: a line saying the store
    /// could not answer, followed by the prompt. So they are written to tell
    /// the user what happens next, not to sound like an error.
    pub fn describe(self) -> String {
        match self {
            Self::Done => "the Secure Enclave answered".into(),
            Self::Unavailable => "this Mac has no Secure Enclave".into(),
            Self::Refused => "Touch ID was not confirmed".into(),
            Self::Lost => "what was kept behind Touch ID can no longer be opened — a \
                           fingerprint added or removed since will do that — so the master \
                           password is asked for, and kept afresh"
                .into(),
            Self::Failed(code) => format!("the Secure Enclave refused the request (code {code})"),
        }
    }
}

/// The room the shim is given to write a blob and a ciphertext into.
///
/// A wrapped P-256 key runs to a few hundred bytes, and the ciphertext is the
/// secret plus a fixed 93, so both are far above anything it produces. Past
/// either it refuses rather than truncates.
pub const MAX_BLOB: usize = 4096;
pub const MAX_CIPHER: usize = 4096;

/// A sealed secret: the Enclave key's wrapped blob, and the ciphertext only
/// that key opens.
#[derive(Debug, PartialEq, Eq)]
pub struct Sealed {
    pub blob: Vec<u8>,
    pub cipher: Vec<u8>,
}

/// The Enclave's two operations, as the shim performs them.
///
/// Blocking, both: opening waits on the fingerprint sensor for as long as the
/// person takes. A trait so that everything `Kept` decides around them is
/// tested without a Mac.
pub trait Enclave: Send + Sync + 'static {
    /// Make a new key and encrypt the secret to it. Never prompts: the access
    /// control is enforced when a key is used, not when it is made.
    fn seal(&self, secret: &[u8]) -> Result<Sealed, Outcome>;
    /// Decrypt, which is where the fingerprint is asked for.
    fn open(&self, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>, Outcome>;
}

/// The master-password store `touchid` uses: one sealed copy, held here.
pub struct Kept {
    enclave: Arc<dyn Enclave>,
    sealed: Mutex<Option<Arc<Sealed>>>,
}

impl Kept {
    pub fn new(enclave: Arc<dyn Enclave>) -> Self {
        Self {
            enclave,
            sealed: Mutex::new(None),
        }
    }

    fn sealed(&self) -> MutexGuard<'_, Option<Arc<Sealed>>> {
        self.sealed.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait::async_trait]
impl MasterPasswordStore for Kept {
    fn name(&self) -> &'static str {
        "the Secure Enclave"
    }

    async fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        let Some(sealed) = self.sealed().clone() else {
            return Ok(None);
        };
        let enclave = self.enclave.clone();
        match blocking(move || enclave.open(&sealed)).await? {
            Ok(secret) => Ok(Some(secret)),
            // Dropped, and reported as nothing kept: asking the Enclave again
            // would cost a fingerprint for an answer that cannot change.
            Err(Outcome::Lost) => {
                *self.sealed() = None;
                tracing::warn!("{}", Outcome::Lost.describe());
                Ok(None)
            }
            // A declined fingerprint above all: the copy is still good, and
            // the next unlock may ask for it again.
            Err(other) => Err(other.describe()),
        }
    }

    async fn set(&self, secret: &[u8]) -> Result<(), String> {
        // The copy that crosses to the blocking thread: one allocation, wiped
        // there when the call ends.
        let secret = Zeroizing::new(secret.to_vec());
        let enclave = self.enclave.clone();
        let sealed = blocking(move || enclave.seal(&secret))
            .await?
            .map_err(Outcome::describe)?;
        *self.sealed() = Some(Arc::new(sealed));
        Ok(())
    }

    async fn forget(&self) {
        *self.sealed() = None;
    }
}

/// Run one Enclave call off the runtime thread: the agent runs on one, and a
/// Touch ID sheet inline would freeze every other connection until somebody
/// noticed it.
async fn blocking<T: Send + 'static>(
    call: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(call)
        .await
        .map_err(did_not_finish)
}

/// The call panicked, which is reported rather than propagated: the same
/// secret is still reachable by asking for it.
#[expect(
    clippy::needless_pass_by_value,
    reason = "by value is what map_err hands a function"
)]
fn did_not_finish(e: tokio::task::JoinError) -> String {
    format!("the Secure Enclave call did not finish: {e}")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn expect_meaning(stage: i32, os_error: i32, expected: Outcome) {
        assert_eq!(
            meaning(stage, os_error),
            expected,
            "stage {stage} with code {os_error}"
        );
    }

    #[test]
    fn success_is_success() {
        expect_meaning(STAGE_OK, 0, Outcome::Done);
    }

    #[test]
    fn a_mac_without_an_enclave_says_so() {
        expect_meaning(STAGE_UNAVAILABLE, 0, Outcome::Unavailable);
    }

    #[test]
    fn a_blob_that_will_not_load_is_lost() {
        expect_meaning(STAGE_RESTORE, -25293, Outcome::Lost);
    }

    #[test]
    fn a_ciphertext_that_is_too_short_is_lost() {
        expect_meaning(STAGE_MALFORMED, 0, Outcome::Lost);
    }

    #[test]
    fn a_ciphertext_that_will_not_open_is_lost() {
        // The fingerprint was given and the agreement worked, so this is not a
        // fault anyone can retry past.
        expect_meaning(STAGE_DECRYPT, -1, Outcome::Lost);
    }

    #[test]
    fn a_cancelled_prompt_is_a_refusal_not_a_fault() {
        for code in NOT_AUTHENTICATED {
            expect_meaning(STAGE_AGREEMENT, code, Outcome::Refused);
        }
    }

    #[test]
    fn any_other_agreement_failure_keeps_its_code() {
        expect_meaning(STAGE_AGREEMENT, -25300, Outcome::Failed(-25300));
    }

    /// The stages this deliberately does not name: a buffer too small, an
    /// access control that would not build, a key that would not create, a box
    /// that would not seal — and a stage from some later shim.
    #[test]
    fn every_other_stage_is_a_failure_carrying_its_code() {
        for stage in [1, 3, 4, 7, 99] {
            expect_meaning(stage, -5, Outcome::Failed(-5));
        }
    }

    #[test]
    fn every_outcome_describes_itself_usefully() {
        for (outcome, expected) in [
            (Outcome::Done, "answered"),
            (Outcome::Unavailable, "no Secure Enclave"),
            (Outcome::Refused, "Touch ID"),
            (Outcome::Lost, "kept afresh"),
            (Outcome::Failed(-7), "code -7"),
        ] {
            let described = outcome.describe();
            assert!(described.contains(expected), "{outcome:?}: {described}");
        }
    }

    /// An Enclave that "seals" by keeping the secret as the blob, and opens
    /// with whatever the case says the sensor did.
    #[derive(Default)]
    struct FakeEnclave {
        seal_fails: Option<Outcome>,
        open_fails: Mutex<Option<Outcome>>,
        opened: AtomicUsize,
    }

    impl FakeEnclave {
        fn opening_fails_with(&self, outcome: Option<Outcome>) {
            *self.open_fails.lock().unwrap() = outcome;
        }
        fn opened(&self) -> usize {
            self.opened.load(Ordering::SeqCst)
        }
    }

    impl Enclave for FakeEnclave {
        fn seal(&self, secret: &[u8]) -> Result<Sealed, Outcome> {
            self.seal_fails.map_or_else(
                || {
                    Ok(Sealed {
                        blob: secret.to_vec(),
                        cipher: Vec::new(),
                    })
                },
                Err,
            )
        }
        fn open(&self, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>, Outcome> {
            self.opened.fetch_add(1, Ordering::SeqCst);
            let fails = *self.open_fails.lock().unwrap();
            fails.map_or_else(|| Ok(Zeroizing::new(sealed.blob.clone())), Err)
        }
    }

    fn kept() -> (Kept, Arc<FakeEnclave>) {
        let enclave = Arc::new(FakeEnclave::default());
        (Kept::new(enclave.clone()), enclave)
    }

    #[tokio::test]
    async fn nothing_kept_is_nothing_to_ask_the_enclave_for() {
        let (store, enclave) = kept();
        assert_eq!(store.get().await.unwrap(), None);
        assert_eq!(enclave.opened(), 0, "no fingerprint asked for");
        assert_eq!(store.name(), "the Secure Enclave");
    }

    #[tokio::test]
    async fn what_was_sealed_is_what_opens() {
        let (store, _enclave) = kept();
        store.set(b"master").await.unwrap();
        assert_eq!(store.get().await.unwrap().unwrap().as_slice(), b"master");
    }

    #[tokio::test]
    async fn sealing_again_replaces_what_was_kept() {
        let (store, _enclave) = kept();
        store.set(b"first").await.unwrap();
        store.set(b"second").await.unwrap();
        assert_eq!(store.get().await.unwrap().unwrap().as_slice(), b"second");
    }

    #[tokio::test]
    async fn a_declined_fingerprint_is_an_error_and_the_copy_survives_it() {
        // Calling this "nothing kept" would cost a typed password for what
        // only wanted a fingerprint.
        let (store, enclave) = kept();
        store.set(b"master").await.unwrap();
        enclave.opening_fails_with(Some(Outcome::Refused));
        assert_eq!(store.get().await.unwrap_err(), "Touch ID was not confirmed");
        enclave.opening_fails_with(None);
        assert_eq!(store.get().await.unwrap().unwrap().as_slice(), b"master");
    }

    #[tokio::test]
    async fn a_copy_that_can_never_open_again_is_dropped() {
        let (store, enclave) = kept();
        store.set(b"master").await.unwrap();
        enclave.opening_fails_with(Some(Outcome::Lost));
        assert_eq!(store.get().await.unwrap(), None);
        assert_eq!(store.get().await.unwrap(), None);
        assert_eq!(enclave.opened(), 1, "not asked a second fingerprint for it");
    }

    #[tokio::test]
    async fn a_call_that_panics_is_an_error_not_a_crash() {
        let error = blocking::<()>(|| panic!("the enclave fell over"))
            .await
            .unwrap_err();
        assert!(error.contains("did not finish"), "{error}");
    }

    #[tokio::test]
    async fn forgetting_drops_the_copy() {
        let (store, enclave) = kept();
        store.set(b"master").await.unwrap();
        store.forget().await;
        assert_eq!(store.get().await.unwrap(), None);
        assert_eq!(enclave.opened(), 0);
    }

    #[tokio::test]
    async fn an_enclave_that_will_not_seal_keeps_nothing() {
        let store = Kept::new(Arc::new(FakeEnclave {
            seal_fails: Some(Outcome::Unavailable),
            ..FakeEnclave::default()
        }));
        assert_eq!(
            store.set(b"master").await.unwrap_err(),
            "this Mac has no Secure Enclave"
        );
        assert_eq!(store.get().await.unwrap(), None);
    }
}
