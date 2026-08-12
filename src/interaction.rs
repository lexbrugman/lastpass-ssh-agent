//! The gate that keeps two signing requests from talking to the user at once.
//!
//! Confirmation and passphrase entry each serialize against themselves, but not
//! against each other, so without this one request's confirmation and another's
//! passphrase prompt could hold the same terminal together — and whichever read
//! first would take the answer meant for the other, landing a passphrase in the
//! confirmer's ordinary `String`, which nothing wipes.
//!
//! Two rules, and the gate exists to hold both at once:
//!
//! - **Taken late.** Only a request that actually reaches the user takes it. A
//!   signature that neither confirms nor prompts — confirmation off, key
//!   unencrypted or its passphrase in the vault — never touches the gate, so
//!   several can fetch and sign concurrently. Taking it at the top of every
//!   request instead would serialize the `lpass` round trip too, and that is
//!   most of the wall-clock cost of a signature.
//! - **Released late.** Once taken it is held to the end of the request, not
//!   returned between prompts. A request that confirms and *then* asks for a
//!   passphrase would otherwise leave a gap between the two for another
//!   request's prompt to land in — exactly the interleaving above, just
//!   narrower.

use std::sync::Arc;

use tokio::sync::{Mutex, OwnedMutexGuard};

/// One request's claim on the user's attention.
///
/// Built per signing request and dropped with it. `enter` is idempotent: the
/// first call takes the gate, later ones confirm this request already holds it.
pub struct InteractionGate {
    lock: Arc<Mutex<()>>,
    held: Option<OwnedMutexGuard<()>>,
}

impl InteractionGate {
    pub const fn new(lock: Arc<Mutex<()>>) -> Self {
        Self { lock, held: None }
    }

    /// Wait until nothing else is talking to the user, then keep it that way
    /// until this request is done.
    pub async fn enter(&mut self) {
        if self.held.is_none() {
            self.held = Some(self.lock.clone().lock_owned().await);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// Long enough to tell "blocked" from "slow", short enough to keep the
    /// suite quick. Only ever the *expected* wait, never a race: the gate is
    /// already held before either check.
    const A_MOMENT: std::time::Duration = std::time::Duration::from_millis(100);

    #[tokio::test]
    async fn a_second_request_waits_for_the_first_to_finish() {
        let lock = Arc::new(Mutex::new(()));
        let mut first = InteractionGate::new(lock.clone());
        first.enter().await;

        // Nothing is released between a request's own prompts, so the gate is
        // still held here and the second request cannot get in.
        let mut second = InteractionGate::new(lock.clone());
        assert!(
            tokio::time::timeout(A_MOMENT, second.enter())
                .await
                .is_err(),
            "a second request talked to the user while the first still held the gate"
        );

        drop(first);
        second.enter().await;
        drop(second);
    }

    #[tokio::test]
    async fn entering_twice_keeps_the_gate_rather_than_deadlocking_on_it() {
        // What a request that confirms and then asks for a passphrase does. The
        // second call must be a no-op: re-locking would wait on a guard this
        // very request is holding, and so wait forever.
        let mut gate = InteractionGate::new(Arc::new(Mutex::new(())));
        gate.enter().await;
        assert!(
            tokio::time::timeout(A_MOMENT, gate.enter()).await.is_ok(),
            "a request deadlocked against its own gate"
        );
        drop(gate);
    }
}
