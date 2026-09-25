//! Approvals remembered until the vault locks.
//!
//! Opt-in. With it on, approving a signature for one key from one place — the
//! same process started from the same chain, bound to the same hosts — answers
//! the same question the next time, until the vault locks. That is the
//! arrangement 1Password's agent offers, and the trade is the same: one prompt
//! per key per application per unlock, instead of one per signature, in
//! exchange for anything that can drive that application signing unasked for
//! as long as the vault stays open.
//!
//! "Until the vault locks" is `LockEpoch`: a counter `crate::unlock` bumps
//! whenever it forgets the master password, for whatever reason. An approval
//! records the epoch it was given in, and is only honoured in that epoch — so
//! nothing has to find and clear them when the lock happens. A lock this
//! agent never saw — a vault a shell had open, expiring — shows up as having
//! to ask for the master password, which `LockEpoch` counts separately; the
//! signing path turns that into a lock at the moment it learns of it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// How many times the vault has locked, and how many times the master
/// password has had to be asked for. Bumped by whoever forgets or asks; read
/// by whoever remembers something that should not outlive a lock.
#[derive(Default)]
pub struct LockEpoch {
    locks: AtomicU64,
    unlocks: AtomicU64,
}

impl LockEpoch {
    pub fn current(&self) -> u64 {
        self.locks.load(Ordering::SeqCst)
    }

    /// The vault has locked: nothing remembered before now is honoured again.
    pub fn bump(&self) {
        self.locks.fetch_add(1, Ordering::SeqCst);
    }

    /// The master password had to be asked for.
    pub fn unlocked(&self) {
        self.unlocks.fetch_add(1, Ordering::SeqCst);
    }

    pub fn unlocks(&self) -> u64 {
        self.unlocks.load(Ordering::SeqCst)
    }
}

pub struct Approvals {
    enabled: bool,
    epoch: Arc<LockEpoch>,
    /// Each remembered question, with the epoch it was answered in.
    remembered: Mutex<HashMap<String, u64>>,
}

impl Approvals {
    pub fn new(enabled: bool, epoch: Arc<LockEpoch>) -> Self {
        Self {
            enabled,
            epoch,
            remembered: Mutex::new(HashMap::new()),
        }
    }

    /// Remembering nothing, which is the default.
    pub fn off() -> Self {
        Self::new(false, Arc::new(LockEpoch::default()))
    }

    /// The epoch an answer given now belongs to.
    pub fn epoch(&self) -> u64 {
        self.epoch.current()
    }

    /// How often the master password has had to be asked for, so a caller can
    /// tell whether a request of its own found the vault locked.
    pub fn unlocks(&self) -> u64 {
        self.epoch.unlocks()
    }

    /// The vault has turned out to be locked: end everything remembered.
    pub fn lock(&self) {
        self.epoch.bump();
    }

    /// The epoch this question was approved in, if that is the current one.
    ///
    /// Returned rather than checked here, so the caller holds the epoch its
    /// answer belongs to as one reading: a lock landing between a yes and a
    /// second look at the counter would otherwise pass for none.
    pub fn remembered_in(&self, question: &str) -> Option<u64> {
        let now = self.epoch.current();
        self.remembered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(question)
            .copied()
            .filter(|answered_in| *answered_in == now)
    }

    /// The user approved this question in `epoch`. Kept only when remembering
    /// is on — the caller need not know — and only while that is still the
    /// epoch: an answer given before a lock is not carried past it.
    pub fn remember_in(&self, question: String, epoch: u64) {
        if !self.enabled || epoch != self.epoch.current() {
            return;
        }
        let mut remembered = self
            .remembered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Anything from before the last lock is dead already; dropping it here
        // keeps the map to what a session actually approved.
        remembered.retain(|_, answered_in| *answered_in == epoch);
        remembered.insert(question, epoch);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn an_approval_is_remembered_until_the_vault_locks() {
        let epoch = Arc::new(LockEpoch::default());
        let approvals = Approvals::new(true, epoch.clone());
        assert_eq!(approvals.remembered_in("github from Terminal"), None);
        approvals.remember_in("github from Terminal".into(), approvals.epoch());
        assert_eq!(approvals.remembered_in("github from Terminal"), Some(0));
        assert_eq!(approvals.remembered_in("github from elsewhere"), None);

        epoch.bump();
        assert_eq!(
            approvals.remembered_in("github from Terminal"),
            None,
            "locked"
        );
        // an answer from before the lock is not carried past it
        approvals.remember_in("stale".into(), 0);
        assert_eq!(approvals.remembered_in("stale"), None);
        // and a new approval afterwards clears the dead one out
        approvals.remember_in("other".into(), 1);
        assert_eq!(approvals.remembered.lock().unwrap().len(), 1);
        assert_eq!(approvals.remembered_in("other"), Some(1));

        // asking for the master password is counted, and turned into a lock
        // by whoever learns of it
        assert_eq!(approvals.unlocks(), 0);
        epoch.unlocked();
        assert_eq!(approvals.unlocks(), 1);
        approvals.lock();
        assert_eq!(approvals.epoch(), 2);
    }

    #[test]
    fn switched_off_nothing_is_remembered() {
        let approvals = Approvals::off();
        approvals.remember_in("github from Terminal".into(), 0);
        assert_eq!(approvals.remembered_in("github from Terminal"), None);
    }
}
