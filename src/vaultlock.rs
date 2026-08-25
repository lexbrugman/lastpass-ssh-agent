//! Forgetting the vault's cached key when the session locks.
//!
//! `lpass` keeps the key it derived from the master password in an agent
//! process of its own, for an hour by default. That agent is what makes a
//! signature cost no password — and it is also what makes the whole vault, not
//! just the SSH keys, readable by anything running as this user until it
//! expires. Walking away locks the screen; it does not lock the vault.
//!
//! So when the screen locks, the agent process is asked to go away. What
//! survives is the *session*: `lpass` still knows who is logged in, so the way
//! back is the master password rather than a fresh login with a second factor.
//! `lpass logout` would take the session too, which is a much bigger hammer
//! than this deserves.
//!
//! Everything here is portable. Learning that the screen locked is the one
//! platform-specific part, and it lives behind `ScreenLock` as a value this
//! module looks up.

use std::sync::Arc;
use std::time::Duration;

/// How often the lock state is sampled.
///
/// A lock lasts as long as someone is away from the machine, so there is
/// nothing to gain from a tight loop: the question is only how long the key
/// outlives the lock, and a few seconds either way does not change what an
/// attacker at the keyboard could do. Slow enough that the cost of asking is
/// irrelevant, quick enough that "I locked it" and "the vault is shut" are the
/// same moment to a person.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// How many unreadable readings in a row end a watch that had been working.
///
/// Not one: restarting logind — which a distribution does whenever it updates
/// systemd — makes the state unreadable for about a second, and treating that as
/// the end would cost the whole session's protection over an outage nobody
/// noticed. Bounded all the same, so a probe that is never going to answer again
/// stops rather than polling for the life of the process.
const MAX_UNREADABLE_IN_A_ROW: u32 = 3;

/// Somewhere the session's screen-lock state can be read.
///
/// A trait for the same reason `VaultKey` is one: it keeps the watcher's rules
/// testable without a desktop. The real implementation asks the platform, and a
/// test's hands out a scripted sequence.
///
/// Async because one implementation asks another process over D-Bus, and a
/// synchronous answer would mean blocking a runtime thread until it replies.
#[async_trait::async_trait]
pub trait ScreenLock: Send + Sync {
    /// Whether the screen is locked right now, or `None` when it cannot be read.
    ///
    /// `None` is never "unlocked": the watcher stops if the first reading fails
    /// and retries if a later one does, and keeping "no answer" apart from "not
    /// locked" is what lets this module have no `cfg` in it. An implementation
    /// therefore does not need to know which kind of failure it is looking at.
    async fn is_locked(&self) -> Option<bool>;
}

/// Somewhere holding a derived vault key that can be told to forget it.
///
/// A trait so the watcher's rules are testable without a vault: the real
/// implementation ends a process, and a test's counts calls.
#[async_trait::async_trait]
pub trait VaultKey: Send + Sync {
    /// Drop the cached key. Best effort — a vault that was already locked, or
    /// an agent that had already expired, is a success with nothing to do.
    async fn forget(&self);
}

/// Whether a sample means the key should be forgotten now.
///
/// The *transition* into locked, not the state: sampling a locked screen every
/// few seconds would otherwise re-kill an agent nobody restarted, and — worse —
/// stop the user from re-authenticating at a prompt while still locked, which
/// is exactly what unlocking through a screen saver does on some setups.
const fn locking_now(previous: bool, current: bool) -> bool {
    current && !previous
}

/// Watch the lock state until the process ends, forgetting the vault key each
/// time the screen goes from unlocked to locked.
///
/// `screen` is `platform::SessionScreen` in production. A `None` on the very
/// first sample means this platform cannot answer at all, and the watch stops
/// rather than spinning: there is nothing to learn by asking again. Once one
/// reading has succeeded the platform has proved it can answer, so a later `None`
/// is a failure rather than an absence and is retried — see `MAX_UNREADABLE_IN_A_ROW`.
/// `enabled` is the config setting rather than a caller-side `if`, so that the
/// decision lives here with the rest of the logic. A branch in the startup path
/// could only ever go one way on a platform that refuses the setting at load,
/// and a branch no test can take both sides of is exactly what `#[cfg]` exists
/// to avoid — but this is not platform-specific, it is opt-in.
///
/// Both arguments are trait objects rather than generics: this runs once for the
/// life of the process, so there is nothing to gain from monomorphising it, and
/// a single instantiation is what lets every path through it be accounted for in
/// one place.
pub async fn watch(
    enabled: bool,
    screen: Arc<dyn ScreenLock>,
    key: Arc<dyn VaultKey>,
    interval: Duration,
) {
    if !enabled {
        return;
    }
    tracing::info!(
        "locking the vault with the screen — the LastPass agent's cached key is dropped on \
         lock, and the master password is asked for when it is next needed"
    );
    let Some(locked_at_startup) = screen.is_locked().await else {
        tracing::debug!("no way to read the screen lock state here; not watching");
        return;
    };

    // "Before we looked" counts as unlocked, so a screen that is already locked
    // when the agent starts is a lock like any other. Tempting to call it a
    // baseline instead — but `start` logs in, discovers items and loads keys
    // before this runs, and every one of those calls makes lpass cache the
    // derived key. Waiting for a later unlock/relock would leave the vault open
    // for the whole locked session, which is the window this exists to close.
    let mut previous = false;
    let mut current = locked_at_startup;
    let mut unreadable_in_a_row = 0u32;
    loop {
        if locking_now(previous, current) {
            tracing::info!(
                "screen locked — dropping the LastPass agent's cached key, so the next \
                 signature asks for the master password"
            );
            key.forget().await;
        }
        previous = current;

        tokio::time::sleep(interval).await;
        if let Some(next) = screen.is_locked().await {
            unreadable_in_a_row = 0;
            current = next;
        } else {
            // `current` is deliberately left as it was rather than guessed at, so
            // a screen that locks while the state cannot be read is still caught
            // by the first reading that succeeds.
            unreadable_in_a_row += 1;
            if unreadable_in_a_row >= MAX_UNREADABLE_IN_A_ROW {
                tracing::warn!(
                    "the screen lock state has been unreadable \
                     {unreadable_in_a_row} checks running, so the vault is no longer being \
                     locked with the screen — it now stays open until it expires or the \
                     agent is restarted"
                );
                return;
            }
            tracing::debug!("could not read the screen lock state; trying again shortly");
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Counts how often the key was forgotten.
    #[derive(Default)]
    struct CountingKey(Mutex<usize>);

    impl CountingKey {
        fn times(&self) -> usize {
            *self.0.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl VaultKey for CountingKey {
        async fn forget(&self) {
            *self.0.lock().unwrap() += 1;
        }
    }

    /// Hands out a scripted sequence of samples, `None` standing for a reading
    /// that failed. Past the end it answers `None` forever, which is what ends
    /// each watch once `MAX_UNREADABLE_IN_A_ROW` of them have run together.
    struct Scripted(Mutex<std::vec::IntoIter<Option<bool>>>);

    impl Scripted {
        fn new(states: Vec<Option<bool>>) -> Arc<Self> {
            Arc::new(Self(Mutex::new(states.into_iter())))
        }
    }

    #[async_trait::async_trait]
    impl ScreenLock for Scripted {
        async fn is_locked(&self) -> Option<bool> {
            self.0.lock().unwrap().next().flatten()
        }
    }

    /// A screen this platform cannot read at all.
    struct Unreadable;

    #[async_trait::async_trait]
    impl ScreenLock for Unreadable {
        async fn is_locked(&self) -> Option<bool> {
            None
        }
    }

    /// Unlocked whenever asked, and records that it was asked.
    #[derive(Default)]
    struct Noted(std::sync::atomic::AtomicBool);

    #[async_trait::async_trait]
    impl ScreenLock for Noted {
        async fn is_locked(&self) -> Option<bool> {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            Some(false)
        }
    }

    /// Run the watch over a sequence of readings that all succeed.
    async fn forgets_for(states: Vec<bool>) -> usize {
        forgets_for_readings(states.into_iter().map(Some).collect()).await
    }

    /// The same, for a sequence with failed readings in it.
    async fn forgets_for_readings(readings: Vec<Option<bool>>) -> usize {
        let key = Arc::new(CountingKey::default());
        // A real but negligible interval, so no clock control is needed.
        watch(
            true,
            Scripted::new(readings),
            key.clone(),
            Duration::from_millis(1),
        )
        .await;
        key.times()
    }

    #[tokio::test]
    async fn locking_forgets_the_key_once() {
        assert_eq!(forgets_for(vec![false, true]).await, 1);
    }

    #[tokio::test]
    async fn staying_locked_does_not_keep_forgetting() {
        // Re-killing an agent nobody restarted is pointless, and would fight a
        // master-password prompt answered while the screen is still locked.
        assert_eq!(forgets_for(vec![false, true, true, true]).await, 1);
    }

    #[tokio::test]
    async fn locking_again_after_an_unlock_forgets_again() {
        assert_eq!(forgets_for(vec![false, true, false, true]).await, 2);
    }

    #[tokio::test]
    async fn a_screen_that_never_locks_never_forgets() {
        assert_eq!(forgets_for(vec![false, false, false]).await, 0);
    }

    #[tokio::test]
    async fn starting_up_locked_drops_the_key_straight_away() {
        // Startup itself caches the key — logging in, discovering items and
        // loading them all go through lpass — so a screen that is already
        // locked must be acted on rather than recorded as a baseline.
        assert_eq!(forgets_for(vec![true, true]).await, 1);
        // and it is still a single drop across a locked stretch
        assert_eq!(forgets_for(vec![true, true, false, true]).await, 2);
    }

    #[tokio::test]
    async fn switched_off_it_never_even_looks() {
        // The default. Nothing samples, nothing is forgotten, and no task sits
        // in a loop for a feature nobody asked for.
        let key = Arc::new(CountingKey::default());
        let screen = Arc::new(Noted::default());
        watch(false, screen.clone(), key.clone(), Duration::from_millis(1)).await;
        assert!(
            !screen.0.load(std::sync::atomic::Ordering::SeqCst),
            "a disabled watch must not even look at the screen"
        );
        assert_eq!(key.times(), 0);
    }

    #[tokio::test]
    async fn a_failed_reading_is_survived_and_the_lock_after_it_still_counts() {
        // Restarting logind makes one reading fail. Giving up there would leave
        // the vault open for the rest of the session, so the lock that follows
        // must still be seen.
        assert_eq!(
            forgets_for_readings(vec![Some(false), None, Some(true)]).await,
            1
        );
    }

    #[tokio::test]
    async fn a_failed_reading_is_not_mistaken_for_an_unlocked_screen() {
        // The state is left as it was rather than guessed at, so a failure in the
        // middle of a locked stretch does not read as an unlock — and the relock
        // that never happened does not drop the key a second time.
        assert_eq!(
            forgets_for_readings(vec![Some(false), Some(true), None, Some(true)]).await,
            1
        );
    }

    #[tokio::test]
    async fn readings_that_keep_failing_end_the_watch() {
        // Patience is bounded by `MAX_UNREADABLE_IN_A_ROW`, so the
        // `Some(true)` behind them is never reached and never acted on.
        assert_eq!(
            forgets_for_readings(vec![Some(false), None, None, None, Some(true)]).await,
            0
        );
    }

    #[tokio::test]
    async fn a_platform_that_cannot_answer_is_not_watched() {
        let key = Arc::new(CountingKey::default());
        watch(
            true,
            Arc::new(Unreadable),
            key.clone(),
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(key.times(), 0);
    }
}
