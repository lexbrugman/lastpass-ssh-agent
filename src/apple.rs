//! Running one of Apple's calls without stopping the agent.
//!
//! Both macOS stores need this and for the same reason: the agent runs on a
//! single thread, and a locked keychain or a Touch ID sheet puts a dialog on
//! screen and waits. Inline, that would freeze every other connection until
//! somebody noticed the prompt.

/// Run one blocking call off the runtime thread.
///
/// A panic is reported rather than propagated: whatever the call was, the
/// caller can still reach the same secret by asking for it.
pub async fn blocking<T, F>(call: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(call)
        .await
        .map_err(|e| format!("the call did not finish: {e}"))?
}
