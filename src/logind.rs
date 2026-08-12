//! Whether logind says this session's screen is locked.
//!
//! `LockedHint` is the flag a desktop sets when it locks the screen and clears
//! when it unlocks, and logind keeps it per session — which makes it the one
//! place to ask that does not depend on which desktop is running.
//!
//! Its limit is that a desktop which never sets it looks permanently unlocked,
//! and nothing here can tell that apart from a screen nobody has locked. There
//! is no second source to cross-check against, so this reports what logind says
//! and `vaultlock` decides what to do with it.

/// The proxy, built on first use and then kept.
///
/// The probe runs every few seconds for the life of the process, so opening a
/// connection and completing a D-Bus handshake per sample would be pure waste.
/// A `None` in here is a connection that could not be made, and is not retried:
/// the caller reports that as "cannot say", which stops the watch for good.
static SESSION: tokio::sync::OnceCell<Option<LoginSessionProxy<'static>>> =
    tokio::sync::OnceCell::const_new();

/// One property on one object, which is the whole of what this needs.
///
/// `gen_blocking = false` because nothing here blocks: the blocking variant
/// would be generated, never called, and warn about being dead.
#[zbus::proxy(
    interface = "org.freedesktop.login1.Session",
    default_service = "org.freedesktop.login1",
    // Resolved by logind to the caller's own session or, for a user service
    // that belongs to no session, to the user's display session. Either way
    // that is the session whose screen locks, so asking for it by name saves
    // looking one up by pid.
    default_path = "/org/freedesktop/login1/session/auto",
    gen_blocking = false
)]
trait LoginSession {
    /// Read live rather than from the proxy's property cache: a cached value is
    /// only as fresh as the change signals behind it, and a stale `false` here
    /// would mean the vault quietly never locks. `emits_changed_signal =
    /// "false"` is what turns that caching off.
    #[zbus(property(emits_changed_signal = "false"))]
    fn locked_hint(&self) -> zbus::Result<bool>;
}

/// The flag, or `None` when there is no bus, no logind or no session to ask
/// about — a container, a plain ssh login, a machine without systemd.
pub async fn locked_hint() -> Option<bool> {
    SESSION
        .get_or_init(|| async {
            let bus = zbus::Connection::system().await.ok()?;
            LoginSessionProxy::new(&bus).await.ok()
        })
        .await
        .as_ref()?
        .locked_hint()
        .await
        .ok()
}
