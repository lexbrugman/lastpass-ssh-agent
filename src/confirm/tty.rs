use std::path::PathBuf;
use std::time::Duration;

use super::{ConfirmContext, Confirmer, Decision};
use crate::tty;

/// Prompt on the agent's controlling terminal (`/dev/tty`). Useful when the
/// agent runs in a foreground terminal, and as the default on Linux.
///
/// Prompts are strictly serialized: concurrent signing requests would
/// otherwise interleave their prompts and a single "yes" could approve a
/// different request than the one the user read. The whole exchange runs
/// under one deadline, so an expired prompt gives up instead of lingering
/// and swallowing input meant for the next one.
pub struct TtyConfirmer {
    timeout: Duration,
    tty_path: PathBuf,
    serialize: tokio::sync::Mutex<()>,
}

impl TtyConfirmer {
    pub fn new(timeout: Duration) -> Self {
        Self::with_tty(PathBuf::from("/dev/tty"), timeout)
    }

    /// Tests point this at a pty slave instead of the real terminal.
    pub fn with_tty(tty_path: PathBuf, timeout: Duration) -> Self {
        Self {
            timeout,
            tty_path,
            serialize: tokio::sync::Mutex::new(()),
        }
    }
}

#[async_trait::async_trait]
impl Confirmer for TtyConfirmer {
    async fn confirm(&self, ctx: &ConfirmContext) -> Decision {
        // One prompt at a time; see the type's documentation.
        let _one_at_a_time = self.serialize.lock().await;

        let message = super::describe_request(ctx);
        match tokio::time::timeout(self.timeout, prompt_on_tty(&self.tty_path, &message)).await {
            Ok(Ok(answered)) => {
                if answered {
                    Decision::Approve
                } else {
                    // Said, not left silent: "denied" in the agent's log should
                    // always have a line saying which kind of denial it was.
                    tracing::info!("confirmation declined at the terminal, denying");
                    Decision::Deny
                }
            }
            Ok(Err(e)) => {
                tracing::warn!("no usable terminal for confirmation, denying: {e}");
                Decision::Deny
            }
            Err(_) => {
                tracing::info!("confirmation timed out, denying");
                Decision::Deny
            }
        }
    }
}

/// The answer to a yes/no question is one short word, so this is already far
/// past anything real. It exists for the same reason every other reader here is
/// capped: nothing that arrives from outside gets to decide how much this
/// process allocates. The deadline alone is not a bound — at an hour, the most
/// a confirmation timeout can be, a terminal writing steadily would grow this
/// without limit.
const MAX_ANSWER_BYTES: usize = 64;

/// Ask on the terminal and wait for an answer. The caller imposes the
/// deadline by dropping this future, which is why every wait here is a
/// cancellation point rather than a blocking call.
async fn prompt_on_tty(path: &std::path::Path, message: &str) -> std::io::Result<bool> {
    let terminal = tty::open(path)?;
    // A stale `yes` left over from a prompt that timed out must not approve
    // this request, which the user has not read yet.
    tty::discard_pending_input(&terminal);

    let prompt = format!("\n{message}\nAllow? (type 'yes' to approve, anything else denies): ");
    tty::write_all(&terminal, prompt.as_bytes()).await?;

    // A byte at a time, stopping at the newline: a larger read could swallow
    // input typed after the answer, which belongs to whatever prompts next.
    // Bytes rather than a `String`, because the terminal delivers bytes and the
    // cap counts them. Pushing each through `char::from` would decode it as
    // Latin-1, so any byte from 0x80 up would take two bytes of the buffer and
    // the length could step over the limit without ever meeting it — leaving
    // the buffer to grow as far as an untrusted writer liked, which is the one
    // thing the cap is here to stop.
    let mut answer: Vec<u8> = Vec::with_capacity(MAX_ANSWER_BYTES);
    let mut too_long = false;
    loop {
        let mut byte = [0u8; 1];
        tty::read_once(&terminal, &mut byte).await?;
        if byte[0] == b'\n' {
            break;
        }
        if answer.len() == MAX_ANSWER_BYTES {
            // Keep draining to the newline rather than returning here: the rest
            // of the line would otherwise be left queued and read as the answer
            // to the next prompt.
            too_long = true;
            continue;
        }
        answer.push(byte[0]);
    }
    // A line past the cap is not an answer to this question, whatever its first
    // bytes spell — approving on the strength of a prefix would let "yes" with
    // something else after it read as consent to what follows.
    Ok(!too_long && answer.trim_ascii() == b"yes")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::confirm::PeerInfo;
    use crate::testutil::open_pty;
    use std::io::{Read as _, Write as _};
    use std::time::Instant;

    /// Block until the prompt has reached the terminal, then answer it.
    ///
    /// Sleeping a fixed time instead would make these tests flaky by
    /// construction: input typed before the prompt appears is deliberately
    /// discarded, so on a slow run the answer is flushed and the prompt waits
    /// out its whole timeout — denying for the wrong reason. Reading the banner
    /// is the only reliable signal that the prompt is listening.
    fn answer_prompt(master: &mut std::fs::File, answer: &[u8]) {
        const BANNER: &[u8] = b"anything else denies): ";
        let mut seen: Vec<u8> = Vec::new();
        let mut buf = [0u8; 512];
        while !seen.windows(BANNER.len()).any(|window| window == BANNER) {
            let read = master.read(&mut buf).expect("the pty stays open");
            seen.extend_from_slice(&buf[..read]);
        }
        master.write_all(answer).unwrap();
    }

    fn ctx() -> ConfirmContext {
        ConfirmContext {
            key_name: "tty test".into(),
            fingerprint: "SHA256:tty".into(),
            item_id: "1".into(),
            peer: Some(PeerInfo {
                pid: None,
                uid: 501,
            }),
            bindings: Vec::new(),
        }
    }

    /// Long enough that it can only expire if something is badly wrong.
    ///
    /// These cases are about what an answer *means*, never how quickly it
    /// arrives — but an expired prompt denies, so a deadline tight enough to be
    /// reached under load turns into a wrong-looking decision rather than a
    /// timeout. The answer is read one byte per readiness wakeup, so the longest
    /// of them needs sixty-odd round trips and is the first to feel a loaded
    /// machine; that is what used to fail here, roughly one run in ten with a
    /// second instrumented build running alongside.
    const UNHURRIED: Duration = Duration::from_secs(120);

    /// Shared body for the plain answer cases, so each stays one line and still
    /// gets its own name and `cargo test` filter.
    async fn expect_decision(typed: &'static [u8], expected: Decision) {
        let (mut master, _keepalive, slave_path) = open_pty();
        let confirmer = TtyConfirmer::with_tty(slave_path, UNHURRIED);
        let answer = tokio::task::spawn_blocking(move || {
            answer_prompt(&mut master, typed);
            master
        });
        assert_eq!(
            confirmer.confirm(&ctx()).await,
            expected,
            "typed {:?}",
            String::from_utf8_lossy(typed)
        );
        drop(answer.await.unwrap());
    }

    #[tokio::test]
    async fn yes_approves() {
        expect_decision(b"yes\n", Decision::Approve).await;
    }

    #[tokio::test]
    async fn anything_else_denies() {
        expect_decision(b"no\n", Decision::Deny).await;
    }

    #[tokio::test]
    async fn an_answer_may_be_padded_with_spaces() {
        expect_decision(b"  yes  \n", Decision::Approve).await;
    }

    /// As `expect_decision`, for a line built rather than written out.
    async fn expect_decision_for(typed: Vec<u8>, expected: Decision) {
        let (mut master, _keepalive, slave_path) = open_pty();
        let confirmer = TtyConfirmer::with_tty(slave_path, UNHURRIED);
        let answer = tokio::task::spawn_blocking(move || {
            answer_prompt(&mut master, &typed);
            master
        });
        assert_eq!(confirmer.confirm(&ctx()).await, expected);
        drop(answer.await.unwrap());
    }

    #[tokio::test]
    async fn a_line_exactly_at_the_cap_is_still_an_answer() {
        // The boundary belongs to the answer: the cap refuses what is past it,
        // not what reaches it.
        let mut typed = b"yes".to_vec();
        typed.resize(MAX_ANSWER_BYTES, b' ');
        typed.push(b'\n');
        expect_decision_for(typed, Decision::Approve).await;
    }

    #[tokio::test]
    async fn an_overlong_line_is_refused_rather_than_buffered() {
        // The cap keeps an untrusted writer from growing this without bound.
        // A line past it denies whatever its first bytes spell: approving on a
        // prefix would read "yes" with something else after it as consent to
        // the something else.
        //
        // Padded with a byte above 0x7f on purpose. Counted as anything but raw
        // bytes — decoded to a `char` and pushed to a `String`, say — each of
        // these would take two bytes of the buffer, so the length would step
        // over the limit rather than land on it and the cap would never fire.
        let mut typed = b"yes".to_vec();
        typed.resize(MAX_ANSWER_BYTES * 2, 0xff);
        typed.push(b'\n');
        expect_decision_for(typed, Decision::Deny).await;
    }

    #[tokio::test]
    async fn silence_times_out_to_deny() {
        let (master, _keepalive, slave_path) = open_pty();
        let confirmer = TtyConfirmer::with_tty(slave_path, Duration::from_millis(200));
        let start = Instant::now();
        assert_eq!(confirmer.confirm(&ctx()).await, Decision::Deny);
        // the deadline is honored in full: poll rounds its wait up, so an
        // expiry can never come early
        assert!(start.elapsed() >= Duration::from_millis(200));
        // generous hang-guard: parallel test load can starve the blocking pool
        assert!(start.elapsed() < Duration::from_secs(30));
        drop(master);
    }

    #[tokio::test]
    async fn input_typed_before_the_prompt_is_discarded() {
        // The user answers an earlier prompt too late; that queued "yes"
        // must not silently approve the request that comes next.
        let (mut master, _keepalive, slave_path) = open_pty();
        master.write_all(b"yes\n").unwrap();
        // give the pty time to queue it before the prompt is shown
        tokio::time::sleep(Duration::from_millis(100)).await;

        let confirmer = TtyConfirmer::with_tty(slave_path, Duration::from_millis(400));
        assert_eq!(
            confirmer.confirm(&ctx()).await,
            Decision::Deny,
            "stale input must not answer a later prompt"
        );
    }

    #[tokio::test]
    async fn a_half_typed_answer_still_times_out() {
        // noncanonical-mode hazard: bytes arrive without a newline. The
        // deadline must still fire instead of blocking forever.
        let (mut master, _keepalive, slave_path) = open_pty();
        master.write_all(b"ye").unwrap();
        let confirmer = TtyConfirmer::with_tty(slave_path, Duration::from_millis(300));
        let start = Instant::now();
        assert_eq!(confirmer.confirm(&ctx()).await, Decision::Deny);
        assert!(start.elapsed() >= Duration::from_millis(300));
        assert!(start.elapsed() < Duration::from_secs(30));
    }

    #[tokio::test]
    async fn missing_tty_denies() {
        let confirmer =
            TtyConfirmer::with_tty(PathBuf::from("/nonexistent/tty"), Duration::from_secs(1));
        assert_eq!(confirmer.confirm(&ctx()).await, Decision::Deny);
    }

    #[tokio::test]
    async fn concurrent_prompts_are_serialized_one_answer_each() {
        let (master, _keepalive, slave_path) = open_pty();
        let confirmer = std::sync::Arc::new(TtyConfirmer::with_tty(slave_path, UNHURRIED));
        // Answer each prompt as it appears: input queued before a prompt is
        // discarded by design, and the second prompt only starts once the
        // first has been answered.
        let responder = tokio::task::spawn_blocking(move || {
            let mut master = master;
            answer_prompt(&mut master, b"yes\n");
            answer_prompt(&mut master, b"no\n");
            master
        });

        let (a, b) = tokio::join!(
            {
                let c = confirmer.clone();
                async move { c.confirm(&ctx()).await }
            },
            {
                let c = confirmer.clone();
                async move { c.confirm(&ctx()).await }
            },
        );
        drop(responder.await.unwrap());
        let approvals = [a, b].iter().filter(|d| **d == Decision::Approve).count();
        assert_eq!(approvals, 1, "got {a:?} and {b:?}");
    }
}
