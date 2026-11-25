//! The agent's socket: how many clients are let in at once, and how a request
//! is read off the wire.
//!
//! Both are this crate's to decide rather than `ssh_agent_lib::agent::listen`'s,
//! which decides neither: it stops at the first connection it cannot accept,
//! and waits for as many bytes as a client says are coming.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::proto::{Request, Response};
use ssh_agent_lib::ssh_encoding::{Decode as _, Encode as _};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};

/// The longest request read. Nothing is known about a client before its
/// first request is, so without a bound each could have the agent hold four
/// gigabytes of bytes it will never parse. OpenSSH's agent stops at the same
/// length, and the largest thing `ssh` sends — a session binding carrying a
/// host certificate — is a quarter of it.
pub const MAX_FRAME_BYTES: usize = 256 * 1024;

/// How many clients are served at once. A connection costs a descriptor for
/// as long as its client cares to keep it, and running out of those must not
/// be what a client can do to the agent: past this many the next one waits
/// in the listen queue, where it costs nothing. Far below the descriptors a
/// service manager allows, because each signature needs a few for `lpass`.
pub const MAX_CONNECTIONS: usize = 64;

/// How long to leave the socket alone after it refuses a connection.
const ACCEPT_RETRY: Duration = Duration::from_millis(200);

/// Serve `listener` until the task is dropped, each connection as its own
/// session.
///
/// Never returns: a connection that cannot be accepted is the system short of
/// something — descriptors, usually — and that passes. Stopping instead would
/// let whoever exhausted it take the agent down, and the master password with
/// it.
pub async fn listen<S: Session>(
    listener: UnixListener,
    mut new_session: impl FnMut(&UnixStream) -> S,
) -> Infallible {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    // Said once per shortage, not once per attempt.
    let mut refusing = false;
    loop {
        // Taken before accepting, so that a client past the limit is never
        // given a descriptor at all.
        let slot = slots
            .clone()
            .acquire_owned()
            .await
            .expect("the semaphore is never closed");
        match listener.accept().await {
            Ok((stream, _)) => {
                refusing = false;
                let session = new_session(&stream);
                tokio::task::spawn(async move {
                    let _slot = slot;
                    if let Err(e) = connection(stream, session).await {
                        tracing::warn!(
                            error = %crate::text::display_bounded(&e.to_string()),
                            "closing an agent connection"
                        );
                    }
                });
            }
            Err(e) => {
                if refusing {
                    tracing::debug!("still cannot accept an agent connection: {e}");
                } else {
                    tracing::warn!(
                        "cannot accept an agent connection, still serving the others: {e}"
                    );
                }
                refusing = true;
                tokio::time::sleep(ACCEPT_RETRY).await;
            }
        }
    }
}

/// Answer one client's requests until it hangs up.
///
/// An error ends the connection and nothing else: what a client sent could
/// not be read as a request, or the client went away mid-sentence.
pub async fn connection<IO, S>(mut io: IO, mut session: S) -> std::io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    S: Session,
{
    while let Some(request) = read_request(&mut io).await? {
        // A session answers a refusal itself; an `Err` is a fault it could
        // not turn into an answer, and the client is owed one all the same.
        let response = session.handle(request).await.unwrap_or(Response::Failure);
        let length = response.encoded_len().map_err(malformed)?;
        let mut frame = Vec::with_capacity(4 + length);
        frame.extend_from_slice(&u32::try_from(length).map_err(malformed)?.to_be_bytes());
        response.encode(&mut frame).map_err(malformed)?;
        io.write_all(&frame).await?;
    }
    Ok(())
}

/// The next request, or `None` when the client hung up between two.
async fn read_request<IO: AsyncRead + Unpin>(io: &mut IO) -> std::io::Result<Option<Request>> {
    let mut length = [0; 4];
    // The first byte on its own: no bytes at all is a client that is done,
    // where some and then none is one that stopped mid-request.
    if io.read(&mut length[..1]).await? == 0 {
        return Ok(None);
    }
    io.read_exact(&mut length[1..]).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(malformed(format!(
            "a request of {length} bytes, more than the {MAX_FRAME_BYTES} read"
        )));
    }
    // Wiped when dropped, read or not: a client may send a key to add, which
    // is refused, and its bytes are in here all the same.
    let mut frame = zeroize::Zeroizing::new(vec![0; length]);
    io.read_exact(&mut frame).await?;
    // From the frame and no further: the next request's bytes are not this
    // one's to be decoded from.
    Request::decode(&mut &frame[..])
        .map(Some)
        .map_err(malformed)
}

fn malformed(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use ssh_agent_lib::error::AgentError;

    const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;

    /// Answers a listing with success, and cannot answer anything else.
    struct OnlyListing;

    #[ssh_agent_lib::async_trait]
    impl Session for OnlyListing {
        async fn handle(&mut self, message: Request) -> Result<Response, AgentError> {
            match message {
                Request::RequestIdentities => Ok(Response::Success),
                _ => Err(AgentError::Failure),
            }
        }
    }

    /// What the agent wrote back for `sent`, and how the connection ended.
    async fn exchange(sent: &[u8]) -> (Vec<u8>, std::io::Result<()>) {
        let (mut client, server) = tokio::io::duplex(2 * MAX_FRAME_BYTES);
        client.write_all(sent).await.unwrap();
        client.shutdown().await.unwrap();
        let ended = connection(server, OnlyListing).await;
        let mut received = Vec::new();
        client.read_to_end(&mut received).await.unwrap();
        (received, ended)
    }

    #[tokio::test]
    async fn each_request_is_answered_until_the_client_hangs_up() {
        let listing = [0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES];
        let (received, ended) = exchange(&[listing, listing].concat()).await;
        // SSH_AGENT_SUCCESS, twice
        assert_eq!(received, [0, 0, 0, 1, 6, 0, 0, 0, 1, 6]);
        ended.unwrap();
    }

    #[tokio::test]
    async fn a_request_the_session_cannot_answer_is_answered_with_failure() {
        let (received, ended) = exchange(&[0, 0, 0, 1, SSH_AGENTC_REMOVE_ALL_IDENTITIES]).await;
        // SSH_AGENT_FAILURE, and the connection carries on
        assert_eq!(received, [0, 0, 0, 1, 5]);
        ended.unwrap();
    }

    #[tokio::test]
    async fn a_request_longer_than_the_limit_ends_the_connection_unread() {
        // one byte past the limit, and none of the body it announces
        let (received, ended) = exchange(&[0, 4, 0, 1]).await;
        assert_eq!(received, b"");
        let error = ended.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("262145 bytes"), "{error}");
    }

    #[tokio::test]
    async fn a_request_exactly_at_the_limit_is_read() {
        // a listing padded out to the limit: what follows the request inside
        // its frame is ignored, as it always was
        let mut sent = vec![0, 4, 0, 0, SSH_AGENTC_REQUEST_IDENTITIES];
        sent.resize(4 + MAX_FRAME_BYTES, 0);
        let (received, ended) = exchange(&sent).await;
        assert_eq!(received, [0, 0, 0, 1, 6]);
        ended.unwrap();
    }

    #[tokio::test]
    async fn a_client_that_stops_mid_request_ends_the_connection() {
        for (sent, case) in [
            (&[0, 0][..], "inside the length"),
            (
                &[0, 0, 0, 9, SSH_AGENTC_REQUEST_IDENTITIES][..],
                "inside the body",
            ),
        ] {
            let (received, ended) = exchange(sent).await;
            assert_eq!(received, b"", "{case}");
            assert_eq!(
                ended.unwrap_err().kind(),
                std::io::ErrorKind::UnexpectedEof,
                "{case}"
            );
        }
    }

    #[tokio::test]
    async fn bytes_that_are_no_request_end_the_connection() {
        for (sent, case) in [
            (&[0, 0, 0, 0][..], "an empty frame"),
            (&[0, 0, 0, 1, 255][..], "a message number nothing has"),
        ] {
            let (received, ended) = exchange(sent).await;
            assert_eq!(received, b"", "{case}");
            assert_eq!(
                ended.unwrap_err().kind(),
                std::io::ErrorKind::InvalidData,
                "{case}"
            );
        }
    }
}
