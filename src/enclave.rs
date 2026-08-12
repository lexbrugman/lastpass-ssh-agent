//! What the Secure Enclave shim's answers mean, and how its two outputs are
//! written down.
//!
//! The shim itself is Swift behind a `cfg`, so only one CI job can reach it and
//! nobody without a Mac can compile it. Everything that is a *decision* lives
//! here instead: which stage of a failed call means what, what to tell the user
//! about it, and the format of the file the blob and the ciphertext are kept
//! in. All of it is ordinary logic over integers and bytes, so it is tested on
//! every platform — which leaves the `cfg`-gated part with nothing in it but
//! three calls.
//!
//! Neither of the two stored values is a secret. The blob is a key wrapped
//! under a key that never leaves this machine's Enclave, and the ciphertext
//! cannot be opened without it; both are useless on any other computer, and
//! useless on this one without the sensor. They are still written 0600, on the
//! principle that nothing about the arrangement should be easier to read than
//! it has to be.

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

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::{Error, Result};

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
    /// The stored key cannot be used again and only seeding fixes it. A
    /// fingerprint added or removed since it was created invalidates it by
    /// design, and so does a truncated file.
    Reseed,
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
pub const fn meaning(stage: i32, os_error: i32) -> Outcome {
    match stage {
        STAGE_OK => Outcome::Done,
        STAGE_UNAVAILABLE => Outcome::Unavailable,
        // Three ways for the stored state to be past saving: the blob would
        // not load at all, the ciphertext is too short to be one, or it would
        // not open despite a fingerprint that worked. None of them can ever
        // yield the secret again, so all three ask for seeding rather than
        // reporting a fault the user could do nothing about.
        STAGE_RESTORE | STAGE_MALFORMED | STAGE_DECRYPT => Outcome::Reseed,
        STAGE_AGREEMENT if is_not_authenticated(os_error) => Outcome::Refused,
        _ => Outcome::Failed(os_error),
    }
}

/// Whether a `LocalAuthentication` code means "no fingerprint happened".
const fn is_not_authenticated(os_error: i32) -> bool {
    let mut i = 0;
    while i < NOT_AUTHENTICATED.len() {
        if NOT_AUTHENTICATED[i] == os_error {
            return true;
        }
        i += 1;
    }
    false
}

impl Outcome {
    /// How this reads in the agent's log.
    ///
    /// Every one of these ends up in the same place: an `info` line saying the
    /// store could not answer, followed by the prompt. So they are written to
    /// tell the user what to do, not to sound like an error.
    pub fn describe(self) -> String {
        match self {
            Self::Done => "the Secure Enclave answered".into(),
            Self::Unavailable => "this Mac has no Secure Enclave".into(),
            Self::Refused => "Touch ID was not confirmed".into(),
            Self::Reseed => {
                "what is stored can no longer be opened — a fingerprint added or removed \
                 since it was kept will do that, and so will a damaged file — so run \
                 `lastpass-ssh-agent store-master-password` again"
                    .into()
            }
            Self::Failed(code) => format!("the Secure Enclave refused the request (code {code})"),
        }
    }
}

/// The size every secret is sealed at, whatever its own length.
///
/// AES-GCM does not pad, so without this the ciphertext would be exactly the
/// master password plus a fixed 93 bytes — and `stat` on the stored file would
/// disclose how long the password is to anyone who can read the directory.
/// That is a small leak, since reading it at all means already being this user,
/// but it narrows a guess for nothing gained. Padding to a constant costs a
/// kilobyte on disk and removes it: every stored file is now the same size.
///
/// Two bytes of length in front, then the secret, then zeros. The cap fits in
/// those two bytes with room to spare.
pub const PADDED_LEN: usize = 2 + crate::passphrase::MAX_PASSPHRASE_BYTES;

/// Put a secret into a fixed-size block.
///
/// One allocation, at its final size, the way every buffer holding a secret in
/// this codebase is: growing one would copy the bytes into a new allocation and
/// free the old one unwiped.
pub fn pad(secret: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if secret.len() > crate::passphrase::MAX_PASSPHRASE_BYTES {
        return Err(Error::ConfigInvalid(format!(
            "a master password longer than {} bytes cannot be stored",
            crate::passphrase::MAX_PASSPHRASE_BYTES
        )));
    }
    let mut block = Zeroizing::new(vec![0u8; PADDED_LEN]);
    let len = u16::try_from(secret.len()).expect("the cap just checked is far below u16::MAX");
    block[..2].copy_from_slice(&len.to_be_bytes());
    block[2..2 + secret.len()].copy_from_slice(secret);
    Ok(block)
}

/// Take one back out again.
///
/// Consumes the block and shortens it in place rather than copying the secret
/// into a buffer of its own — same reason as above, and truncating is safe to
/// do to a secret because zeroizing a `Vec` wipes its whole capacity.
pub fn unpad(padded: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>> {
    let mut padded = padded;
    if padded.len() != PADDED_LEN {
        return Err(malformed("not a block this wrote"));
    }
    let len = usize::from(u16::from_be_bytes([padded[0], padded[1]]));
    if len > crate::passphrase::MAX_PASSPHRASE_BYTES {
        return Err(malformed("a length larger than anything this stores"));
    }
    padded.copy_within(2..2 + len, 0);
    padded.truncate(len);
    Ok(padded)
}

/// What a finished unwrap means to a `MasterPasswordStore`.
///
/// The distinction this draws is the one `askpass::seed` depends on. Seeding
/// reads the store first and refuses to touch it if that read fails, because
/// overwriting a store that would not answer could destroy a password that
/// works. So exactly one failure must read as *empty* instead:
///
/// - `Reseed` — the key cannot be used again, by anyone, ever. There is
///   nothing recoverable behind it, so seeding over it is safe, and it is the
///   only way out. Reported as an error instead, it would make
///   `store-master-password` refuse the very state it exists to repair.
/// - everything else — a declined fingerprint above all — may well be sitting
///   on a working secret. Calling that "nothing is stored" would invite the
///   next seed to overwrite it because nobody happened to be at the machine.
pub fn unwrapped(
    result: std::result::Result<Zeroizing<Vec<u8>>, Outcome>,
) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, String> {
    match result {
        // Whatever the Enclave handed back still has to be a block this wrote.
        // If it is not, the fingerprint was given and the decryption worked and
        // the contents are still not ours — which is as past saving as a key
        // that will not load, and reads as empty for the same reason.
        Ok(padded) => Ok(unpad(padded).map_or_else(|_| past_saving(), Some)),
        Err(Outcome::Reseed) => Ok(past_saving()),
        Err(other) => Err(other.describe()),
    }
}

/// Stored state that can never produce the secret again, reported as an empty
/// store so that seeding may replace it.
///
/// Said here rather than left to the caller's "nothing stored yet", which would
/// be true but would not explain why it stopped working.
fn past_saving() -> Option<Zeroizing<Vec<u8>>> {
    tracing::warn!("{}", Outcome::Reseed.describe());
    None
}

/// Longest blob and ciphertext this will read back.
///
/// A wrapped P-256 key runs to a few hundred bytes and the ciphertext is one
/// padded block plus a fixed 93, so both of these are far above anything this
/// code writes. They are here because the file is on disk where anything
/// could rewrite it: a length field is not a promise, and a header claiming
/// four gigabytes must be refused rather than allocated.
pub const MAX_BLOB: usize = 4096;
pub const MAX_CIPHER: usize = 4096;

/// Says whose file this is and which arrangement it belongs to. A later format
/// gets a later magic, so an old file is refused rather than misread.
///
/// v2 because v1 sealed the secret at its own length. Reading one of those here
/// would decrypt fine and then fail an inner size check, which is a confusing
/// way to say "different format" — and the alternative, accepting a block that
/// is not one this wrote, would give up the very check that makes a corrupted
/// ciphertext detectable. A v1 file is therefore declared foreign and the user
/// is told to seed again, which costs one command and no secret: the master
/// password was never only here.
const MAGIC: &[u8] = b"lastpass-ssh-agent secure enclave v2\n";

/// The blob and the ciphertext, as they sit on disk.
#[derive(Debug, PartialEq, Eq)]
pub struct Stored {
    pub blob: Vec<u8>,
    pub cipher: Vec<u8>,
}

impl Stored {
    /// One allocation, sized before anything is written into it.
    ///
    /// Refuses the same sizes `decode` refuses, so the two cannot disagree
    /// about what this format can hold — writing a file that will not read back
    /// would strand a working key.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(MAGIC.len() + 8 + self.blob.len() + self.cipher.len());
        out.extend_from_slice(MAGIC);
        for (part, max) in [(&self.blob, MAX_BLOB), (&self.cipher, MAX_CIPHER)] {
            if part.len() > max {
                return Err(malformed("a value larger than this format holds"));
            }
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the cap checked immediately above is far below u32::MAX"
            )]
            out.extend_from_slice(&(part.len() as u32).to_be_bytes());
            out.extend_from_slice(part);
        }
        Ok(out)
    }

    /// Read one back, refusing anything that is not exactly what was written.
    ///
    /// Trailing bytes are an error rather than something to ignore: this file
    /// is written whole every time, so extra bytes mean it is not the file this
    /// code thinks it is.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let rest = bytes
            .strip_prefix(MAGIC)
            .ok_or_else(|| malformed("not this agent's Secure Enclave file"))?;
        let (blob, rest) = take(rest, MAX_BLOB)?;
        let (cipher, rest) = take(rest, MAX_CIPHER)?;
        if !rest.is_empty() {
            return Err(malformed("trailing bytes"));
        }
        Ok(Self {
            blob: blob.to_vec(),
            cipher: cipher.to_vec(),
        })
    }
}

/// One length-prefixed field, bounded by what it is allowed to be.
fn take(bytes: &[u8], max: usize) -> Result<(&[u8], &[u8])> {
    let (header, rest) = bytes
        .split_at_checked(4)
        .ok_or_else(|| malformed("truncated length"))?;
    let len =
        u32::from_be_bytes(header.try_into().expect("split_at_checked gave four bytes")) as usize;
    if len > max {
        return Err(malformed("a length larger than anything this writes"));
    }
    rest.split_at_checked(len)
        .ok_or_else(|| malformed("truncated value"))
}

/// Where the blob and ciphertext live, given the socket.
///
/// Named after the socket for the same reason the askpass wrapper is: the
/// socket path is the one thing the user chooses that every part of a running
/// agent already agrees on, so nothing else has to be configured to keep them
/// together.
pub fn path_for(socket: &Path) -> PathBuf {
    let mut name = socket.as_os_str().to_os_string();
    name.push(".master");
    PathBuf::from(name)
}

/// Read it back, or `None` when there is nothing stored yet.
///
/// Bounded, because a file on disk is not necessarily the file this wrote. One
/// byte past the largest thing `save` can produce is read deliberately: it
/// turns an oversized file into a refusal rather than a silent truncation that
/// happens to parse.
pub fn load(path: &Path) -> Result<Option<Stored>> {
    use std::io::Read as _;

    // This name is derived from a path the user chooses, so something else can
    // be sitting on it — and a FIFO would make the read below wait for a writer
    // that never comes, on the one thread the agent serves every connection
    // from. `open_regular` settles that on the open file rather than on the
    // path, so nothing can be swapped in between the two.
    let Some(file) = crate::files::open_regular(path)? else {
        return Ok(None);
    };

    let limit = MAGIC.len() + 8 + MAX_BLOB + MAX_CIPHER + 1;
    let mut bytes = Vec::with_capacity(limit);
    file.take(limit as u64).read_to_end(&mut bytes)?;

    match Stored::decode(&bytes) {
        Ok(stored) => Ok(Some(stored)),
        // Bytes that will not decode hold nothing recoverable, exactly like a
        // key that will not load, and are treated the same way: an empty store
        // rather than an unreadable one. Reported as an error they would make
        // `store-master-password` refuse to replace them — the one command that
        // repairs this — and the file would have to be deleted by hand.
        //
        // Not the same as a read that *failed*: there the contents are unknown,
        // something usable may be there, and seeding must not overwrite it.
        Err(e) => {
            tracing::warn!("{e}");
            Ok(None)
        }
    }
}

/// Write it, replacing whatever was there. 0600 because it is the agent's own
/// state; `files::write_private` explains why the write is staged and renamed.
pub fn save(path: &Path, stored: &Stored) -> Result<()> {
    crate::files::write_private(path, &stored.encode()?, 0o600)
}

/// Forget it. Already gone is the state this asks for, so that is success.
pub fn remove(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(()) => Ok(()),
    }
}

fn malformed(why: &str) -> Error {
    Error::ConfigInvalid(format!(
        "the stored Secure Enclave key is unreadable ({why}) — run \
         `lastpass-ssh-agent store-master-password` again"
    ))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn sample() -> Stored {
        Stored {
            blob: vec![1, 2, 3, 4, 5],
            cipher: vec![9, 8, 7],
        }
    }

    #[test]
    fn a_written_file_reads_back_identical() {
        assert_eq!(
            Stored::decode(&sample().encode().unwrap()).unwrap(),
            sample()
        );
    }

    #[test]
    fn empty_parts_survive_the_round_trip() {
        let empty = Stored {
            blob: Vec::new(),
            cipher: Vec::new(),
        };
        assert_eq!(Stored::decode(&empty.encode().unwrap()).unwrap(), empty);
    }

    fn expect_rejected(bytes: &[u8], case: &str) {
        let error = Stored::decode(bytes).unwrap_err().to_string();
        assert!(error.contains("store-master-password"), "{case}: {error}");
    }

    #[test]
    fn a_file_from_something_else_is_refused() {
        expect_rejected(b"some other file entirely", "wrong magic");
    }

    #[test]
    fn a_file_cut_short_in_its_header_is_refused() {
        let encoded = sample().encode().unwrap();
        expect_rejected(&encoded[..MAGIC.len() + 2], "truncated length");
    }

    #[test]
    fn a_file_cut_short_in_its_value_is_refused() {
        let encoded = sample().encode().unwrap();
        expect_rejected(&encoded[..encoded.len() - 1], "truncated value");
    }

    #[test]
    fn a_length_beyond_the_cap_is_refused_without_allocating() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        expect_rejected(&bytes, "huge length");
    }

    #[test]
    fn a_second_length_beyond_the_cap_is_refused() {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        expect_rejected(&bytes, "huge second length");
    }

    #[test]
    fn anything_after_the_last_value_is_refused() {
        let mut encoded = sample().encode().unwrap();
        encoded.push(0);
        expect_rejected(&encoded, "trailing bytes");
    }

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
    fn a_blob_that_will_not_load_asks_for_seeding() {
        expect_meaning(STAGE_RESTORE, -25293, Outcome::Reseed);
    }

    #[test]
    fn a_ciphertext_that_is_too_short_asks_for_seeding() {
        expect_meaning(STAGE_MALFORMED, 0, Outcome::Reseed);
    }

    #[test]
    fn a_ciphertext_that_will_not_open_asks_for_seeding() {
        // The fingerprint was given and the agreement worked, so this is not a
        // fault anyone can retry past — the stored bytes are simply gone.
        expect_meaning(STAGE_DECRYPT, -1, Outcome::Reseed);
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
    /// that would not open — and a stage from some later shim.
    #[test]
    fn every_other_stage_is_a_failure_carrying_its_code() {
        for stage in [1, 3, 4, 7, 99] {
            expect_meaning(stage, -5, Outcome::Failed(-5));
        }
    }

    fn expect_round_trip(secret: &[u8], case: &str) {
        let block = pad(secret).unwrap();
        assert_eq!(block.len(), PADDED_LEN, "{case}: padded to a constant");
        assert_eq!(&*unpad(block).unwrap(), secret, "{case}");
    }

    #[test]
    fn a_padded_secret_comes_back_unchanged() {
        expect_round_trip(b"", "empty");
        expect_round_trip(b"x", "one byte");
        expect_round_trip(b"correct horse battery staple", "ordinary");
        expect_round_trip(
            &vec![b'z'; crate::passphrase::MAX_PASSPHRASE_BYTES],
            "exactly at the cap",
        );
    }

    #[test]
    fn the_padded_size_says_nothing_about_the_secret() {
        // The whole point: two secrets of very different lengths must be
        // indistinguishable by size, or the stored file discloses how long the
        // master password is to anyone who can stat it.
        assert_eq!(pad(b"a").unwrap().len(), pad(&[b'a'; 900]).unwrap().len());
    }

    #[test]
    fn a_secret_beyond_the_cap_is_refused() {
        let error = pad(&vec![0; crate::passphrase::MAX_PASSPHRASE_BYTES + 1])
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot be stored"), "{error}");
    }

    #[test]
    fn a_block_of_the_wrong_size_is_refused() {
        // What an older format, or anything else that happened to decrypt,
        // would look like.
        assert!(unpad(Zeroizing::new(vec![0; PADDED_LEN - 1])).is_err());
        assert!(unpad(Zeroizing::new(vec![0; PADDED_LEN + 1])).is_err());
    }

    #[test]
    fn a_block_claiming_more_than_it_holds_is_refused() {
        let mut block = vec![0; PADDED_LEN];
        block[..2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(unpad(Zeroizing::new(block)).is_err());
    }

    #[test]
    fn a_block_that_will_not_unpad_reads_as_an_empty_store() {
        // Decryption succeeded and the contents are still not ours: as past
        // saving as a key that will not load, and treated the same way.
        assert_eq!(unwrapped(Ok(Zeroizing::new(vec![0; 3]))).unwrap(), None);
    }

    #[test]
    fn an_unwrapped_secret_comes_back() {
        let block = pad(b"master").unwrap();
        assert_eq!(unwrapped(Ok(block)).unwrap().unwrap().as_slice(), b"master");
    }

    #[test]
    fn a_key_that_can_never_work_again_reads_as_an_empty_store() {
        // The one failure that must not look like "could not ask": seeding
        // refuses to overwrite a store it cannot read, so reporting this as an
        // error would make `store-master-password` refuse to repair it.
        assert_eq!(unwrapped(Err(Outcome::Reseed)).unwrap(), None);
    }

    #[test]
    fn every_other_failure_stays_a_failure() {
        // Especially a declined prompt: something usable may be stored, and
        // calling that "empty" would let the next seed overwrite it.
        for outcome in [Outcome::Refused, Outcome::Unavailable, Outcome::Failed(-1)] {
            let error = unwrapped(Err(outcome)).unwrap_err();
            assert_eq!(error, outcome.describe(), "{outcome:?}");
        }
    }

    #[test]
    fn writing_more_than_the_format_holds_is_refused() {
        // Both fields, because a cap enforced on only one of them would let a
        // file be written that `decode` then refuses to read back.
        for stored in [
            Stored {
                blob: vec![0; MAX_BLOB + 1],
                cipher: Vec::new(),
            },
            Stored {
                blob: Vec::new(),
                cipher: vec![0; MAX_CIPHER + 1],
            },
        ] {
            let error = stored.encode().unwrap_err().to_string();
            assert!(error.contains("store-master-password"), "{error}");
        }
    }

    #[test]
    fn a_file_that_cannot_be_read_is_an_error_not_an_absence() {
        // "Nothing stored" and "something is there but unreadable" must not
        // look alike: the second would silently seed over a working key.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stored");
        save(&path, &sample()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(load(&path).is_err());
    }

    #[test]
    fn a_removal_that_cannot_happen_is_reported() {
        // A directory in its place: not something this writes, but the error
        // must travel rather than be read as "already gone".
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stored");
        std::fs::create_dir(&path).unwrap();
        assert!(remove(&path).is_err());
    }

    #[test]
    fn the_stored_file_sits_beside_the_socket() {
        assert_eq!(
            path_for(Path::new("/run/user/1000/agent.sock")),
            Path::new("/run/user/1000/agent.sock.master")
        );
    }

    #[test]
    fn nothing_stored_yet_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(&dir.path().join("absent")).unwrap(), None);
    }

    #[test]
    fn what_was_saved_is_what_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stored");
        save(&path, &sample()).unwrap();
        assert_eq!(load(&path).unwrap().unwrap(), sample());
    }

    #[test]
    fn saving_twice_replaces_rather_than_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stored");
        save(&path, &sample()).unwrap();
        let second = Stored {
            blob: vec![7; 40],
            cipher: vec![6; 20],
        };
        save(&path, &second).unwrap();
        assert_eq!(load(&path).unwrap().unwrap(), second);
    }

    #[test]
    fn the_stored_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stored");
        save(&path, &sample()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    /// Bytes that will not decode read as an empty store rather than a broken
    /// one, so `store-master-password` can replace them. An error here would
    /// make the documented repair refuse to run.
    fn expect_reads_as_empty(bytes: &[u8], case: &str) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stored");
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(load(&path).unwrap(), None, "{case}");
    }

    #[test]
    fn a_file_larger_than_anything_this_writes_reads_as_empty() {
        let mut bytes = sample().encode().unwrap();
        bytes.resize(MAGIC.len() + 8 + MAX_BLOB + MAX_CIPHER + 64, 0);
        expect_reads_as_empty(&bytes, "oversized");
    }

    #[test]
    fn a_truncated_or_foreign_file_reads_as_empty() {
        let encoded = sample().encode().unwrap();
        expect_reads_as_empty(&encoded[..encoded.len() - 1], "truncated");
        expect_reads_as_empty(b"some other file entirely", "not ours");
    }

    #[test]
    fn forgetting_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stored");
        save(&path, &sample()).unwrap();
        remove(&path).unwrap();
        assert_eq!(load(&path).unwrap(), None);
    }

    #[test]
    fn forgetting_what_is_already_gone_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        remove(&dir.path().join("absent")).unwrap();
    }

    #[test]
    fn every_outcome_describes_itself_usefully() {
        for (outcome, expected) in [
            (Outcome::Done, "answered"),
            (Outcome::Unavailable, "no Secure Enclave"),
            (Outcome::Refused, "Touch ID"),
            (Outcome::Reseed, "store-master-password"),
            (Outcome::Failed(-7), "code -7"),
        ] {
            let described = outcome.describe();
            assert!(described.contains(expected), "{outcome:?}: {described}");
        }
    }
}
