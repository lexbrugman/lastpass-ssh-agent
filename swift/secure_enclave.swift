// The Secure Enclave, reached through CryptoKit because nothing else can.
//
// Everything here would rather have been Rust. `security-framework` already
// binds the calls that create a Secure Enclave key, attach an access control to
// it, and run ECIES against it — but not the one that matters for a process
// that exits. Apple documents the hole plainly: SecKeyCopyExternalRepresentation
// "fails if the key is not exportable, for example if it is bound to a smart
// card or to the Secure Enclave", so a key the keychain never took cannot be
// written down from the Security framework at all. CryptoKit's
// `dataRepresentation` is the only way to get the wrapped blob back, it exists
// in Swift and nowhere else, and a key restored from it is a CryptoKit object
// rather than a SecKey — so the use of the key has to follow it across.
//
// Keeping the key in the keychain instead is the route that is closed: that
// needs the data-protection keychain, which needs `com.apple.application-
// identifier`, which needs a provisioning profile and an app bundle. A command
// line tool gets errSecMissingEntitlement (-34018) and no way forward. Holding
// the blob ourselves never touches the keychain, so no entitlement is involved.
//
// Two rules govern this file, and both exist to keep it from growing:
//
// - No decisions. Every failure returns the stage it failed at and the
//   underlying error code, and `enclave::meaning` in Rust decides what
//   that means. A `match` here would be logic behind a `cfg` that only one CI
//   job can reach; the same match in Rust is tested on every platform.
// - No LAContext that is authenticated, and none that outlives a call. Both
//   halves matter: an LAContext that has been through `evaluatePolicy` keeps
//   its authorisation for its whole lifetime — not for some window — so one
//   Touch ID would let every later use of the key through silently. Survivable
//   for a tool that exits in milliseconds; not for an agent that runs for
//   weeks. The context in `lssha_se_open` is made inside the call that uses
//   it, is never authenticated here, and is gone when that call returns, so
//   each unwrap prompts. Its only job is to carry the sentence the user reads:
//   `localizedReason` is what the system shows when an implicit prompt was
//   given no reason of its own, and an unexplained fingerprint request is one
//   nobody can sensibly refuse.
//   `touchIDAuthenticationAllowableReuseDuration` is left at its default zero.
//
// Buffers are the caller's, sized by the caller, and never grown. The secret
// only touches memory this file was handed, plus what CryptoKit allocates for
// itself on the way past.

import CryptoKit
import Foundation
import LocalAuthentication

// Where a call stopped. Facts, not judgements — see `meaning` on the Rust side.
private let ok: Int32 = 0
private let stageBufferTooSmall: Int32 = 1
private let stageUnavailable: Int32 = 2
private let stageAccessControl: Int32 = 3
private let stageCreate: Int32 = 4
private let stageRestore: Int32 = 5
private let stageAgreement: Int32 = 6
private let stageCipher: Int32 = 7
private let stageMalformed: Int32 = 8
private let stageDecrypt: Int32 = 9

/// Domain separation for the key derivation, so the bytes agreed here cannot
/// double as a key for anything else that ever agrees the same secret.
///
/// Its `v1` is not `enclave::MAGIC`'s `v2` and must not be made to match. The
/// magic versions the *file*, and was bumped when padding changed its layout;
/// this versions the *derivation*, which has never changed. Changing this
/// string derives a different key, so every password already stored becomes
/// permanently unreadable — bump it only to deliberately invalidate them all,
/// and never to tidy up the numbers.
private let salt = Data("lastpass-ssh-agent secure enclave v1".utf8)

/// An uncompressed P-256 point: `04 || X || Y`. The ciphertext carries the
/// ephemeral public key in front, so this is where the sealed box starts.
private let x963PointBytes = 65

/// What the Touch ID sheet says this is for. The system renders it as "<name>
/// is trying to <reason>", so it reads as a verb phrase — and it names the
/// vault rather than the agent, because what is being opened is the thing the
/// user has to decide about.
private let reason = "unlock your LastPass vault"

/// Best guess at an OS error code inside whatever CryptoKit threw.
///
/// Diagnostic only. Nothing here branches on it — it is written out so the
/// agent's log can say what the system said, and so Rust can tell a refused
/// fingerprint from a broken one.
private func code(of error: Error) -> Int32 {
    let ns = error as NSError
    if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError {
        return Int32(truncatingIfNeeded: underlying.code)
    }
    return Int32(truncatingIfNeeded: ns.code)
}

private func code(of error: Unmanaged<CFError>?) -> Int32 {
    guard let error else { return 0 }
    return Int32(truncatingIfNeeded: CFErrorGetCode(error.takeRetainedValue()))
}

/// Copy `data` into the caller's buffer, refusing rather than truncating.
private func copy(
    _ data: Data,
    into out: UnsafeMutablePointer<UInt8>,
    cap: UInt,
    len: UnsafeMutablePointer<UInt>
) -> Int32 {
    guard UInt(data.count) <= cap else { return stageBufferTooSmall }
    data.copyBytes(to: out, count: data.count)
    len.pointee = UInt(data.count)
    return ok
}

/// Whether this machine has a Secure Enclave at all.
@_cdecl("lssha_se_available")
public func lssha_se_available() -> Int32 {
    return SecureEnclave.isAvailable ? 1 : 0
}

/// Create a key that only a fingerprint can use, and encrypt `secret` to it.
///
/// Creating the key costs nothing: the access control is enforced when the key
/// is *used*, so seeding never prompts. The blob and the ciphertext are both
/// the caller's to store; neither is a secret, and neither is usable without
/// this machine's Secure Enclave and a finger on the sensor.
@_cdecl("lssha_se_seal")
public func lssha_se_seal(
    _ secret: UnsafePointer<UInt8>,
    _ secretLen: UInt,
    _ blobOut: UnsafeMutablePointer<UInt8>,
    _ blobCap: UInt,
    _ blobLen: UnsafeMutablePointer<UInt>,
    _ cipherOut: UnsafeMutablePointer<UInt8>,
    _ cipherCap: UInt,
    _ cipherLen: UnsafeMutablePointer<UInt>,
    _ osError: UnsafeMutablePointer<Int32>
) -> Int32 {
    osError.pointee = 0
    guard SecureEnclave.isAvailable else { return stageUnavailable }

    // `.biometryCurrentSet` rather than `.userPresence`: the login password is
    // not an acceptable substitute for a secret that opens the whole vault, and
    // enrolling a new finger must invalidate the key rather than inherit it.
    // The cost is that a fingerprint change means seeding again, which the Rust
    // side turns into a message saying so.
    var accessError: Unmanaged<CFError>?
    guard
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &accessError
        )
    else {
        osError.pointee = code(of: accessError)
        return stageAccessControl
    }

    let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
    } catch {
        osError.pointee = code(of: error)
        return stageCreate
    }

    // Ordinary ECIES: an ephemeral key agrees with the Enclave's public half,
    // and the agreed bytes key one AES-GCM box. Only the Enclave can repeat the
    // agreement, and only after the sensor says so.
    let ephemeral = P256.KeyAgreement.PrivateKey()
    let ephemeralPublic = ephemeral.publicKey.x963Representation
    var cipher: Data
    do {
        let agreed = try ephemeral.sharedSecretFromKeyAgreement(with: key.publicKey)
        let symmetric = agreed.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: ephemeralPublic,
            outputByteCount: 32
        )
        var plaintext = Data(bytes: secret, count: Int(clamping: secretLen))
        defer { plaintext.resetBytes(in: 0..<plaintext.count) }
        guard let sealed = try AES.GCM.seal(plaintext, using: symmetric).combined else {
            return stageCipher
        }
        cipher = ephemeralPublic + sealed
    } catch {
        osError.pointee = code(of: error)
        return stageCipher
    }

    let blob = key.dataRepresentation
    let wrote = copy(blob, into: blobOut, cap: blobCap, len: blobLen)
    guard wrote == ok else { return wrote }
    return copy(cipher, into: cipherOut, cap: cipherCap, len: cipherLen)
}

/// Restore the key from its blob and decrypt — which is where Touch ID happens.
///
/// The blob is inert: it is wrapped under a key that never leaves this
/// machine's Enclave, and the access control travels inside it, so another
/// binary loading the same file still has to ask for the same finger.
@_cdecl("lssha_se_open")
public func lssha_se_open(
    _ blob: UnsafePointer<UInt8>,
    _ blobLen: UInt,
    _ cipher: UnsafePointer<UInt8>,
    _ cipherLen: UInt,
    _ out: UnsafeMutablePointer<UInt8>,
    _ cap: UInt,
    _ len: UnsafeMutablePointer<UInt>,
    _ osError: UnsafeMutablePointer<Int32>
) -> Int32 {
    osError.pointee = 0
    guard cipherLen > UInt(x963PointBytes) else { return stageMalformed }

    // Created here and dropped when this returns: see the rules at the top.
    // Never authenticated by us, so CryptoKit still raises the prompt itself
    // for every unwrap — this only gives that prompt something to say.
    let context = LAContext()
    context.localizedReason = reason

    let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: Data(bytes: blob, count: Int(clamping: blobLen)),
            authenticationContext: context
        )
    } catch {
        osError.pointee = code(of: error)
        return stageRestore
    }

    let ephemeralPublic = Data(bytes: cipher, count: x963PointBytes)
    let sealed = Data(
        bytes: cipher + x963PointBytes,
        count: Int(clamping: cipherLen) - x963PointBytes
    )

    let symmetric: SymmetricKey
    do {
        let agreed = try key.sharedSecretFromKeyAgreement(
            with: P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublic)
        )
        symmetric = agreed.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: ephemeralPublic,
            outputByteCount: 32
        )
    } catch {
        osError.pointee = code(of: error)
        return stageAgreement
    }

    do {
        var plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: symmetric)
        defer { plaintext.resetBytes(in: 0..<plaintext.count) }
        return copy(plaintext, into: out, cap: cap, len: len)
    } catch {
        // Its own stage rather than the sealing one: the agreement already
        // succeeded, so the fingerprint was given and the Enclave is fine —
        // what is wrong is the stored ciphertext, which will never open again.
        osError.pointee = code(of: error)
        return stageDecrypt
    }
}
