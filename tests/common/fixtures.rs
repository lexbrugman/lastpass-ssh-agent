//! The throwaway keypairs under `tests/fixtures`, as the tests name them.
//!
//! Shared by the unit tests (through `testutil`) and the crates under
//! `tests/`, each of which declares this file as a module of its own.
#![allow(dead_code)] // each crate uses the keys it needs

pub const ED25519: &str = include_str!("../fixtures/ed25519");
pub const ED25519_PUB: &str = include_str!("../fixtures/ed25519.pub");
pub const ED25519_PW: &str = include_str!("../fixtures/ed25519_pw");
pub const ED25519_PW_PUB: &str = include_str!("../fixtures/ed25519_pw.pub");
pub const RSA: &str = include_str!("../fixtures/rsa");
pub const RSA_PUB: &str = include_str!("../fixtures/rsa.pub");
pub const ECDSA: &str = include_str!("../fixtures/ecdsa");
pub const ECDSA_PUB: &str = include_str!("../fixtures/ecdsa.pub");
pub const SK_ED25519_PUB: &str = include_str!("../fixtures/sk_ed25519.pub");
