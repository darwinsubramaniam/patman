//! The sealed token file format, and the passphrase-derived key that opens it.
//!
//! A sealed file is `MAGIC || nonce || XChaCha20-Poly1305(key, nonce, plaintext,
//! aad = service)`. Three properties are worth naming:
//!
//! - **The magic prefix makes the format self-identifying.** `token::read` can
//!   tell a sealed file from a legacy plaintext one and give a precise error
//!   instead of handing 40 bytes of ciphertext to curl as a Bearer token.
//! - **The service name is the AAD.** The ciphertext is bound to its filename,
//!   so copying `~/.pat/github` over `~/.pat/jira` does not silently make the
//!   GitHub token authenticate as Jira — it fails to open.
//! - **A decrypt failure is deliberately opaque.** AEAD cannot distinguish a
//!   wrong key from a tampered file, and pretending otherwise would invent a
//!   distinction the construction does not provide.
//!
//! Nothing here decides *whether* to seal, or where the key comes from. That is
//! `vault`'s job.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use crate::error::{Context, Error, Result, bail};

/// Prefix identifying a sealed file, including a format version byte. Bumping
/// the version is how a future format change stays distinguishable rather than
/// producing a confusing authentication failure.
pub const MAGIC: &[u8] = b"PATMAN\x01\x00";

pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

/// Poly1305 authentication tag length — the floor for a well-formed ciphertext.
const TAG_LEN: usize = 16;

/// A derived symmetric key. Like [`crate::token::Secret`] it has a redacted
/// `Debug`, no `Display`, and is wiped on drop. Unlike `Secret` it is a fixed
/// array, so the wipe is not defeated by a reallocation.
pub struct Key([u8; KEY_LEN]);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// The hex hop exists only to hand the key to the unlock agent over a pipe, and
/// the agent is unix-only — so on Windows these would be dead code.
#[cfg(any(unix, test))]
impl Key {
    /// Rebuild a key from the hex form used to hand it to the agent over a pipe.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = from_hex(s.trim())?;
        let arr: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| Error("key material is the wrong length".into()))?;
        Ok(Self(arr))
    }

    /// Hex form, for the single hop from `patman unlock` into the agent's stdin.
    /// Never logged, never in argv — see `cmds::unlock`.
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

/// Argon2id cost parameters. Recorded in `vault.json` rather than hardcoded at
/// the open site, so raising the defaults later does not lock anyone out of a
/// vault created under the old ones.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// The RFC 9106 second-recommended option (19 MiB, 2 passes), which is also
    /// the `argon2` crate's default. Chosen over the 64 MiB first option because
    /// this runs on the devcontainers and CI sandboxes patman targets.
    fn default() -> Self {
        Self {
            m_cost: Params::DEFAULT_M_COST,
            t_cost: Params::DEFAULT_T_COST,
            p_cost: Params::DEFAULT_P_COST,
        }
    }
}

pub fn derive(passphrase: &str, salt: &[u8], p: KdfParams) -> Result<Key> {
    let params = Params::new(p.m_cost, p.t_cost, p.p_cost, Some(KEY_LEN))
        .map_err(|e| Error(format!("invalid Argon2 parameters in the vault: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| Error(format!("deriving the vault key: {e}")))?;
    Ok(Key(out))
}

pub fn random_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).ctx("gathering randomness for a salt")?;
    Ok(salt)
}

/// Does this byte string look like a sealed file?
pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

fn cipher(key: &Key) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&key.0.into())
}

pub fn seal(key: &Key, aad: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).ctx("gathering randomness for a nonce")?;

    let ct = cipher(key)
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| Error("sealing the token failed".into()))?;

    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(key: &Key, aad: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    if !is_sealed(bytes) {
        return bail("not a sealed patman file");
    }
    let body = &bytes[MAGIC.len()..];
    if body.len() < NONCE_LEN + TAG_LEN {
        return bail("the sealed file is truncated");
    }
    let (nonce, ct) = body.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split_at guarantees the length");

    cipher(key)
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ct,
                aad: aad.as_bytes(),
            },
        )
        // Opaque on purpose: an AEAD cannot tell a wrong key from a modified
        // file, so the message names both possibilities instead of guessing.
        .map_err(|_| {
            Error(
                "could not open the sealed file — wrong passphrase, or the file \
                 has been modified or renamed"
                    .into(),
            )
        })
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return bail("hex string has an odd length");
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| Error("hex string contains a non-hex character".into()))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| Error("hex string contains a non-hex character".into()))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap parameters: these tests exercise the format, not the KDF's cost.
    fn test_key(pass: &str) -> Key {
        derive(
            pass,
            b"0123456789abcdef",
            KdfParams {
                m_cost: 8,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap()
    }

    #[test]
    fn round_trips() {
        let key = test_key("correct horse");
        let sealed = seal(&key, "github", b"ghp_example").unwrap();
        assert!(is_sealed(&sealed));
        assert_eq!(open(&key, "github", &sealed).unwrap(), b"ghp_example");
    }

    #[test]
    fn plaintext_is_not_mistaken_for_sealed() {
        assert!(!is_sealed(b"ghp_averyordinarylookingtoken"));
        assert!(!is_sealed(b""));
    }

    #[test]
    fn the_ciphertext_does_not_contain_the_plaintext() {
        let key = test_key("correct horse");
        let sealed = seal(&key, "github", b"ghp_example").unwrap();
        assert!(
            !sealed.windows(11).any(|w| w == b"ghp_example"),
            "plaintext leaked into the sealed file"
        );
    }

    #[test]
    fn a_wrong_passphrase_does_not_open_it() {
        let sealed = seal(&test_key("correct horse"), "github", b"ghp_example").unwrap();
        assert!(open(&test_key("wrong horse"), "github", &sealed).is_err());
    }

    /// The AAD binding. Renaming a token file must not repurpose the token.
    #[test]
    fn a_file_moved_to_another_service_does_not_open() {
        let key = test_key("correct horse");
        let sealed = seal(&key, "github", b"ghp_example").unwrap();
        assert!(open(&key, "jira", &sealed).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let key = test_key("correct horse");
        let mut sealed = seal(&key, "github", b"ghp_example").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open(&key, "github", &sealed).is_err());
    }

    #[test]
    fn a_truncated_file_is_rejected_not_panicked_on() {
        let key = test_key("correct horse");
        let sealed = seal(&key, "github", b"ghp_example").unwrap();
        for cut in 0..sealed.len() {
            assert!(open(&key, "github", &sealed[..cut]).is_err());
        }
    }

    /// Distinct nonces per seal — the one mistake that would break XChaCha20.
    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let key = test_key("correct horse");
        let a = seal(&key, "github", b"ghp_example").unwrap();
        let b = seal(&key, "github", b"ghp_example").unwrap();
        let n = MAGIC.len() + NONCE_LEN;
        assert_ne!(a[MAGIC.len()..n], b[MAGIC.len()..n]);
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00u8, 0x0f, 0xf0, 0xff, 0x5a];
        assert_eq!(to_hex(&bytes), "000ff0ff5a");
        assert_eq!(from_hex("000ff0ff5a").unwrap(), bytes);
        assert!(from_hex("abc").is_err());
        assert!(from_hex("zz").is_err());
    }

    #[test]
    fn a_key_survives_the_hex_hop_to_the_agent() {
        let key = test_key("correct horse");
        let sealed = seal(&key, "github", b"ghp_example").unwrap();
        let revived = Key::from_hex(&key.to_hex()).unwrap();
        assert_eq!(open(&revived, "github", &sealed).unwrap(), b"ghp_example");
    }
}
