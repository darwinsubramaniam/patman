//! `$HOME/.pat/vault.json` — the public half of the sealing setup, and the
//! passphrase prompt that turns it into a key.
//!
//! Like the manifest, this file holds **no secrets**: an Argon2 salt and cost
//! parameters are not confidential, and the verifier is a sealed constant. It is
//! safe for an agent to read. What it does do is answer two questions that would
//! otherwise be guesswork:
//!
//! - **Is this installation sealed?** The file's presence is the switch. There is
//!   no config flag to disagree with the files on disk.
//! - **Is this the right passphrase?** Deriving a key always succeeds, so without
//!   a verifier a typo would be indistinguishable from a corrupted token file,
//!   and the user would learn about it one confusing `curl` failure at a time.

use std::io::IsTerminal;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Context, Result, bail};
use crate::sealed::{self, KdfParams, Key};
use crate::{paths, secure};

/// Sealed under the vault key to prove a passphrase is the right one. The value
/// is arbitrary; only the fact that it opens matters.
const VERIFIER_PLAINTEXT: &[u8] = b"patman-vault-v1";

/// The verifier's AAD. A service name is `^[A-Za-z0-9_-]+$`, so a NUL byte here
/// puts this outside the namespace a token file can ever occupy — the verifier
/// cannot be swapped for a token file or vice versa.
const VERIFIER_AAD: &str = "\u{0}vault-verifier";

#[derive(Debug, Serialize, Deserialize)]
pub struct Vault {
    pub version: u32,
    /// Named rather than assumed, so a future KDF change is a readable error on
    /// an old binary instead of a wrong key.
    pub kdf: String,
    #[serde(flatten)]
    pub params: KdfParams,
    /// Hex. Not secret — a salt's job is uniqueness, not confidentiality.
    pub salt: String,
    /// Hex sealed blob over [`VERIFIER_PLAINTEXT`].
    pub verifier: String,
}

pub fn path() -> Result<PathBuf> {
    Ok(paths::pat_dir()?.join("vault.json"))
}

/// Is this installation sealed? The file on disk is the only authority.
pub fn is_sealed_install() -> bool {
    path().map(|p| p.is_file()).unwrap_or(false)
}

pub fn load() -> Result<Vault> {
    let p = path()?;
    let raw = std::fs::read_to_string(&p).ctx(format!("reading {}", p.display()))?;
    let vault: Vault = serde_json::from_str(&raw).ctx(format!(
        "{} is not valid vault JSON — do not delete it, sealed token files cannot \
         be opened without its salt",
        p.display()
    ))?;
    if vault.version != 1 {
        return bail(format!(
            "{} was written by a newer patman (vault version {}). Upgrade patman.",
            p.display(),
            vault.version
        ));
    }
    if vault.kdf != "argon2id" {
        return bail(format!(
            "{} uses an unsupported KDF ({:?}). Upgrade patman.",
            p.display(),
            vault.kdf
        ));
    }
    Ok(vault)
}

/// Derive the key and prove it against the verifier.
pub fn unlock(vault: &Vault, passphrase: &str) -> Result<Key> {
    let salt = sealed::from_hex(&vault.salt).ctx("the vault salt is not valid hex")?;
    let key = sealed::derive(passphrase, &salt, vault.params)?;
    let verifier = sealed::from_hex(&vault.verifier).ctx("the vault verifier is not valid hex")?;

    match sealed::open(&key, VERIFIER_AAD, &verifier) {
        Ok(v) if v == VERIFIER_PLAINTEXT => Ok(key),
        // The verifier opened but holds something else: the file is damaged, not
        // the passphrase wrong. Worth distinguishing — the remedies differ.
        Ok(_) => bail("the vault verifier is corrupt — restore vault.json from a backup"),
        Err(_) => bail("wrong passphrase"),
    }
}

/// Create `vault.json` for a fresh passphrase. Refuses to clobber an existing
/// one: that would orphan every sealed token file, unrecoverably.
pub fn create(passphrase: &str) -> Result<Vault> {
    let p = path()?;
    if p.exists() {
        return bail(format!(
            "{} already exists. Changing the passphrase is `patman vault rekey`; \
             deleting this file would make every sealed token unopenable.",
            p.display()
        ));
    }

    let salt = sealed::random_salt()?;
    let params = KdfParams::default();
    let key = sealed::derive(passphrase, &salt, params)?;
    let verifier = sealed::seal(&key, VERIFIER_AAD, VERIFIER_PLAINTEXT)?;

    let vault = Vault {
        version: 1,
        kdf: "argon2id".into(),
        params,
        salt: sealed::to_hex(&salt),
        verifier: sealed::to_hex(&verifier),
    };
    save(&vault)?;
    Ok(vault)
}

pub fn save(vault: &Vault) -> Result<()> {
    let mut json = serde_json::to_string_pretty(vault)?;
    json.push('\n');
    secure::write_private_atomic(&path()?, json.as_bytes())
}

/// Is there a terminal to prompt on?
///
/// This asks the real question — can this process reach a console — rather than
/// whether stdin happens to be one. They differ in the case that matters:
/// `op read ... | patman save x --stdin` has a pipe on stdin and still has a
/// terminal for the passphrase.
///
/// The probe deliberately mirrors what rpassword will do moments later:
/// `/dev/tty` on unix, `CONIN$` on Windows. Checking a different thing than the
/// prompt uses is how you get a refusal on a machine that could have prompted
/// perfectly well.
pub fn has_tty() -> bool {
    #[cfg(unix)]
    const CONSOLE: &str = "/dev/tty";
    #[cfg(windows)]
    const CONSOLE: &str = "CONIN$";

    #[cfg(any(unix, windows))]
    {
        std::io::stdin().is_terminal()
            || std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(CONSOLE)
                .is_ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::io::stdin().is_terminal()
    }
}

/// Prompt for the vault passphrase, echo off.
///
/// The caller decides the policy; this only refuses when there is physically no
/// terminal to read from. Note what this check is and is not: it proves a
/// terminal exists, not that a human is at it. A harness that allocates a pty
/// for its subprocesses satisfies it. The property the agent design actually
/// rests on is in `agent.rs` — the key never leaves the daemon — not here.
pub fn prompt_passphrase(prompt: &str) -> Result<String> {
    if !has_tty() {
        return bail(
            "no terminal available to read the vault passphrase.\n\n\
             The vault is locked and unlocking needs masked input, which an agent's \
             tool call cannot provide.\n\n\
             Run it yourself in a terminal window (not Claude Code's `!` prefix, which has no terminal to prompt on):\n\
             \x20   patman unlock",
        );
    }
    let pass = rpassword::prompt_password(prompt).ctx("reading the passphrase")?;
    if pass.is_empty() {
        return bail("empty passphrase");
    }
    Ok(pass)
}

/// Prompt twice and require a match — for `vault init`, where a typo would seal
/// tokens under a passphrase the user does not know.
pub fn prompt_new_passphrase() -> Result<String> {
    let first = prompt_passphrase("New vault passphrase (input hidden): ")?;
    if first.chars().count() < 8 {
        return bail("passphrase is too short — use at least 8 characters");
    }
    let again = prompt_passphrase("Repeat it: ")?;
    if first != again {
        return bail("the two passphrases do not match — nothing written");
    }
    Ok(first)
}
