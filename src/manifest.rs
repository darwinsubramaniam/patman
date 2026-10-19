//! The manifest: `service -> { description, username?, updated }`.
//!
//! It holds **no secrets**. That is the whole point — it is the one file in
//! `$HOME/.pat/` that is safe to read, print, and paste into a conversation, so
//! a token can be *identified* without ever being *read*.
//!
//! Note what is deliberately absent: the token's path. Storing an absolute path
//! would break the moment the manifest moved between machines or between Windows
//! and POSIX, and storing a literal `~` produces a path no program can open. The
//! service key *is* the filename; the path is always derived.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Context, Result};
use crate::secure;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// What the token is for: which account/site, which scopes.
    pub description: String,

    /// The account identifier the service pairs with the token for Basic auth —
    /// an email for Atlassian Cloud, a short corporate ID for most self-hosted
    /// servers. Not a secret. Absent for Bearer-only services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Hosts `patman curl` may send this token to (exact hostname, or
    /// `*.example.com` for subdomains). Empty means unrestricted — allowed for
    /// compatibility, but `patman curl` warns until hosts are pinned.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,

    /// Whether `patman exec` may use this token. Defaults to false, and only
    /// consulted under a sealed vault — see [`crate::usage::authorize_exec`].
    /// exec bypasses host pinning and argument vetting by design, so on a sealed
    /// install it is a per-service decision rather than an ambient capability.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_exec: bool,

    /// Whether an open unlock session is enough to spend this token, or every
    /// use needs its own approval. Only meaningful under a sealed vault.
    #[serde(default, skip_serializing_if = "Approval::is_session")]
    pub approval: Approval,

    /// Hex seal over the policy fields above, made with the vault key. See
    /// [`crate::policy`] — it is what stops the policy being loosened by
    /// anything that can merely write this file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_seal: Option<String>,

    /// `YYYY-MM-DD`, last time the token value was written.
    pub updated: String,

    /// Fields written by a future version are round-tripped rather than dropped,
    /// so an older binary can't silently strip them.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// How much human involvement spending a sealed token takes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Approval {
    /// An open unlock session is enough: `patman curl` works unattended until
    /// it expires. For low-risk tokens.
    #[default]
    Session,
    /// Every use is approved on its own — Touch ID (or the login password) on
    /// macOS, the vault passphrase elsewhere — and the prompt shows what is
    /// being sent where. An unlock session alone is not enough.
    Request,
}

impl Approval {
    pub fn is_session(&self) -> bool {
        *self == Approval::Session
    }
}

/// `BTreeMap` rather than a preserve-order map: keys stay sorted, so rewriting
/// the manifest produces a stable diff instead of reshuffling on every save.
#[derive(Debug, Default)]
pub struct Manifest {
    pub entries: BTreeMap<String, Entry>,
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => {
                return Err(crate::error::Error(format!(
                    "reading {}: {e}",
                    path.display()
                )));
            }
        };
        if raw.trim().is_empty() {
            return Ok(Self::default());
        }
        let entries = serde_json::from_str(&raw).ctx(format!(
            "{} is not valid manifest JSON (fix or delete it; token files are untouched)",
            path.display()
        ))?;
        Ok(Self { entries })
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut json = serde_json::to_string_pretty(&self.entries)?;
        json.push('\n');
        secure::write_private_atomic(path, json.as_bytes())
    }

    pub fn get(&self, service: &str) -> Option<&Entry> {
        self.entries.get(service)
    }
}

/// Today, local time, as `YYYY-MM-DD`.
pub fn today() -> String {
    chrono::Local::now().format("%Y-%m-%d").to_string()
}
