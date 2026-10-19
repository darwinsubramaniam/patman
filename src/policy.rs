//! Signed per-service policy: the manifest fields that decide *how* a token may
//! be spent, bound to the vault key so only someone holding the passphrase can
//! loosen them.
//!
//! Without this, every per-service control is one edit away from gone. The agent
//! runs as the user, so it can write `manifest.json` — or just run
//! `patman describe github --approval session --clear-hosts` — and the unlock
//! agent would read the weakened policy and act on it. Encrypting tokens at rest
//! means little if the rules for spending them are plaintext anyone can rewrite.
//!
//! So under a sealed vault each entry carries a seal over its policy fields:
//! `sealed::seal(key, aad = canonical policy, plaintext = "")`. The plaintext is
//! empty because nothing is hidden; the AEAD tag over the AAD is what matters.
//! Whoever holds the key (the unlock agent, or a passphrase prompt) checks it
//! before acting, so an edited policy is refused rather than obeyed.
//!
//! What is covered: username (it picks Basic vs Bearer), pinned hosts,
//! `allow_exec`, and the approval mode. What is not: the description and the
//! `updated` date, which only help a human find a token.
//!
//! Known limit: a seal does not stop **rollback**. An old copy of the manifest
//! carries valid seals for its old policy, so restoring it re-arms whatever that
//! policy allowed. Defeating that needs a counter somewhere the agent cannot
//! write, which a same-user design does not have.

use serde::Serialize;

use crate::error::{Result, bail};
use crate::manifest::{Approval, Entry, Manifest};
use crate::sealed::{self, Key};

/// The signed view of an entry. Field order is fixed by the struct, so the
/// serialized form is deterministic — which an AAD has to be.
#[derive(Serialize)]
struct Signed<'a> {
    v: u32,
    service: &'a str,
    username: Option<&'a str>,
    hosts: &'a [String],
    allow_exec: bool,
    approval: Approval,
}

/// The AAD for a service's policy. The NUL prefix puts it outside the namespace
/// of token AADs (a bare service name) and the vault verifier, so no sealed blob
/// can stand in for another kind.
fn aad(service: &str, e: &Entry) -> String {
    let view = Signed {
        v: 1,
        service,
        username: e.username.as_deref(),
        hosts: &e.hosts,
        allow_exec: e.allow_exec,
        approval: e.approval,
    };
    let json = serde_json::to_string(&view).expect("policy view always serializes");
    format!("\u{0}policy:{json}")
}

/// Do two entries carry the same policy? Used to decide whether an edit needs
/// the passphrase at all — rewording a description should not.
pub fn same(service: &str, a: &Entry, b: &Entry) -> bool {
    aad(service, a) == aad(service, b)
}

/// Seal `e`'s current policy and store the result on it.
pub fn sign(key: &Key, service: &str, e: &mut Entry) -> Result<()> {
    let blob = sealed::seal(key, &aad(service, e), b"")?;
    e.policy_seal = Some(sealed::to_hex(&blob));
    Ok(())
}

/// Sign every entry in the manifest — `vault seal`'s way of vouching for the
/// policies as they stand when the human runs it.
pub fn sign_all(key: &Key, manifest: &mut Manifest) -> Result<usize> {
    for (service, entry) in manifest.entries.iter_mut() {
        sign(key, service, entry)?;
    }
    Ok(manifest.entries.len())
}

/// Refuse to act on a policy the key did not sign.
///
/// A missing entry is refused too: otherwise deleting a service's manifest
/// entry would be the easy way to fall back to the unrestricted defaults.
pub fn verify(key: &Key, manifest: &Manifest, service: &str) -> Result<()> {
    let Some(entry) = manifest.get(service) else {
        return bail(format!(
            "{service:?} has no manifest entry, and under a sealed vault a token is \
             only spent under a signed policy.\n\
             Describe it yourself (needs the passphrase) — in Claude Code prefix it with `!`:\n\
             \x20   !patman describe {service} -d \"...\" --host api.example.com"
        ));
    };
    let Some(hex) = &entry.policy_seal else {
        return bail(format!(
            "the policy for {service:?} is not signed, so it cannot be trusted under a \
             sealed vault.\n\
             Sign it yourself (needs the passphrase) — in Claude Code prefix it with `!`:\n\
             \x20   !patman describe {service} --sign"
        ));
    };
    let ok = sealed::from_hex(hex)
        .ok()
        .and_then(|blob| sealed::open(key, &aad(service, entry), &blob).ok())
        .is_some();
    if !ok {
        return bail(format!(
            "the policy for {service:?} has been changed without the vault passphrase \
             (hosts, username, exec or approval differ from what was signed) — refusing.\n\
             If you made the change, re-sign it — in Claude Code prefix it with `!`:\n\
             \x20   !patman describe {service} --sign"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn key() -> Key {
        Key::from_hex(&"11".repeat(sealed::KEY_LEN)).unwrap()
    }

    fn entry() -> Entry {
        Entry {
            description: "test".into(),
            username: None,
            hosts: vec!["api.github.com".into()],
            allow_exec: false,
            approval: Approval::Request,
            policy_seal: None,
            updated: "2026-10-19".into(),
            extra: BTreeMap::new(),
        }
    }

    fn manifest(service: &str, e: Entry) -> Manifest {
        let mut m = Manifest::default();
        m.entries.insert(service.into(), e);
        m
    }

    #[test]
    fn a_signed_policy_verifies() {
        let mut e = entry();
        sign(&key(), "github", &mut e).unwrap();
        verify(&key(), &manifest("github", e), "github").unwrap();
    }

    /// The attack this module exists for: the agent edits the manifest to
    /// loosen a rule, and the unlock agent must notice.
    #[test]
    fn every_policy_field_is_covered() {
        let tamperings: [fn(&mut Entry); 5] = [
            |e| e.approval = Approval::Session,
            |e| e.hosts.push("evil.com".into()),
            |e| e.hosts.clear(),
            |e| e.allow_exec = true,
            |e| e.username = Some("someone".into()),
        ];
        for tamper in tamperings {
            let mut e = entry();
            sign(&key(), "github", &mut e).unwrap();
            tamper(&mut e);
            assert!(verify(&key(), &manifest("github", e), "github").is_err());
        }
    }

    #[test]
    fn the_description_is_not_policy() {
        let mut e = entry();
        sign(&key(), "github", &mut e).unwrap();
        e.description = "reworded".into();
        e.updated = "2030-01-01".into();
        verify(&key(), &manifest("github", e), "github").unwrap();
    }

    /// A seal copied from a permissive service onto a strict one must not open.
    #[test]
    fn a_seal_is_bound_to_its_service() {
        let mut e = entry();
        sign(&key(), "loose", &mut e).unwrap();
        assert!(verify(&key(), &manifest("github", e), "github").is_err());
    }

    #[test]
    fn unsigned_missing_and_wrong_key_are_refused() {
        assert!(verify(&key(), &manifest("github", entry()), "github").is_err());
        assert!(verify(&key(), &Manifest::default(), "github").is_err());

        let mut e = entry();
        sign(&key(), "github", &mut e).unwrap();
        let other = Key::from_hex(&"22".repeat(sealed::KEY_LEN)).unwrap();
        assert!(verify(&other, &manifest("github", e), "github").is_err());
    }
}
