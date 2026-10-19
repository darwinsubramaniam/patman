//! Deciding whether a token may be used, and building the curl config that uses
//! it. Shared by the local command path (`cmds::curl`) and the unlock agent
//! (`agent`).
//!
//! This module exists because of one hazard specific to the agent design. Once a
//! socket accepts requests, an attacker running as the user no longer has to go
//! through the `patman` binary — they can speak the protocol themselves. So the
//! host allowlist and the curl flag blocklist cannot live only in the client;
//! they have to be enforced by whoever holds the key. Putting the rules here, and
//! having both callers use them, is what keeps the two paths from drifting.

use crate::error::{Result, bail};
use crate::guard;
use crate::manifest::{Approval, Manifest};
use crate::token::Secret;

#[derive(
    Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Auth {
    /// `Authorization: Bearer <token>`
    Bearer,
    /// `Authorization: Basic base64(username:token)` — needs a manifest username.
    Basic,
    /// Basic when the manifest records a username, Bearer otherwise.
    Auto,
}

/// Everything the manifest has to say about how a service's token may be used,
/// resolved once so the decision and the use cannot disagree.
#[derive(Debug)]
pub struct Plan {
    pub mode: Auth,
    pub username: Option<String>,
    pub hosts: Vec<String>,
    pub allow_exec: bool,
    /// Read only by the unlock agent. Without one (Windows) every sealed use
    /// already prompts for the passphrase, which is a per-request approval.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub approval: Approval,
}

pub fn plan(manifest: &Manifest, service: &str, auth: Auth) -> Plan {
    let entry = manifest.get(service);
    let username = entry.and_then(|e| e.username.clone());
    let mode = match auth {
        Auth::Auto if username.is_some() => Auth::Basic,
        Auth::Auto => Auth::Bearer,
        other => other,
    };
    Plan {
        mode,
        username,
        hosts: entry.map(|e| e.hosts.clone()).unwrap_or_default(),
        allow_exec: entry.map(|e| e.allow_exec).unwrap_or(false),
        approval: entry.map(|e| e.approval).unwrap_or_default(),
    }
}

/// Vet the pass-through arguments and the destination, before the token is read
/// from disk. Returns a warning to show the caller when nothing is pinned.
pub fn authorize_curl(service: &str, args: &[String], plan: &Plan) -> Result<Option<String>> {
    guard::vet_args(args, matches!(plan.mode, Auth::Bearer))?;
    if plan.hosts.is_empty() {
        return Ok(Some(format!(
            "warning: no hosts pinned for {service:?} — the token will be sent to \
             whatever URL curl is given.\n\
             pin the API host with: patman describe {service} --host api.example.com"
        )));
    }
    guard::enforce_hosts(service, args, &plan.hosts)?;
    Ok(None)
}

/// `patman exec` hands the raw token to a child process chosen by the caller,
/// with no host pinning and no argument vetting — `sh -c 'echo $PAT_TOKEN'` is a
/// complete bypass of every other control in this tool. That is tolerable when a
/// human types it and indefensible when whatever is driving patman can pick the
/// command, so under a sealed vault it takes an explicit per-service opt-in.
pub fn authorize_exec(service: &str, plan: &Plan, sealed: bool) -> Result<()> {
    if !sealed || plan.allow_exec {
        return Ok(());
    }
    bail(format!(
        "`patman exec` is not enabled for {service:?}.\n\n\
         exec puts the token in a child process's environment and skips host \
         pinning and argument vetting, so with a sealed vault it is opt-in per \
         service.\n\n\
         Prefer: patman curl {service} -- <curl args>\n\
         Or enable it: patman describe {service} --allow-exec"
    ))
}

/// The curl config fed to `--config -` on stdin.
///
/// Returned as a plain `String` rather than a `Secret` because it is written
/// straight to a pipe and dropped; the caller must not print it. Every consumer
/// in this crate passes it directly to [`crate::token::feed_stdin`].
pub fn curl_config(service: &str, plan: &Plan, secret: &Secret) -> Result<String> {
    // With pinned hosts, restrict curl itself to https. This is what stops a
    // schemeless stowaway URL (which curl would guess as http) from slipping
    // past the argument scan: curl refuses the protocol before connecting.
    let proto_line = if plan.hosts.is_empty() {
        ""
    } else {
        "proto = \"=https\"\n"
    };

    let auth_line = match plan.mode {
        Auth::Basic => {
            let Some(user) = &plan.username else {
                return bail(format!(
                    "Basic auth needs an account identifier, and the manifest has none for \
                     {service:?}.\nSet it with: patman describe {service} --username <id>"
                ));
            };
            format!("user = \"{}:{}\"\n", escape(user), escape(secret.expose()))
        }
        _ => format!(
            "header = \"Authorization: Bearer {}\"\n",
            escape(secret.expose())
        ),
    };

    Ok(format!("{proto_line}{auth_line}"))
}

/// Escape a value for curl's config-file quoting rules.
///
/// The config format is line-oriented, so a raw newline in a value would start
/// a new config directive — an injection, not a quoting problem. Newlines, CRs
/// and tabs use curl's supported in-string escapes; any other control character
/// has no representation and is dropped. Tokens and usernames are additionally
/// rejected upstream if they contain control characters at all, so for them
/// this is defense in depth rather than the only line.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// curl's config parser treats backslash and double-quote as special inside
    /// a quoted value, and the format itself is line-oriented. A value must not
    /// be able to terminate the quoted string early, and must never contain a
    /// raw newline — that would start a fresh config directive.
    #[test]
    fn escapes_curl_config_metacharacters() {
        assert_eq!(escape("plain-token-123"), "plain-token-123");
        assert_eq!(escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape(r"a\b"), r"a\\b");
        assert_eq!(escape("a\nb"), r"a\nb");
        assert_eq!(escape("a\r\tb"), r"a\r\tb");
        // Other control characters (ESC, NUL) are dropped; the printable
        // remainder of an ANSI sequence is harmless in a config value.
        assert_eq!(escape("a\x1bb\x00c"), "abc");
        let escaped = escape("x\"\nurl = \"https://evil.com\"");
        assert!(
            !escaped.contains('\n'),
            "no raw newline may survive: {escaped:?}"
        );
        assert_eq!(escaped, "x\\\"\\nurl = \\\"https://evil.com\\\"");
    }

    /// exec stays unguarded on a plaintext install (no behaviour change for
    /// existing users) and becomes opt-in once a vault exists.
    #[test]
    fn exec_is_opt_in_only_under_a_sealed_vault() {
        let open = Plan {
            mode: Auth::Bearer,
            username: None,
            hosts: vec![],
            allow_exec: false,
            approval: Approval::Session,
        };
        assert!(authorize_exec("gh", &open, false).is_ok());
        assert!(authorize_exec("gh", &open, true).is_err());

        let opted_in = Plan {
            allow_exec: true,
            ..open
        };
        assert!(authorize_exec("gh", &opted_in, true).is_ok());
    }
}
