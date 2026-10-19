//! Per-request approval: the gate a `--approval request` service passes before
//! the unlock agent will spend its token, even inside an open session.
//!
//! Two properties make this a control rather than a formality:
//!
//! 1. **The prompt is out of band.** The caller asking for the request cannot
//!    answer it. On macOS it is a LocalAuthentication prompt — Touch ID, or the
//!    login password — raised by the agent process itself, not on the caller's
//!    terminal. Elsewhere it is the vault passphrase, which the human types and
//!    the agent has never seen.
//! 2. **The daemon writes the prompt, not the client.** What the human approves
//!    is derived here from the actual curl arguments, so a caller cannot ask for
//!    approval of one thing and then send another.
//!
//! The approval covers exactly one request. Nothing is cached: a second call is
//! a second prompt.

#![cfg(unix)]

use std::sync::Mutex;

use crate::error::{Result, bail};
use crate::guard;
use crate::vault;

/// One prompt at a time. Two requests racing for Touch ID would stack dialogs,
/// and a human approving the top one could not tell which request it was for.
static PROMPT: Mutex<()> = Mutex::new(());

/// How long the agent waits for a human before refusing.
#[cfg(target_os = "macos")]
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Keeps one argument readable in a dialog without letting it swamp the rest.
const MAX_SHOWN: usize = 160;

/// What a curl request will do, in words a human can approve. The macOS prompt
/// reads "patman is trying to <this>", so it is phrased to finish that sentence.
pub fn describe_curl(service: &str, args: &[String]) -> String {
    let mut method: Option<String> = None;
    let mut body: Vec<String> = Vec::new();

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_string())),
            _ => (arg.as_str(), None),
        };
        let mut value = || inline.clone().or_else(|| iter.next().cloned());
        match name {
            "-X" | "--request" => method = value(),
            _ if name.starts_with("-X") && name.len() > 2 && !name.starts_with("--") => {
                method = Some(name[2..].to_string());
            }
            "-d" | "--data" | "--data-raw" | "--data-binary" | "--data-urlencode" | "--json"
            | "-F" | "--form" | "-T" | "--upload-file" => {
                if let Some(v) = value() {
                    body.push(v);
                }
            }
            _ => {}
        }
    }

    let method = method.unwrap_or_else(|| if body.is_empty() { "GET" } else { "POST" }.into());
    let urls = guard::collect_urls(args);
    let target = if urls.is_empty() {
        "(no URL)".to_string()
    } else {
        urls.iter().map(|u| shown(u)).collect::<Vec<_>>().join(", ")
    };

    let mut s = format!("send your {service:?} token: {} {target}", shown(&method));
    if !body.is_empty() {
        let joined = body.iter().map(|b| shown(b)).collect::<Vec<_>>().join(" ");
        s.push_str(&format!(" with body {}", shown(&joined)));
    }
    s
}

pub fn describe_exec(service: &str, args: &[String]) -> String {
    format!(
        "give your {service:?} token to the command: {}",
        shown(&args.join(" "))
    )
}

/// Make caller-controlled text safe to put in a dialog: no control characters
/// (a newline could fake a second line of the prompt) and a bounded length.
fn shown(s: &str) -> String {
    let clean: String = s
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if clean.chars().count() > MAX_SHOWN {
        let cut: String = clean.chars().take(MAX_SHOWN).collect();
        format!("{cut}…")
    } else {
        clean
    }
}

/// Get a human's yes for this one request, or fail.
///
/// A passphrase, when the client sent one, is checked first: it works on every
/// platform and over SSH, where a Touch ID dialog would appear on a screen
/// nobody is looking at. Without one, macOS falls back to LocalAuthentication.
pub fn approve(what: &str, passphrase: Option<&str>) -> Result<()> {
    let _turn = PROMPT
        .lock()
        .map_err(|_| crate::error::Error("approval lock poisoned".into()))?;

    if let Some(pass) = passphrase {
        let v = vault::load()?;
        return vault::unlock(&v, pass)
            .map(drop)
            .map_err(|_| crate::error::Error("not approved: wrong passphrase".into()));
    }

    #[cfg(target_os = "macos")]
    if std::env::var_os("PATMAN_NO_TOUCHID").is_none() {
        return touch_id(what);
    }

    bail(format!(
        "this service needs approval for every request, and none was given.\n\
         Approving takes the vault passphrase, which an agent's tool call cannot \
         supply. Run the command yourself in a terminal window (not Claude Code's `!` \
         prefix, which has no terminal to prompt on).\n\
         (Request: {what})"
    ))
}

/// Raise the system authentication prompt and wait for the answer.
///
/// `DeviceOwnerAuthentication` rather than the biometrics-only policy: it is
/// Touch ID where there is a sensor and the login password where there is not
/// (or the lid is closed), and both are things only the human has.
#[cfg(target_os = "macos")]
fn touch_id(what: &str) -> Result<()> {
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    let policy = LAPolicy::DeviceOwnerAuthentication;
    // SAFETY: plain Objective-C calls on an object this function owns; the reply
    // block only moves a value into a channel.
    let ctx = unsafe { LAContext::new() };
    if let Err(e) = unsafe { ctx.canEvaluatePolicy_error(policy) } {
        return bail(format!(
            "Touch ID / password approval is not available here ({}).\n\
             Run the command yourself in a terminal window so you can type the vault \
             passphrase (Claude Code's `!` prefix has no terminal to prompt on).",
            e.localizedDescription()
        ));
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let reply = RcBlock::new(move |ok: Bool, err: *mut NSError| {
        // SAFETY: LocalAuthentication passes either null or a valid NSError.
        let why = unsafe { err.as_ref() }.map(|e| e.localizedDescription().to_string());
        let _ = tx.send((ok.as_bool(), why));
    });
    let reason = NSString::from_str(what);
    unsafe { ctx.evaluatePolicy_localizedReason_reply(policy, &reason, &reply) };

    match rx.recv_timeout(TIMEOUT) {
        Ok((true, _)) => Ok(()),
        Ok((false, why)) => bail(format!(
            "not approved{}",
            why.map(|w| format!(": {w}")).unwrap_or_default()
        )),
        Err(_) => {
            unsafe { ctx.invalidate() };
            bail("not approved: nobody answered the approval prompt in time")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_plain_request_reads_as_a_get() {
        let s = describe_curl("github", &v(&["-sS", "https://api.github.com/user"]));
        assert_eq!(
            s,
            r#"send your "github" token: GET https://api.github.com/user"#
        );
    }

    /// The body is what a reflection attack hides the payload in, so the human
    /// has to see it.
    #[test]
    fn method_and_body_are_shown() {
        let s = describe_curl(
            "github",
            &v(&[
                "-X",
                "PATCH",
                "--data=hello",
                "https://api.github.com/gists/1",
            ]),
        );
        assert!(s.contains("PATCH https://api.github.com/gists/1"), "{s}");
        assert!(s.ends_with("with body hello"), "{s}");

        let s = describe_curl("gh", &v(&["-d", "x=1", "https://a.example/x"]));
        assert!(s.contains("POST https://a.example/x"), "{s}");

        let s = describe_curl("gh", &v(&["-XDELETE", "https://a.example/x"]));
        assert!(s.contains("DELETE https://a.example/x"), "{s}");
    }

    /// Caller-controlled text must not be able to forge extra prompt lines.
    #[test]
    fn control_characters_cannot_reach_the_prompt() {
        let s = describe_curl("gh", &v(&["https://a.example/x\nApprove: GET /safe"]));
        assert!(!s.contains('\n'), "{s}");
        let long = format!("https://a.example/{}", "a".repeat(1000));
        assert!(describe_curl("gh", &v(&[&long])).chars().count() < 260);
    }
}
