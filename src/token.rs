//! Reading and writing token values.
//!
//! Every function here treats the value as write-only with respect to the
//! outside world: it can reach a file, a child process's stdin, or a child
//! process's environment, and nowhere else. Nothing in this module prints a
//! token, includes one in an error message, or returns one to a code path that
//! formats output.

use std::io::{IsTerminal, Read, Write};
use std::path::Path;

use crate::error::{Context, Result, bail};
use crate::{sealed, secure};

/// Wrapper that makes a token hard to leak by accident: its `Debug` is redacted,
/// so it cannot show up via `{:?}` in a log line or a panic message, and it has
/// no `Display` at all.
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Best-effort zeroing on drop. Rust may have moved the `String`'s buffer during
/// its lifetime, so this is a reduction in exposure, not a guarantee.
impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: overwriting UTF-8 with ASCII spaces keeps the string valid.
        unsafe {
            self.0.as_mut_vec().fill(0);
        }
    }
}

/// Read a token, sealed or plaintext.
///
/// The format is detected from the file's own bytes rather than from a config
/// flag, so a half-migrated directory behaves correctly file by file. Passing a
/// key for a plaintext file is fine — that is the state during `vault seal` —
/// but a sealed file with no key is a hard error rather than a fallback, since
/// the only alternative would be feeding ciphertext to curl as a Bearer token.
pub fn read(service: &str, key: Option<&sealed::Key>) -> Result<Secret> {
    let path = crate::paths::token_path(service)?;
    let raw = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return bail(format!(
                "no token file for {service:?} (expected at {}). Run: patman save {service}",
                path.display()
            ));
        }
        Err(e) => return bail(format!("reading token file for {service:?}: {e}")),
    };

    let bytes = if sealed::is_sealed(&raw) {
        let Some(key) = key else {
            return bail(format!(
                "the token for {service:?} is sealed and the vault is locked.\n\n\
                 Unlocking needs your passphrase, which an agent's tool call cannot \
                 supply.\n\n\
                 Run it yourself — in Claude Code prefix it with `!`:\n\
                 \x20   !patman unlock"
            ));
        };
        sealed::open(key, service, &raw)?
    } else {
        raw
    };

    let text = String::from_utf8(bytes).map_err(|_| {
        crate::error::Error(format!(
            "the token for {service:?} is not valid UTF-8 — refusing to use it"
        ))
    })?;
    validated(service, &text)
}

/// The checks every token value passes on the way out of a file, whichever
/// format it was stored in.
fn validated(service: &str, text: &str) -> Result<Secret> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return bail(format!(
            "the token file for {service:?} is empty — it was saved wrong or truncated. \
             Re-run: patman save {service}"
        ));
    }
    // A control character inside a token is never legitimate, and an embedded
    // newline would let the value inject extra lines into curl's line-oriented
    // config. Enforced on read as well as on save, so a file edited out of
    // band gets the same treatment.
    if trimmed.chars().any(char::is_control) {
        return bail(format!(
            "the token file for {service:?} contains control characters (an embedded \
             newline or similar) — refusing to use it. Re-run: patman save {service}"
        ));
    }
    Ok(Secret(trimmed.to_string()))
}

pub fn exists(service: &str) -> bool {
    crate::paths::token_path(service)
        .map(|p| p.is_file())
        .unwrap_or(false)
}

/// Is this service's token file sealed? Reads only the magic prefix — it needs
/// no key and discloses nothing, so `doctor` and `vault seal` can call it freely.
pub fn is_sealed(service: &str) -> bool {
    let Ok(path) = crate::paths::token_path(service) else {
        return false;
    };
    let Ok(mut f) = std::fs::File::open(&path) else {
        return false;
    };
    let mut head = [0u8; 8];
    match f.read_exact(&mut head) {
        Ok(()) => sealed::is_sealed(&head),
        Err(_) => false,
    }
}

/// Where a token value is allowed to come from.
pub enum Source {
    /// Prompt on the terminal with echo disabled.
    Tty,
    /// Read stdin to EOF — for piping out of a password manager
    /// (`op read ... | patman save github --stdin`).
    Stdin,
}

/// Obtain a token value, refusing anything empty or whitespace-only.
///
/// That guard is load-bearing. Without it a failed read silently produces a
/// zero-byte credential file and still reports success, which then gets recorded
/// in the manifest as a working token and surfaces days later as an unexplained
/// 401.
pub fn prompt(service: &str, source: Source) -> Result<Secret> {
    let value = match source {
        Source::Stdin => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .ctx("reading token from stdin")?;
            buf
        }
        Source::Tty => {
            if !std::io::stdin().is_terminal() {
                return bail(format!(
                    "refusing to read a token without a terminal.\n\n\
                     Secret entry is yours to run, not an agent's: masked input needs a real \
                     interactive session, and anything a tool call prints lands in the \
                     transcript.\n\n\
                     Run it yourself — in Claude Code prefix it with `!`:\n\
                     \x20   !patman save {service}\n\n\
                     To pipe from a password manager instead, pass --stdin explicitly."
                ));
            }
            rpassword::prompt_password(format!("Paste the {service} token (input hidden): "))
                .ctx("reading token from the terminal")?
        }
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return bail("empty token — nothing written");
    }
    if trimmed.chars().any(char::is_control) {
        return bail(
            "the token contains control characters (an embedded newline or tab) — \
             nothing written. Real tokens are a single line; check what was pasted \
             or piped in.",
        );
    }
    Ok(Secret(trimmed.to_string()))
}

/// Write the token, owner-only, with no trailing newline — sealed when a key is
/// supplied, plaintext when it is not.
///
/// A trailing newline is the classic cause of a token that looks right in the
/// file but fails auth, since it ends up inside the header value. Sealing makes
/// that moot for the stored bytes but not for the value itself, which is why the
/// trim happens at `prompt` time rather than here.
pub fn write(
    service: &str,
    secret: &Secret,
    key: Option<&sealed::Key>,
) -> Result<std::path::PathBuf> {
    let path = crate::paths::token_path(service)?;
    let plaintext = secret.expose().as_bytes();
    match key {
        Some(key) => secure::write_private_atomic(&path, &sealed::seal(key, service, plaintext)?)?,
        None => secure::write_private_atomic(&path, plaintext)?,
    }
    Ok(path)
}

/// Hand a token to a child process on its stdin. Used by `patman curl` so the
/// value never appears in argv, where any other user on the machine could read
/// it out of the process table for the duration of the request.
pub fn feed_stdin(child: &mut std::process::Child, data: &str) -> Result<()> {
    let mut sink = child
        .stdin
        .take()
        .ok_or_else(|| crate::error::Error("child process has no stdin".into()))?;
    sink.write_all(data.as_bytes())
        .ctx("passing credentials to the child process")?;
    drop(sink); // EOF, or the child waits forever
    Ok(())
}

pub fn remove(service: &str) -> Result<bool> {
    let path = crate::paths::token_path(service)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => bail(format!("removing {}: {e}", path.display())),
    }
}

/// Files directly under `$HOME/.pat/` that are not the manifest — i.e. the
/// token files that actually exist on disk, whatever the manifest claims.
pub fn list_files(dir: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return bail(format!("listing {}: {e}", dir.display())),
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        // Skip patman's own files and any interrupted atomic write. Missing one
        // here would report it as an orphaned token and invite deleting it —
        // which for vault.json would strand every sealed token permanently.
        // (agent.sock needs no entry: it is not a regular file.)
        if name == "manifest.json" || name == "vault.json" || name.starts_with('.') {
            continue;
        }
        out.push(name);
    }
    out.sort();
    Ok(out)
}
