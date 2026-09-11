//! Command implementations. Everything the skill used to spell out as two
//! parallel shell dialects lives here once.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::error::{bail, Context, Result};
use crate::guard;
use crate::manifest::{today, Entry, Manifest};
use crate::paths;
use crate::secure;
use crate::token;

/// A username lands inside the curl config (`user = "name:token"`), so control
/// characters are rejected the same way they are for tokens. It is metadata,
/// not a secret, but it shares the injection-sensitive sink.
fn validate_username(u: &str) -> Result<()> {
    if u.trim().is_empty() {
        return bail("username is empty");
    }
    if u.chars().any(char::is_control) {
        return bail("invalid username: control characters are not allowed");
    }
    Ok(())
}

/// Preflight, run before every command. Idempotent and cheap, so there is no
/// reason to make callers remember it — and no way to forget it.
pub struct Ctx {
    pub dir: PathBuf,
    pub manifest_path: PathBuf,
}

pub fn bootstrap() -> Result<Ctx> {
    let dir = paths::pat_dir()?;
    paths::assert_not_cloud_synced(&dir)?;
    secure::ensure_private_dir(&dir)?;
    let manifest_path = paths::manifest_path()?;
    if !manifest_path.exists() {
        Manifest::default().save(&manifest_path)?;
    }
    Ok(Ctx { dir, manifest_path })
}

pub fn init(ctx: &Ctx) -> Result<()> {
    println!("Ready: {}", ctx.dir.display());
    println!("Manifest: {}", ctx.manifest_path.display());
    println!("\nStore your first token with:  patman save <service> -d \"what it's for\"");
    Ok(())
}

// ---------------------------------------------------------------- read side

pub fn list(ctx: &Ctx, json: bool) -> Result<()> {
    let manifest = Manifest::load(&ctx.manifest_path)?;

    if json {
        let rows: Vec<_> = manifest
            .entries
            .iter()
            .map(|(name, e)| describe_json(&ctx.dir, name, e))
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    if manifest.entries.is_empty() {
        println!("No PATs recorded. Add one with: patman save <service> -d \"...\"");
    } else {
        let mut rows = vec![[
            "SERVICE".to_string(),
            "USERNAME".to_string(),
            "UPDATED".to_string(),
            "DESCRIPTION".to_string(),
        ]];
        for (name, e) in &manifest.entries {
            // A manifest entry whose token file has gone missing is worth
            // flagging inline: it will fail at use time, not at lookup time.
            let missing = if token::exists(name) { "" } else { "  [FILE MISSING]" };
            rows.push([
                name.clone(),
                e.username.clone().unwrap_or_else(|| "-".into()),
                e.updated.clone(),
                format!("{}{}", e.description, missing),
            ]);
        }
        print_table(&rows);
    }

    let undocumented = orphan_list(ctx)?;
    if !undocumented.is_empty() {
        println!(
            "\nUndocumented token files (usable, but no manifest entry): {}",
            undocumented.join(", ")
        );
        println!("Describe one with: patman describe <service> -d \"...\"");
    }
    Ok(())
}

pub fn lookup(ctx: &Ctx, service: &str, json: bool) -> Result<()> {
    paths::validate_service(service)?;
    let manifest = Manifest::load(&ctx.manifest_path)?;

    let Some(entry) = manifest.get(service) else {
        if token::exists(service) {
            return bail(format!(
                "{service:?} has a token file but no manifest entry. \
                 Describe it with: patman describe {service} -d \"...\""
            ));
        }
        return bail(format!("no PAT recorded for {service:?} (try: patman list)"));
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&describe_json(&ctx.dir, service, entry))?
        );
        return Ok(());
    }

    println!("service:     {service}");
    println!("path:        {}", paths::token_path(service)?.display());
    println!("description: {}", entry.description);
    if let Some(u) = &entry.username {
        println!("username:    {u}");
    }
    if entry.hosts.is_empty() {
        println!("hosts:       (none pinned — patman curl will warn; pin with --host)");
    } else {
        println!("hosts:       {}", entry.hosts.join(", "));
    }
    println!("updated:     {}", entry.updated);
    if !token::exists(service) {
        println!("\nWARNING: the token file is missing. Run: patman save {service}");
    }
    Ok(())
}

pub fn search(ctx: &Ctx, keyword: &str) -> Result<()> {
    let manifest = Manifest::load(&ctx.manifest_path)?;
    let needle = keyword.to_lowercase();
    let mut hits = 0;

    for (name, e) in &manifest.entries {
        let haystack = format!(
            "{} {} {}",
            name,
            e.description,
            e.username.as_deref().unwrap_or("")
        )
        .to_lowercase();
        if haystack.contains(&needle) {
            println!("{name}\t{}", e.description);
            hits += 1;
        }
    }
    if hits == 0 {
        println!("No PAT matches {keyword:?}.");
    }
    Ok(())
}

fn describe_json(dir: &std::path::Path, name: &str, e: &Entry) -> serde_json::Value {
    serde_json::json!({
        "service": name,
        "path": dir.join(name).to_string_lossy(),
        "description": e.description,
        "username": e.username,
        "hosts": e.hosts,
        "updated": e.updated,
        "token_file_exists": token::exists(name),
    })
}

// --------------------------------------------------------------- write side

pub fn save(
    ctx: &Ctx,
    service: &str,
    description: Option<String>,
    username: Option<String>,
    hosts: Vec<String>,
    from_stdin: bool,
) -> Result<()> {
    paths::validate_service(service)?;
    if let Some(u) = &username {
        validate_username(u)?;
    }
    for h in &hosts {
        guard::validate_host(h)?;
    }
    let mut manifest = Manifest::load(&ctx.manifest_path)?;
    let existing = manifest.get(service).cloned();

    // A new token with no description is exactly the entry that is useless in
    // three months, so it is required up front rather than nagged about later.
    let description = match (description, &existing) {
        (Some(d), _) => d,
        (None, Some(prev)) => prev.description.clone(),
        (None, None) => {
            return bail(format!(
                "a new PAT needs a description — that's what makes it findable later.\n\
                 Try: patman save {service} -d \"which account/site, which scopes\""
            ))
        }
    };

    let source = if from_stdin {
        token::Source::Stdin
    } else {
        token::Source::Tty
    };
    let secret = token::prompt(service, source)?;

    // Token first, manifest second. If the manifest write fails, the result is
    // an untracked token file — harmless, and surfaced by `patman orphans`.
    // The reverse order would leave a manifest entry pointing at nothing.
    let path = token::write(service, &secret)?;
    let bytes = secret.len();
    drop(secret);

    let hosts = if hosts.is_empty() {
        existing.as_ref().map(|p| p.hosts.clone()).unwrap_or_default()
    } else {
        hosts
    };
    let pinned = !hosts.is_empty();

    manifest.entries.insert(
        service.to_string(),
        Entry {
            description,
            username: username.or_else(|| existing.as_ref().and_then(|p| p.username.clone())),
            hosts,
            updated: today(),
            extra: existing.map(|p| p.extra).unwrap_or_default(),
        },
    );
    manifest.save(&ctx.manifest_path)?;

    println!("Saved {} ({bytes} bytes) and recorded it in the manifest.", path.display());
    if !pinned {
        println!(
            "Tip: pin the API host so this token can only be sent there:\n\
             \x20 patman describe {service} --host api.example.com"
        );
    }
    Ok(())
}

pub fn describe(
    ctx: &Ctx,
    service: &str,
    description: Option<String>,
    username: Option<String>,
    clear_username: bool,
    hosts: Vec<String>,
    clear_hosts: bool,
) -> Result<()> {
    paths::validate_service(service)?;
    if let Some(u) = &username {
        validate_username(u)?;
    }
    for h in &hosts {
        guard::validate_host(h)?;
    }
    let mut manifest = Manifest::load(&ctx.manifest_path)?;
    let existing = manifest.get(service).cloned();

    if existing.is_none() && !token::exists(service) {
        return bail(format!(
            "no token file and no manifest entry for {service:?} — nothing to describe. \
             Store it first: patman save {service} -d \"...\""
        ));
    }

    let description = match (description, &existing) {
        (Some(d), _) => d,
        (None, Some(prev)) => prev.description.clone(),
        (None, None) => return bail("pass -d/--description to describe a new entry"),
    };

    let username = if clear_username {
        None
    } else {
        username.or_else(|| existing.as_ref().and_then(|p| p.username.clone()))
    };

    let hosts = if clear_hosts {
        Vec::new()
    } else if hosts.is_empty() {
        existing.as_ref().map(|p| p.hosts.clone()).unwrap_or_default()
    } else {
        hosts
    };

    manifest.entries.insert(
        service.to_string(),
        Entry {
            description,
            username,
            hosts,
            // Metadata-only edit: `updated` tracks the token value, so an entry
            // whose description was reworded must not look freshly rotated.
            updated: existing
                .as_ref()
                .map(|p| p.updated.clone())
                .unwrap_or_else(today),
            extra: existing.map(|p| p.extra).unwrap_or_default(),
        },
    );
    manifest.save(&ctx.manifest_path)?;
    println!("Updated manifest entry for {service}.");
    Ok(())
}

pub fn delete(ctx: &Ctx, service: &str, assume_yes: bool) -> Result<()> {
    paths::validate_service(service)?;
    let mut manifest = Manifest::load(&ctx.manifest_path)?;
    let known = manifest.get(service).is_some();
    let file = token::exists(service);

    if !known && !file {
        return bail(format!("nothing to delete for {service:?}"));
    }

    if !assume_yes {
        return bail(format!(
            "deleting a PAT is destructive and cannot be undone.\n\
             Confirm with: patman delete {service} --yes\n\
             (Revoke the token at the issuing service too — removing the local \
             file does not invalidate it.)"
        ));
    }

    // Manifest first: a partial failure then leaves an untracked file, which is
    // harmless and detectable, rather than an entry pointing at nothing.
    if known {
        manifest.entries.remove(service);
        manifest.save(&ctx.manifest_path)?;
    }
    let removed = token::remove(service)?;

    println!(
        "Deleted {service} (manifest entry: {}, token file: {}).",
        if known { "removed" } else { "none" },
        if removed { "removed" } else { "none" }
    );
    println!("Remember to revoke it at the issuing service — this only deleted the local copy.");
    Ok(())
}

pub fn migrate(ctx: &Ctx, service: &str, from: Option<PathBuf>) -> Result<()> {
    paths::validate_service(service)?;
    let src = match from {
        Some(p) => p,
        None => paths::home()?.join(format!(".{service}_pat")),
    };
    if !src.is_file() {
        return bail(format!("no file at {}", src.display()));
    }
    let dest = paths::token_path(service)?;
    if dest.exists() {
        return bail(format!(
            "{} already exists — refusing to overwrite an existing token",
            dest.display()
        ));
    }

    std::fs::rename(&src, &dest)
        .ctx(format!("moving {} to {}", src.display(), dest.display()))?;
    secure::lock_down_file(&dest)?;

    println!("Moved {} -> {}", src.display(), dest.display());
    println!(
        "Now describe it:  patman describe {service} -d \"...\"\n\
         (Check nothing else still reads the old path first.)"
    );
    let _ = ctx;
    Ok(())
}

// ------------------------------------------------------------- maintenance

fn orphan_list(ctx: &Ctx) -> Result<Vec<String>> {
    let manifest = Manifest::load(&ctx.manifest_path)?;
    Ok(token::list_files(&ctx.dir)?
        .into_iter()
        .filter(|f| !manifest.entries.contains_key(f))
        .collect())
}

pub fn orphans(ctx: &Ctx) -> Result<()> {
    let undocumented = orphan_list(ctx)?;
    let manifest = Manifest::load(&ctx.manifest_path)?;
    let missing: Vec<_> = manifest
        .entries
        .keys()
        .filter(|s| !token::exists(s))
        .cloned()
        .collect();

    if undocumented.is_empty() && missing.is_empty() {
        println!("Manifest and token files agree.");
        return Ok(());
    }
    if !undocumented.is_empty() {
        println!("Token files with no manifest entry:");
        for f in &undocumented {
            println!("  {f}");
        }
    }
    if !missing.is_empty() {
        println!("Manifest entries with no token file:");
        for f in &missing {
            println!("  {f}");
        }
    }
    Ok(())
}

pub fn fix_perms(ctx: &Ctx) -> Result<()> {
    secure::lock_down_dir(&ctx.dir)?;
    secure::lock_down_file(&ctx.manifest_path)?;
    let mut n = 0;
    for f in token::list_files(&ctx.dir)? {
        secure::lock_down_file(&ctx.dir.join(&f))?;
        n += 1;
    }
    println!("Locked down {} and {n} token file(s) to the current user.", ctx.dir.display());
    Ok(())
}

pub fn doctor(ctx: &Ctx) -> Result<()> {
    println!("directory:  {}", ctx.dir.display());
    println!("cloud sync: not detected (checked before every command)");

    match Manifest::load(&ctx.manifest_path) {
        Ok(m) => println!("manifest:   valid, {} entr{}", m.entries.len(), if m.entries.len() == 1 { "y" } else { "ies" }),
        Err(e) => println!("manifest:   INVALID — {e}"),
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut bad = Vec::new();
        if let Ok(md) = std::fs::metadata(&ctx.dir) {
            let mode = md.permissions().mode() & 0o777;
            if mode != 0o700 {
                bad.push(format!("{} is {mode:o}, want 700", ctx.dir.display()));
            }
        }
        for f in token::list_files(&ctx.dir)? {
            let p = ctx.dir.join(&f);
            if let Ok(md) = std::fs::metadata(&p) {
                let mode = md.permissions().mode() & 0o777;
                if mode != 0o600 {
                    bad.push(format!("{f} is {mode:o}, want 600"));
                }
            }
        }
        if bad.is_empty() {
            println!("perms:      owner-only");
        } else {
            println!("perms:      NEEDS REPAIR (run: patman fix-perms)");
            for b in bad {
                println!("              {b}");
            }
        }
    }

    println!();
    orphans(ctx)
}

// ------------------------------------------------------------------ usage

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Auth {
    /// `Authorization: Bearer <token>`
    Bearer,
    /// `Authorization: Basic base64(username:token)` — needs a manifest username.
    Basic,
    /// Basic when the manifest records a username, Bearer otherwise.
    Auto,
}

/// Run curl with the token supplied over its stdin via `--config -`.
///
/// The secret never enters argv. A secret in a command-line argument is visible
/// in the process table for the duration of the request — `ps -o args=` on the
/// curl PID would print the `Authorization` header verbatim, readable by any
/// other user on the machine.
pub fn curl(ctx: &Ctx, service: &str, auth: Auth, args: &[String]) -> Result<()> {
    let manifest = Manifest::load(&ctx.manifest_path)?;
    let entry = manifest.get(service);
    let username = entry.and_then(|e| e.username.clone());
    let hosts = entry.map(|e| e.hosts.clone()).unwrap_or_default();

    let mode = match auth {
        Auth::Auto if username.is_some() => Auth::Basic,
        Auth::Auto => Auth::Bearer,
        other => other,
    };

    // Both checks run before the token is even read from disk. The flag
    // blocklist is unconditional; the host allowlist applies when the manifest
    // pins hosts for this service.
    guard::vet_args(args, matches!(mode, Auth::Bearer))?;
    if hosts.is_empty() {
        eprintln!(
            "patman: warning: no hosts pinned for {service:?} — the token will be sent \
             to whatever URL curl is given.\n\
             patman: pin the API host with: patman describe {service} --host api.example.com"
        );
    } else {
        guard::enforce_hosts(service, args, &hosts)?;
    }

    let secret = token::read(service)?;
    // With pinned hosts, restrict curl itself to https. This is what stops a
    // schemeless stowaway URL (which curl would guess as http) from slipping
    // past the argument scan: curl refuses the protocol before connecting.
    let proto_line = if hosts.is_empty() { "" } else { "proto = \"=https\"\n" };
    let auth_line = match mode {
        Auth::Basic => {
            let Some(user) = username else {
                return bail(format!(
                    "Basic auth needs an account identifier, and the manifest has none for \
                     {service:?}.\nSet it with: patman describe {service} --username <id>"
                ));
            };
            format!(
                "user = \"{}:{}\"\n",
                escape(&user),
                escape(secret.expose())
            )
        }
        _ => format!(
            "header = \"Authorization: Bearer {}\"\n",
            escape(secret.expose())
        ),
    };
    let config = format!("{proto_line}{auth_line}");

    // `--config -` is the only curl option that reads settings from stdin, which
    // is what keeps argv clean.
    let mut child = Command::new("curl")
        .arg("--config")
        .arg("-")
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .ctx("running curl (is it installed and on PATH?)")?;

    token::feed_stdin(&mut child, &config)?;
    drop(secret);

    let status = child.wait().ctx("waiting for curl")?;
    if !status.success() {
        // Deliberately terse. Do not re-run with -v/--trace on failure: those
        // echo the Authorization header straight into the transcript.
        return bail(format!(
            "curl exited {}. Do not retry with -v or --trace — they print the \
             Authorization header.",
            status.code().map(|c| c.to_string()).unwrap_or_else(|| "by signal".into())
        ));
    }
    Ok(())
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

/// Run an arbitrary command with the token in its environment.
///
/// Environment is a step down from stdin but a large step up from argv: it is
/// not shown by `ps` to other users, and `/proc/<pid>/environ` is readable only
/// by the owner. Prefer `patman curl` when the tool is curl.
pub fn exec(ctx: &Ctx, service: &str, args: &[String]) -> Result<()> {
    let Some((program, rest)) = args.split_first() else {
        return bail("nothing to run — usage: patman exec <service> -- <command> [args...]");
    };

    let manifest = Manifest::load(&ctx.manifest_path)?;
    let username = manifest.get(service).and_then(|e| e.username.clone());
    let secret = token::read(service)?;

    let mut cmd = Command::new(program);
    cmd.args(rest);
    cmd.env("PAT_SERVICE", service);
    cmd.env("PAT_TOKEN", secret.expose());
    if let Some(u) = &username {
        cmd.env("PAT_USERNAME", u);
    }

    let mut child = cmd.spawn().ctx(format!("running {program}"))?;
    drop(secret);

    let status = child.wait().ctx(format!("waiting for {program}"))?;
    std::process::exit(status.code().unwrap_or(1));
}

// ------------------------------------------------------------------ output

fn print_table(rows: &[[String; 4]]) {
    let mut widths = [0usize; 4];
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    for row in rows {
        let mut line = String::new();
        for (i, cell) in row.iter().enumerate() {
            if i == row.len() - 1 {
                line.push_str(cell);
            } else {
                line.push_str(&format!("{:w$}  ", cell, w = widths[i]));
            }
        }
        println!("{}", line.trim_end());
    }
}

#[cfg(test)]
mod tests {
    use super::escape;

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
        assert!(!escaped.contains('\n'), "no raw newline may survive: {escaped:?}");
        assert_eq!(escaped, "x\\\"\\nurl = \\\"https://evil.com\\\"");
    }
}
