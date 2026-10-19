//! Command implementations. Everything the skill used to spell out as two
//! parallel shell dialects lives here once.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::error::{Context, Result, bail};
use crate::guard;
use crate::manifest::{Approval, Entry, Manifest, today};
use crate::paths;
use crate::policy;
use crate::sealed;
use crate::secure;
use crate::token;
use crate::usage;
use crate::vault;

#[cfg(unix)]
use crate::agent;

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
            let missing = if token::exists(name) {
                ""
            } else {
                "  [FILE MISSING]"
            };
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
        return bail(format!(
            "no PAT recorded for {service:?} (try: patman list)"
        ));
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
    if entry.allow_exec {
        println!("exec:        allowed");
    }
    if vault::is_sealed_install() {
        println!(
            "approval:    {}{}",
            match entry.approval {
                Approval::Session => "session (an open unlock session is enough)",
                Approval::Request => "request (every use is approved on its own)",
            },
            if entry.policy_seal.is_some() {
                ""
            } else {
                "  [POLICY NOT SIGNED — patman describe --sign]"
            }
        );
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
        "allow_exec": e.allow_exec,
        "approval": e.approval,
        "policy_signed": e.policy_seal.is_some(),
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
            ));
        }
    };

    // Passphrase before the token, so a mistyped passphrase is discovered before
    // the user has pasted a credential rather than after. Note this does not use
    // a running agent: the agent protocol has no message that writes a token,
    // deliberately, so `save` always asks the human directly.
    let key = if vault::is_sealed_install() {
        let v = vault::load()?;
        let pass = vault::prompt_passphrase("Vault passphrase (input hidden): ")?;
        Some(vault::unlock(&v, &pass)?)
    } else {
        None
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
    let path = token::write(service, &secret, key.as_ref())?;
    let bytes = secret.len();
    drop(secret);

    let hosts = if hosts.is_empty() {
        existing
            .as_ref()
            .map(|p| p.hosts.clone())
            .unwrap_or_default()
    } else {
        hosts
    };
    let pinned = !hosts.is_empty();

    let mut entry = Entry {
        description,
        allow_exec: existing.as_ref().map(|p| p.allow_exec).unwrap_or(false),
        approval: existing.as_ref().map(|p| p.approval).unwrap_or_default(),
        policy_seal: None,
        username: username.or_else(|| existing.as_ref().and_then(|p| p.username.clone())),
        hosts,
        updated: today(),
        extra: existing.map(|p| p.extra).unwrap_or_default(),
    };
    // The passphrase was just typed, so whatever policy this save leaves in
    // place is signed — including any hosts or username it changed.
    if let Some(key) = &key {
        policy::sign(key, service, &mut entry)?;
    }
    manifest.entries.insert(service.to_string(), entry);
    manifest.save(&ctx.manifest_path)?;

    println!(
        "Saved {} ({bytes} bytes) and recorded it in the manifest.",
        path.display()
    );
    if !pinned {
        println!(
            "Tip: pin the API host so this token can only be sent there:\n\
             \x20 patman describe {service} --host api.example.com"
        );
    }
    Ok(())
}

/// The edits `describe` can make. Every field is "leave it alone" by default, so
/// adding a new piece of metadata does not mean touching every call site.
#[derive(Default)]
pub struct Edits {
    pub description: Option<String>,
    pub username: Option<String>,
    pub clear_username: bool,
    pub hosts: Vec<String>,
    pub clear_hosts: bool,
    /// `None` leaves the flag as it is; `Some` sets it.
    pub allow_exec: Option<bool>,
    pub approval: Option<Approval>,
    /// Re-sign the policy as it stands, after a hand edit or for an entry
    /// written before the vault existed.
    pub sign: bool,
}

pub fn describe(ctx: &Ctx, service: &str, edits: Edits) -> Result<()> {
    let Edits {
        description,
        username,
        clear_username,
        hosts,
        clear_hosts,
        allow_exec,
        approval,
        sign,
    } = edits;

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
        existing
            .as_ref()
            .map(|p| p.hosts.clone())
            .unwrap_or_default()
    } else {
        hosts
    };

    let mut entry = Entry {
        description,
        allow_exec: allow_exec
            .unwrap_or_else(|| existing.as_ref().map(|p| p.allow_exec).unwrap_or(false)),
        approval: approval
            .unwrap_or_else(|| existing.as_ref().map(|p| p.approval).unwrap_or_default()),
        policy_seal: existing.as_ref().and_then(|p| p.policy_seal.clone()),
        username,
        hosts,
        // Metadata-only edit: `updated` tracks the token value, so an entry
        // whose description was reworded must not look freshly rotated.
        updated: existing
            .as_ref()
            .map(|p| p.updated.clone())
            .unwrap_or_else(today),
        extra: existing
            .as_ref()
            .map(|p| p.extra.clone())
            .unwrap_or_default(),
    };

    // Under a sealed vault, changing the policy is a human act: it takes the
    // passphrase, the same as unlocking. Otherwise anything that can run
    // `patman describe` could switch a service from `request` to `session`, or
    // add a host, and the unlock agent would obey. A description-only edit
    // keeps the existing seal and asks for nothing.
    let mut signed = false;
    if vault::is_sealed_install() {
        let changed = existing
            .as_ref()
            .is_none_or(|prev| !policy::same(service, prev, &entry));
        if sign || changed || entry.policy_seal.is_none() {
            let key = passphrase_for_policy(service)?;
            policy::sign(&key, service, &mut entry)?;
            signed = true;
        }
    } else {
        if approval.is_some() || sign {
            return bail(
                "approval modes and policy signing only apply to a sealed vault — \
                 run: patman vault init",
            );
        }
        entry.policy_seal = None;
    }

    manifest.entries.insert(service.to_string(), entry);
    manifest.save(&ctx.manifest_path)?;
    println!(
        "Updated manifest entry for {service}.{}",
        if signed { " Policy signed." } else { "" }
    );
    Ok(())
}

/// The vault key, for signing a policy change. Its refusal is worded for the
/// case that matters: an agent trying to loosen a rule it is bound by.
fn passphrase_for_policy(service: &str) -> Result<sealed::Key> {
    if !vault::has_tty() {
        return bail(format!(
            "changing how {service:?} may be used (hosts, username, exec, approval) \
             needs the vault passphrase under a sealed vault, and there is no terminal \
             to type it on.\n\
             Run it yourself in a terminal window (Claude Code's `!` prefix has no \
             terminal for the passphrase prompt):\n\
             \x20   patman describe {service} ..."
        ));
    }
    let v = vault::load()?;
    let pass =
        vault::prompt_passphrase("Vault passphrase, to sign the policy change (input hidden): ")?;
    vault::unlock(&v, &pass)
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

    std::fs::rename(&src, &dest).ctx(format!("moving {} to {}", src.display(), dest.display()))?;
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
    println!(
        "Locked down {} and {n} token file(s) to the current user.",
        ctx.dir.display()
    );
    Ok(())
}

pub fn doctor(ctx: &Ctx) -> Result<()> {
    println!("directory:  {}", ctx.dir.display());
    println!("cloud sync: not detected (checked before every command)");

    match Manifest::load(&ctx.manifest_path) {
        Ok(m) => println!(
            "manifest:   valid, {} entr{}",
            m.entries.len(),
            if m.entries.len() == 1 { "y" } else { "ies" }
        ),
        Err(e) => println!("manifest:   INVALID — {e}"),
    }

    // Report sealing per file rather than from vault.json alone. A vault with
    // unsealed tokens still under it is exactly the state that looks protected
    // and is not, so it gets named rather than averaged away.
    let files = token::list_files(&ctx.dir)?;
    let plaintext: Vec<&String> = files.iter().filter(|s| !token::is_sealed(s)).collect();

    if !vault::is_sealed_install() {
        println!("vault:      none — token files are plaintext at rest");
        println!("            (patman vault init to encrypt them)");
    } else if plaintext.is_empty() {
        println!(
            "vault:      sealed, all {} token file(s) encrypted",
            files.len()
        );
    } else {
        println!(
            "vault:      MIXED — {} of {} token file(s) are still plaintext:",
            plaintext.len(),
            files.len()
        );
        for s in &plaintext {
            println!("              {s}");
        }
        println!("            Seal them with: patman vault seal");
    }

    #[cfg(unix)]
    if vault::is_sealed_install() {
        if agent::is_running() {
            println!("session:    unlocked (patman status for the remaining time)");
        } else {
            println!("session:    locked");
        }
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

/// Re-exported so `main`'s clap derive keeps its `cmds::Auth` path, while the
/// rules themselves live in `usage` beside the agent that also enforces them.
pub use crate::usage::Auth;

/// The key needed to read this service's token, or `None` when none is.
///
/// Checks the file, not the config: a vault can exist while some tokens are
/// still plaintext (between `vault init` and `vault seal`), and those need no
/// passphrase. Prompting for one anyway would train the habit of typing the
/// vault passphrase at prompts that do not need it.
fn key_for(service: &str) -> Result<Option<sealed::Key>> {
    if !vault::is_sealed_install() || !token::is_sealed(service) {
        return Ok(None);
    }
    let v = vault::load()?;
    let pass = vault::prompt_passphrase("Vault passphrase (input hidden): ")?;
    vault::unlock(&v, &pass).map(Some)
}

/// For a `request` service, collect the passphrase that approves this one call
/// — but only where the unlock agent cannot ask the human itself.
///
/// On macOS the agent raises a Touch ID prompt, so nothing is collected here.
/// Elsewhere the human types the passphrase at this prompt, after being shown
/// what they are approving. With no terminal (an agent's tool call) nothing is
/// sent and the agent refuses, which is the point. This reads the manifest only
/// to decide whether to prompt; the agent re-checks the signed policy and
/// decides for itself.
#[cfg(unix)]
fn approval_passphrase(
    ctx: &Ctx,
    service: &str,
    what: impl FnOnce() -> String,
) -> Result<Option<String>> {
    let manifest = Manifest::load(&ctx.manifest_path)?;
    let needs = manifest
        .get(service)
        .is_some_and(|e| e.approval == Approval::Request);
    let touch_id = cfg!(target_os = "macos") && std::env::var_os("PATMAN_NO_TOUCHID").is_none();
    if !needs || touch_id || !vault::has_tty() {
        return Ok(None);
    }
    eprintln!("patman: {service:?} needs approval for this request:");
    eprintln!("  {}", what());
    vault::prompt_passphrase("Vault passphrase to approve (input hidden): ").map(Some)
}

fn curl_result(code: Option<i32>) -> Result<()> {
    match code {
        Some(0) => Ok(()),
        other => bail(format!(
            "curl exited {}. Do not retry with -v or --trace — they print the \
             Authorization header.",
            other
                .map(|c| c.to_string())
                .unwrap_or_else(|| "by signal".into())
        )),
    }
}

/// Run curl authenticated as `service`.
///
/// Three paths, chosen by what is on disk rather than by a flag:
///
/// 1. **Plaintext install** — read the file and spawn curl here, exactly as
///    before. Sealing is opt-in, so nobody's setup changes until they run
///    `patman vault init`.
/// 2. **Sealed, agent running** — hand the request to the agent, which holds the
///    key. This process never sees the token; it relays output and an exit code.
/// 3. **Sealed, no agent** — prompt for the passphrase, if there is a terminal.
///    That is the human path. Without a terminal it fails with instructions,
///    which is the entire point: an agent-driven call cannot spend a locked
///    credential, and cannot unlock one either.
pub fn curl(ctx: &Ctx, service: &str, auth: Auth, args: &[String]) -> Result<()> {
    paths::validate_service(service)?;

    #[cfg(unix)]
    if vault::is_sealed_install() && agent::is_running() {
        let approval = approval_passphrase(ctx, service, || {
            crate::approve::describe_curl(service, args)
        })?;
        let code = agent::send(&agent::Request::Curl {
            service: service.to_string(),
            auth,
            args: args.to_vec(),
            approval,
        })?;
        return curl_result(Some(code));
    }

    // Locked: the passphrase typed here is itself a per-request approval, so a
    // `request` service needs nothing extra on this path.
    let key = key_for(service)?;
    let manifest = Manifest::load(&ctx.manifest_path)?;
    if let Some(key) = &key {
        policy::verify(key, &manifest, service)?;
    }
    let plan = usage::plan(&manifest, service, auth);

    // Both checks run before the token is read from disk. The flag blocklist is
    // unconditional; the host allowlist applies when the manifest pins hosts.
    if let Some(warning) = usage::authorize_curl(service, args, &plan)? {
        eprintln!("patman: {warning}");
    }

    let secret = token::read(service, key.as_ref())?;
    let config = usage::curl_config(service, &plan, &secret)?;
    drop(secret);

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
    let status = child.wait().ctx("waiting for curl")?;
    curl_result(status.code())
}

/// Run an arbitrary command with the token in its environment.
///
/// Environment is a step down from stdin but a large step up from argv: it is
/// not shown by `ps` to other users, and `/proc/<pid>/environ` is readable only
/// by the owner. Prefer `patman curl` when the tool is curl.
pub fn exec(ctx: &Ctx, service: &str, args: &[String]) -> Result<()> {
    paths::validate_service(service)?;
    let sealed_install = vault::is_sealed_install();

    #[cfg(unix)]
    if sealed_install && agent::is_running() {
        let approval = approval_passphrase(ctx, service, || {
            crate::approve::describe_exec(service, args)
        })?;
        let code = agent::send(&agent::Request::Exec {
            service: service.to_string(),
            args: args.to_vec(),
            approval,
        })?;
        std::process::exit(code);
    }

    let Some((program, rest)) = args.split_first() else {
        return bail("nothing to run — usage: patman exec <service> -- <command> [args...]");
    };

    let manifest = Manifest::load(&ctx.manifest_path)?;
    let plan = usage::plan(&manifest, service, Auth::Auto);
    usage::authorize_exec(service, &plan, sealed_install)?;

    let key = key_for(service)?;
    if let Some(key) = &key {
        policy::verify(key, &manifest, service)?;
    }
    let secret = token::read(service, key.as_ref())?;

    let mut cmd = Command::new(program);
    cmd.args(rest);
    cmd.env("PAT_SERVICE", service);
    cmd.env("PAT_TOKEN", secret.expose());
    if let Some(u) = &plan.username {
        cmd.env("PAT_USERNAME", u);
    }

    let mut child = cmd.spawn().ctx(format!("running {program}"))?;
    drop(secret);

    let status = child.wait().ctx(format!("waiting for {program}"))?;
    std::process::exit(status.code().unwrap_or(1));
}

// ------------------------------------------------------------------ vault

pub fn vault_init(ctx: &Ctx) -> Result<()> {
    if vault::is_sealed_install() {
        return bail(format!(
            "{} already exists — this installation is already sealed.",
            vault::path()?.display()
        ));
    }

    println!(
        "This passphrase encrypts every token file. There is no recovery: lose it \
         and the tokens are gone (rotate them at the provider instead)."
    );
    let pass = vault::prompt_new_passphrase()?;
    let v = vault::create(&pass)?;
    let key = vault::unlock(&v, &pass)?;

    println!("\nCreated {}", vault::path()?.display());
    sign_policies(ctx, &key)?;

    let plaintext: Vec<String> = token::list_files(&ctx.dir)?
        .into_iter()
        .filter(|s| !token::is_sealed(s))
        .collect();

    if plaintext.is_empty() {
        println!("New tokens will be sealed as they are saved.");
    } else {
        println!(
            "\n{} existing token file(s) are still plaintext.\nSeal them with:  patman vault seal",
            plaintext.len()
        );
    }
    Ok(())
}

/// Encrypt every plaintext token file in place.
///
/// Per-file and atomic, so an interruption leaves each token either wholly
/// plaintext or wholly sealed — and `token::read` detects the format per file,
/// so a partly-sealed directory keeps working either way.
pub fn vault_seal(ctx: &Ctx) -> Result<()> {
    let v = vault::load()?;
    let pass = vault::prompt_passphrase("Vault passphrase (input hidden): ")?;
    let key = vault::unlock(&v, &pass)?;

    let mut sealed_count = 0usize;
    let mut already = 0usize;

    for service in token::list_files(&ctx.dir)? {
        if paths::validate_service(&service).is_err() {
            eprintln!("patman: skipping {service:?} — not a valid service name");
            continue;
        }
        if token::is_sealed(&service) {
            already += 1;
            continue;
        }
        let secret = token::read(&service, None)?;
        token::write(&service, &secret, Some(&key))?;
        drop(secret);
        sealed_count += 1;
        println!("sealed {service}");
    }

    println!("\n{sealed_count} sealed, {already} already sealed.");
    sign_policies(ctx, &key)?;
    if sealed_count > 0 {
        println!("Start a session with:  patman unlock");
    }
    Ok(())
}

/// Sign every manifest entry's policy as it stands. Run by `vault init` and
/// `vault seal`, where the human has just typed the passphrase — which makes it
/// their endorsement of the current hosts, exec and approval settings.
fn sign_policies(ctx: &Ctx, key: &sealed::Key) -> Result<()> {
    let mut manifest = Manifest::load(&ctx.manifest_path)?;
    let n = policy::sign_all(key, &mut manifest)?;
    manifest.save(&ctx.manifest_path)?;
    if n > 0 {
        println!(
            "Signed the policy of {n} service(s) as it stands now — review it with \
             `patman list --json` if anything else could have edited the manifest."
        );
    }
    Ok(())
}

#[cfg(unix)]
pub fn unlock(ttl_secs: u64) -> Result<()> {
    if !vault::is_sealed_install() {
        return bail("this installation is not sealed — run: patman vault init");
    }
    if agent::is_running() {
        return bail("already unlocked — see: patman status");
    }
    let v = vault::load()?;
    let pass = vault::prompt_passphrase("Vault passphrase (input hidden): ")?;
    let key = vault::unlock(&v, &pass)?;
    agent::spawn(&key, ttl_secs)?;

    println!(
        "Unlocked for {}m. `patman curl` and `patman exec` will work without a \
         passphrase until it expires.",
        ttl_secs / 60
    );
    println!("Lock early with:  patman lock");
    Ok(())
}

#[cfg(unix)]
pub fn lock() -> Result<()> {
    if !agent::is_running() {
        println!("Already locked.");
        return Ok(());
    }
    agent::send(&agent::Request::Lock)?;
    Ok(())
}

#[cfg(unix)]
pub fn status() -> Result<()> {
    if !vault::is_sealed_install() {
        println!("vault:   none — token files are plaintext (patman vault init to seal)");
        return Ok(());
    }
    if agent::is_running() {
        print!("vault:   ");
        agent::send(&agent::Request::Status)?;
    } else {
        println!("vault:   sealed, locked — run: patman unlock");
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn unlock(_ttl_secs: u64) -> Result<()> {
    bail(
        "unlock sessions are unix-only — they use a unix-domain socket, and the \
         Windows named-pipe equivalent is not implemented.\n\n\
         Sealed tokens still work here: `patman curl` and `patman exec` prompt for \
         the passphrase on every use.\n\n\
         Note that this means an agent cannot use a sealed token on Windows, since \
         a tool call has no console to answer the prompt. If that is what you need, \
         leave the vault unsealed.",
    )
}

#[cfg(not(unix))]
pub fn lock() -> Result<()> {
    bail("the unlock agent is unix-only — there is no session to lock.")
}

#[cfg(not(unix))]
pub fn status() -> Result<()> {
    if vault::is_sealed_install() {
        println!("vault:   sealed (passphrase prompted per use; no agent on Windows)");
    } else {
        println!("vault:   none — token files are plaintext");
    }
    Ok(())
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
