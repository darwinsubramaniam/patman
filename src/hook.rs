//! `patman hook <harness>`: the pre-tool-use guard each AI harness runs before
//! a tool call, refusing any call that reads, writes, or lists `~/.pat/`.
//!
//! This is a guardrail, not a boundary. It matches paths in the call's
//! arguments and in shell command text, so it stops an agent that is careless
//! or casually prompt-injected; a command built to dodge the match (`cd ~;
//! cat .p''at/x`) gets through. Sealing the vault is what makes a read useless.
//!
//! The hook never fails closed on its own account: input it cannot parse is
//! allowed, because a guard that blocks every call when a harness changes its
//! input shape gets uninstalled, and then guards nothing.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde_json::{Value, json};

use crate::harness::Harness;
use crate::paths;

/// Argument keys that name a path, across the harnesses' tool schemas.
const PATH_KEYS: &[&str] = &[
    "file_path",
    "filePath",
    "path",
    "paths",
    "absolute_path",
    "dir_path",
    "directory",
    "notebook_path",
    "target_file",
    "file",
    "files",
    "include",
];

/// Argument keys that hold shell command text.
const COMMAND_KEYS: &[&str] = &["command", "cmd", "script"];

const REASON: &str = "patman guard: this touches ~/.pat/, where token files live. \
Agents never read, list, or write it. Use `patman list --json` or \
`patman lookup <service> --json` for metadata, `patman curl <service> ...` to make \
an authenticated request, and ask the user to run `patman save <service>` in a \
terminal to store a token.";

pub fn run(harness: Harness) {
    let mut input = String::new();
    let denied = std::io::stdin().read_to_string(&mut input).is_ok()
        && serde_json::from_str::<Value>(&input).is_ok_and(|v| touches_vault(&v));
    respond(harness, denied);
}

fn respond(harness: Harness, denied: bool) {
    let out = match (harness, denied) {
        // Cursor treats missing or invalid output from a permission hook as a
        // block, so it always gets an explicit answer.
        (Harness::Cursor, false) => json!({ "permission": "allow" }),
        (_, false) => return,
        (Harness::Claude | Harness::Codex, true) => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": REASON,
            }
        }),
        (Harness::Gemini, true) => json!({ "decision": "deny", "reason": REASON }),
        (Harness::Copilot, true) => json!({
            "permissionDecision": "deny",
            "permissionDecisionReason": REASON,
        }),
        (Harness::Cursor, true) => json!({
            "permission": "deny",
            "user_message": "Blocked by patman: the agent tried to access ~/.pat/.",
            "agent_message": REASON,
        }),
        // OpenCode is guarded by its own permission rules, not this hook.
        (Harness::Opencode, true) => return,
    };
    println!("{out}");
}

/// Whether a tool call, as any supported harness describes it, reaches `~/.pat`.
pub fn touches_vault(input: &Value) -> bool {
    let Ok(home) = paths::home() else {
        return false;
    };
    let cwd = find_cwd(input).unwrap_or_else(|| home.clone());
    let vault = normalize(&home.join(".pat"));
    let mut hit = false;
    walk(input, None, &mut |key, s| {
        hit |= if COMMAND_KEYS.contains(&key) {
            command_touches(s, &home, &cwd, &vault)
        } else {
            path_touches(s, &home, &cwd, &vault)
        };
    });
    hit
}

fn find_cwd(input: &Value) -> Option<PathBuf> {
    let get = |v: &Value| {
        v.get("cwd")
            .or_else(|| v.get("working_directory"))?
            .as_str()
            .map(PathBuf::from)
    };
    get(input).or_else(|| input.get("tool_input").and_then(get))
}

/// Visit every string under a path or command key. A string that is itself a
/// JSON object (Copilot's `toolArgs`, Cursor's MCP `tool_input`) is descended
/// into too. File contents, transcripts, and prompts are never scanned: text
/// that merely mentions `~/.pat/` must not block, e.g. editing patman's README.
fn walk(v: &Value, key: Option<&str>, f: &mut dyn FnMut(&str, &str)) {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                walk(child, Some(k), f);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(item, key, f);
            }
        }
        Value::String(s) => {
            let t = s.trim_start();
            if t.starts_with('{')
                && let Ok(inner) = serde_json::from_str::<Value>(t)
            {
                walk(&inner, key, f);
                return;
            }
            if let Some(k) = key.filter(|k| PATH_KEYS.contains(k) || COMMAND_KEYS.contains(k)) {
                f(k, s);
            }
        }
        _ => {}
    }
}

fn path_touches(s: &str, home: &Path, cwd: &Path, vault: &Path) -> bool {
    let p = expand(s.trim(), home, cwd);
    if within(&normalize(&p), vault) {
        return true;
    }
    // A symlink elsewhere that points into the vault.
    std::fs::canonicalize(&p).is_ok_and(|real| {
        within(&real, vault) || std::fs::canonicalize(vault).is_ok_and(|v| within(&real, &v))
    })
}

/// Look for path-like words in command text that resolve into the vault. A
/// Codex `apply_patch` "command" is a patch, so only its file headers count.
fn command_touches(cmd: &str, home: &Path, cwd: &Path, vault: &Path) -> bool {
    if cmd.trim_start().starts_with("*** Begin Patch") {
        return cmd.lines().any(|l| {
            [
                "*** Add File:",
                "*** Update File:",
                "*** Delete File:",
                "*** Move to:",
            ]
            .iter()
            .any(|h| {
                l.strip_prefix(h)
                    .is_some_and(|p| path_touches(p, home, cwd, vault))
            })
        });
    }
    // ASCII-only folding keeps byte offsets identical to `cmd`'s.
    let lower = if cfg!(any(target_os = "macos", windows)) {
        cmd.to_ascii_lowercase()
    } else {
        cmd.to_string()
    };
    let bytes = lower.as_bytes();
    let mut from = 0;
    while let Some(i) = lower[from..].find(".pat").map(|i| i + from) {
        from = i + 4;
        // `.patch`, `.pattern`, `x.pat2`: a different name.
        if bytes
            .get(i + 4)
            .is_some_and(|&c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
        {
            continue;
        }
        let start = lower[..i]
            .rfind(|c: char| c.is_whitespace() || "=;|&()<>`,".contains(c))
            .map_or(0, |j| j + 1);
        let end = lower[i..]
            .find(|c: char| c.is_whitespace() || ";|&()<>`,".contains(c))
            .map_or(lower.len(), |j| i + j);
        let word: String = cmd[start..end]
            .chars()
            .filter(|c| !"'\"".contains(*c))
            .collect();
        if path_touches(&word, home, cwd, vault) {
            return true;
        }
    }
    false
}

/// Expand the home-directory spellings a shell or an agent would use, then
/// resolve a relative path against the tool call's working directory.
fn expand(s: &str, home: &Path, cwd: &Path) -> PathBuf {
    let s = s.replace('\\', "/");
    let h = home.to_string_lossy().replace('\\', "/");
    let lower = s.to_ascii_lowercase();
    for prefix in ["~", "$home", "${home}", "%userprofile%", "$env:userprofile"] {
        if lower == prefix || lower.starts_with(&format!("{prefix}/")) {
            return PathBuf::from(format!("{h}{}", &s[prefix.len()..]));
        }
    }
    let p = PathBuf::from(&s);
    if p.is_absolute() || s.starts_with('/') {
        p
    } else {
        cwd.join(p)
    }
}

/// Lexically resolve `.` and `..`, and case-fold where the filesystem usually
/// does (macOS, Windows), so `~/.PAT/x` and `~/a/../.pat` both match.
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    PathBuf::from(fold(&out.to_string_lossy().replace('\\', "/")))
}

fn fold(s: &str) -> String {
    if cfg!(any(target_os = "macos", windows)) {
        s.to_lowercase()
    } else {
        s.to_string()
    }
}

fn within(p: &Path, vault: &Path) -> bool {
    p.starts_with(vault)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> PathBuf {
        paths::home().unwrap()
    }

    fn bash(cmd: &str) -> Value {
        json!({ "cwd": "/repo", "tool_name": "Bash", "tool_input": { "command": cmd } })
    }

    #[test]
    fn blocks_shell_access_in_every_home_spelling() {
        let h = home().display().to_string();
        for cmd in [
            "cat ~/.pat/github",
            "cat $HOME/.pat/github",
            "cat \"$HOME\"/.pat/github",
            "cat ${HOME}/.pat/jira | head",
            &format!("cat {h}/.pat/x"),
            "ls ~/.pat",
            "ls -la ~/.pat/",
            "TOKEN=$(cat ~/.pat/jira); curl -H \"Authorization: Bearer $TOKEN\" x",
            "cp ~/.pat/github /tmp/x",
            "cat ~/a/../.pat/github",
        ] {
            assert!(touches_vault(&bash(cmd)), "{cmd}");
        }
    }

    #[test]
    fn leaves_patman_and_lookalikes_alone() {
        for cmd in [
            "patman curl github https://api.github.com/user",
            "patman list --json",
            "git apply fix.patch",
            "cat ~/.patterns",
            "cat ~/.pat2/x",
            "cat /repo/.pat/x",
            "grep -rn '~/.pat' src",
        ] {
            // The last one names the vault only as a search string. It is a
            // known false positive the guard accepts: the word is a vault path.
            let want = cmd.starts_with("grep");
            assert_eq!(touches_vault(&bash(cmd)), want, "{cmd}");
        }
    }

    #[test]
    fn relative_paths_resolve_against_cwd() {
        let h = home().display().to_string();
        let v = json!({ "cwd": h, "tool_input": { "command": "cat .pat/github" } });
        assert!(touches_vault(&v));
    }

    #[test]
    fn blocks_file_tools_across_harness_schemas() {
        let h = home().display().to_string();
        for v in [
            json!({ "tool_name": "Read", "tool_input": { "file_path": format!("{h}/.pat/github") } }),
            json!({ "tool_name": "read_file", "tool_input": { "absolute_path": "~/.pat/github" } }),
            json!({ "tool_name": "read_many_files", "tool_input": { "paths": ["README.md", "~/.pat/x"] } }),
            json!({ "toolName": "view", "toolArgs": "{\"path\":\"~/.pat/github\"}" }),
            json!({ "file_path": format!("{h}/.pat/github"), "content": "secret" }),
            json!({ "tool_name": "Read", "tool_input": { "file_path": "~/.pat/manifest.json" } }),
        ] {
            assert!(touches_vault(&v), "{v}");
        }
    }

    #[test]
    fn content_that_mentions_the_vault_is_not_a_path() {
        let v = json!({
            "tool_name": "Write",
            "tool_input": { "file_path": "/repo/README.md", "content": "tokens live in ~/.pat/" }
        });
        assert!(!touches_vault(&v));
    }

    #[test]
    fn apply_patch_counts_only_file_headers() {
        let h = home().display().to_string();
        let doc =
            "*** Begin Patch\n*** Update File: /repo/README.md\n+see ~/.pat/github\n*** End Patch";
        assert!(!touches_vault(&bash(doc)));
        let bad = format!("*** Begin Patch\n*** Add File: {h}/.pat/x\n+t\n*** End Patch");
        assert!(touches_vault(&bash(&bad)));
    }

    #[test]
    fn unparseable_or_unrelated_input_is_allowed() {
        assert!(!touches_vault(
            &json!({ "tool_name": "Bash", "tool_input": { "command": "ls" } })
        ));
        assert!(!touches_vault(&json!(42)));
    }
}
