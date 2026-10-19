//! Registering the `~/.pat` guard with each harness's own config.
//!
//! Every edit is a merge into a file the user owns: other settings are kept in
//! their order, re-running changes nothing, and a file that does not parse as
//! JSON is left untouched rather than rewritten. The previous version of any
//! file patman changes is kept beside it as `<name>.patman-backup`.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::error::{Context, Result};
use crate::harness::{self, Harness};

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Changed,
    Unchanged,
    /// Not valid JSON (JSONC with comments, say). Left as it was.
    Unparseable,
}

pub enum State {
    Installed,
    Missing,
    Unparseable,
}

/// The file each harness reads the guard from.
pub fn config_file(h: Harness) -> Result<PathBuf> {
    let dir = h.config_dir()?;
    Ok(match h {
        Harness::Claude => dir.join("settings.json"),
        Harness::Codex => dir.join("hooks.json"),
        Harness::Gemini => dir.join("settings.json"),
        // Copilot loads every *.json in its hooks directory, so patman gets a
        // file of its own and never edits one it did not write.
        Harness::Copilot => dir.join("hooks").join("patman.json"),
        Harness::Cursor => dir.join("hooks.json"),
        Harness::Opencode => {
            let jsonc = dir.join("opencode.jsonc");
            if jsonc.exists() {
                jsonc
            } else {
                dir.join("opencode.json")
            }
        }
    })
}

pub fn install(h: Harness) -> Result<Outcome> {
    let cmd = hook_command(h);
    edit(h, |root| apply(h, root, Some(&cmd)))
}

pub fn remove(h: Harness) -> Result<Outcome> {
    if h == Harness::Copilot {
        let f = config_file(h)?;
        if !f.exists() {
            return Ok(Outcome::Unchanged);
        }
        std::fs::remove_file(&f).ctx(format!("removing {}", f.display()))?;
        return Ok(Outcome::Changed);
    }
    edit(h, |root| apply(h, root, None))
}

pub fn state(h: Harness) -> Result<State> {
    let Some(mut root) = load(&config_file(h)?)? else {
        return Ok(State::Unparseable);
    };
    let before = root.clone();
    apply(h, &mut root, Some(&hook_command(h)));
    Ok(if root == before {
        State::Installed
    } else {
        State::Missing
    })
}

/// `None` when the file exists but is not JSON. A missing file is `{}`.
fn load(file: &Path) -> Result<Option<Value>> {
    match std::fs::read_to_string(file) {
        Ok(s) if s.trim().is_empty() => Ok(Some(json!({}))),
        Ok(s) => Ok(serde_json::from_str::<Value>(&s)
            .ok()
            .filter(Value::is_object)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Some(json!({}))),
        Err(e) => Err(e).ctx(format!("reading {}", file.display())),
    }
}

fn edit(h: Harness, f: impl FnOnce(&mut Value)) -> Result<Outcome> {
    let file = config_file(h)?;
    let Some(mut root) = load(&file)? else {
        return Ok(Outcome::Unparseable);
    };
    let before = root.clone();
    f(&mut root);
    if root == before {
        return Ok(Outcome::Unchanged);
    }

    let dir = file.parent().expect("config files live in a directory");
    std::fs::create_dir_all(dir).ctx(format!("creating {}", dir.display()))?;
    let name = file.file_name().unwrap().to_string_lossy();
    let original = std::fs::metadata(&file).ok();
    if original.is_some() {
        let backup = dir.join(format!("{name}.patman-backup"));
        std::fs::copy(&file, &backup).ctx(format!("backing up to {}", backup.display()))?;
    }
    let tmp = dir.join(format!(".{name}.patman-tmp"));
    let mut text = serde_json::to_string_pretty(&root)?;
    text.push('\n');
    std::fs::write(&tmp, text).ctx(format!("writing {}", tmp.display()))?;
    // Keep the original's mode: some of these files hold credentials of their
    // own and are owner-only for that reason.
    if let Some(md) = original {
        std::fs::set_permissions(&tmp, md.permissions())
            .ctx(format!("writing {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, &file).ctx(format!("writing {}", file.display()))?;
    Ok(Outcome::Changed)
}

/// Add the guard (`cmd` is `Some`) or take it out (`None`).
fn apply(h: Harness, root: &mut Value, cmd: Option<&str>) {
    let tag = format!("hook {}", hook_name(h));
    let ours = |s: &str| s.contains("patman") && s.trim_end().ends_with(&tag);
    match h {
        Harness::Claude => {
            // Built-in deny rules cover Claude's own file tools (Read, Edit,
            // Grep, Glob, @-mentions); the hook covers shell commands.
            for rule in ["Read(~/.pat/**)", "Edit(~/.pat/**)"] {
                set_in_list(root, &["permissions", "deny"], json!(rule), cmd.is_some());
            }
            let group = cmd.map(|c| json!({ "matcher": "Bash|PowerShell", "hooks": [{ "type": "command", "command": c }] }));
            set_group(root, "PreToolUse", group, &ours);
        }
        Harness::Codex => {
            let group = cmd.map(|c| json!({ "hooks": [{ "type": "command", "command": c, "statusMessage": "patman guard" }] }));
            set_group(root, "PreToolUse", group, &ours);
        }
        Harness::Gemini => {
            let group = cmd.map(|c| json!({ "hooks": [{ "name": "patman-guard", "type": "command", "command": c, "timeout": 5000 }] }));
            set_group(root, "BeforeTool", group, &ours);
        }
        Harness::Copilot => {
            if let Some(c) = cmd {
                *root = json!({
                    "version": 1,
                    "hooks": { "preToolUse": [copilot_entry(c)] }
                });
            }
        }
        Harness::Cursor => {
            if cmd.is_some() && root.get("version").is_none() {
                root.as_object_mut()
                    .unwrap()
                    .insert("version".into(), json!(1));
            }
            // preToolUse sees Shell/Read/Write/Grep/Delete calls; beforeReadFile
            // also sees files attached as context.
            for event in ["preToolUse", "beforeReadFile"] {
                let list = list_at(root, &["hooks", event], cmd.is_some());
                if let Some(list) = list {
                    list.retain(|e| !e.get("command").and_then(Value::as_str).is_some_and(ours));
                    if let Some(c) = cmd {
                        list.push(json!({ "command": c }));
                    }
                }
                prune(root, &["hooks", event]);
            }
            prune(root, &["hooks"]);
        }
        Harness::Opencode => {
            // OpenCode has native permission rules, so no hook process at all.
            // Rules are last-match-wins, so ours go at the end.
            let rules: &[(&str, &[&str])] = &[
                ("read", &["~/.pat", "~/.pat/**"]),
                ("edit", &["~/.pat", "~/.pat/**"]),
                ("external_directory", &["~/.pat", "~/.pat/**"]),
                ("bash", &["*/.pat", "*/.pat/*", "*/.pat *"]),
            ];
            let perm = root.as_object_mut().unwrap();
            if cmd.is_none() && !perm.contains_key("permission") {
                return;
            }
            let perm = perm.entry("permission").or_insert_with(|| json!({}));
            if let Value::String(s) = perm {
                *perm = json!({ "*": s.clone() });
            }
            let Some(perm) = perm.as_object_mut() else {
                return;
            };
            for (tool, patterns) in rules {
                if cmd.is_none() && !perm.contains_key(*tool) {
                    continue;
                }
                let entry = perm.entry(*tool).or_insert_with(|| json!({}));
                if let Value::String(s) = entry {
                    *entry = json!({ "*": s.clone() });
                }
                let Some(map) = entry.as_object_mut() else {
                    continue;
                };
                for p in *patterns {
                    map.shift_remove(*p);
                    if cmd.is_some() {
                        map.insert((*p).into(), json!("deny"));
                    }
                }
                if map.is_empty() {
                    perm.shift_remove(*tool);
                }
            }
            if perm.is_empty() {
                root.as_object_mut().unwrap().shift_remove("permission");
            }
        }
    }
}

fn copilot_entry(cmd: &str) -> Value {
    // Copilot denies the tool call when a preToolUse command fails, so a
    // missing patman binary would block everything. Check for it first.
    let (bin, rest) = cmd.split_once(" hook ").unwrap();
    json!({
        "type": "command",
        "bash": format!("command -v {bin} >/dev/null 2>&1 || exit 0; {cmd}"),
        "powershell": format!("if (Get-Command {bin} -ErrorAction SilentlyContinue) {{ & {bin} hook {rest} }}"),
        "timeoutSec": 10
    })
}

/// Replace patman's matcher group under `hooks.<event>`, keeping everyone else's.
fn set_group(root: &mut Value, event: &str, group: Option<Value>, ours: &dyn Fn(&str) -> bool) {
    if let Some(list) = list_at(root, &["hooks", event], group.is_some()) {
        for g in list.iter_mut() {
            if let Some(hooks) = g.get_mut("hooks").and_then(Value::as_array_mut) {
                hooks.retain(|h| !h.get("command").and_then(Value::as_str).is_some_and(ours));
            }
        }
        list.retain(|g| {
            g.get("hooks")
                .and_then(Value::as_array)
                .is_none_or(|h| !h.is_empty())
        });
        if let Some(g) = group {
            list.push(g);
        }
    }
    prune(root, &["hooks", event]);
    prune(root, &["hooks"]);
}

fn set_in_list(root: &mut Value, path: &[&str], item: Value, present: bool) {
    if let Some(list) = list_at(root, path, present) {
        if present {
            if !list.contains(&item) {
                list.push(item);
            }
        } else {
            list.retain(|v| v != &item);
        }
    }
    prune(root, path);
    prune(root, &path[..path.len() - 1]);
}

/// The array at `path`, created along the way when `create` is set.
fn list_at<'a>(root: &'a mut Value, path: &[&str], create: bool) -> Option<&'a mut Vec<Value>> {
    let mut v = root;
    for (i, key) in path.iter().enumerate() {
        let map: &mut Map<String, Value> = v.as_object_mut()?;
        if !map.contains_key(*key) {
            if !create {
                return None;
            }
            let fresh = if i + 1 == path.len() {
                json!([])
            } else {
                json!({})
            };
            map.insert((*key).into(), fresh);
        }
        v = map.get_mut(*key)?;
    }
    v.as_array_mut()
}

/// Drop an empty array or object at `path` that removing patman's entry left.
fn prune(root: &mut Value, path: &[&str]) {
    let Some((last, parents)) = path.split_last() else {
        return;
    };
    let mut v = &mut *root;
    for key in parents {
        match v.get_mut(*key) {
            Some(next) => v = next,
            None => return,
        }
    }
    let Some(map) = v.as_object_mut() else { return };
    let empty = match map.get(*last) {
        Some(Value::Array(a)) => a.is_empty(),
        Some(Value::Object(o)) => o.is_empty(),
        _ => false,
    };
    if empty {
        map.shift_remove(*last);
    }
}

/// The `patman hook <name>` argument; must match `Harness`'s clap value names.
fn hook_name(h: Harness) -> &'static str {
    match h {
        Harness::Claude => "claude",
        Harness::Codex => "codex",
        Harness::Gemini => "gemini",
        Harness::Copilot => "copilot",
        Harness::Cursor => "cursor",
        Harness::Opencode => "opencode",
    }
}

/// How a harness should invoke patman: plain `patman` when that is what PATH
/// finds (so a reinstall elsewhere, or a Homebrew upgrade that moves the
/// Cellar path, keeps working), the absolute path to this binary otherwise.
fn hook_command(h: Harness) -> String {
    let me = std::env::current_exe().and_then(std::fs::canonicalize).ok();
    let found = harness::on_path("patman").and_then(|p| std::fs::canonicalize(p).ok());
    let bin = match (&me, &found) {
        (Some(a), Some(b)) if a == b => "patman".to_string(),
        (Some(a), _) => shell_quote(&a.to_string_lossy()),
        _ => "patman".to_string(),
    };
    format!("{bin} hook {}", hook_name(h))
}

fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-+:\\".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMD: &str = "patman hook claude";

    #[test]
    fn claude_merge_keeps_other_settings_and_is_idempotent() {
        let mut root = json!({
            "model": "opus",
            "permissions": { "allow": ["Bash(ls)"], "deny": ["Read(./.env)"] },
            "hooks": { "PreToolUse": [{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "other" }] }] }
        });
        apply(Harness::Claude, &mut root, Some(CMD));
        let once = root.clone();
        apply(Harness::Claude, &mut root, Some(CMD));
        assert_eq!(root, once);

        assert_eq!(root["model"], "opus");
        let deny = root["permissions"]["deny"].as_array().unwrap();
        assert!(deny.contains(&json!("Read(./.env)")) && deny.contains(&json!("Read(~/.pat/**)")));
        let groups = root["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["hooks"][0]["command"], "other");

        apply(Harness::Claude, &mut root, None);
        assert_eq!(
            root,
            json!({
                "model": "opus",
                "permissions": { "allow": ["Bash(ls)"], "deny": ["Read(./.env)"] },
                "hooks": { "PreToolUse": [{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "other" }] }] }
            })
        );
    }

    #[test]
    fn a_moved_binary_replaces_the_old_hook() {
        let mut root = json!({});
        apply(Harness::Codex, &mut root, Some("/old/patman hook codex"));
        apply(Harness::Codex, &mut root, Some("patman hook codex"));
        let groups = root["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["hooks"][0]["command"], "patman hook codex");
    }

    #[test]
    fn removal_from_an_empty_file_changes_nothing() {
        for h in [
            Harness::Claude,
            Harness::Codex,
            Harness::Gemini,
            Harness::Cursor,
            Harness::Opencode,
        ] {
            let mut root = json!({});
            apply(h, &mut root, None);
            assert_eq!(root, json!({}), "{h:?}");
        }
    }

    #[test]
    fn cursor_round_trip() {
        let mut root =
            json!({ "version": 1, "hooks": { "afterFileEdit": [{ "command": "fmt" }] } });
        apply(Harness::Cursor, &mut root, Some("patman hook cursor"));
        assert_eq!(
            root["hooks"]["preToolUse"][0]["command"],
            "patman hook cursor"
        );
        assert_eq!(
            root["hooks"]["beforeReadFile"][0]["command"],
            "patman hook cursor"
        );
        apply(Harness::Cursor, &mut root, None);
        assert_eq!(
            root,
            json!({ "version": 1, "hooks": { "afterFileEdit": [{ "command": "fmt" }] } })
        );
    }

    #[test]
    fn opencode_rules_go_last_and_come_out_cleanly() {
        let mut root = json!({ "permission": { "bash": "allow", "read": { "*.env": "deny", "~/.pat/**": "allow" } } });
        apply(Harness::Opencode, &mut root, Some(""));
        let bash = root["permission"]["bash"].as_object().unwrap();
        assert_eq!(bash.keys().next().unwrap(), "*");
        let read = root["permission"]["read"].as_object().unwrap();
        assert_eq!(read.keys().next_back().unwrap(), "~/.pat/**");
        assert_eq!(read["~/.pat/**"], "deny");

        apply(Harness::Opencode, &mut root, None);
        assert_eq!(
            root,
            json!({ "permission": { "bash": { "*": "allow" }, "read": { "*.env": "deny" } } })
        );
    }

    #[test]
    fn hook_names_match_the_cli() {
        use clap::ValueEnum;
        for h in harness::ALL {
            assert_eq!(h.to_possible_value().unwrap().get_name(), hook_name(h));
        }
    }

    #[test]
    fn copilot_hook_tolerates_a_missing_binary() {
        let e = copilot_entry("patman hook copilot");
        assert!(e["bash"].as_str().unwrap().starts_with("command -v patman"));
        assert!(
            e["powershell"]
                .as_str()
                .unwrap()
                .contains("Get-Command patman")
        );
    }
}
