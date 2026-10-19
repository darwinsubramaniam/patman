//! The AI coding harnesses patman knows how to set up, and how to tell which
//! of them this user has.

use std::path::PathBuf;

use crate::error::Result;
use crate::paths;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Harness {
    Claude,
    Codex,
    Gemini,
    Copilot,
    Cursor,
    Opencode,
}

pub const ALL: [Harness; 6] = [
    Harness::Claude,
    Harness::Codex,
    Harness::Gemini,
    Harness::Copilot,
    Harness::Cursor,
    Harness::Opencode,
];

impl Harness {
    pub fn label(self) -> &'static str {
        match self {
            Harness::Claude => "Claude Code",
            Harness::Codex => "Codex",
            Harness::Gemini => "Gemini CLI",
            Harness::Copilot => "Copilot",
            Harness::Cursor => "Cursor",
            Harness::Opencode => "OpenCode",
        }
    }

    /// The harness's own config directory, honouring its env override.
    pub fn config_dir(self) -> Result<PathBuf> {
        let (var, default) = match self {
            Harness::Claude => (Some("CLAUDE_CONFIG_DIR"), ".claude"),
            Harness::Codex => (Some("CODEX_HOME"), ".codex"),
            Harness::Gemini => (None, ".gemini"),
            Harness::Copilot => (Some("COPILOT_HOME"), ".copilot"),
            Harness::Cursor => (None, ".cursor"),
            Harness::Opencode => (None, ".config/opencode"),
        };
        if let Some(d) = var.and_then(std::env::var_os).filter(|d| !d.is_empty()) {
            return Ok(PathBuf::from(d));
        }
        Ok(paths::home()?.join(default))
    }

    /// Whether this harness looks installed: its env override is set, its
    /// marker exists, or its binary is on PATH.
    pub fn detected(self) -> bool {
        let Ok(dir) = self.config_dir() else {
            return false;
        };
        let (env, marker, bins): (Option<&str>, PathBuf, &[&str]) = match self {
            Harness::Claude => (Some("CLAUDE_CONFIG_DIR"), dir, &["claude"]),
            Harness::Codex => (Some("CODEX_HOME"), dir, &["codex"]),
            // Not the directory alone: Google's Antigravity also creates
            // ~/.gemini, without Gemini CLI being installed.
            Harness::Gemini => (None, dir.join("settings.json"), &["gemini"]),
            Harness::Copilot => (Some("COPILOT_HOME"), dir, &["copilot"]),
            Harness::Cursor => (None, dir, &["cursor", "cursor-agent"]),
            Harness::Opencode => (None, dir, &["opencode"]),
        };
        env.is_some_and(|v| std::env::var_os(v).is_some())
            || marker.exists()
            || bins.iter().any(|b| on_path(b).is_some())
    }
}

/// The first `bin` on PATH, if any.
pub fn on_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let p = dir.join(bin);
        if p.is_file() {
            return Some(p);
        }
        let exe = p.with_extension("exe");
        (cfg!(windows) && exe.is_file()).then_some(exe)
    })
}
