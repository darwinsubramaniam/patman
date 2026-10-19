//! Installing the patman skill into AI coding harnesses.
//!
//! The skill is compiled into the binary, so `patman init` installs the copy
//! that matches the CLI it describes — no checkout of this repo needed, and a
//! `cargo install` upgrade followed by `patman init` brings the skill along.

use std::path::{Path, PathBuf};

use crate::error::{Context, Result};
use crate::harness::Harness;
use crate::paths;

/// The skill text, embedded at build time. Listed in `Cargo.toml`'s `include`
/// so a published crate still builds.
pub const SKILL_MD: &str = include_str!("../skills/patman/SKILL.md");

/// A skills directory to install into. Not one per tool: most harnesses now
/// read the open-standard `.agents/skills`, so two directories cover them all,
/// and writing more would only show the same skill twice in tools that scan
/// several (Cursor and OpenCode read both of these already).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Target {
    /// Claude Code: ~/.claude/skills (or $CLAUDE_CONFIG_DIR/skills), .claude/skills in a repo.
    Claude,
    /// The shared ~/.agents/skills (.agents/skills in a repo), read by Codex,
    /// Gemini CLI, GitHub Copilot, Cursor, and OpenCode.
    #[value(
        alias = "codex",
        alias = "gemini",
        alias = "copilot",
        alias = "cursor",
        alias = "opencode"
    )]
    Agents,
}

pub const ALL: [Target; 2] = [Target::Claude, Target::Agents];

impl Target {
    pub fn label(self) -> &'static str {
        match self {
            Target::Claude => "Claude Code",
            Target::Agents => ".agents",
        }
    }

    /// The harnesses that read this target.
    pub fn harnesses(self) -> &'static [Harness] {
        match self {
            Target::Claude => &[Harness::Claude],
            Target::Agents => &[
                Harness::Codex,
                Harness::Gemini,
                Harness::Copilot,
                Harness::Cursor,
                Harness::Opencode,
            ],
        }
    }

    /// Where the skill goes: the user's own skills directory, or a repo's.
    pub fn skills_dir(self, project: Option<&Path>) -> Result<PathBuf> {
        Ok(match (self, project) {
            (Target::Claude, Some(root)) => root.join(".claude").join("skills"),
            (Target::Agents, Some(root)) => root.join(".agents").join("skills"),
            (Target::Claude, None) => Harness::Claude.config_dir()?.join("skills"),
            (Target::Agents, None) => paths::home()?.join(".agents").join("skills"),
        })
    }

    /// The harnesses reading this target that look installed for this user.
    pub fn found(self) -> Vec<&'static str> {
        self.harnesses()
            .iter()
            .filter(|h| h.detected())
            .map(|h| h.label())
            .collect()
    }

    /// Every harness this target serves, found or not.
    pub fn serves(self) -> Vec<&'static str> {
        self.harnesses().iter().map(|h| h.label()).collect()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Installed,
    Updated,
    UpToDate,
    /// A symlink, as `install-skill.sh` makes for a dev checkout. Left alone:
    /// it already tracks the source, and replacing it would break that.
    Linked(PathBuf),
}

/// What `doctor` reports for one skill location.
#[derive(Debug, PartialEq, Eq)]
pub enum State {
    Missing,
    Current,
    Stale,
    Linked(PathBuf),
}

/// Write the embedded skill to `<skills_dir>/patman/SKILL.md`.
pub fn install(skills_dir: &Path) -> Result<Outcome> {
    let dest = skills_dir.join("patman");
    let outcome = match state(skills_dir) {
        State::Linked(target) => return Ok(Outcome::Linked(target)),
        State::Current => return Ok(Outcome::UpToDate),
        State::Stale => Outcome::Updated,
        State::Missing => Outcome::Installed,
    };

    std::fs::create_dir_all(&dest).ctx(format!("creating {}", dest.display()))?;
    // Temp file then rename, so a harness starting up mid-write never loads a
    // truncated skill.
    let file = dest.join("SKILL.md");
    let tmp = dest.join(".SKILL.md.tmp");
    std::fs::write(&tmp, SKILL_MD).ctx(format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &file).ctx(format!("writing {}", file.display()))?;
    Ok(outcome)
}

pub enum Removed {
    Yes,
    Linked,
    Absent,
}

/// Remove `<skills_dir>/patman`. A symlink is a dev install from
/// `install-skill.sh`, which owns removing it.
pub fn remove(skills_dir: &Path) -> Result<Removed> {
    let dest = skills_dir.join("patman");
    Ok(match state(skills_dir) {
        State::Linked(_) => Removed::Linked,
        State::Missing if !dest.exists() => Removed::Absent,
        _ => {
            std::fs::remove_dir_all(&dest).ctx(format!("removing {}", dest.display()))?;
            Removed::Yes
        }
    })
}

pub fn state(skills_dir: &Path) -> State {
    let dest = skills_dir.join("patman");
    if let Ok(target) = std::fs::read_link(&dest) {
        return State::Linked(target);
    }
    match std::fs::read_to_string(dest.join("SKILL.md")) {
        Ok(s) if s == SKILL_MD => State::Current,
        Ok(_) => State::Stale,
        Err(_) => State::Missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("patman-skill-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn install_then_up_to_date_then_update() {
        let d = scratch("cycle");
        assert_eq!(state(&d), State::Missing);
        assert_eq!(install(&d).unwrap(), Outcome::Installed);
        assert_eq!(state(&d), State::Current);
        assert_eq!(install(&d).unwrap(), Outcome::UpToDate);

        std::fs::write(d.join("patman/SKILL.md"), "old").unwrap();
        assert_eq!(state(&d), State::Stale);
        assert_eq!(install(&d).unwrap(), Outcome::Updated);
        assert_eq!(
            std::fs::read_to_string(d.join("patman/SKILL.md")).unwrap(),
            SKILL_MD
        );
        assert!(!d.join("patman/.SKILL.md.tmp").exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_install_is_left_alone() {
        let d = scratch("link");
        let src = d.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("SKILL.md"), "dev copy").unwrap();
        let skills = d.join("skills");
        std::fs::create_dir_all(&skills).unwrap();
        std::os::unix::fs::symlink(&src, skills.join("patman")).unwrap();

        assert_eq!(install(&skills).unwrap(), Outcome::Linked(src.clone()));
        assert_eq!(
            std::fs::read_to_string(src.join("SKILL.md")).unwrap(),
            "dev copy"
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn project_dirs_are_per_target() {
        let root = Path::new("/repo");
        assert_eq!(
            Target::Claude.skills_dir(Some(root)).unwrap(),
            root.join(".claude/skills")
        );
        assert_eq!(
            Target::Agents.skills_dir(Some(root)).unwrap(),
            root.join(".agents/skills")
        );
    }

    #[test]
    fn tool_names_are_accepted_as_the_agents_target() {
        use clap::ValueEnum;
        for name in ["agents", "codex", "gemini", "copilot", "cursor", "opencode"] {
            assert_eq!(
                Target::from_str(name, false).unwrap(),
                Target::Agents,
                "{name}"
            );
        }
        assert_eq!(Target::from_str("claude", false).unwrap(), Target::Claude);
    }
}
