# The patman skill

`skills/patman/SKILL.md` teaches a coding agent to authenticate API calls through the
`patman` CLI instead of handling token values. It loads itself when a task needs a
personal access token — a GitHub/Jira/GitLab call, a 401, or the user mentioning a PAT —
and it encodes the rules the CLI enforces: never read a token file, never pass `-v` to
`patman curl`, never run `patman save` on the user's behalf.

The skill assumes the `patman` binary is on `PATH`:

```sh
cargo install --path .     # from a checkout of this repo
```

## Installing it

### 1. `patman init` (the normal route)

The skill is compiled into the binary, so `patman init` installs the copy matching the
CLI into every harness it detects:

| `--agent` | Read by | Personal | Project (`--project [DIR]`) |
|---|---|---|---|
| `claude` | Claude Code | `~/.claude/skills/patman` (`$CLAUDE_CONFIG_DIR` honoured) | `DIR/.claude/skills/patman` |
| `agents` | Codex, Gemini CLI, GitHub Copilot, Cursor, OpenCode | `~/.agents/skills/patman` | `DIR/.agents/skills/patman` |

`.agents/skills` is the open-standard location most harnesses now share, so patman
writes there rather than into each tool's own directory (`~/.gemini/skills`,
`~/.cursor/skills`, ...). Extra copies would only show up twice in tools that scan
several directories. Cursor and OpenCode read `~/.claude/skills` as well, so they may
list the skill twice already.

```sh
patman init                          # each directory a harness found here reads
patman init --agent gemini           # only .agents (tool names alias it; repeatable)
patman init --project ~/code/repo    # both, into a repo, to commit
```

A harness counts as found when its config directory (`~/.claude`, `~/.codex`,
`~/.gemini`, `~/.copilot`, `~/.cursor`, `~/.config/opencode`) exists, its env var
(`CLAUDE_CONFIG_DIR`, `CODEX_HOME`) is set, or its binary is on `PATH`. Re-run after
upgrading patman; `patman doctor` reports a stale copy.

### 2. Symlink from a checkout (while editing the skill)

```sh
./install-skill.sh                 # symlinks skills/patman -> ~/.claude/skills/patman
./install-skill.sh --uninstall
```

A symlink means edits here take effect without a rebuild. `patman init` sees the link
and leaves it alone.

### 3. As a plugin (`/plugin`, kept up to date by Claude Code)

This repo is also a single-plugin marketplace (`.claude-plugin/`). Once it is pushed to a
git host:

```
/plugin marketplace add <owner>/<repo>
/plugin install patman@patman
```

A local clone works too: `/plugin marketplace add /path/to/patman`.

Add a `"repository"` field to `.claude-plugin/plugin.json` once the repo has a canonical
URL.

## The guard

`patman init` also registers a guard with each harness it finds, so a tool call that
reads, lists, or writes `~/.pat/` is refused before it runs, whatever the skill says. The
[guide](../docs/guide.md#the-guard) lists the file each harness gets. `--no-guard` skips
it, `patman init --remove` undoes both, and `--project` installs the skill only: a
committed hook would make every teammate's harness depend on having patman.

## Checking it works

Start a fresh session and run `/doctor`, or just ask for something that needs a token —
"list my open Jira issues". The agent should reach for `patman list` first and then
`patman curl`, and should ask *you* to run `patman save <service>` in a terminal if nothing is recorded.
