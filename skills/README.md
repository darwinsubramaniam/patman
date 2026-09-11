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

Three routes, in rough order of how permanent the install is.

### 1. Personal (every project on this machine)

```sh
./install-skill.sh                 # symlinks skills/patman -> ~/.claude/skills/patman
./install-skill.sh --copy          # copy instead, if this checkout may move
./install-skill.sh --uninstall
```

A symlink means `git pull` here updates the installed skill. `CLAUDE_CONFIG_DIR` is
honoured if set.

### 2. Project-scoped (checked into a repo, shared with the team)

```sh
./install-skill.sh --project                    # into ./.claude/skills/patman
./install-skill.sh --project ~/code/other-repo  # into another repo
```

Use `--copy` for this one if the result is meant to be committed — a symlink pointing at
someone else's home directory does not travel.

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

## Checking it works

Start a fresh session and run `/doctor`, or just ask for something that needs a token —
"list my open Jira issues". The agent should reach for `patman list` first and then
`patman curl`, and should ask *you* to run `!patman save <service>` if nothing is recorded.
