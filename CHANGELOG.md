# Changelog

All notable changes to patman. Generated from commit messages by git-cliff.

## [1.1.0] - 2026-10-24

### Features

- Prototype sealed token files and unlock sessions
- Enhance documentation for sealed vault and unlock sessions
- Hybrid approval per service, and signed policies
- Stamp the version with a build number
- Add `patman tui`, a terminal UI for editing and maintenance
- `patman init` installs the skill and a ~/.pat guard into AI harnesses
- `patman update` installs the latest signed release

### Bug fixes

- Make the sealed vault work on Windows
- Send passphrase prompts to a terminal window, not Claude Code's `!`

### Documentation

- Explain what patman is for, move dev notes out
- Rewrite the README as a short guide, move the reference to docs/guide.md
- Use Jira and GitLab, not GitHub, in the README and guide examples

## [1.0.0] - 2026-09-11

### Features

- Introduce patman for managing personal access tokens

