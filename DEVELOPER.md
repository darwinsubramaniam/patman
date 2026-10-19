# Developing patman

Rust 2024 edition, toolchain 1.98.1+. A devcontainer is checked in — open the
repo in it and everything is ready.

```sh
cargo build            # debug build at target/debug/patman
cargo test             # unit tests
cargo clippy --all-targets
cargo fmt
cargo run -- list      # run a subcommand from the working tree
```

## Source layout

`main.rs` defines the clap CLI, `cmds.rs` holds every command implementation,
and the rest is one concern each — `token.rs` (read/write/prompt), `manifest.rs`
(metadata), `paths.rs` (path validation), `secure.rs` (permissions), `guard.rs`
(host pinning and curl-arg vetting), `error.rs`. `tui.rs` is the `patman tui`
front end (behind the default `tui` feature): it only collects arguments and
calls the same `cmds` functions, suspending itself for any prompt.

The invariant the code exists to enforce is stated at the top of `main.rs`: a
token value moves from the terminal into a file, and from that file into a
request, and nowhere else. Two places carry most of the weight:

- `guard.rs` — the curl flag blocklist (`vet_args`) and the host allowlist
  (`enforce_hosts`). Both run *before* the token is read from disk, and both are
  covered by tests for the tricks they exist to stop: userinfo disguises,
  wildcard-vs-apex, suffix lookalikes, a second smuggled URL, short-option
  bundles hiding a `-v`.
- `secure.rs` — owner-only creation and atomic replacement, so a token file is
  never world-readable for even an instant.

Anything that would give a token value a path to stdout is a bug, not a missing
feature. There is deliberately no `patman show`.

## The agent skill

The skill lives in `skills/patman/SKILL.md` and is compiled into the binary
(`src/skill.rs`, via `include_str!`), so `patman init` installs the copy that matches
the CLI into `~/.claude/skills/` (Claude Code) and `~/.agents/skills/` (Codex, Gemini
CLI, Copilot, Cursor, OpenCode). Harness detection is `src/harness.rs`.

`init` also registers the `~/.pat` guard: `src/guardrail.rs` merges it into each
harness's config, and `src/hook.rs` is `patman hook <harness>`, the check those configs
run before every tool call. Try the hook by piping it a tool call:

```sh
echo '{"tool_name":"Bash","tool_input":{"command":"cat ~/.pat/x"}}' | patman hook claude
``` Edit
the file, rebuild, re-run `patman init`.

While iterating on the skill, a symlink saves the rebuild — `patman init` leaves a
symlinked install alone:

```sh
./install-skill.sh              # ~/.claude/skills/patman -> skills/patman
./install-skill.sh --uninstall
```

## Releasing

CI (`.github/workflows/ci.yml`) builds and tests on Linux, macOS, and Windows for
every push and PR, and gates on `cargo fmt` + `cargo clippy -D warnings`.

Tagging cuts a release:

```sh
# bump version in Cargo.toml, commit, then:
git tag v1.0.1 && git push origin v1.0.1
```

`.github/workflows/release.yml` builds five targets (macOS arm64/x86_64, Linux
arm64/x86_64 static musl, Windows x86_64), publishes them with `SHA256SUMS` on a
GitHub release, then pushes the crate to crates.io.

The crates.io step needs a `CARGO_REGISTRY_TOKEN` secret on this repo
(`cargo login` token from <https://crates.io/settings/tokens>, scoped to
publish-update; `gh secret set CARGO_REGISTRY_TOKEN`). Without it that job logs a
skip and the GitHub release still happens. It also no-ops if the version is
already on crates.io, so re-running a release is safe.

### Version and build number

`build.rs` stamps the version with a build number — the commit count of `HEAD`.
The count orders builds but is not unique across branches, so dev builds carry
the commit hash as well, and `.dirty` when uncommitted changes were compiled in:

| Build | `patman -V` | `patman --version` |
|---|---|---|
| Local / any non-release build | `1.0.0-dev:42+fc2256d` | same |
| …with uncommitted changes | `1.0.0-dev:42+fc2256d.dirty` | same |
| Release workflow (`PATMAN_RELEASE=1`) | `1.0.0:42` | `1.0.0:42 (fc2256d)` |
| crates.io source (no git history) | `1.0.0` | `1.0.0` |

The release workflow checks out with `fetch-depth: 0`; a shallow clone would
count one commit and report every release as build 1.

`[package.metadata.binstall]` in `Cargo.toml` maps `cargo binstall` onto those
release archives — if the archive naming in the release workflow changes, that
block has to change with it.
