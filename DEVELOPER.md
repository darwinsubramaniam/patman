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
(host pinning and curl-arg vetting), `error.rs`.

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

## The Claude Code skill

The skill lives in `skills/patman/`. Install it into a harness with:

```sh
./install-skill.sh              # ~/.claude/skills/patman (symlink)
./install-skill.sh --project    # ./.claude/skills/patman
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

`[package.metadata.binstall]` in `Cargo.toml` maps `cargo binstall` onto those
release archives — if the archive naming in the release workflow changes, that
block has to change with it.
