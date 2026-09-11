# patman

[![CI](https://github.com/darwinsubramaniam/patman/actions/workflows/ci.yml/badge.svg)](https://github.com/darwinsubramaniam/patman/actions/workflows/ci.yml)

Store personal access tokens in `$HOME/.pat/`, locked to your user. Token values
live in `$HOME/.pat/<service>`; metadata (description, username, pinned hosts)
lives in `$HOME/.pat/manifest.json` and holds no secrets. No command ever prints
a token value.

## Install

```sh
cargo install patman
```

Builds from source — needs a Rust toolchain, takes a minute. To skip the compile
and drop in the prebuilt binary for your platform instead:

```sh
cargo binstall patman
```

([cargo-binstall](https://github.com/cargo-bins/cargo-binstall) pulls the release
archive and verifies it; `cargo install cargo-binstall` if you don't have it.)

Note it's `cargo install`, not `cargo add` — `cargo add` writes a dependency into
a project's `Cargo.toml`, and patman is a binary, not a library.

Prebuilt archives are also on the
[latest release](https://github.com/darwinsubramaniam/patman/releases/latest) if
you'd rather not involve cargo — macOS (arm64/x86_64), Linux (arm64/x86_64,
static musl), Windows (x86_64), with checksums in `SHA256SUMS`:

```sh
tar -xzf patman-<version>-aarch64-apple-darwin.tar.gz
sudo install -m 755 patman-<version>-aarch64-apple-darwin/patman /usr/local/bin/
```

From a clone:

```sh
cargo install --path .
```

## Usage

### Save a token

Run it yourself in a real terminal — it prompts with echo off and refuses to run
without a TTY, so a token is never typed into a tool call. In Claude Code, prefix
the command with `!`.

```sh
patman save github -d "personal account, repo + read:org scopes" -u darwin
# Paste the github token (input hidden):  <- nothing echoes
```

- `-d/--description` — what it's for; required for a new service.
- `-u/--username` — account id used for Basic auth (an email for Atlassian Cloud,
  a corporate ID for most self-hosted servers). Skip it for Bearer-only APIs.
- `--host api.github.com` — pin where the token may be sent. Recommended.
- `--stdin` — read the token from a pipe instead: `op read ... | patman save github --stdin`.

Saving an existing service replaces the token and keeps the description
(`patman rotate github` is the same thing).

See what you have with `patman list`, `patman lookup github`, or
`patman search jira`.

### Edit the details

`describe` touches metadata only, never the secret:

```sh
patman describe github -d "work account, repo scope only"
patman describe github -u darwin@example.com
patman describe github --clear-username          # Bearer-only service
patman describe github --host api.github.com --host "*.github.com"
patman describe github --clear-hosts             # unpin (token may go anywhere)
```

### Delete a token

Destructive and unconfirmable, so it needs `--yes`:

```sh
patman delete github --yes
```

This removes the local file and manifest entry only — revoke the token at the
issuing service too.

### Using a token

```sh
patman curl jira -- -sS "https://x.atlassian.net/rest/api/3/myself"
patman exec gh -- sh -c 'GH_TOKEN=$PAT_TOKEN gh pr list'
```

`patman curl` passes the token to curl over stdin, never in argv. Housekeeping
lives in `patman doctor`, `patman orphans`, and `patman fix-perms`.

## Dev

Rust 2024 edition, toolchain 1.98.1+. A devcontainer is checked in — open the
repo in it and everything is ready.

```sh
cargo build            # debug build at target/debug/patman
cargo test             # unit tests
cargo clippy --all-targets
cargo fmt
cargo run -- list      # run a subcommand from the working tree
```

Source layout: `main.rs` defines the clap CLI, `cmds.rs` holds every command
implementation, and the rest is one concern each — `token.rs` (read/write/prompt),
`manifest.rs` (metadata), `paths.rs` (path validation), `secure.rs` (permissions),
`guard.rs` (host pinning and curl-arg vetting), `error.rs`.

The Claude Code skill lives in `skills/patman/`. Install it into a harness with:

```sh
./install-skill.sh              # ~/.claude/skills/patman (symlink)
./install-skill.sh --project    # ./.claude/skills/patman
./install-skill.sh --uninstall
```

### Releasing

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

## License

MIT — see [LICENSE](LICENSE).
