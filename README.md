# patman

Store personal access tokens in `$HOME/.pat/`, locked to your user. Token values
live in `$HOME/.pat/<service>`; metadata (description, username, pinned hosts)
lives in `$HOME/.pat/manifest.json` and holds no secrets. No command ever prints
a token value.

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

## License

MIT — see [LICENSE](LICENSE).
