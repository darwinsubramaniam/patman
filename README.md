# patman

[![CI](https://github.com/darwinsubramaniam/patman/actions/workflows/ci.yml/badge.svg)](https://github.com/darwinsubramaniam/patman/actions/workflows/ci.yml)

**What it is for: holding the personal access tokens and passwords you need to
hand to an AI coding agent — so it can reach GitHub, Jira, GitLab, Confluence or
your internal APIs on your behalf, without the secret ever passing through the
model, the transcript, or the process table.**

You tell the agent *which* credential to use. It never learns *what* the
credential is.

Token values live in `$HOME/.pat/<service>`, locked to your user; metadata
(description, username, pinned hosts) lives in `$HOME/.pat/manifest.json` and
holds no secrets, so the agent can look up what exists without opening anything
sensitive. No command ever prints a token value.

## Why patman exists

The situation it is built for: you are working with an agent in your terminal and
the task needs a credential. *Create the Jira ticket. List the open PRs. Call the
internal API.* The agent cannot do any of it without a token — and every obvious
way of giving it one hands over the secret itself, permanently, to a transcript
you no longer control.

So patman is not another answer to *where do I store a secret*. Encrypted stores
already answer that well. It answers the part they leave open: **how a secret
gets used without leaking into the places secrets actually leak.**

Every general-purpose secret store ends its happy path the same way — `pass
show`, `op read`, `security find-generic-password -w`, `vault kv get` — printing
the secret to stdout and handing you the problem back. That was tolerable when a
human read stdout. It is not tolerable when an AI agent, a CI log, or a shell
history file reads it.

### The problem

1. **Transcript disclosure.** The moment an agent runs `cat ~/.pat/github` or
   `TOKEN=$(cat ...)`, the value is in the session history, in every summary made
   of that history, and in anything the user later shares. Rotation is the only
   remedy.
2. **argv disclosure.** `curl -H "Authorization: Bearer $T"` puts the token in
   the process table, readable by any other process on the machine, and in shell
   history.
3. **No binding between a credential and a destination.** A GitHub token will
   authenticate just as happily to `evil.com`. With an agent in the loop, the URL
   may have arrived in an issue body or a web page — prompt injection becomes
   credential exfiltration in one hop.
4. **Flag-level exfiltration.** Even aimed at the right host, `-v`, `--trace`,
   `-D`, `-K`, `--proxy`, `--resolve`, `--insecure` and `-L` (which re-sends
   custom headers across hosts) each turn *make this request* into *disclose the
   token*. A warning in the docs is not a control.
5. **No inventory.** `~/.npmrc`, `~/.netrc`, `~/.github_token`, a `.env`, a
   `GH_TOKEN` in `.bashrc`. Nobody remembers which tokens exist, which account
   each belongs to, what scopes it has, or whether it is still needed — because
   the only file that knows is the one you cannot safely open.
6. **Permission drift.** A token file created by a shell redirect is `0644` for
   as long as it takes someone to notice.
7. **No keychain to use.** Headless Linux, devcontainers, SSH boxes and CI
   sandboxes have no macOS Keychain, often no D-Bus for `gnome-keyring`, and no
   Vault server to talk to.

### The idea

One invariant, enforced in code rather than in documentation:

> A token value moves from the terminal into a file, and from that file into a
> request. Nowhere else. It is never printed, never returned to a caller that
> formats output, and never placed in a command-line argument.

That single rule produces the whole design:

- **There is no read path.** No `patman show`, by choice. The value leaves disk
  only into curl's stdin (`--config -`) or into a child process's environment
  (`patman exec`) — never stdout, never argv.
- **Metadata is split from the secret.** `manifest.json` carries the
  description, username, pinned hosts and timestamps and no secrets at all, so
  `list`, `lookup` and `search` are safe for anyone — including an agent — to run
  freely. That split is what makes the inventory problem solvable without opening
  the sensitive file.
- **Pinned hosts are a capability check.** A token pinned to `api.github.com` or
  `*.atlassian.net` cannot be sent anywhere else: the request is refused before
  the token is even read from disk. Userinfo disguises
  (`https://api.github.com@evil.com/`), wildcards against the apex, suffix
  lookalikes (`x.atlassian.net.evil.com`) and a second URL smuggled in beside a
  good one are all refused and all covered by tests.
- **The pass-through argument list is vetted.** The options above are blocked
  outright, and with hosts pinned curl itself is restricted to https, so a
  schemeless stowaway URL dies inside curl rather than being guessed into `http`.
- **`save` refuses to run without a TTY.** The agent structurally cannot be the
  party that handles plaintext; it can only hand the user a command to run
  themselves.
- **A Claude Code skill ships in the repo**, so the agent-side contract —
  never read these files, authenticate through patman — travels with the tool
  instead of living in someone's notes.

### How it compares

|  | at rest | used without printing | bound to a host | inventory | requires |
|---|---|---|---|---|---|
| `~/.token` + `cat` | 0600, if you remember | no | no | no | — |
| `.env` / direnv | plaintext | no — whole process tree, visible in `ps` | no | no | — |
| macOS Keychain, `secret-tool` | encrypted | no — `-w` prints it | no | partial | login session / keyring daemon |
| `pass` (GPG) | encrypted | no — `pass show` | no | names only | GPG setup |
| 1Password / Bitwarden CLI | encrypted | no — `op read` prints | no | yes | account, network |
| HashiCorp Vault | encrypted | no | policy-side | yes | server and ops |
| git credential helper | varies | yes | per host | no | git only |
| **patman** | **0600 plaintext** | **yes** | **yes** | **yes** | **nothing** |

Read honestly: patman is **weaker at rest** than every encrypted store and
**stronger at the point of use** than all of them. It is not a replacement for
1Password or Vault — it composes with them, taking over the last mile they get
wrong:

```sh
op read "op://Private/GitHub PAT/credential" | patman save github --stdin --host api.github.com
```

### Where it fits

- **Agentic coding**, the case it was built for. Claude Code, Copilot agents,
  anything that reads your terminal output and may be steered by text it fetched
  from the internet.
- **Devcontainers, headless servers, VMs, throwaway boxes** — one static binary,
  no daemon, no GPG, no network, no account.
- **A pile of self-hosted services** (Jira, Confluence, GitLab, Artifactory,
  internal APIs) where every vendor CLI keeps its own credential silo and none of
  them share an inventory.

### Where it doesn't

- **Not for a threat model that includes code running as you.** `$HOME/.pat/*`
  is plaintext at `0600`; anything with your uid can read it. The adversary
  patman is built against is accidental disclosure — transcripts, `ps`, shell
  history, logs, screen shares, injected URLs — not local malware. If you need
  encryption at rest, keep the token in a real vault and pipe it in with
  `--stdin`.
- **Not for teams.** No sharing, no rotation automation, no audit log, no expiry
  tracking.
- **Windows is weaker.** Files are restricted by ACL to your SID, but local
  Administrators can still read them; there is no equivalent of POSIX `0600`.
- **`patman exec` trades away the guarantees.** It hands `PAT_TOKEN` to a child
  process and from there patman controls nothing — no host pinning, no argument
  vetting. Prefer `patman curl`, which keeps them, and treat `exec` as the
  deliberate escape hatch it is.

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

The stored value does not have to be a PAT. For a service that authenticates with
a plain password, save the password and set `-u` — patman uses the pair as the
Basic auth credentials.

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

Building, source layout, the Claude Code skill, and the release process live in
[DEVELOPER.md](DEVELOPER.md).

## License

MIT — see [LICENSE](LICENSE).
