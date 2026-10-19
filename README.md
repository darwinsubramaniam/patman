# patman

[![CI](https://github.com/darwinsubramaniam/patman/actions/workflows/ci.yml/badge.svg)](https://github.com/darwinsubramaniam/patman/actions/workflows/ci.yml)

Store the personal access tokens and passwords you hand to an AI coding agent, and
let it authenticate as you without ever learning the secret.

You tell the agent *which* credential to use. It never learns *what* the
credential is.

- Token values live in `$HOME/.pat/<service>`, locked to your user. They can be
  [encrypted under a passphrase](#encrypting-tokens-at-rest).
- Metadata — description, username, pinned hosts — lives in
  `$HOME/.pat/manifest.json` and holds no secrets, so it is safe to read and
  share.
- **No command ever prints a token value.** There is no `patman show`. The value
  goes from your terminal into a file, and from that file into a request.

Why it works this way: [docs/design.md](docs/design.md).

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
[latest release](https://github.com/darwinsubramaniam/patman/releases/latest) —
macOS (arm64/x86_64), Linux (arm64/x86_64, static musl), Windows (x86_64), with
checksums in `SHA256SUMS`:

```sh
tar -xzf patman-<version>-aarch64-apple-darwin.tar.gz
sudo install -m 755 patman-<version>-aarch64-apple-darwin/patman /usr/local/bin/
```

From a clone:

```sh
cargo install --path .
```

## Quick start

```sh
patman save github -d "personal account, repo + read:org" --host api.github.com
patman curl github -- -sS https://api.github.com/user
```

## Saving a token

Run this yourself in a real terminal. It prompts with echo off and refuses to run
without a TTY, so a token is never typed into a tool call. Using Claude Code? Run
it in a separate terminal window — the `!` prefix runs commands without a terminal,
so the prompt cannot appear there.

```sh
patman save github -d "personal account, repo + read:org scopes" -u darwin
# Paste the github token (input hidden):  <- nothing echoes
```

- `-d/--description` — what it's for; required for a new service.
- `-u/--username` — account id used for Basic auth (an email for Atlassian Cloud,
  a corporate ID for most self-hosted servers). Skip it for Bearer-only APIs.
- `--host api.github.com` — pin where the token may be sent. Recommended; see
  [host pinning](#host-pinning).
- `--stdin` — read the token from a pipe instead of prompting:

  ```sh
  op read "op://Private/GitHub PAT/credential" | patman save github --stdin --host api.github.com
  ```

The stored value does not have to be a PAT. For a service that authenticates with
a plain password, save the password and set `-u` — patman uses the pair as the
Basic auth credentials.

Saving an existing service replaces the token and keeps the description
(`patman rotate github` is the same thing).

## Using a token

```sh
patman curl jira -- -sS "https://x.atlassian.net/rest/api/3/myself"
```

Everything after `--` is passed to curl. The credential reaches curl over stdin
(`--config -`), so it never appears in `ps` output or your shell history.

The auth scheme is chosen for you: **Basic** (`username:token`) when the manifest
records a username, **Bearer** otherwise. Override with `--auth bearer` or
`--auth basic` before the `--`.

For tools that are not curl, `patman exec` runs a command with `PAT_TOKEN`,
`PAT_USERNAME` and `PAT_SERVICE` in its environment:

```sh
patman exec gh -- sh -c 'GH_TOKEN=$PAT_TOKEN gh pr list'
```

Use single quotes, so the token is expanded inside the child process rather than
in the command you are building. `exec` is the deliberate escape hatch: it hands
the raw value to whatever runs and applies no host pinning and no argument
vetting. Prefer `curl` when the tool is curl. Under a sealed vault, `exec` is
refused unless the service opts in with `patman describe <service> --allow-exec`.

### Host pinning

A pinned host list limits where a token can be sent, so a wrong or injected URL
cannot carry it somewhere else. `patman curl` warns when a service has no pins,
and refuses any URL outside the list when it has them.

```sh
patman describe jira --host acme.atlassian.net
patman describe gh --host api.github.com --host "*.github.com"
```

`*.example.com` matches subdomains, not the apex. With hosts pinned, curl is also
restricted to `https`, and every URL in the arguments must be a full `https://`
URL — a schemeless one is refused rather than guessed at.

### Refused curl options

Some curl options turn "make this request" into "disclose the token", so patman
refuses them rather than warning about them: anything that echoes the
`Authorization` header (`-v`, `--trace*`, `-D`, `--libcurl`), reroutes the request
(`--proxy*`, `--socks*`, `--resolve`, `--connect-to`, `--unix-socket`), weakens
transport security (`-k`, `--proto*`), loads another config (`-K`), starts a
second unvetted request (`--next`), or follows redirects while carrying a Bearer
token (`-L`, `--location-trusted`) — curl re-sends custom headers to the redirect
target, including one on another host.

Pass short options separately from their values (`-d value`, not `-dvalue`);
bundles are scanned character by character, so `-dv` reads as a hidden `-v`.

When a request fails, do not re-run it with `-v` or `--trace` to debug — those
print the `Authorization` header. Use `-sS -w '\n%{http_code}\n'` instead.

## Encrypting tokens at rest

By default token files are plaintext at `0600`. Sealing encrypts them under a
passphrase, and makes each use happen inside a session you open and that expires
on its own.

Nothing changes until you run `vault init`.

```sh
patman vault init          # set a passphrase; writes $HOME/.pat/vault.json
patman vault seal          # encrypt every existing token file in place
```

Files become XChaCha20-Poly1305 ciphertext under an Argon2id key. `vault.json`
holds the salt and cost parameters and no secrets, so it stays as safe to read as
the manifest. **There is no recovery** — if you lose the passphrase, rotate the
tokens at the issuing service.

New tokens are sealed as you save them.

### Unlock sessions

Open a session to use sealed tokens. Run this yourself in a real terminal — like
`save`, it needs masked input that a tool call cannot provide:

```sh
patman unlock --minutes 30
patman status              # sealed? unlocked? how long left?
patman lock                # end it early
```

While unlocked, `patman curl` and `patman exec` work exactly as before — same
syntax, no passphrase. The key is held by a small background process and never
leaves it: your command sends the *request*, that process decrypts and runs curl,
and only the output comes back. The session then expires on its own.

When it is locked, a tool call is told what to do rather than failing obscurely:

```
patman: no terminal available to read the vault passphrase.

The vault is locked and unlocking needs masked input, which an agent's tool call
cannot provide.

Run it yourself in a terminal window (not Claude Code's `!` prefix, which has no terminal to prompt on):
    patman unlock
```

Metadata stays readable throughout: `list`, `lookup`, `search`, `status` and
`doctor` never need the passphrase, so an agent can still see what exists.

### Approval per request, for sensitive tokens

A session lets every sealed token be spent unattended until it expires. For a
token you want to approve call by call, switch it to per-request approval:

```sh
patman describe github --approval request    # asks for the passphrase
```

Then, even inside an open session, every `patman curl github ...` waits for you:

- **macOS** — a Touch ID dialog (or your login password) that names the request,
  e.g. *patman is trying to send your "github" token: POST
  https://api.github.com/repos/... with body ...*
- **Linux / other unix** — the command shows the request and asks for the vault
  passphrase. From an agent's tool call, with no terminal, it is refused with
  instructions to run it yourself in a terminal window.

Leave low-risk tokens on the default, `--approval session`. Mixing the two is the
point: a read-only token runs unattended, while a write token needs you.

### Policy changes need the passphrase

Under a sealed vault, how a token may be used — its pinned hosts, username,
`--allow-exec` and `--approval` — is signed with the vault key. Changing any of
them with `patman describe` asks for the passphrase, and an edit to
`manifest.json` that skips patman is refused at use time:

```
patman: the policy for "github" has been changed without the vault passphrase
```

So nothing running as you can loosen a token's rules to get around them. Changing
only the description needs no passphrase. If you edit the manifest by hand on
purpose, re-sign with `patman describe <service> --sign`.

### Windows

Unlock sessions are unix-only — they are built on a unix-domain socket, and
`patman unlock` reports that rather than starting one.

Sealing itself works on Windows: files are encrypted, and `patman curl` and
`patman exec` prompt for the passphrase on **every** use. That is fine when you
are driving patman yourself, but it means **an agent cannot use a sealed token on
Windows** — a tool call has no console to type a passphrase into, so every
authenticated request fails (or, if the tool call happens to have a console
attached, waits at a prompt nobody will answer).

So on Windows, pick one:

- **Leave the vault unsealed** if the point is to let an agent authenticate. This
  is the same posture as patman before sealing existed.
- **Seal it** if you use patman by hand and want encryption at rest, and accept
  typing the passphrase per request.

Sessions on Windows need a named-pipe transport, which is not implemented yet.

## Seeing what you have

```sh
patman list                   # table: service, username, updated, description
patman list --json            # same, machine-readable
patman lookup github          # one service: path, username, pinned hosts, updated
patman search atlassian       # find a token by what it is used for
```

None of these read a token value, so they are safe to run at any time — including
from an agent, and including while a vault is locked.

## Editing and deleting

`describe` touches metadata only, never the secret:

```sh
patman describe github -d "work account, repo scope only"
patman describe github -u darwin@example.com
patman describe github --clear-username          # Bearer-only service
patman describe github --host api.github.com --host "*.github.com"
patman describe github --clear-hosts             # unpin (token may go anywhere)
patman describe github --allow-exec              # permit `patman exec`
patman describe github --deny-exec               # withdraw it
```

Deleting is destructive and unconfirmable, so it needs `--yes`:

```sh
patman delete github --yes
```

That removes the local file and manifest entry only — revoke the token at the
issuing service too.

## Terminal UI

```sh
patman tui
```

A full-screen editor over the same commands: browse and filter services, edit
the description, username, pinned hosts, exec permission and approval mode, store
or rotate a token, delete one (type its name to confirm), re-sign a policy,
migrate a legacy file, unlock or lock a session, and run `doctor`, `orphans`,
`fix-perms` and `vault init`/`seal`. Press `?` for the keys.

It never shows a token value and has no field to type one into. Anything that
prompts — a token, the vault passphrase — runs with the UI suspended, on the plain
terminal with echo off, exactly as the CLI does. Like `save` and `unlock`, it
needs a real terminal, so an agent's tool call cannot drive it.

The list marks entries that need attention: `!` token file missing, `?` file
with no manifest entry, `~` no hosts pinned. Build without it with
`cargo install patman --no-default-features`.

## Housekeeping

```sh
patman doctor        # permissions, manifest validity, sealing state, orphans
patman orphans       # token files with no manifest entry, and entries with no file
patman fix-perms     # re-apply owner-only permissions
patman migrate jira  # move a legacy ~/.jira_pat into $HOME/.pat/jira
```

patman refuses to run if `$HOME/.pat` sits inside a cloud-sync root (OneDrive,
Dropbox, iCloud and friends), including via a symlink — tokens written there
upload in plaintext and survive deletion through version history.

## What patman does not protect against

- **Code running as you, while a token is reachable.** Unsealed, `$HOME/.pat/*`
  is plaintext at `0600` and anything with your uid can read it. Sealed and
  unlocked, anything with your uid can ask the agent to spend a `session`
  credential — within its pinned hosts, without learning its value. Shorten the
  exposure with `patman unlock --minutes`, or use `--approval request`.
- **Approving without reading.** A per-request prompt shows the method, URL and
  body. Approve a request that posts the token to a pinned host that echoes it
  back (a gist, an issue comment), and it is out.
- **Manifest rollback.** Policy signatures stop edits, not the restore of an
  older, validly signed manifest.
- **`patman exec`.** It hands the raw token to a child process; from there patman
  controls nothing.
- **Windows file permissions.** Files are restricted by ACL to your SID, but local
  Administrators can still read them; there is no equivalent of POSIX `0600`.
  Sealing closes that gap, at the cost of [no agent use on
  Windows](#windows).
- **Team use.** No sharing, no rotation automation, no audit log, no expiry
  tracking.

## Claude Code

A skill ships in `skills/patman/`, so an agent working in your terminal knows to
authenticate through patman instead of reading the files. Install it with
`./install-skill.sh`.

## Dev

Building, source layout, and the release process live in
[DEVELOPER.md](DEVELOPER.md).

## License

MIT — see [LICENSE](LICENSE).
