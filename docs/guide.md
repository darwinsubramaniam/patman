# patman guide

The full reference. For a quick introduction, start with the [README](../README.md).

- [Where things live](#where-things-live)
- [Saving a token](#saving-a-token)
- [Using a token](#using-a-token)
- [Pinning hosts](#pinning-hosts)
- [Refused curl options](#refused-curl-options)
- [Encrypting tokens](#encrypting-tokens)
- [Approving each request](#approving-each-request)
- [Policy changes need the passphrase](#policy-changes-need-the-passphrase)
- [Windows](#windows)
- [Seeing, editing, and deleting](#seeing-editing-and-deleting)
- [Terminal UI](#terminal-ui)
- [Housekeeping](#housekeeping)
- [AI coding agents](#ai-coding-agents)
- [What patman does not protect against](#what-patman-does-not-protect-against)

## Where things live

- Token values: `~/.pat/<service>`, one file per token, readable only by your user.
- Metadata (description, username, pinned hosts): `~/.pat/manifest.json`. It holds no
  secrets.
- Encryption settings, once you turn encryption on: `~/.pat/vault.json`. It holds no
  secrets either.

patman refuses to run if `~/.pat` is inside a cloud-sync folder (OneDrive, Dropbox,
iCloud, Google Drive and others), including through a symlink. Tokens written there
would be uploaded, and version history would keep them even after you delete them.

## Saving a token

Run `save` yourself, in a terminal window. It prompts with echo off, and it refuses
to run without a terminal, so a token can never be typed into an agent's tool call.
In Claude Code, use a separate terminal window: the `!` prefix has no terminal, so
the prompt can't appear there.

```sh
patman save github -d "personal account, repo + read:org scopes" -u darwin
# Paste the github token (input hidden):
```

| Option | Meaning |
|---|---|
| `-d`, `--description` | What the token is for. Required for a new service. |
| `-u`, `--username` | Account name for Basic auth: an email for Atlassian Cloud, a corporate ID for most company servers. Leave it out for APIs that take a plain token. |
| `--host <host>` | Where the token may be sent. Repeatable. See [Pinning hosts](#pinning-hosts). |
| `--stdin` | Read the token from a pipe instead of prompting. |

```sh
op read "op://Private/GitHub PAT/credential" | patman save github --stdin --host api.github.com
```

The value doesn't have to be a personal access token. For a service that logs in with
a password, save the password and set `-u`; patman sends the pair as Basic auth.

Saving a service that already exists replaces the token and keeps the description.
`patman rotate github` does the same thing.

## Using a token

```sh
patman curl jira -- -sS "https://x.atlassian.net/rest/api/3/myself"
```

Everything after `--` goes to curl. patman hands curl the credential on stdin
(`--config -`), so it never shows up in `ps` or your shell history.

patman picks the auth scheme: **Basic** (`username:token`) when the service has a
username, **Bearer** otherwise. Override it with `--auth bearer` or `--auth basic`,
placed before the `--`.

For tools other than curl, `patman exec` runs a command with `PAT_TOKEN`,
`PAT_USERNAME` and `PAT_SERVICE` set in its environment:

```sh
patman exec gh -- sh -c 'GH_TOKEN=$PAT_TOKEN gh pr list'
```

Use single quotes, so the token is expanded inside the child process and not in the
command you're typing. `exec` is a deliberate escape hatch: it gives the raw token to
whatever runs, with no host pinning and no argument checks. Prefer `curl` when the
tool is curl. With encryption on, `exec` is refused unless the service opts in with
`patman describe <service> --allow-exec`.

## Pinning hosts

A pinned host list limits where a token can be sent, so a wrong or injected URL can't
carry it somewhere else. `patman curl` warns when a service has no pins, and refuses
any URL outside the list when it has them.

```sh
patman describe jira --host acme.atlassian.net
patman describe gh --host api.github.com --host "*.github.com"
```

`*.example.com` matches subdomains, not `example.com` itself. With hosts pinned,
curl is limited to `https`, and every URL must be a full `https://` URL. A URL
without a scheme is refused rather than guessed at.

## Refused curl options

Some curl options turn "make this request" into "reveal the token", so patman
refuses them outright:

- options that print the `Authorization` header: `-v`, `--trace*`, `-D`, `--libcurl`
- options that reroute the request: `--proxy*`, `--socks*`, `--resolve`,
  `--connect-to`, `--unix-socket`
- options that weaken TLS: `-k`, `--proto*`
- `-K`, which loads another config file
- `--next`, which starts a second request patman hasn't checked
- following redirects with a Bearer token (`-L`, `--location-trusted`), because curl
  re-sends custom headers to the redirect target, even on another host

Pass short options separately from their values (`-d value`, not `-dvalue`). patman
scans bundles letter by letter, so `-dv` reads as a hidden `-v`.

To debug a failing request, don't add `-v` or `--trace`: they print the
`Authorization` header. Use `-sS -w '\n%{http_code}\n'` instead.

## Encrypting tokens

By default, token files are plain text with `0600` permissions. Encryption seals them
under a passphrase, and every use then happens inside a session that you open and
that expires on its own.

Nothing changes until you run `vault init`:

```sh
patman vault init          # choose a passphrase; writes ~/.pat/vault.json
patman vault seal          # encrypt every existing token file in place
```

Files are encrypted with XChaCha20-Poly1305 under a key derived with Argon2id.
`vault.json` holds the salt and cost settings, nothing secret. New tokens are
encrypted as you save them.

**There is no recovery.** If you lose the passphrase, revoke the tokens and create
new ones at each service.

### Unlock sessions

To use encrypted tokens, open a session. Like `save`, this needs hidden input, so run
it yourself in a terminal:

```sh
patman unlock --minutes 30
patman status              # encrypted? unlocked? how long left?
patman lock                # end the session early
```

While a session is open, `patman curl` and `patman exec` work as usual, with no
passphrase. The key stays inside a small background process: your command sends the
request to it, it decrypts and runs curl, and only the output comes back.

When the vault is locked, an agent's tool call gets a clear explanation rather than
an obscure failure:

```
patman: no terminal available to read the vault passphrase.

The vault is locked and unlocking needs masked input, which an agent's tool call
cannot provide.

Run it yourself in a terminal window (not Claude Code's `!` prefix, which has no terminal to prompt on):
    patman unlock
```

`list`, `lookup`, `search`, `status` and `doctor` never need the passphrase, so an
agent can still see which tokens exist while the vault is locked.

## Approving each request

A session lets every encrypted token be used without you until it expires. For a
token you want to approve call by call, turn on per-request approval:

```sh
patman describe github --approval request    # asks for the passphrase
```

From then on, even inside an open session, every `patman curl github ...` waits for
you:

- **macOS**: a Touch ID dialog (or your login password) that names the request, for
  example *patman is trying to send your "github" token: POST
  https://api.github.com/repos/... with body ...*
- **Linux and other unix systems**: the command shows the request and asks for the
  vault passphrase. From an agent's tool call, which has no terminal, it's refused
  with instructions to run it yourself.

Leave low-risk tokens on the default, `--approval session`. Mixing the two is the
point: a read-only token runs on its own, a write token needs you.

## Policy changes need the passphrase

With encryption on, a token's usage rules (pinned hosts, username, `--allow-exec`
and `--approval`) are signed with the vault key. Changing any of them with
`patman describe` asks for the passphrase. An edit to `manifest.json` made outside
patman is refused when the token is next used:

```
patman: the policy for "github" has been changed without the vault passphrase
```

So nothing running as you can loosen a token's rules to get around them. Changing
only the description needs no passphrase. If you edit the manifest by hand on
purpose, re-sign it with `patman describe <service> --sign`.

## Windows

Unlock sessions are unix-only, because they run over a unix-domain socket.
`patman unlock` says so rather than starting one.

Encryption itself works on Windows: files are encrypted, and `patman curl` and
`patman exec` ask for the passphrase on **every** use. That's fine when you drive
patman yourself, but it means **an agent can't use an encrypted token on Windows**.
A tool call has no console to type a passphrase into, so every request fails.

So on Windows, choose one:

- **Leave encryption off** if you want an agent to use your tokens.
- **Turn it on** if you use patman by hand and want encryption at rest, and accept
  typing the passphrase for each request.

Windows sessions need a named-pipe transport, which isn't built yet.

## Seeing, editing, and deleting

```sh
patman list                   # table: service, username, updated, description
patman list --json            # the same, as JSON
patman lookup github          # one service: path, username, pinned hosts, updated
patman search atlassian       # find a token by what it's used for
```

None of these read a token, so they're safe to run at any time, from an agent too,
and while the vault is locked.

`describe` changes metadata only, never the token:

```sh
patman describe github -d "work account, repo scope only"
patman describe github -u darwin@example.com
patman describe github --clear-username          # plain-token service
patman describe github --host api.github.com --host "*.github.com"
patman describe github --clear-hosts             # unpin: the token may go anywhere
patman describe github --allow-exec              # permit `patman exec`
patman describe github --deny-exec               # take that back
```

Deleting can't be undone, so it needs `--yes`:

```sh
patman delete github --yes
```

This removes the local file and its manifest entry only. Revoke the token at the
service too.

## Terminal UI

```sh
patman tui
```

A full-screen editor over the same commands: browse and filter services, edit the
description, username, pinned hosts, exec permission and approval mode, store or
replace a token, delete one (type its name to confirm), re-sign a policy, migrate an
old token file, unlock or lock a session, and run `doctor`, `orphans`, `fix-perms` and
`vault init`/`seal`. Press `?` for the keys.

It never shows a token and has no field to type one into. Anything that prompts runs
with the UI paused, on the plain terminal with echo off. Like `save` and `unlock`, it
needs a real terminal, so an agent can't drive it.

The list marks entries that need attention: `!` token file missing, `?` file with no
manifest entry, `~` no hosts pinned. To build patman without it:
`cargo install patman --no-default-features`.

## Housekeeping

```sh
patman doctor        # permissions, manifest, encryption, agent setup, stray files
patman orphans       # token files with no manifest entry, and entries with no file
patman fix-perms     # reapply owner-only permissions
patman migrate jira  # move a token file you kept yourself into ~/.pat/jira
```

`migrate` is for tokens you stored before using patman. It moves `~/.<service>_pat`
(for example `~/.jira_pat`) into `~/.pat/<service>`; `--from <path>` takes any other
file. Then describe it with `patman describe <service> -d "..."`.

## AI coding agents

`patman init` sets up every AI coding tool it finds with a **skill** and a **guard**.

### The skill

The skill is a set of instructions that teaches the agent to authenticate through
patman: find tokens with `patman list`, make requests with `patman curl`, and ask you
to run `patman save` when a token is missing. It goes in two folders, which between
them cover every supported tool:

| Folder | Read by |
|---|---|
| `~/.claude/skills/patman` | Claude Code |
| `~/.agents/skills/patman` | Codex, Gemini CLI, GitHub Copilot, Cursor, OpenCode |

```sh
patman init                      # every tool found on this machine
patman init --agent claude       # only one folder: claude or agents
                                 # (codex, gemini, copilot, cursor, opencode mean agents)
patman init --project            # into ./.claude/skills and ./.agents/skills, to commit
patman init --no-skill           # set up ~/.pat only
```

A tool counts as found when its config folder exists or its program is on your
`PATH`. Cursor and OpenCode read both folders, so they may list the skill twice; it
does no harm.

### The guard

The skill is advice. The guard enforces it: before every action the agent takes, the
tool checks with patman, which blocks anything that reads, lists, or writes `~/.pat/`,
the manifest included. The agent gets metadata from `patman list --json` instead.

| Tool | How it's blocked | File changed |
|---|---|---|
| Claude Code | Built-in `Read`/`Edit` deny rules, plus a hook for shell commands | `~/.claude/settings.json` |
| Codex | A `PreToolUse` hook. Codex asks you to trust it once, in `/hooks`. | `~/.codex/hooks.json` |
| Gemini CLI | A `BeforeTool` hook | `~/.gemini/settings.json` |
| GitHub Copilot | A `preToolUse` hook | `~/.copilot/hooks/patman.json` |
| Cursor | `preToolUse` and `beforeReadFile` hooks | `~/.cursor/hooks.json` |
| OpenCode | Its own permission rules, no hook | `~/.config/opencode/opencode.json` |

Each change is merged into the file you already have. Your other settings stay as
they are, the previous version is saved as `<file>.patman-backup`, and running
`init` again changes nothing. A file that isn't plain JSON (one with comments, say)
is left alone, and `init` tells you so; add the entry from the table by hand.

```sh
patman init --no-guard           # install the skill, leave tool settings alone
patman init --remove             # take the skill and the guard back out
```

`--project` installs the skill only. A guard committed to a repo would make every
teammate's tool depend on patman being installed.

The guard matches paths, so it stops an agent that is careless or tricked by
something it read, not a command written to get around it. Encrypt your tokens to
make a file useless even when it is read.

After upgrading patman, run `patman init` again to refresh the skill and the guard.
`patman doctor` reports a stale skill or a missing guard.

## What patman does not protect against

- **Code running as you while a token is reachable.** Without encryption,
  `~/.pat/*` is plain text at `0600`, and anything running as your user can read it.
  With encryption and an open session, anything running as you can ask the session to
  spend a token (within its pinned hosts) without learning its value. Keep sessions
  short with `patman unlock --minutes`, or use `--approval request`.
- **Approving without reading.** A per-request prompt shows the method, URL and body.
  Approve a request that posts the token to a pinned host that echoes it back (a
  gist, an issue comment), and it's out.
- **Manifest rollback.** Policy signatures stop edits, not the restoring of an older,
  validly signed manifest.
- **`patman exec`.** It hands the raw token to a child process, and from there patman
  controls nothing.
- **Windows file permissions.** Files are restricted to your account, but local
  Administrators can still read them; Windows has no exact equivalent of POSIX
  `0600`. Encryption closes that gap, at the cost of [no agent use on
  Windows](#windows).
- **Team use.** No sharing, no automatic rotation, no audit log, no expiry tracking.
