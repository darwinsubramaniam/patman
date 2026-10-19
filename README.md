# patman

[![CI](https://github.com/darwinsubramaniam/patman/actions/workflows/ci.yml/badge.svg)](https://github.com/darwinsubramaniam/patman/actions/workflows/ci.yml)

**Let your AI coding agent use your API tokens without ever seeing them.**

Say you ask Claude Code, Codex, or Cursor to "list my open Jira tickets". There's no
logged-in command-line tool for that, so the agent has to call Jira's API, and the
API needs your token. The usual ways to hand it over all leak it: paste it into the
chat, or leave it in a file the agent reads, and the token ends up in the
conversation history for good.

With patman, you store the token once, and the agent asks patman to make the request
for it:

```
you:    patman save jira              ← you type the token once, hidden
agent:  patman curl jira -- https://company.atlassian.net/rest/api/3/search?jql=...
                                       ← patman adds the token; the agent gets
                                         the response, never the token
```

The agent knows *which* token to use. It never learns *what* the token is.

patman is for APIs the agent reaches with a token: Jira, Confluence, GitLab, an
internal company API, and so on. A service whose own CLI is already logged in, like
GitHub with `gh`, doesn't need it.

## Install

```sh
cargo binstall patman     # prebuilt binary, fastest
cargo install patman      # or build from source
```

## Get started

**1. Set up patman and your AI tools.**

```sh
patman init
```

This creates `~/.pat/`, where tokens are stored, and sets up every AI coding tool it
finds on your machine (Claude Code, Codex, Gemini CLI, GitHub Copilot, Cursor,
OpenCode):

- it teaches the agent to use patman (a **skill**), and
- it stops the agent from opening the token files directly (a **guard**).

**2. Save a token.** Run this yourself, in a terminal window:

```sh
patman save jira -d "work Jira" -u me@company.com --host company.atlassian.net
```

patman asks for the token and hides what you type. `-d` says what the token is for,
`-u` is your account name (Jira logs in with email + token), and `--host` says where
the token may be sent, so it can't go anywhere else.

**3. Ask your agent.** Start a new agent session and ask it something that needs the
token, like "list my open Jira tickets". The agent finds the token with `patman list`
and makes the call with `patman curl`.

## Who does what

Some commands are for you only. They need you to type something secret, so they
refuse to run inside an agent.

| You run, in a terminal | The agent can run |
|---|---|
| `patman save <name>`: store or replace a token | `patman list`: see which tokens exist |
| `patman delete <name> --yes`: remove one | `patman lookup <name>`: details for one |
| `patman unlock`: open a session (sealed vault only) | `patman search <word>`: find a token by what it's for |
| `patman tui`: a full-screen editor | `patman curl <name> -- <curl args>`: make a request |
| | `patman doctor`: check that everything is healthy |

None of these commands ever prints a token, not even for you. There is no
`patman show`.

## Everyday use

```sh
# Store a token that needs no username (GitLab, most token-only APIs)
patman save gitlab -d "company GitLab, read_api" --host gitlab.company.com

# Make a request (everything after -- goes to curl)
patman curl gitlab -- -sS https://gitlab.company.com/api/v4/user

# Replace a token that expired (keeps the description)
patman save jira

# Change the description, username, or allowed hosts
patman describe jira -d "work Jira, read-only"

# Read a token from a password manager instead of typing it
op read "op://Work/GitLab/token" | patman save gitlab --stdin
```

patman picks the login method for you: username + token when you set `-u`, a plain
token otherwise. Passwords work too: save the password and set `-u`.

## Making it safer

All three are optional. Each one closes a gap the one before leaves open.

**Pin hosts** (`--host`). This limits where a token can be sent, so a wrong or
malicious URL can't carry it somewhere else. patman warns you about any token
without pinned hosts.

**Encrypt your tokens** (`patman vault init`). By default, token files are plain
text that only your user account can read. Encrypting them under a passphrase means
a file is useless even if something reads it. Then you open a session when you want
the agent to work:

```sh
patman vault init          # choose a passphrase, encrypt everything
patman unlock --minutes 30 # let the agent use tokens for 30 minutes
patman lock                # end it early
```

There is no recovery. If you forget the passphrase, create new tokens.

**Approve each request** (`--approval request`). For a token that can do damage, such
as one with write access, you approve every use. On macOS that's a Touch ID prompt
showing exactly what is being sent:

```sh
patman describe gitlab --approval request
```

## How the agent is kept away from your tokens

`patman init` sets up two things in each AI tool:

1. **A skill**: instructions that teach the agent to use `patman curl` and never to
   read token files.
2. **A guard**: a check the tool runs before every action, which blocks anything
   that touches `~/.pat/`.

The guard is added to each tool's own settings file. Your other settings are kept
as they are, and the old file is saved as `<file>.patman-backup`.

```sh
patman init              # set up, or refresh after upgrading patman
patman init --no-guard   # the skill only, leave tool settings alone
patman init --remove     # take it all back out
patman doctor            # shows whether each tool is set up
```

Be realistic about what the guard does. It stops an agent that is careless, or that
has been tricked by something it read. It does not stop a command written
specifically to get around it. For that, [encrypt your tokens](#making-it-safer).

## What patman can't protect against

- **Other programs running as you.** Without encryption, anything running under
  your user account can read the token files. With encryption and an open session,
  it can use (but not see) your tokens. Keep sessions short.
- **Approving without reading.** If you approve a request that posts your token
  somewhere public, it's public.
- **`patman exec`**. It hands the token to another program, and patman can't
  control what that program does with it.
- **Windows.** Encrypted tokens can't be used by an agent on Windows yet, because
  sessions are not implemented there.
- **Teams.** patman is for one person. There's no sharing or audit log.

## More

- [docs/guide.md](docs/guide.md): every command and option in detail
- [docs/design.md](docs/design.md): why patman works the way it does
- [docs/sealed-vault.md](docs/sealed-vault.md): how encryption and sessions work
- [DEVELOPER.md](DEVELOPER.md): building and contributing

MIT licensed. See [LICENSE](LICENSE).
