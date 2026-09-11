---
name: patman
description: This skill should be used when a task needs a personal access token or API credential - calling the GitHub, Jira, Confluence, GitLab, or any other authenticated HTTP API, hitting 401/403 auth failures, or when the user mentions a PAT, an API token, `~/.pat/`, or patman. Explains how to authenticate requests through the patman CLI so a token value never enters the transcript, and which commands the user must run themselves.
---

# Authenticating with patman

`patman` stores personal access tokens in `$HOME/.pat/<service>` (owner-only) with
secret-free metadata in `$HOME/.pat/manifest.json`. It exists to enforce one rule:

> A token value moves from the user's terminal into a file, and from that file into a
> request. Nowhere else. It is never printed, never returned to a caller that formats
> output, and never placed in a command-line argument.

An agent working in this repo — or in any repo, with patman installed — inherits that
rule. Authenticate **through** patman; never handle the value.

## The one hard constraint

Never read, print, or interpolate a token value. Concretely, never run any of these:

```
cat ~/.pat/github                 # the value lands in the transcript, permanently
TOKEN=$(cat ~/.pat/jira); curl -H "Authorization: Bearer $TOKEN" ...
curl -u "user:$(cat ~/.pat/x)" ...
echo $PAT_TOKEN                   # inside patman exec
```

Also never use the Read tool on a file under `~/.pat/` other than `manifest.json`.
Once a token is in the transcript it is disclosed: it is in the session history, in any
context that gets summarized, and in anything the user shares. Rotating it is then the
only remedy.

`~/.pat/manifest.json`, by contrast, holds no secrets and is safe to read.

## Division of labour

| Action | Who runs it |
|---|---|
| `list`, `lookup`, `search`, `orphans`, `doctor` | agent, freely |
| `curl`, `exec` | agent — this is how requests get made |
| `describe` (metadata, host pinning) | agent, after proposing it to the user |
| `save`, `rotate` | **user only** |
| `delete`, `migrate`, `fix-perms` | user, or agent on explicit request |

`patman save` refuses to run without a TTY, on purpose: masked input needs a real
interactive session, and anything a tool call prints lands in the transcript. Do not try
to work around it. Ask the user to run it themselves — in Claude Code, prefixed with `!`:

```
!patman save jira -d "Atlassian Cloud, read:jira-work" -u alice@example.com --host acme.atlassian.net
```

## Workflow

**1. Find out what exists.** Cheap, secret-free, always the first step:

```bash
patman list                       # table: service, username, updated, description
patman list --json                # same, machine-readable
patman search atlassian           # find a PAT by what it is used for
patman lookup jira --json         # one service: path, username, pinned hosts, updated
```

If the service is not recorded, stop and ask the user to `!patman save <service>`. Give
them the full command including a suggested `-d` description and `--host` pin.

**2. Make the request with `patman curl`.** Everything after `--` is passed to curl; the
credential reaches curl over stdin (`--config -`), so it never appears in `ps` output:

```bash
patman curl jira -- -sS "https://acme.atlassian.net/rest/api/3/myself"
patman curl github -- -sS -X POST -H "Content-Type: application/json" \
  -d '{"title":"..."}' "https://api.github.com/repos/o/r/issues"
```

Auth scheme is chosen automatically: **Basic** (`username:token`) when the manifest
records a username, **Bearer** otherwise. Override with `--auth bearer` or `--auth basic`,
placed *before* the `--`.

**3. For tools that are not curl, use `patman exec`.** It runs a command with `PAT_TOKEN`,
`PAT_USERNAME`, and `PAT_SERVICE` in its environment:

```bash
patman exec github -- sh -c 'GH_TOKEN=$PAT_TOKEN gh pr list'
```

Use **single quotes** so the shell inside the child expands `$PAT_TOKEN` — double quotes
would expand it in the command being constructed and leak the value into the transcript.
`exec` is weaker than `curl`: it applies no argument vetting and no host allowlist, and it
hands the raw value to whatever runs. Prefer `curl` when the tool is curl, and never run
`env`, `printenv`, `set`, or anything that logs its environment underneath `exec`.

## Host pinning

A pinned host list limits where a token can be sent, which is what stops a bad or injected
URL from exfiltrating it. `patman curl` warns when a service has no pins, and refuses any
URL outside the list when it has them.

```bash
patman describe jira --host acme.atlassian.net     # replace the pinned list
patman describe gh --host api.github.com --host '*.github.com'
```

With hosts pinned, curl is additionally restricted to `https` and every URL in the
arguments must be a full `https://` URL — schemeless URLs are refused, because curl would
guess a scheme and request them anyway. `*.example.com` matches subdomains, not the apex.

Widening an allowlist is a security decision. Propose the exact `describe` command and get
the user's agreement before running it; do not silently pin a host to make a call work.

## Blocked curl options — do not reach for them

These are refused in code, not merely discouraged, because each turns "make this request"
into "disclose the token":

- `-v/--verbose`, `--trace*`, `-D/--dump-header`, `--libcurl` — echo the `Authorization` header
- `-K/--config` — loads another config that could do any of the above
- `--proxy*`, `--socks*`, `--preproxy`, `--resolve`, `--connect-to`, `--unix-socket`, `--doh-url` — reroute the request
- `-k/--insecure` — a MITM then reads the header
- `--proto*` — overrides the https-only restriction
- `--location-trusted`, and `-L/--location` with Bearer auth — curl re-sends credentials to redirect targets, including other hosts. Request the final URL directly.
- `--next`, `-:` — starts a second, unvetted request

Pass short options separately from their values (`-d value`, not `-dvalue`); bundles are
scanned character by character, so `-dv` reads as a hidden `-v`.

## When a request fails

`patman curl` returns curl's exit status and stays terse on failure. **Do not re-run with
`-v` or `--trace` to debug** — that prints the `Authorization` header into the transcript.
Instead:

- **401/403** — the token is likely expired or under-scoped. Ask the user to
  `!patman rotate <service>` (keeps the description), or to check the scopes at the
  issuing service. Check `patman lookup <service>` for the recorded `updated` date.
- **"host X is not on the allowed list"** — intended behaviour. Confirm the host is right,
  then propose the `patman describe --host` command.
- **"no token file for X"** or `[FILE MISSING]` in `list` — ask the user to `!patman save X`.
- **"contains control characters" / "is empty"** — the file was saved wrong. Ask the user
  to re-save.
- Anything odd about permissions or stray files: `patman doctor`, then `patman fix-perms`.

Debug the request itself with `-sS -w '\n%{http_code}\n'` and by echoing the response body
— never by making curl dump its own headers.

## If patman is not installed

```bash
command -v patman || cargo install --path .    # from a checkout of this repo
```

Then `patman init` (idempotent) creates `$HOME/.pat/` and an empty manifest. Every command
runs that preflight anyway, so `init` is only needed to see where things live.

Full flag reference for any subcommand: `patman <subcommand> --help`.
