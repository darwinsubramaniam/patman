# Sealed files and unlock sessions

Design rationale for `patman vault` and `patman unlock`. For how to use them, see
the [guide](guide.md#encrypting-tokens).

## What problem this actually solves

patman's threat model has always had one uncomfortable corner. The agent runs as
your user. File permissions do not separate you from it, so `0600` was never what
kept a token away from the model — what kept it away was that patman has no read
path and the skill says not to `cat` the files.

That is a real control, and it is also an instruction rather than a mechanism.
Encryption at rest changes it into a mechanism, but only if the key is not
sitting somewhere the agent can reach unattended. Which rules most things out:

| Key custody | Real gain | Verdict |
|---|---|---|
| Key file at `0600` | Backups only; key sits beside the ciphertext | Theatre |
| OS keychain / DPAPI | Backups, accidental `cat`; auto-unlocks for the user | No gain vs. the agent, and absent on the headless Linux / devcontainer / CI targets patman is built for |
| Passphrase per use | Locked files are genuinely useless without you | Breaks agent-driven use entirely |
| **Passphrase + unlock session** | Same, and time-bounded | What this prototype builds |

So the honest claim is not "tokens are encrypted". It is:

> A credential can only be spent during a window a human opened, for as long as
> that window lasts, and only at the hosts it was already pinned to.

Encryption at rest is what makes the window meaningful. It is not the point on
its own.

## Shape

```
patman vault init     set a passphrase; write vault.json (salt + KDF params + verifier)
patman vault seal     encrypt every plaintext token file in place
patman unlock         derive the key, hand it to an agent process, start the clock
patman status         is it sealed? is a session open? how long left?
patman lock           wipe the key, exit, remove the socket
```

**Sealed file format** — `MAGIC || nonce || XChaCha20-Poly1305(key, nonce, token, aad = service)`.

Three properties earn their place:

- The magic prefix makes the format self-identifying, so `token::read` detects it
  per file. A half-sealed directory works file by file, which is what makes
  `vault seal` safe to interrupt.
- The **service name is the AAD**, so ciphertext is bound to its filename.
  Copying `~/.pat/github` over `~/.pat/jira` fails to open rather than silently
  authenticating as the wrong service.
- Decrypt failure is opaque. An AEAD cannot distinguish a wrong key from a
  tampered file, and the error says so instead of inventing a distinction.

**Key derivation** — Argon2id, 19 MiB / 2 passes / 1 lane (RFC 9106's second
recommended profile, chosen over the 64 MiB one because this has to run in
devcontainers and CI sandboxes). Parameters live in `vault.json` so raising them
later does not lock anyone out of an existing vault.

**vault.json holds no secrets** — a salt, cost parameters, and a sealed constant
used to tell "wrong passphrase" from "corrupt file". Safe for an agent to read,
same as the manifest.

## The agent, and why it is a daemon

The rule the whole design rests on:

> The key never leaves the agent process, and neither does the token. A client
> sends *what it wants done*; the agent decides whether that is allowed,
> decrypts, spawns the program, and streams back only its output.

There is no protocol message that returns a token. A caller that can reach the
socket can *spend* a credential within its pinned limits; it cannot *read* one.
That is strictly less than what `cat ~/.pat/github` gives you today.

Two consequences that are easy to get wrong:

1. **Authorization runs in the agent, not the client.** Once a socket exists,
   anything can speak the protocol without going through the `patman` binary, so
   client-side checks would be advisory only. Host pinning and the curl flag
   blocklist moved to `usage.rs`, which both paths call. This is verified in the
   e2e run by a raw Python client asking for `evil.com` and being refused.
2. **The socket is the capability.** `0600` in a `0700` directory — the same
   boundary as the token files. What the TTL adds is that it expires.

Transport: unix socket at `~/.pat/agent.sock`, one JSON request line, then binary
response frames (`[kind u8][len u32be][payload]`) for stdout / stderr / exit /
error. Startup is a one-line handshake on the child's stdout, because the agent's
output is otherwise `/dev/null` and a bind failure would reach the user as
nothing but a timeout.

## `exec` became opt-in

`patman exec <svc> -- sh -c 'echo $PAT_TOKEN'` is a complete bypass of every
other control — no host pinning, no argument vetting, raw token into a child the
caller chose. The README always documented this. It is tolerable when a human
types it and indefensible when the thing choosing the command is the model.

Under a sealed vault it now needs `patman describe <svc> --allow-exec` per
service. On a plaintext install nothing changes.

This is the single highest-value change here, and it is independent of the
crypto. It caps how much the unlock window can be abused.

## Hybrid approval: session or per request

An unlock window is all-or-nothing: while it is open, every sealed token can be
spent unattended. That is fine for a read-only CI token and too loose for one
that can push to `main` or move money. So approval is a per-service setting:

```
patman describe ci-reader --approval session   # default: the window is enough
patman describe github    --approval request   # every use needs its own yes
```

For a `request` service, an open session is necessary but not sufficient. The
unlock agent checks the request against the policy, then asks the human about
**this one request** before decrypting:

| Platform | How the human approves | Where the prompt appears |
|---|---|---|
| macOS | Touch ID, or the login password | System dialog raised by the unlock agent |
| Linux, other unix | Vault passphrase | The terminal of whoever ran `patman curl` |
| Windows | Vault passphrase (no session exists, so every use already prompts) | Console |

Three details matter:

- **The daemon writes the prompt.** On macOS the dialog reads *"patman is trying
  to send your "github" token: POST https://api.github.com/... with body ..."*,
  built from the actual curl arguments, with control characters replaced so an
  argument cannot forge a second line. On the passphrase path the client shows
  the same description before prompting.
- **No caching.** One approval covers one request. A second call is a second
  prompt. Prompts are serialised so stacked dialogs cannot be confused.
- **Authorization runs before approval.** A request that host pinning or the
  flag blocklist would refuse is refused without asking anyone.

With no terminal and no Touch ID — an agent's tool call on Linux — a `request`
service fails with instructions to run the command in a terminal window. That is the design:
the agent proposes, the human runs.

`PATMAN_NO_TOUCHID=1` in the environment of `patman unlock` makes the agent use
the passphrase path instead of Touch ID (useful over SSH, and for the e2e test).
It cannot weaken anything: it swaps one human-only approval for another.

The closest thing to "always sealed" is every service on `request` with a long
unlock window. The key sits in the daemon, but nothing can be spent without a
fingerprint or passphrase per call.

## Signed policy

Per-service controls are only as strong as the file that holds them. The agent
runs as the user, so without protection it could run
`patman describe github --approval session --clear-hosts` (or edit
`manifest.json` directly) and the unlock agent would obey the weakened rules.

So under a sealed vault each manifest entry carries `policy_seal`: an AEAD seal,
made with the vault key, over the policy fields — `username`, `hosts`,
`allow_exec`, `approval` — with the service name bound in. Whoever holds the key
(the unlock agent, or a passphrase prompt on the locked path) verifies it before
acting:

- a changed field → refused: *"the policy for "github" has been changed without
  the vault passphrase"*;
- no seal, or no manifest entry at all → refused, so deleting an entry is not a
  way back to the unrestricted defaults;
- a seal copied from another service → refused (the service name is in the AAD).

Changing a policy field with `describe` therefore prompts for the passphrase, and
fails without a terminal. A description-only edit keeps the seal and asks for
nothing. `vault init` and `vault seal` sign every entry as it stands — the human
typing the passphrase is endorsing the current policy — and
`patman describe <svc> --sign` re-signs after a deliberate hand edit.

**Not covered: rollback.** An older copy of the manifest carries valid seals for
its older policy. Restoring it re-arms whatever that policy allowed. Preventing
that needs a counter the agent cannot write, which a same-user design lacks.

## What this does not do

- **Does not protect against a compromised agent during an open session** for
  `session` services. That is the deliberate tradeoff. The window is the security
  boundary; shrink it with `--minutes`, or put the service on `--approval request`.
- **A per-request approval is only as good as the human reading it.** The prompt
  shows the method, URL and body; approving without reading it approves anything
  within the pinned hosts — including a request whose body reflects the token
  back (a gist, an issue comment).
- **The Touch ID path has not been run by the e2e script**, which uses
  `PATMAN_NO_TOUCHID=1` so it can run unattended. Exercise it by hand (see
  below).
- **`--allow-exec` hands over the raw token,** by construction. The opt-in makes
  it a decision, not a default.
- **The TTY check is a speed bump, not a boundary.** `vault::has_tty` proves a
  terminal exists, not that a human is at it — a harness that allocates a pty
  satisfies it. The property that actually holds is the agent one above.
- **The unlock session is unix only.** Windows needs named pipes. Sealing itself
  works there — `curl` and `exec` prompt for the passphrase per use, and
  `unlock`/`lock` fail with a message saying so. Verified by cross-compiling
  (`cargo check --target x86_64-pc-windows-msvc`), clean under clippy.
- **No rekey.** Changing the passphrase means `vault init` on a fresh directory.
- **No fd passing**, so curl sees a pipe, not a tty: no progress meter, nothing
  interactive. Fixing it needs `SCM_RIGHTS`, which std does not expose.
- **Socket path length.** `sockaddr_un.sun_path` is 104 bytes on macOS. A deep
  `$HOME` gets a clear error and falls back to passphrase-per-use; an env-var
  override would be the fix.

## Verifying it

```
cargo test                                  # 36 tests
cargo check --target x86_64-pc-windows-msvc # the Windows path still builds
tests/manual/e2e.sh                         # 16-step end-to-end exercise
tests/manual/ttl.sh                         # session expiry (takes ~70s)
tests/manual/stdin_with_tty.py              # piped token + console passphrase
```

The e2e run covers: plaintext still works → seal → token absent from disk →
locked+no-TTY refuses with instructions → metadata still readable → unlock →
curl succeeds with the right `Authorization` header → cleartext refused for a
pinned service → exec refused until opt-in → **a raw socket client is refused a
non-pinned host** → **a raw socket client cannot ask for the token** → **a
hand-edited policy is refused** → **the agent cannot change exec or approval
settings** → a `request` service is refused without approval, runs with the
passphrase, refuses a wrong one, and refuses a raw socket client → a `session`
service still runs unattended → lock → refused again, socket cleaned up.

Touch ID, by hand on macOS:

```
patman describe github --approval request    # passphrase, to sign it
patman unlock --minutes 5
patman curl github -- -sS https://api.github.com/user   # dialog shows the request
```

Approve once (works), cancel once (refused), and run it from a tool call with no
terminal (the dialog still appears — that is the out-of-band part).
