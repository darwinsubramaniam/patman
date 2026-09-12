# Sealed files and unlock sessions

Status: **prototype**, on `prototype/sealed-unlock-session`. Working end to end;
not yet load-bearing for anyone's credentials.

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

## What this does not do

- **Does not protect against a compromised agent during an open session.** That
  is the deliberate tradeoff. The window is the security boundary; shrink it with
  `--minutes`.
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
cargo test                                  # 28 tests
cargo check --target x86_64-pc-windows-msvc # the Windows path still builds
tests/manual/e2e.sh                         # 14-step end-to-end exercise
tests/manual/ttl.sh                         # session expiry (takes ~70s)
tests/manual/stdin_with_tty.py              # piped token + console passphrase
```

The e2e run covers: plaintext still works → seal → token absent from disk →
locked+no-TTY refuses with instructions → metadata still readable → unlock →
curl succeeds with the right `Authorization` header → cleartext refused for a
pinned service → exec refused until opt-in → **a raw socket client is refused a
non-pinned host** → **a raw socket client cannot ask for the token** → lock →
refused again, socket cleaned up.
