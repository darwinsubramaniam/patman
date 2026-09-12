#!/usr/bin/env bash
# Does the unlock session actually expire on its own?
set -uo pipefail
SCRATCH="$(cd "$(dirname "$0")" && pwd)"
PATMAN="${PATMAN:-$SCRATCH/../../target/debug/patman}"
export HOME="/tmp/pm-ttl"
rm -rf "$HOME"; mkdir -p "$HOME"
PASS="correct-horse-battery"

"$PATMAN" init >/dev/null
printf 'tok_abc123' | "$PATMAN" save svc --stdin -d "ttl test" >/dev/null 2>&1
python3 "$SCRATCH/ptyrun.py" "passphrase (input hidden)=$PASS||Repeat it=$PASS" "$PATMAN" vault init >/dev/null
python3 "$SCRATCH/ptyrun.py" "passphrase (input hidden)=$PASS" "$PATMAN" vault seal >/dev/null
python3 "$SCRATCH/ptyrun.py" "passphrase (input hidden)=$PASS" "$PATMAN" unlock --minutes 1 >/dev/null

echo "t=0    $("$PATMAN" status)"
sleep 30
echo "t=30   $("$PATMAN" status)"
sleep 40
echo "t=70   $("$PATMAN" status)"

if [ -S "$HOME/.pat/agent.sock" ]; then
  echo "FAIL: socket still present after expiry"
elif pgrep -f 'patman agent-serve' >/dev/null; then
  echo "FAIL: agent process still alive after expiry"
else
  echo "PASS: agent exited and cleaned up its socket on TTL expiry"
fi
out=$("$PATMAN" curl svc -- -sS https://example.com/ 2>&1)
grep -q "patman unlock" <<<"$out" && echo "PASS: curl refuses after expiry" || echo "FAIL: $out"
