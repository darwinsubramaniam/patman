"""The case `has_tty` exists for: stdin is a PIPE, but a console is available.

`op read ... | patman save github --stdin` under a sealed vault has to work —
the token arrives on stdin while the passphrase is read from the terminal.
Checking `stdin().is_terminal()` would wrongly refuse it, which is exactly the
bug this reproduces.

Forks a pty (so the process has a controlling terminal), then replaces the
child's fd 0 with a pipe carrying the token.
"""
import os
import pty
import select
import subprocess
import sys
import tempfile
import time

PATMAN = os.path.join(os.path.dirname(__file__), "..", "..", "target", "debug", "patman")
PASS = "pw-correct-horse"
TOKEN = "tok_from_password_manager_42"


def run_with_piped_stdin(argv, stdin_bytes, answers, env, timeout=25):
    r, w = os.pipe()
    pid, fd = pty.fork()
    if pid == 0:
        # Child: controlling terminal is the pty (so /dev/tty resolves), but
        # fd 0 is the pipe — the shape a password-manager pipeline produces.
        os.close(w)
        os.dup2(r, 0)
        os.close(r)
        os.execvpe(argv[0], argv, env)

    os.close(r)
    os.write(w, stdin_bytes)
    os.close(w)

    out = b""
    pending = list(answers)
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            out += data
        if pending and pending[0][0].encode() in out:
            os.write(fd, (pending[0][1] + "\n").encode())
            pending.pop(0)
            out += b"\n<<sent>>\n"
    try:
        os.close(fd)
    except OSError:
        pass
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), out.decode(errors="replace")


def main():
    home = tempfile.mkdtemp(prefix="pm-stdin-", dir="/tmp")
    env = dict(os.environ, HOME=home)
    patman = os.path.abspath(PATMAN)

    subprocess.run([patman, "init"], env=env, capture_output=True, check=True)

    # Create the vault first, so the save below happens under a sealed install.
    code, out = run_with_piped_stdin(
        [patman, "vault", "init"], b"",
        [("passphrase (input hidden)", PASS), ("Repeat it", PASS)], env)
    assert code == 0, f"vault init failed:\n{out}"

    # The real test: token on a pipe, passphrase on the terminal.
    code, out = run_with_piped_stdin(
        [patman, "save", "github", "--stdin", "-d", "piped from a password manager"],
        TOKEN.encode(), [("Vault passphrase", PASS)], env)

    ok = True
    if code != 0:
        print(f"FAIL: save --stdin under a sealed vault exited {code}")
        print(out)
        ok = False
    else:
        print("PASS: save --stdin accepted with a pipe on stdin and a console for the passphrase")

    blob = open(os.path.join(home, ".pat", "github"), "rb").read()
    if not blob.startswith(b"PATMAN\x01\x00"):
        print("FAIL: token file is not sealed")
        ok = False
    elif TOKEN.encode() in blob:
        print("FAIL: plaintext token present in the sealed file")
        ok = False
    else:
        print("PASS: the piped token was sealed on disk")

    # And it must still be usable: unlock, then spend it.
    code, out = run_with_piped_stdin(
        [patman, "unlock", "--minutes", "2"], b"",
        [("Vault passphrase", PASS)], env)
    assert code == 0, f"unlock failed:\n{out}"

    got = subprocess.run(
        [patman, "exec", "github", "--", "sh", "-c", "printf %s \"$PAT_TOKEN\""],
        env=env, capture_output=True, text=True)
    subprocess.run([patman, "describe", "github", "--allow-exec"], env=env, capture_output=True)
    got = subprocess.run(
        [patman, "exec", "github", "--", "sh", "-c", "printf %s \"$PAT_TOKEN\""],
        env=env, capture_output=True, text=True)
    if got.stdout == TOKEN:
        print("PASS: the sealed token round-trips back to its original value")
    else:
        print(f"FAIL: round-trip gave {got.stdout!r} / {got.stderr!r}")
        ok = False

    subprocess.run([patman, "lock"], env=env, capture_output=True)
    subprocess.run(["rm", "-rf", home])
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
