"""Run a command on a real pty and answer its prompts.

patman deliberately reads passphrases from /dev/tty, so driving it from a test
needs a controlling terminal, not a pipe.
"""
import os
import pty
import select
import sys
import time


def run(argv, script=(), env=None, timeout=25):
    """script: list of (substring_to_wait_for, text_to_send)."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(argv[0], argv, env or os.environ)

    out = b""
    pending = list(script)
    deadline = time.time() + timeout

    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            out += data
        if pending:
            needle, send = pending[0]
            if needle.encode() in out:
                os.write(fd, send.encode())
                pending.pop(0)
                out += b"\n<<sent>>\n"
    try:
        os.close(fd)
    except OSError:
        pass
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), out.decode(errors="replace")


if __name__ == "__main__":
    # argv: ptyrun.py "needle1=reply1,needle2=reply2" cmd args...
    spec = sys.argv[1]
    script = []
    if spec:
        for pair in spec.split("||"):
            needle, _, reply = pair.partition("=")
            script.append((needle, reply + "\n"))
    code, out = run(sys.argv[2:], script)
    sys.stdout.write(out)
    sys.exit(code)
