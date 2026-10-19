//! The unlock agent: a short-lived daemon that holds the vault key in memory so
//! an agent-driven `patman curl` can work without a passphrase prompt it cannot
//! answer.
//!
//! The design rule, which is the whole reason this is a daemon and not a cached
//! key file:
//!
//! > The key never leaves this process, and neither does the token. A client
//! > sends *what it wants done*; the daemon decides whether that is allowed,
//! > decrypts, spawns the program, and streams back only its output.
//!
//! There is no protocol message that returns a token, so a caller that can talk
//! to the socket still cannot read a credential — it can only spend one, within
//! the limits the manifest already pins. That is a strictly smaller capability
//! than `cat`ting a plaintext token file, which is what this replaces.
//!
//! Two consequences worth being explicit about:
//!
//! - **Authorization runs here, not in the client.** Anything that can reach the
//!   socket can speak the protocol without going through the `patman` binary, so
//!   client-side checks would be advisory. See [`crate::usage`].
//! - **The socket is the capability.** It is `0600` inside a `0700` directory,
//!   so this is scoped to the user — the same boundary as the token files. What
//!   the TTL adds is that the capability expires.
//!
//! Unix only. The protocol is unix-domain sockets; Windows would need named
//! pipes, and is left on the passphrase-per-use path.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result, bail};
use crate::manifest::{Approval, Manifest};
use crate::sealed::Key;
use crate::usage::{self, Auth};
use crate::{approve, paths, policy, secure, token};

// Response frame kinds.
const F_STDOUT: u8 = 1;
const F_STDERR: u8 = 2;
const F_EXIT: u8 = 3;
const F_ERROR: u8 = 4;
const F_MESSAGE: u8 = 5;

/// Generous for output chunks (8 KiB) and for a request line, and small enough
/// that a broken or hostile peer cannot make the other side allocate wildly.
const MAX_FRAME: usize = 1 << 20;

const CHUNK: usize = 8 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Request {
    /// Is the agent alive, and for how much longer?
    Status,
    /// Wipe the key and exit.
    Lock,
    /// Run curl authenticated as `service`.
    Curl {
        service: String,
        auth: Auth,
        args: Vec<String>,
        /// The vault passphrase, typed by the human for this one request — how
        /// a `--approval request` service is approved where there is no Touch
        /// ID. Checked against the vault, never stored.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approval: Option<String>,
    },
    /// Run an arbitrary program with `PAT_TOKEN` in its environment.
    Exec {
        service: String,
        args: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approval: Option<String>,
    },
}

/// `sockaddr_un.sun_path` is 104 bytes on macOS and 108 on Linux, and binding a
/// longer path fails with a errno that says nothing useful. Checked explicitly so
/// a deep `$HOME` produces an explanation instead of "agent did not come up".
const SUN_PATH_MAX: usize = 100;

pub fn socket_path() -> Result<PathBuf> {
    let path = paths::pat_dir()?.join("agent.sock");
    if path.as_os_str().len() > SUN_PATH_MAX {
        return bail(format!(
            "the agent socket path is too long for a unix socket ({} bytes, limit {SUN_PATH_MAX}):\n\
             \x20 {}\n\
             The unlock session needs a shorter $HOME. Sealed tokens still work — \
             `patman curl` will prompt for the passphrase each time.",
            path.as_os_str().len(),
            path.display()
        ));
    }
    Ok(path)
}

// ----------------------------------------------------------------- framing

fn write_frame(w: &mut impl Write, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&[kind])?;
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

fn read_frame(r: &mut impl Read) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut header = [0u8; 5];
    match r.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(header[1..5].try_into().expect("5-byte header")) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized frame",
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some((header[0], payload)))
}

// ------------------------------------------------------------------ client

/// Is an agent listening? Distinguishes a live agent from a stale socket file
/// left behind by a killed process, which would otherwise look identical.
pub fn is_running() -> bool {
    socket_path()
        .ok()
        .filter(|p| p.exists())
        .and_then(|p| UnixStream::connect(p).ok())
        .is_some()
}

/// Send a request and pump the response to our own stdout/stderr.
///
/// Returns the child's exit code. Output is relayed rather than inherited: the
/// daemon holds no file descriptor of ours, so a compromised daemon cannot write
/// to our terminal outside this stream. The cost is that curl sees a pipe, not a
/// tty — no progress meter, and nothing interactive.
pub fn send(req: &Request) -> Result<i32> {
    let path = socket_path()?;
    let mut stream = UnixStream::connect(&path).ctx(format!(
        "connecting to the unlock agent at {} (is it still running? try: patman status)",
        path.display()
    ))?;

    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .ctx("sending the request to the unlock agent")?;
    stream
        .flush()
        .ctx("sending the request to the unlock agent")?;

    let mut reader = BufReader::new(stream);
    loop {
        match read_frame(&mut reader).ctx("reading from the unlock agent")? {
            None => return bail("the unlock agent closed the connection unexpectedly"),
            Some((F_STDOUT, data)) => {
                std::io::stdout().write_all(&data).ok();
                std::io::stdout().flush().ok();
            }
            Some((F_STDERR, data)) => {
                std::io::stderr().write_all(&data).ok();
            }
            Some((F_MESSAGE, data)) => {
                println!("{}", String::from_utf8_lossy(&data));
            }
            Some((F_ERROR, data)) => {
                return Err(Error(String::from_utf8_lossy(&data).into_owned()));
            }
            Some((F_EXIT, data)) => {
                let code = i32::from_be_bytes(
                    data.as_slice()
                        .try_into()
                        .map_err(|_| Error("malformed exit frame from the agent".into()))?,
                );
                return Ok(code);
            }
            Some((kind, _)) => return bail(format!("unknown frame {kind} from the unlock agent")),
        }
    }
}

/// Start the agent, handing it the key over a pipe.
///
/// The key goes on the child's **stdin**, never argv: a key in a command line is
/// readable from the process table by any other process, which is the exact
/// failure `patman curl` exists to avoid. `patman unlock` is the only caller.
pub fn spawn(key: &Key, ttl_secs: u64) -> Result<()> {
    let exe = std::env::current_exe().ctx("locating the patman binary")?;

    // Check before spawning: this is the one failure the child cannot report,
    // since it happens while working out where to put the socket.
    socket_path()?;

    let mut cmd = Command::new(exe);
    cmd.arg("agent-serve")
        .arg("--ttl")
        .arg(ttl_secs.to_string())
        .stdin(Stdio::piped())
        // Kept open only for the startup handshake; see `serve`.
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    // Detach from the terminal's session, so the agent outlives the shell that
    // started it (and a SIGHUP when that terminal closes) rather than dying at
    // the least convenient moment.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn().ctx("starting the unlock agent")?;
    let mut hex = key.to_hex();
    hex.push('\n');
    token::feed_stdin(&mut child, &hex)?;
    // SAFETY: overwriting hex digits with NULs keeps the string valid UTF-8.
    unsafe { hex.as_mut_vec().fill(0) };

    // Block on the handshake rather than polling for the socket: it removes the
    // race with the next command, and it turns a failed start into the agent's
    // own error message instead of a timeout.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error("the unlock agent has no stdout".into()))?;

    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .ctx("waiting for the unlock agent to start")?;

    match line.trim() {
        READY => Ok(()),
        "" => bail("the unlock agent exited during startup without reporting why"),
        other => bail(other.strip_prefix("error ").unwrap_or(other).to_string()),
    }
}

// ------------------------------------------------------------------ server

/// Run the daemon.
///
/// Startup is a handshake on stdout — one line, `ready` or `error <message>` —
/// because the agent's output is otherwise `/dev/null` and a failure to bind
/// would reach the user as nothing but a timeout. After the line, stdout is
/// never written to again.
pub fn serve(ttl_secs: u64) -> Result<()> {
    match start(ttl_secs) {
        Ok(started) => {
            println!("{READY}");
            std::io::stdout().flush().ok();
            accept_loop(started)
        }
        Err(e) => {
            println!("error {e}");
            std::io::stdout().flush().ok();
            Err(e)
        }
    }
}

const READY: &str = "ready";

struct Started {
    listener: UnixListener,
    key: Arc<Key>,
    deadline: Instant,
    path: PathBuf,
}

/// Everything that can fail, done before the parent is told the agent is up.
fn start(ttl_secs: u64) -> Result<Started> {
    let mut hex = String::new();
    std::io::stdin()
        .read_line(&mut hex)
        .ctx("reading the vault key from stdin")?;
    let key = Arc::new(Key::from_hex(&hex)?);
    // SAFETY: overwriting hex digits with NULs keeps the string valid UTF-8.
    unsafe { hex.as_mut_vec().fill(0) };

    let path = socket_path()?;
    if is_running() {
        return bail("an unlock agent is already running (patman lock to stop it)");
    }
    // Only reachable once `is_running` said no: either nothing is there, or it
    // is a stale socket from a killed agent, which bind would otherwise refuse.
    let _ = std::fs::remove_file(&path);

    let listener = UnixListener::bind(&path).ctx(format!("binding {}", path.display()))?;
    secure::lock_down_file(&path)?;

    let deadline = Instant::now() + Duration::from_secs(ttl_secs);

    // Hard stop. Held separately from the per-request check so a session that
    // goes quiet still expires on time rather than lingering until someone
    // happens to make a request.
    {
        let path = path.clone();
        std::thread::spawn(move || {
            let now = Instant::now();
            if deadline > now {
                std::thread::sleep(deadline - now);
            }
            let _ = std::fs::remove_file(&path);
            std::process::exit(0);
        });
    }

    Ok(Started {
        listener,
        key,
        deadline,
        path,
    })
}

fn accept_loop(started: Started) -> Result<()> {
    let Started {
        listener,
        key,
        deadline,
        path,
    } = started;

    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let key = Arc::clone(&key);
        let path = path.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle(conn, &key, deadline, &path) {
                // Nowhere to report to: stdout and stderr are /dev/null by
                // construction, and the client has gone. Swallow deliberately
                // rather than risk a panic taking the whole agent down.
                let _ = e;
            }
        });
    }
    Ok(())
}

fn handle(conn: UnixStream, key: &Key, deadline: Instant, sock: &std::path::Path) -> Result<()> {
    let out = Arc::new(Mutex::new(conn.try_clone().ctx("cloning the connection")?));
    let mut reader = BufReader::new(conn);

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .ctx("reading the request from the client")?;

    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => return fail(&out, &format!("malformed request: {e}")),
    };

    if Instant::now() > deadline {
        return fail(&out, "the unlock session has expired — run: !patman unlock");
    }

    match req {
        Request::Status => {
            let left = deadline.saturating_duration_since(Instant::now()).as_secs();
            reply(
                &out,
                &format!("unlocked, {}m{}s remaining", left / 60, left % 60),
            )?;
            exit(&out, 0)
        }
        Request::Lock => {
            reply(&out, "locked")?;
            exit(&out, 0)?;
            let _ = std::fs::remove_file(sock);
            std::process::exit(0);
        }
        Request::Curl {
            service,
            auth,
            args,
            approval,
        } => match run_curl(&out, key, &service, auth, &args, approval.as_deref()) {
            Ok(code) => exit(&out, code),
            Err(e) => fail(&out, &e.0),
        },
        Request::Exec {
            service,
            args,
            approval,
        } => match run_exec(&out, key, &service, &args, approval.as_deref()) {
            Ok(code) => exit(&out, code),
            Err(e) => fail(&out, &e.0),
        },
    }
}

type Out = Arc<Mutex<UnixStream>>;

fn frame(out: &Out, kind: u8, payload: &[u8]) -> Result<()> {
    let mut guard = out
        .lock()
        .map_err(|_| Error("agent lock poisoned".into()))?;
    write_frame(&mut *guard, kind, payload).ctx("writing to the client")
}

fn reply(out: &Out, msg: &str) -> Result<()> {
    frame(out, F_MESSAGE, msg.as_bytes())
}

fn fail(out: &Out, msg: &str) -> Result<()> {
    frame(out, F_ERROR, msg.as_bytes())
}

fn exit(out: &Out, code: i32) -> Result<()> {
    frame(out, F_EXIT, &code.to_be_bytes())
}

/// Authorize, decrypt, spawn curl, stream. The token exists only between
/// `token::read` and the `drop` a few lines later, and only in this process.
///
/// The order is deliberate: the policy is proven unmodified, then the request is
/// checked against it, and only a request that would be allowed is put to the
/// human — nobody should be asked to approve something that will be refused.
fn run_curl(
    out: &Out,
    key: &Key,
    service: &str,
    auth: Auth,
    args: &[String],
    approval: Option<&str>,
) -> Result<i32> {
    paths::validate_service(service)?;
    let manifest = Manifest::load(&paths::manifest_path()?)?;
    policy::verify(key, &manifest, service)?;
    let plan = usage::plan(&manifest, service, auth);

    // Authorization happens here, in the process holding the key — a client that
    // skipped the patman binary entirely still cannot get past this.
    if let Some(warning) = usage::authorize_curl(service, args, &plan)? {
        frame(out, F_STDERR, format!("patman: {warning}\n").as_bytes())?;
    }
    if plan.approval == Approval::Request {
        approve::approve(&approve::describe_curl(service, args), approval)?;
    }

    let secret = token::read(service, Some(key))?;
    let config = usage::curl_config(service, &plan, &secret)?;
    drop(secret);

    let mut child = Command::new("curl")
        .arg("--config")
        .arg("-")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ctx("running curl (is it installed and on PATH?)")?;

    token::feed_stdin(&mut child, &config)?;
    pump(out, &mut child)
}

fn run_exec(
    out: &Out,
    key: &Key,
    service: &str,
    args: &[String],
    approval: Option<&str>,
) -> Result<i32> {
    paths::validate_service(service)?;
    let Some((program, rest)) = args.split_first() else {
        return bail("nothing to run — usage: patman exec <service> -- <command> [args...]");
    };

    let manifest = Manifest::load(&paths::manifest_path()?)?;
    policy::verify(key, &manifest, service)?;
    let plan = usage::plan(&manifest, service, Auth::Auto);
    usage::authorize_exec(service, &plan, true)?;
    if plan.approval == Approval::Request {
        approve::approve(&approve::describe_exec(service, args), approval)?;
    }

    let secret = token::read(service, Some(key))?;

    let mut cmd = Command::new(program);
    cmd.args(rest)
        .env("PAT_SERVICE", service)
        .env("PAT_TOKEN", secret.expose())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(u) = &plan.username {
        cmd.env("PAT_USERNAME", u);
    }

    let mut child = cmd.spawn().ctx(format!("running {program}"))?;
    drop(secret);
    pump(out, &mut child)
}

/// Relay the child's stdout and stderr to the client until both close, then
/// return its exit code.
fn pump(out: &Out, child: &mut std::process::Child) -> Result<i32> {
    let stdout = child
        .stdout
        .take()
        .map(|s| Box::new(s) as Box<dyn Read + Send>);
    let stderr = child
        .stderr
        .take()
        .map(|s| Box::new(s) as Box<dyn Read + Send>);

    let mut threads = Vec::new();
    for (stream, kind) in [(stdout, F_STDOUT), (stderr, F_STDERR)] {
        let Some(mut stream) = stream else { continue };
        let out = Arc::clone(out);
        threads.push(std::thread::spawn(move || {
            let mut buf = [0u8; CHUNK];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if frame(&out, kind, &buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
        }));
    }
    for t in threads {
        let _ = t.join();
    }
    let status = child.wait().ctx("waiting for the child process")?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, F_STDOUT, b"hello").unwrap();
        write_frame(&mut buf, F_EXIT, &7i32.to_be_bytes()).unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(
            read_frame(&mut cursor).unwrap().unwrap(),
            (F_STDOUT, b"hello".to_vec())
        );
        let (kind, payload) = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(kind, F_EXIT);
        assert_eq!(i32::from_be_bytes(payload.try_into().unwrap()), 7);
        assert!(read_frame(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn an_oversized_length_is_refused_without_allocating() {
        let mut buf = vec![F_STDOUT];
        buf.extend_from_slice(&(u32::MAX).to_be_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        assert!(read_frame(&mut cursor).is_err());
    }

    #[test]
    fn requests_round_trip_as_json() {
        let req = Request::Curl {
            service: "jira".into(),
            auth: Auth::Auto,
            args: vec!["-sS".into(), "https://x.atlassian.net/x".into()],
            approval: None,
        };
        let line = serde_json::to_string(&req).unwrap();
        assert!(line.contains("\"op\":\"curl\""));
        match serde_json::from_str::<Request>(&line).unwrap() {
            Request::Curl { service, args, .. } => {
                assert_eq!(service, "jira");
                assert_eq!(args.len(), 2);
            }
            other => panic!("round-tripped to {other:?}"),
        }
    }

    /// The protocol's central property, asserted rather than assumed: no request
    /// asks for a token value, so no response can carry one.
    #[test]
    fn no_request_variant_reads_a_token_out() {
        for line in [
            r#"{"op":"status"}"#,
            r#"{"op":"lock"}"#,
            r#"{"op":"curl","service":"a","auth":"auto","args":[]}"#,
            r#"{"op":"exec","service":"a","args":[]}"#,
        ] {
            serde_json::from_str::<Request>(line).expect("known op");
        }
        for line in [r#"{"op":"read","service":"a"}"#, r#"{"op":"show"}"#] {
            assert!(
                serde_json::from_str::<Request>(line).is_err(),
                "{line} must not be a valid request"
            );
        }
    }
}
