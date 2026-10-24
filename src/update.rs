//! `patman update` — replace this binary with the latest GitHub release.
//!
//! Touches no token: it talks to GitHub, not to `$HOME/.pat/`. The network goes
//! through `curl`, which patman already requires, so there is no HTTP stack in
//! the binary; extraction goes through `tar`, which macOS, Linux, and Windows 10+
//! all ship (Windows' bsdtar reads the `.zip` too).
//!
//! A checksum published next to the archive only proves the download is intact:
//! whoever can replace the archive can replace the checksum too. So the archive
//! must carry a minisign signature from the release key, whose public half is
//! compiled in (from `[package.metadata.binstall.signing]` in Cargo.toml, via
//! build.rs — the same key `cargo binstall` checks). The secret half is a GitHub
//! environment secret that only the release job on a `v*` tag can read, so an
//! archive swapped on the release page, a corrupted download, or a workflow
//! edited in a branch or PR does not get installed. It does not survive a full
//! takeover of the maintainer's GitHub account, which could push a tag that
//! signs anything; that is guarded by the account's 2FA, not by this code.
//!
//! The order is what makes it safe to interrupt:
//!
//! 1. Ask GitHub for the latest release and compare it with this build.
//! 2. Ask before installing (or take `--yes`).
//! 3. Download the archive and its signature, and refuse unless it verifies.
//! 4. Unpack it and run the new binary's `-V` — it has to start, and has to
//!    report the version it was published as.
//! 5. Only then swap it in, by rename, so the old binary is replaced whole or not
//!    at all.
//! 6. End any unlock session: that agent is still the old binary.
//!
//! A binary that cargo or Homebrew installed is left to that tool, which would
//! otherwise go on recording the old version.

use std::cmp::Ordering;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use minisign_verify::{PublicKey, Signature};

use crate::error::{Context, Error, Result, bail};

const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");
const TARGET: &str = env!("PATMAN_TARGET");
const PUBKEY: &str = env!("PATMAN_UPDATE_PUBKEY");

/// Who owns the binary on disk, and so who should replace it.
#[derive(Debug, PartialEq)]
enum Installer {
    /// A release archive unpacked by hand (or by a previous `patman update`).
    Release,
    /// `cargo install` or `cargo binstall`: lives in `$CARGO_HOME/bin`.
    Cargo,
    /// `brew install`: lives under a Homebrew `Cellar`.
    Homebrew,
}

pub fn run(check_only: bool, yes: bool) -> Result<()> {
    clean_leftover();

    let current = env!("CARGO_PKG_VERSION");
    let latest_tag = latest_tag()?;
    let Some(latest) = parse_version(&latest_tag) else {
        return bail(format!(
            "the latest release has an unexpected tag: {latest_tag}"
        ));
    };
    let Some(here) = parse_version(current) else {
        return bail(format!("cannot read this build's version: {current}"));
    };
    let dev = env!("PATMAN_VERSION").contains("-dev");

    match latest.cmp(&here) {
        Ordering::Greater => {}
        Ordering::Equal if dev => {
            println!(
                "patman {} is a development build of {current}, the latest release.",
                env!("PATMAN_VERSION")
            );
            return Ok(());
        }
        _ => {
            println!("patman {current} is up to date.");
            return Ok(());
        }
    }

    let version = latest_tag.trim_start_matches('v');
    println!(
        "patman {version} is available (you have {}).",
        env!("PATMAN_VERSION")
    );
    println!("Release notes: {REPOSITORY}/releases/tag/{latest_tag}");

    let exe = current_exe()?;
    let installer = installer(&exe);
    if installer == Installer::Homebrew {
        println!("This patman was installed by Homebrew; update it with: brew upgrade patman");
        return Ok(());
    }
    if check_only {
        println!("Run `patman update` to install it.");
        return Ok(());
    }

    let question = match installer {
        Installer::Cargo => format!("Install patman {version} with cargo?"),
        _ => format!("Install patman {version} over {}?", exe.display()),
    };
    if !yes && !confirm(&question)? {
        println!("Not updated.");
        return Ok(());
    }

    match installer {
        Installer::Cargo => install_with_cargo(version)?,
        _ => install(&latest_tag, version, &exe)?,
    }
    println!("Updated patman to {version}.");
    end_unlock_session();
    println!("Run `patman init` to refresh the skill and the guard in your AI harnesses.");
    Ok(())
}

/// Ask on the terminal. Without one there is nobody to ask, and an agent's tool
/// call must not be able to replace the binary by piping in a `y`.
fn confirm(question: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        return bail(
            "no terminal to confirm the update on.\n\
             Run `patman update` yourself in a terminal, or pass --yes to install without asking.",
        );
    }
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .ctx("reading the answer")?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes" | "YES"))
}

fn latest_tag() -> Result<String> {
    let Some(slug) = REPOSITORY.strip_prefix("https://github.com/") else {
        return bail(format!(
            "updates come from GitHub releases; the repository is {REPOSITORY}"
        ));
    };
    let url = format!("https://api.github.com/repos/{slug}/releases/latest");
    let body = curl(&[
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        "X-GitHub-Api-Version: 2022-11-28",
        &url,
    ])
    .ctx("checking for the latest release")?;
    let release: serde_json::Value = serde_json::from_slice(&body)?;
    match release["tag_name"].as_str() {
        Some(tag) => Ok(tag.to_string()),
        None => bail("GitHub's latest-release response has no tag_name"),
    }
}

/// `1.2.3`, `v1.2.3`, `1.2.3-dev:42+abc` → (1, 2, 3).
fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let core = s
        .trim()
        .trim_start_matches('v')
        .split(['-', '+', ':'])
        .next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    let v = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(v)
}

fn installer(exe: &Path) -> Installer {
    let in_cellar = exe.components().any(|c| c.as_os_str() == "Cellar");
    if in_cellar {
        return Installer::Homebrew;
    }
    let cargo_bin = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| crate::paths::home().ok().map(|h| h.join(".cargo")))
        .and_then(|home| home.join("bin").canonicalize().ok());
    match (cargo_bin, exe.parent()) {
        (Some(bin), Some(dir)) if bin == dir => Installer::Cargo,
        _ => Installer::Release,
    }
}

/// Let cargo replace its own install, so its record of what is installed stays
/// true. binstall fetches the same signed release archive and checks the same
/// key; without binstall, cargo builds the crates.io source.
fn install_with_cargo(version: &str) -> Result<()> {
    let spec = format!("patman@{version}");
    let has_binstall = Command::new("cargo")
        .args(["binstall", "-V"])
        .output()
        .is_ok_and(|o| o.status.success());
    let mut cmd = Command::new("cargo");
    if has_binstall {
        cmd.args(["binstall", "--no-confirm", "--only-signed", &spec]);
    } else {
        cmd.args(["install", "--locked", &spec]);
    }
    let status = cmd.status().ctx("running cargo (is it on PATH?)")?;
    if !status.success() {
        return bail("cargo could not install the update; the installed patman is unchanged");
    }
    Ok(())
}

/// The archive name for this build's target. Release builds for Linux are
/// static musl binaries, which run anywhere a glibc build does.
fn asset_target() -> Result<String> {
    if TARGET.is_empty() {
        return bail("this build does not know its target, so it cannot pick a release archive");
    }
    Ok(match TARGET.strip_suffix("-linux-gnu") {
        Some(arch) => format!("{arch}-linux-musl"),
        None => TARGET.to_string(),
    })
}

fn install(tag: &str, version: &str, exe: &Path) -> Result<()> {
    if PUBKEY.is_empty() {
        return bail(
            "this build has no release signing key, so it cannot verify a download.\n\
             Install the update the way you installed patman.",
        );
    }
    let target = asset_target()?;
    let windows = target.contains("-windows-");
    let stem = format!("patman-{version}-{target}");
    let archive = format!("{stem}.{}", if windows { "zip" } else { "tar.gz" });
    let base = format!("{REPOSITORY}/releases/download/{tag}");

    println!("Downloading {archive}...");
    let sig = match curl(&[&format!("{base}/{archive}.sig")]) {
        Ok(sig) => sig,
        Err(e) => {
            return bail(format!(
                "release {tag} has no signature for {archive}: {e}\n\
                 An unsigned release is not installed. Nothing was changed."
            ));
        }
    };
    let bytes = curl(&[&format!("{base}/{archive}")]).ctx(format!("downloading {archive}"))?;
    verify(
        PUBKEY,
        &bytes,
        &String::from_utf8_lossy(&sig),
        tag,
        &archive,
    )?;

    let work = TempDir::new()?;
    let archive_path = work.0.join(&archive);
    std::fs::write(&archive_path, &bytes).ctx("saving the download")?;

    let status = Command::new("tar")
        .arg("-xf")
        .arg(&archive_path)
        .arg("-C")
        .arg(&work.0)
        .status()
        .ctx("running tar (is it on PATH?)")?;
    if !status.success() {
        return bail(format!("tar could not unpack {archive}"));
    }
    let new = work
        .0
        .join(&stem)
        .join(if windows { "patman.exe" } else { "patman" });

    // A binary that will not start, or that reports some other version, is not
    // the one we meant to install.
    let out = Command::new(&new)
        .arg("-V")
        .output()
        .ctx("running the downloaded patman")?;
    let reported = String::from_utf8_lossy(&out.stdout);
    if !out.status.success()
        || parse_version(reported.trim_start_matches("patman ")) != parse_version(version)
    {
        return bail(format!(
            "the downloaded patman did not report version {version} (got: {}). Nothing was changed.",
            reported.trim()
        ));
    }

    replace(&new, exe)
}

/// Check the signature, and that it was made for this file of this release: the
/// release workflow signs with the trusted comment `patman <tag> <file>`, and the
/// trusted comment is covered by the signature. So a validly signed archive from
/// another release cannot be passed off as this one.
fn verify(pubkey: &str, bytes: &[u8], sig: &str, tag: &str, archive: &str) -> Result<()> {
    let refuse = |why: String| -> Result<()> {
        bail(format!(
            "{archive} failed signature verification: {why}. Nothing was changed."
        ))
    };
    let key = PublicKey::from_base64(pubkey)
        .map_err(|e| Error(format!("the compiled-in release key is invalid: {e}")))?;
    let sig = match Signature::decode(sig) {
        Ok(sig) => sig,
        Err(e) => return refuse(e.to_string()),
    };
    if let Err(e) = key.verify(bytes, &sig, false) {
        return refuse(e.to_string());
    }
    let expected = format!("patman {tag} {archive}");
    if sig.trusted_comment() != expected {
        return refuse(format!(
            "it was signed as \"{}\", not \"{expected}\"",
            sig.trusted_comment()
        ));
    }
    Ok(())
}

/// Copy the new binary next to the old one (same filesystem, so the rename is
/// atomic), then rename it over. A running binary can be renamed over on unix;
/// on Windows it cannot be overwritten, only moved aside first.
fn replace(new: &Path, exe: &Path) -> Result<()> {
    let dir = exe
        .parent()
        .ok_or_else(|| Error("the patman binary has no parent directory".into()))?;
    let staged = dir.join(format!(".patman-update-{}", std::process::id()));
    if let Err(e) = std::fs::copy(new, &staged) {
        return bail(permission_hint(e, dir));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
        if let Err(e) = std::fs::rename(&staged, exe) {
            let _ = std::fs::remove_file(&staged);
            return bail(permission_hint(e, dir));
        }
    }

    #[cfg(windows)]
    {
        let old = old_path(exe);
        let _ = std::fs::remove_file(&old);
        if let Err(e) = std::fs::rename(exe, &old) {
            let _ = std::fs::remove_file(&staged);
            return bail(permission_hint(e, dir));
        }
        if let Err(e) = std::fs::rename(&staged, exe) {
            // Put the old binary back rather than leave no patman at all.
            let _ = std::fs::rename(&old, exe);
            let _ = std::fs::remove_file(&staged);
            return bail(permission_hint(e, dir));
        }
    }

    Ok(())
}

fn permission_hint(e: std::io::Error, dir: &Path) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        format!(
            "cannot write to {}: {e}.\n\
             Re-run with the rights to that directory, or update the way you installed \
             (cargo binstall patman / cargo install patman).",
            dir.display()
        )
    } else {
        format!("replacing the patman binary in {}: {e}", dir.display())
    }
}

/// An open unlock session is served by the old binary, which keeps running
/// after the file is replaced — and the new client may not speak its protocol.
/// End it; the next `patman unlock` starts the new one.
fn end_unlock_session() {
    #[cfg(unix)]
    if crate::agent::is_running() {
        match crate::agent::send(&crate::agent::Request::Lock) {
            Ok(_) => println!("Ended the unlock session; run `patman unlock` to start a new one."),
            Err(e) => eprintln!(
                "patman: could not end the unlock session ({e}); run `patman lock`, then `patman unlock`."
            ),
        }
    }
}

/// The real file, not a symlink to it (a package manager's bin link, say):
/// renaming over the link would replace the link and strand the binary.
fn current_exe() -> Result<PathBuf> {
    let exe = std::env::current_exe().ctx("locating the running patman")?;
    exe.canonicalize().ctx("locating the running patman")
}

#[cfg(windows)]
fn old_path(exe: &Path) -> PathBuf {
    exe.with_extension("old.exe")
}

/// The binary Windows had to move aside last time is free to delete now.
fn clean_leftover() {
    #[cfg(windows)]
    if let Ok(exe) = current_exe() {
        let _ = std::fs::remove_file(old_path(&exe));
    }
}

fn curl(args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("curl")
        .args([
            "-fsSL",
            "--proto",
            "=https",
            "--tlsv1.2",
            "-A",
            "patman-update",
        ])
        .args(args)
        .output()
        .ctx("running curl (is it installed and on PATH?)")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return bail(err.trim().trim_start_matches("curl: ").to_string());
    }
    Ok(out.stdout)
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self> {
        let dir = std::env::temp_dir().join(format!("patman-update-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).ctx("creating a temporary directory")?;
        Ok(Self(dir))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_versions() {
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.0.0-dev:42+abc.dirty"), Some((1, 0, 0)));
        assert_eq!(parse_version("patman 1.0.0:42"), None);
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert!(parse_version("v1.10.0") > parse_version("v1.9.9"));
    }

    // A throwaway key, made only for this test; it signs nothing real.
    const TEST_KEY: &str = "RWS4FxFianABoRXWqJcHrt3Ptaxr/nAjp8YpHPk+6K1Y3UCgbWoZjibV";
    const TEST_ARCHIVE: &[u8] = b"patman test archive";
    const TEST_SIG: &str = "untrusted comment: signature from minisign secret key
RUS4FxFianABoaT0WIR8KJxqNUb21urI2bQHyWRNIrK8trWhY0/rIAsm4iYpCJcMwmhA2c1HaXwlvv3Euy77qx313dXlBl69lQQ=
trusted comment: patman v9.9.9 archive.tar.gz
NbayfyhWJzdd2ftoMUi9YbrZj+oqMNyhe+J9mD3dmLx9cKt+UuhUkdKAubup6NUaVVnMuy62ctoONStlzax0Ag==
";

    #[test]
    fn accepts_a_good_signature() {
        verify(TEST_KEY, TEST_ARCHIVE, TEST_SIG, "v9.9.9", "archive.tar.gz").unwrap();
    }

    #[test]
    fn refuses_a_tampered_archive() {
        let err = verify(
            TEST_KEY,
            b"patman evil archive",
            TEST_SIG,
            "v9.9.9",
            "archive.tar.gz",
        );
        assert!(err.is_err());
    }

    #[test]
    fn refuses_a_signature_moved_to_another_release_or_file() {
        assert!(
            verify(
                TEST_KEY,
                TEST_ARCHIVE,
                TEST_SIG,
                "v9.9.10",
                "archive.tar.gz"
            )
            .is_err()
        );
        assert!(verify(TEST_KEY, TEST_ARCHIVE, TEST_SIG, "v9.9.9", "other.tar.gz").is_err());
    }

    #[test]
    fn refuses_another_key() {
        // A valid key, just not the one that signed.
        let other = "RWR8UsgYsARYqQjKDzKGU35RBNqzwDuPzuZO9A/QwzkTVm2NWBu6SQtE";
        assert!(verify(other, TEST_ARCHIVE, TEST_SIG, "v9.9.9", "archive.tar.gz").is_err());
    }

    #[test]
    fn tells_installers_apart() {
        assert_eq!(
            installer(Path::new("/opt/homebrew/Cellar/patman/1.1.0/bin/patman")),
            Installer::Homebrew
        );
        assert_eq!(
            installer(Path::new("/usr/local/bin/patman")),
            Installer::Release
        );
    }
}
