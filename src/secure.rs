//! Owner-only file creation, and atomic replacement of files that must never be
//! observed half-written.
//!
//! Locking a file to its owner has no portable primitive: POSIX has permission
//! bits, NTFS has ACLs. Both paths live here so callers never branch on OS.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::{Context, Result};

/// Create the directory if needed and restrict it to the current user.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).ctx(format!("creating {}", dir.display()))?;
    lock_down_dir(dir)
}

#[cfg(unix)]
pub fn lock_down_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .ctx(format!("chmod 700 {}", dir.display()))
}

#[cfg(unix)]
pub fn lock_down_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .ctx(format!("chmod 600 {}", path.display()))
}

/// Windows: strip inherited ACEs and grant only the current user.
///
/// The grantee is always identified by SID, never by `%USERNAME%`. The bare SAM
/// name has no domain qualifier, so on a domain-joined machine icacls can
/// resolve it to the wrong principal or fail outright. A raw SID prefixed with
/// `*` needs no name resolution at all: it works offline, survives account
/// renames, and is unaffected by localized group names.
///
/// This is weaker than POSIX 0600 — local Administrators can still reach the
/// file — but it is the closest available and does stop other standard accounts
/// on the machine from reading it.
#[cfg(windows)]
fn icacls(path: &Path, grant: &str) -> Result<()> {
    let sid = current_user_sid()?;
    let status = std::process::Command::new("icacls")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("*{sid}:{grant}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ctx("running icacls")?;
    if !status.success() {
        return crate::error::bail(format!(
            "icacls failed to restrict {} (exit {:?})",
            path.display(),
            status.code()
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn current_user_sid() -> Result<String> {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ])
        .output()
        .ctx("resolving current user SID")?;
    let sid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if sid.is_empty() {
        return crate::error::bail("could not resolve the current user's SID");
    }
    Ok(sid)
}

#[cfg(windows)]
pub fn lock_down_dir(dir: &Path) -> Result<()> {
    icacls(dir, "(OI)(CI)F")
}

#[cfg(windows)]
pub fn lock_down_file(path: &Path) -> Result<()> {
    icacls(path, "(R,W)")
}

/// Write `contents` to `path` atomically, owner-only at every instant.
///
/// The temp file is created inside the destination directory (so the rename is
/// a same-filesystem operation, and therefore atomic) and is locked down
/// *before* any bytes are written — never a window where a fresh token file is
/// world-readable. On failure the temp file is removed rather than left behind.
pub fn write_private_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| crate::error::Error(format!("{} has no parent directory", path.display())))?;

    let pid = std::process::id();
    let stem = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = dir.join(format!(".{stem}.{pid}.tmp"));

    let result = (|| -> Result<()> {
        {
            let mut f = create_private(&tmp)?;
            f.write_all(contents)
                .ctx(format!("writing {}", tmp.display()))?;
            f.sync_all().ctx(format!("syncing {}", tmp.display()))?;
        }
        // Windows rename fails if the destination exists; POSIX replaces silently.
        #[cfg(windows)]
        let _ = fs::remove_file(path);

        fs::rename(&tmp, path).ctx(format!("replacing {}", path.display()))?;
        lock_down_file(path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Create a new file that is owner-only from the moment it exists.
#[cfg(unix)]
fn create_private(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .ctx(format!("creating {}", path.display()))
}

#[cfg(windows)]
fn create_private(path: &Path) -> Result<fs::File> {
    let f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .ctx(format!("creating {}", path.display()))?;
    lock_down_file(path)?;
    Ok(f)
}
