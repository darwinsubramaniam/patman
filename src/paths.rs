//! Locating `$HOME/.pat`, validating service names, and refusing cloud-sync roots.

use std::path::{Path, PathBuf};

use crate::error::{bail, Result};

/// Directory components that mean "this path is synced to somebody's cloud".
/// Matched case-insensitively against each component of the *resolved* path.
const SYNC_EXACT: &[&str] = &[
    "CloudStorage",     // macOS File Provider root: ~/Library/CloudStorage/*
    "Mobile Documents", // iCloud Drive's on-disk name
    "Dropbox",
    "Google Drive",
    "GoogleDrive",
    "Nextcloud",
    "ownCloud",
    "Box",
    "Box Sync",
    "Sync.com",
    "MEGA",
    "Tresorit",
];

/// Same idea, but these appear with a suffix in practice: `OneDrive - Contoso`,
/// `pCloudDrive`, `iCloudDrive`.
const SYNC_PREFIX: &[&str] = &["OneDrive", "pCloud", "iCloud"];

/// A service name becomes a filename and is interpolated into paths, so it is
/// restricted to `^[A-Za-z0-9_-]+$`. Anything else is rejected outright rather
/// than escaped — there is no legitimate service name that needs more.
pub fn validate_service(name: &str) -> Result<()> {
    if name.is_empty() {
        return bail("service name is empty");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return bail(format!(
            "invalid service name {name:?}: only A-Z a-z 0-9 _ - are allowed"
        ));
    }
    Ok(())
}

pub fn home() -> Result<PathBuf> {
    // std::env::home_dir was deprecated for years over its Windows behaviour and
    // un-deprecated in 1.85 with that behaviour fixed; reading the vars directly
    // keeps this working on older toolchains too.
    #[cfg(unix)]
    let raw = std::env::var_os("HOME");
    #[cfg(windows)]
    let raw = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"));

    match raw {
        Some(h) if !h.is_empty() => Ok(PathBuf::from(h)),
        _ => bail("cannot determine home directory (HOME is unset or empty)"),
    }
}

pub fn pat_dir() -> Result<PathBuf> {
    Ok(home()?.join(".pat"))
}

pub fn manifest_path() -> Result<PathBuf> {
    Ok(pat_dir()?.join("manifest.json"))
}

/// The path of a service's token file. Always derived from the service name —
/// never read back from the manifest, which would break the moment the manifest
/// moved between machines or between Windows and POSIX.
pub fn token_path(service: &str) -> Result<PathBuf> {
    validate_service(service)?;
    Ok(pat_dir()?.join(service))
}

/// Resolve symlinks as far as the path actually exists, then re-attach the
/// components that don't exist yet. `canonicalize` alone fails on a `.pat` that
/// hasn't been created, which is exactly the first-run case.
fn resolve_as_far_as_possible(path: &Path) -> PathBuf {
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cursor = path.to_path_buf();

    loop {
        if let Ok(real) = cursor.canonicalize() {
            let mut out = real;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match cursor.file_name() {
            Some(name) => {
                tail.push(name.to_os_string());
                if !cursor.pop() {
                    return path.to_path_buf();
                }
            }
            None => return path.to_path_buf(),
        }
    }
}

/// Refuse — never warn-and-continue — if the token directory sits inside a
/// cloud-sync root. Every token written there would be uploaded in plaintext,
/// and version history means a later delete does not fully retract it.
///
/// Scope note: standard OneDrive Known Folder Move redirects Desktop, Documents
/// and Pictures, *not* the whole profile, so a default `C:\Users\<n>\.pat` is
/// normally fine. The real cases this catches are full-profile redirection by
/// GPO, a `$HOME` on a synced drive, and a `.pat` symlinked into a sync folder.
/// Resolving symlinks first is what catches the last one.
pub fn assert_not_cloud_synced(dir: &Path) -> Result<()> {
    let real = resolve_as_far_as_possible(dir);

    for component in real.components() {
        let name = component.as_os_str().to_string_lossy();
        let lower = name.to_ascii_lowercase();

        if SYNC_EXACT.iter().any(|m| m.to_ascii_lowercase() == lower) {
            return refuse(&real, &name);
        }
        if SYNC_PREFIX
            .iter()
            .any(|m| lower.starts_with(&m.to_ascii_lowercase()))
        {
            return refuse(&real, &name);
        }
    }

    // Windows exports the active sync roots as environment variables, which
    // catches renamed or non-default folders the name check would miss.
    for var in [
        "OneDrive",
        "OneDriveCommercial",
        "OneDriveConsumer",
        "Dropbox",
    ] {
        if let Some(root) = std::env::var_os(var) {
            if root.is_empty() {
                continue;
            }
            let root = resolve_as_far_as_possible(Path::new(&root));
            if real.starts_with(&root) {
                return refuse(&real, var);
            }
        }
    }

    Ok(())
}

fn refuse(real: &Path, marker: &str) -> Result<()> {
    bail(format!(
        "REFUSING: {} is inside a cloud-sync root ({}).\n\
         Tokens written there upload in plaintext and survive deletion via version \
         history.\nRelocate $HOME/.pat or exclude it from sync, then re-run.",
        real.display(),
        marker
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_service_names() {
        for ok in ["github", "jira", "my_service", "corp-wiki", "s3"] {
            assert!(validate_service(ok).is_ok(), "{ok} should be valid");
        }
    }

    #[test]
    fn rejects_names_that_could_escape_the_directory() {
        for bad in [
            "",
            "..",
            "../../etc/passwd",
            "a/b",
            "a\\b",
            "a b",
            "a.b",
            "a;rm -rf /",
            "a$(whoami)",
            "a\0b",
        ] {
            assert!(validate_service(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn detects_sync_roots_by_component() {
        for synced in [
            "/Users/x/Dropbox/.pat",
            "/Users/x/Library/CloudStorage/OneDrive-Corp/.pat",
            "/Users/x/Library/Mobile Documents/.pat",
            "/Users/x/OneDrive - Keysight/.pat",
            "/Users/x/Google Drive/.pat",
            "/home/x/Nextcloud/.pat",
            "/home/x/pCloudDrive/.pat",
        ] {
            assert!(
                assert_not_cloud_synced(Path::new(synced)).is_err(),
                "{synced} should be refused"
            );
        }
    }

    #[test]
    fn allows_ordinary_home_directories() {
        for clean in ["/Users/x/.pat", "/home/x/.pat", "/var/tmp/somewhere/.pat"] {
            assert!(
                assert_not_cloud_synced(Path::new(clean)).is_ok(),
                "{clean} should be allowed"
            );
        }
    }

    /// The literal path looks clean; only resolving the symlink reveals that
    /// tokens would land in a sync root. This is the case the check exists for.
    #[test]
    fn follows_symlinks_into_sync_roots() {
        let tmp = std::env::temp_dir().join(format!("patman-symlink-test-{}", std::process::id()));
        let sync_root = tmp.join("Dropbox").join("stash");
        let home = tmp.join("home");
        std::fs::create_dir_all(&sync_root).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let link = home.join(".pat");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&sync_root, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&sync_root, &link).unwrap();

        let verdict = assert_not_cloud_synced(&link);
        std::fs::remove_dir_all(&tmp).ok();
        assert!(verdict.is_err(), "symlink into a sync root should be refused");
    }
}
