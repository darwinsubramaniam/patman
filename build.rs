//! Stamps the version patman reports with a build number.
//!
//! The build number is the commit count of `HEAD` — deterministic, rising with
//! every commit, and the same on a laptop and in CI for the same commit. So a
//! bug report's `patman --version` names the exact build without anyone having
//! to keep a counter.
//!
//! The count alone is not unique — two branches can both be at commit 42 with
//! different code — so dev builds carry the commit hash too, plus `.dirty` when
//! the working tree had uncommitted changes, because then even the hash does not
//! describe what was compiled.
//!
//! - Release CI sets `PATMAN_RELEASE=1`: `1.0.0:42`. Releases come from `main`,
//!   where the count is unambiguous; `--version` adds the hash.
//! - Any other build from a git checkout: `1.0.0-dev:42+fc2256d`, or
//!   `1.0.0-dev:42+fc2256d.dirty`.
//! - No git at all (the crates.io source tarball): plain `1.0.0`. That source
//!   is exactly a tagged release, and there is no history to count.

use std::path::PathBuf;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn main() {
    let version = env!("CARGO_PKG_VERSION");
    let release = std::env::var("PATMAN_RELEASE").is_ok_and(|v| v == "1");

    // Only this crate's own repository counts. A crates.io source tarball is
    // unpacked under CARGO_HOME, which may itself sit inside some unrelated git
    // repo — whose history says nothing about this build.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let own_repo = git(&["rev-parse", "--show-toplevel"])
        .and_then(|top| PathBuf::from(top).canonicalize().ok())
        .is_some_and(|top| manifest_dir.canonicalize().is_ok_and(|m| m == top));

    let (count, hash) = if own_repo {
        (
            git(&["rev-list", "--count", "HEAD"]),
            git(&["rev-parse", "--short", "HEAD"]),
        )
    } else {
        (None, None)
    };
    // Untracked files count: a new source file that is not committed yet is
    // compiled all the same. Ignored files (target/) do not show up here.
    let dirty = if own_repo {
        if git(&["status", "--porcelain"]).is_some() {
            ".dirty"
        } else {
            ""
        }
    } else {
        ""
    };

    let (short, long) = match (&count, &hash) {
        (Some(n), Some(h)) if release => {
            let s = format!("{version}:{n}{dirty}");
            let l = format!("{s} ({h})");
            (s, l)
        }
        (Some(n), Some(h)) => {
            let s = format!("{version}-dev:{n}+{h}{dirty}");
            (s.clone(), s)
        }
        _ => (version.to_string(), version.to_string()),
    };

    println!("cargo:rustc-env=PATMAN_VERSION={short}");
    println!("cargo:rustc-env=PATMAN_LONG_VERSION={long}");

    // Re-run when HEAD moves: on checkout (HEAD itself), on commit (the branch
    // ref, or packed-refs after a gc), and when the release flag flips. Also
    // when anything that gets compiled changes, so `.dirty` appears and clears
    // with the working tree (cargo scans a directory recursively).
    println!("cargo:rerun-if-env-changed=PATMAN_RELEASE");
    for path in ["src", "build.rs", "Cargo.toml", "Cargo.lock"] {
        println!("cargo:rerun-if-changed={path}");
    }
    if let Some(dir) = git(&["rev-parse", "--git-dir"]).map(PathBuf::from) {
        println!("cargo:rerun-if-changed={}", dir.join("HEAD").display());
        println!(
            "cargo:rerun-if-changed={}",
            dir.join("packed-refs").display()
        );
        println!("cargo:rerun-if-changed={}", dir.join("index").display());
        if let Some(r) = git(&["symbolic-ref", "-q", "HEAD"]) {
            println!("cargo:rerun-if-changed={}", dir.join(r).display());
        }
    }
}
