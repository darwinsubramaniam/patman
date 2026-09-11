//! Vetting of pass-through curl arguments, and enforcement of per-service
//! host allowlists.
//!
//! `patman curl` hands the Authorization header to curl, then hands curl an
//! argument list it did not author. Two consequences follow:
//!
//! 1. Some curl options echo the header (verbose/trace/dump-header), load more
//!    configuration (`-K`), or reroute the connection (`--proxy`, `--resolve`,
//!    `--connect-to`). Any of them turns "run this request" into "disclose the
//!    token". They are refused here, in code — an error-message warning is not
//!    a control.
//! 2. Nothing else ties the token to a destination. When the manifest pins
//!    hosts for a service, every URL in the args must be a full `https://` URL
//!    whose host is on the list; schemeless URLs are refused because curl would
//!    guess a scheme and request them anyway.

use crate::error::{bail, Result};

/// Long options refused outright, matched on the part before any `=`.
const BLOCKED_EXACT: &[&str] = &[
    "--verbose",              // prints the Authorization header
    "--dump-header",          // writes headers to a file
    "--libcurl",              // writes generated source including headers
    "--config",               // loads another config that can do any of these
    "--location-trusted",     // re-sends credentials to redirect targets
    "--connect-to",           // reroutes the connection to another host
    "--resolve",              // repoints the hostname at another address
    "--insecure",             // disables TLS verification: MITM reads the header
    "--next",                 // starts a second, unvetted request
    "--unix-socket",          // reroutes to a local socket
    "--abstract-unix-socket", // same
    "--doh-url",              // attacker-chosen resolver
    "--preproxy",             // routes through another hop
    "--proto",                // overrides the https-only restriction
    "--proto-default",        // makes schemeless URLs https and bypass vetting
    "--proto-redir",          // widens redirect protocols
];

/// Families refused by prefix: `--trace`, `--trace-ascii`, `--trace-config`,
/// every `--proxy*`, every `--socks*`.
const BLOCKED_PREFIX: &[&str] = &["--trace", "--proxy", "--socks"];

/// Short options refused wherever they appear in a bundle (`-sSv` hides a `-v`).
/// A bundle with an attached value (`-dvalue`) can false-positive; the error
/// says to pass values as separate arguments, which is the common form anyway.
const BLOCKED_SHORT: &[char] = &[
    'v', // --verbose
    'D', // --dump-header
    'K', // --config
    'x', // --proxy
    'k', // --insecure
    ':', // --next
];

/// Refuse curl options that can disclose the Authorization header or reroute
/// the request. With a Bearer token, redirects are refused too: curl re-sends
/// custom headers to the redirect target, including targets on other hosts.
pub fn vet_args(args: &[String], bearer: bool) -> Result<()> {
    for arg in args {
        if let Some(rest) = arg.strip_prefix("--") {
            let name = rest.split('=').next().unwrap_or(rest);
            let full = format!("--{name}");
            if BLOCKED_EXACT.contains(&full.as_str())
                || BLOCKED_PREFIX.iter().any(|p| full.starts_with(p))
            {
                return refuse(&full);
            }
            if bearer && full == "--location" {
                return refuse_location();
            }
        } else if let Some(rest) = arg.strip_prefix('-') {
            for c in rest.chars() {
                if BLOCKED_SHORT.contains(&c) {
                    return refuse(&format!("-{c}"));
                }
                if bearer && c == 'L' {
                    return refuse_location();
                }
            }
        }
    }
    Ok(())
}

fn refuse<T>(opt: &str) -> Result<T> {
    bail(format!(
        "curl option {opt} is blocked: it can expose the Authorization header \
         (verbose/trace output, header dumps, extra config) or reroute the request \
         (proxy, resolve, connect-to). Re-run without it, and pass short options \
         separately from their values."
    ))
}

fn refuse_location<T>() -> Result<T> {
    bail(
        "-L/--location is blocked with a Bearer token: curl re-sends custom \
         Authorization headers to redirect targets, including other hosts. \
         Request the final URL directly instead.",
    )
}

/// Enforce the manifest's host allowlist: every URL among the args must be a
/// full `https://` URL whose host is pinned for this service. Refuses when no
/// URL is found — a schemeless URL would still be requested by curl, so full
/// URLs are required rather than guessed at.
pub fn enforce_hosts(service: &str, args: &[String], allowed: &[String]) -> Result<()> {
    let urls = collect_urls(args);
    if urls.is_empty() {
        return bail(format!(
            "no https:// URL found in the curl arguments. Hosts are pinned for \
             {service:?}, so the request URL must be passed as a full https:// URL \
             (schemeless URLs are refused)."
        ));
    }
    for url in &urls {
        if !url.to_ascii_lowercase().starts_with("https://") {
            return bail(format!(
                "{url:?} is not https — a token must not travel over cleartext. \
                 Hosts are pinned for {service:?}, so only https:// URLs are allowed."
            ));
        }
        let Some(host) = host_of(url) else {
            return bail(format!("cannot parse a hostname out of {url:?} — refusing"));
        };
        if !host_allowed(&host, allowed) {
            return bail(format!(
                "host {host:?} is not on the allowed list for {service:?} \
                 ({}).\nIf this is intentional, pin it first: \
                 patman describe {service} --host {host}",
                allowed.join(", ")
            ));
        }
    }
    Ok(())
}

/// Everything curl would treat as a URL: `--url <v>` values and any argument
/// with an explicit scheme. Schemeless positionals are curl URLs too, but they
/// cannot be told apart from option values — `enforce_hosts` closes that by
/// refusing when no full URL is present, and `patman curl` restricts curl to
/// https via `proto = "=https"` so a schemeless stowaway (guessed as http) dies
/// inside curl itself.
fn collect_urls(args: &[String]) -> Vec<String> {
    let mut urls = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--url" {
            if let Some(v) = iter.next() {
                urls.push(v.clone());
            }
        } else if let Some(v) = arg.strip_prefix("--url=") {
            urls.push(v.to_string());
        } else {
            let lower = arg.to_ascii_lowercase();
            if lower.starts_with("http://") || lower.starts_with("https://") {
                urls.push(arg.clone());
            }
        }
    }
    urls
}

/// Extract the hostname: authority is everything up to the first `/`, `?` or
/// `#`; userinfo (`user@`) is stripped from the front — `https://good.com@evil.com/`
/// must resolve to `evil.com`, not `good.com` — then any port from the back.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = if let Some(v6) = host.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        host.split(':').next()?
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Exact match, or `*.example.com` matching any subdomain (not the apex).
fn host_allowed(host: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|a| {
        let a = a.to_ascii_lowercase();
        match a.strip_prefix("*.") {
            Some(suffix) => host.ends_with(&format!(".{suffix}")),
            None => host == a,
        }
    })
}

/// A pinned host is a hostname (optionally `*.`-prefixed), nothing more: no
/// scheme, no port, no path. Anything else is a config mistake worth stopping
/// at write time rather than a surprise at request time.
pub fn validate_host(h: &str) -> Result<()> {
    let core = h.strip_prefix("*.").unwrap_or(h);
    let ok = !core.is_empty()
        && core
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !core.starts_with('.')
        && !core.ends_with('.');
    if !ok {
        return bail(format!(
            "invalid host {h:?}: use a bare hostname like api.github.com or \
             *.example.com — no scheme, port, or path"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn blocks_header_echoing_options() {
        for bad in [
            "-v",
            "-sSv",
            "--verbose",
            "--trace",
            "--trace-ascii",
            "--trace-ascii=/tmp/x",
            "-D",
            "--dump-header",
            "-K",
            "--config",
            "--libcurl",
        ] {
            assert!(vet_args(&s(&[bad]), false).is_err(), "{bad} should be blocked");
        }
    }

    #[test]
    fn blocks_rerouting_options() {
        for bad in [
            "-x",
            "--proxy",
            "--proxy=http://evil",
            "--preproxy",
            "--socks5",
            "--connect-to",
            "--resolve",
            "--unix-socket",
            "--doh-url",
            "-k",
            "--insecure",
            "--proto",
            "--proto-default",
            "--next",
            "-:",
            "--location-trusted",
        ] {
            assert!(vet_args(&s(&[bad]), false).is_err(), "{bad} should be blocked");
        }
    }

    #[test]
    fn redirects_blocked_only_for_bearer() {
        assert!(vet_args(&s(&["-L"]), true).is_err());
        assert!(vet_args(&s(&["-sL"]), true).is_err());
        assert!(vet_args(&s(&["--location"]), true).is_err());
        assert!(vet_args(&s(&["-L"]), false).is_ok());
        assert!(vet_args(&s(&["--location"]), false).is_ok());
        // --location-trusted re-sends Basic credentials cross-host: always out.
        assert!(vet_args(&s(&["--location-trusted"]), false).is_err());
    }

    #[test]
    fn allows_ordinary_requests() {
        assert!(vet_args(
            &s(&["-sS", "-X", "POST", "-H", "Accept: application/json",
                 "-d", "{\"a\":1}", "https://api.github.com/user"]),
            true
        )
        .is_ok());
    }

    #[test]
    fn host_parsing_is_not_fooled() {
        assert_eq!(host_of("https://api.github.com/user"), Some("api.github.com".into()));
        assert_eq!(host_of("https://API.GitHub.com:8443/x"), Some("api.github.com".into()));
        // userinfo trick: the real destination is after the @
        assert_eq!(host_of("https://good.com@evil.com/"), Some("evil.com".into()));
        assert_eq!(host_of("https://good.com#@evil.com"), Some("good.com".into()));
        assert_eq!(host_of("https://[::1]:8080/x"), Some("::1".into()));
        assert_eq!(host_of("https:///nohost"), None);
    }

    #[test]
    fn enforces_allowlist() {
        let allowed = s(&["api.github.com", "*.atlassian.net"]);

        assert!(enforce_hosts("gh", &s(&["-sS", "https://api.github.com/user"]), &allowed).is_ok());
        assert!(enforce_hosts("gh", &s(&["--url", "https://x.atlassian.net/rest"]), &allowed).is_ok());

        // wrong host, userinfo disguise, wildcard does not match the apex
        assert!(enforce_hosts("gh", &s(&["https://evil.com/"]), &allowed).is_err());
        assert!(enforce_hosts("gh", &s(&["https://api.github.com@evil.com/"]), &allowed).is_err());
        assert!(enforce_hosts("gh", &s(&["https://atlassian.net/"]), &allowed).is_err());
        assert!(enforce_hosts("gh", &s(&["https://xatlassian.net/"]), &allowed).is_err());
        assert!(enforce_hosts("gh", &s(&["https://x.atlassian.net.evil.com/"]), &allowed).is_err());

        // one good URL does not smuggle a second bad one through
        assert!(enforce_hosts(
            "gh",
            &s(&["https://api.github.com/user", "https://evil.com/x"]),
            &allowed
        )
        .is_err());

        // http, schemeless, and URL-free invocations are refused outright
        assert!(enforce_hosts("gh", &s(&["http://api.github.com/user"]), &allowed).is_err());
        assert!(enforce_hosts("gh", &s(&["-sS", "api.github.com/user"]), &allowed).is_err());
        assert!(enforce_hosts("gh", &s(&["-sS"]), &allowed).is_err());
    }

    #[test]
    fn validates_pinned_hosts() {
        for ok in ["api.github.com", "*.atlassian.net", "localhost", "my-host.corp"] {
            assert!(validate_host(ok).is_ok(), "{ok} should be valid");
        }
        for bad in ["", "https://x.com", "x.com:443", "x.com/path", ".x.com", "x.com.", "a b"] {
            assert!(validate_host(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
