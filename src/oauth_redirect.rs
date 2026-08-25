//! Shared redirect URI validation for the OAuth proxy and DCR shim.

use anyhow::{Context, Result};
use url::Url;

/// Comma-separated exact redirect URI allowlist for proxied OAuth clients.
pub const ENV_OAUTH_REDIRECT_URIS: &str = "CARDDAV_MCP_OAUTH_REDIRECT_URIS";

pub fn parse_allowlist(raw: &str, key: &str) -> Result<Vec<String>> {
    let mut uris = Vec::new();
    for uri in raw.split(',').map(str::trim).filter(|uri| !uri.is_empty()) {
        validate_redirect_uri(uri, key)?;
        if !uris.iter().any(|allowed| allowed == uri) {
            uris.push(uri.to_owned());
        }
    }
    if uris.is_empty() {
        anyhow::bail!("{key} must contain at least one redirect URI");
    }
    Ok(uris)
}

pub fn is_allowed_redirect_uri(allowed: &[String], uri: &str) -> bool {
    if validate_redirect_uri(uri, "redirect_uri").is_err() {
        return false;
    }
    if allowed.iter().any(|entry| entry == uri) {
        return true;
    }
    matches_loopback_entry(allowed, uri)
}

/// RFC 8252 §7.3: the authorization server MUST allow any port for a loopback
/// redirect URI, because a native client binds an ephemeral local port per
/// session. Scheme, host, path and query still have to match an allowlist
/// entry exactly — only the port is free, and only for cleartext loopback.
/// `https` and private-use entries stay byte-for-byte exact, port included.
///
/// The loopback-host check on the requested URI deliberately duplicates the one
/// in `validate_redirect_uri`, so this function stays correct on its own rather
/// than depending on its caller having validated first. No test can falsify it
/// while `is_allowed_redirect_uri` validates before calling here.
fn matches_loopback_entry(allowed: &[String], uri: &str) -> bool {
    let Ok(candidate) = Url::parse(uri) else {
        return false;
    };
    if candidate.scheme() != "http" {
        return false;
    }
    let Some(host) = candidate.host_str() else {
        return false;
    };
    if !is_loopback_host(host) {
        return false;
    }
    allowed.iter().any(|entry| {
        Url::parse(entry).is_ok_and(|entry| {
            entry.scheme() == "http"
                && entry.host_str() == Some(host)
                && entry.path() == candidate.path()
                && entry.query() == candidate.query()
        })
    })
}

/// Loopback hosts accepted for cleartext `http://` redirect URIs
/// (RFC 8252 §7.3). Anything else over `http` would put the authorization
/// code on the wire in cleartext.
fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

fn validate_redirect_uri(uri: &str, key: &str) -> Result<()> {
    if uri.trim() != uri || uri.is_empty() {
        anyhow::bail!(
            "{key} entries must be non-empty absolute URLs without surrounding whitespace"
        );
    }
    let url = Url::parse(uri).with_context(|| format!("invalid {key} redirect URI: {uri}"))?;
    match url.scheme() {
        "https" => {
            if url.host_str().is_none() {
                anyhow::bail!("{key} https entries must include a host: {uri}");
            }
        }
        // RFC 8252 §7.3 loopback interface redirection. Native apps bind an
        // ephemeral local port, so this is the one case where cleartext is
        // acceptable — but only on a loopback host.
        "http" => {
            let host = url.host_str().unwrap_or_default();
            if !is_loopback_host(host) {
                anyhow::bail!(
                    "{key} http entries are only allowed on loopback hosts \
                     (localhost, 127.0.0.1, [::1]): {uri}"
                );
            }
        }
        // RFC 8252 §7.1 private-use ("custom") URI schemes, e.g.
        // `cursor://…` / `grokbot://…` used by native MCP clients. The exact
        // string allowlist in `is_allowed_redirect_uri` is the actual control
        // — an operator must list the URI explicitly — so this arm only
        // rejects structurally broken input.
        scheme => {
            if scheme.is_empty() {
                anyhow::bail!("{key} entries must have a scheme: {uri}");
            }
        }
    }
    if url.fragment().is_some() {
        anyhow::bail!("{key} entries must not contain URI fragments: {uri}");
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("{key} entries must not contain user info: {uri}");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_matches_exact_redirect_uri_only() {
        let allowed = parse_allowlist("https://claude.ai/api/mcp/auth_callback", "TEST").unwrap();

        assert!(is_allowed_redirect_uri(
            &allowed,
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://claude.ai/api/mcp/auth_callback/"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://attacker.example/callback"
        ));
    }

    #[test]
    fn allowlist_rejects_fragments_and_userinfo() {
        assert!(parse_allowlist("https://claude.ai/cb#frag", "TEST").is_err());
        assert!(parse_allowlist("https://user@claude.ai/cb", "TEST").is_err());
    }

    /// RFC 8252 §7.1 — native MCP clients (Cursor / Grok Bot desktop) register
    /// private-use scheme callbacks. They must survive `parse_allowlist` (which
    /// runs at startup over the env var) and then match exactly.
    #[test]
    fn allowlist_accepts_private_use_schemes() {
        let allowed = parse_allowlist(
            "cursor://anysphere.cursor-mcp/oauth/callback,grokbot://mcp/oauth/callback",
            "TEST",
        )
        .unwrap();

        assert!(is_allowed_redirect_uri(
            &allowed,
            "cursor://anysphere.cursor-mcp/oauth/callback"
        ));
        assert!(is_allowed_redirect_uri(
            &allowed,
            "grokbot://mcp/oauth/callback"
        ));
        // Still exact-match: a different private-use URI is not smuggled in.
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "cursor://anysphere.cursor-mcp/oauth/callback/extra"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "evil://mcp/oauth/callback"
        ));
    }

    /// RFC 8252 §7.3 — loopback HTTP is allowed; any other cleartext host is
    /// not. This is a tightening: `http://` on an arbitrary host used to pass.
    #[test]
    fn http_is_loopback_only() {
        for uri in [
            "http://localhost:8787/callback",
            "http://127.0.0.1:8787/callback",
        ] {
            assert!(parse_allowlist(uri, "TEST").is_ok(), "should accept {uri}");
        }
        for uri in [
            "http://evil.example/callback",
            "http://localhost.evil.example/callback",
        ] {
            assert!(parse_allowlist(uri, "TEST").is_err(), "should reject {uri}");
        }
    }

    /// RFC 8252 §7.3 — a native client binds a random loopback port per
    /// session, so an allowlisted loopback entry must match on any port.
    #[test]
    fn loopback_entry_matches_any_port() {
        let allowed = parse_allowlist("http://localhost:8787/callback", "TEST").unwrap();

        assert!(is_allowed_redirect_uri(
            &allowed,
            "http://localhost:3118/callback"
        ));
        assert!(is_allowed_redirect_uri(
            &allowed,
            "http://localhost:8787/callback"
        ));
        // No port at all is still port-agnostic loopback.
        assert!(is_allowed_redirect_uri(
            &allowed,
            "http://localhost/callback"
        ));
    }

    /// The port is the only thing RFC 8252 §7.3 relaxes. Path, host and query
    /// keep matching exactly.
    #[test]
    fn loopback_port_relaxation_does_not_relax_host_or_path() {
        let allowed = parse_allowlist("http://localhost:8787/callback", "TEST").unwrap();

        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://localhost:3118/other"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://localhost:3118/callback/extra"
        ));
        // A different loopback host must be allowlisted in its own right.
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://127.0.0.1:3118/callback"
        ));
        assert!(!is_allowed_redirect_uri(&allowed, "http://[::1]/callback"));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://localhost:3118/callback?next=https://evil.example"
        ));

        let loopback_ip = parse_allowlist("http://127.0.0.1:8787/callback", "TEST").unwrap();
        assert!(is_allowed_redirect_uri(
            &loopback_ip,
            "http://127.0.0.1:51423/callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &loopback_ip,
            "http://localhost:51423/callback"
        ));
    }

    /// The relaxation is loopback-`http`-only: an `https` or private-use entry
    /// keeps exact matching, port included.
    #[test]
    fn non_loopback_entries_keep_exact_port_matching() {
        let allowed = parse_allowlist(
            "https://claude.ai/api/mcp/auth_callback,cursor://anysphere.cursor-mcp/oauth/callback",
            "TEST",
        )
        .unwrap();

        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://claude.ai:8443/api/mcp/auth_callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "cursor://anysphere.cursor-mcp:8443/oauth/callback"
        ));
        // And a loopback candidate cannot borrow a non-loopback entry's path.
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://localhost:3118/api/mcp/auth_callback"
        ));
    }

    /// The requested URI's scheme is guarded, not only the entry's. Without
    /// that check `https://localhost:3118/callback` would match a cleartext
    /// loopback entry, and a client could be redirected somewhere the operator
    /// never allowlisted.
    #[test]
    fn loopback_relaxation_checks_the_requested_scheme() {
        let allowed = parse_allowlist("http://localhost:8787/callback", "TEST").unwrap();

        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://localhost:3118/callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "cursor://localhost/callback"
        ));
    }

    /// The allowlist entry's scheme is checked too, and this is the dangerous
    /// half. An `https` loopback entry also has a loopback host, so without the
    /// check it port-relaxes into cleartext `http` — a TLS downgrade on an
    /// entry the operator wrote expecting TLS, which is worse than the lockout
    /// this change fixes. A private-use entry is the same defect, less severe.
    #[test]
    fn loopback_relaxation_checks_the_entry_scheme() {
        let https_entry = parse_allowlist("https://localhost:8443/callback", "TEST").unwrap();

        assert!(!is_allowed_redirect_uri(
            &https_entry,
            "http://localhost:3118/callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &https_entry,
            "http://localhost:8443/callback"
        ));
        assert!(is_allowed_redirect_uri(
            &https_entry,
            "https://localhost:8443/callback"
        ));

        // The URL parser canonicalises the host before the loopback check, so
        // `127.1` and `0177.0.0.1` reach the relaxation identically to
        // `127.0.0.1`. Host spelling enforces nothing here: the entry-scheme
        // guard is the whole control.
        for entry in [
            "https://127.0.0.1:8443/callback",
            "https://127.1:8443/callback",
            "https://0177.0.0.1:8443/callback",
        ] {
            let allowed = parse_allowlist(entry, "TEST").unwrap();
            assert!(
                !is_allowed_redirect_uri(&allowed, "http://127.0.0.1:3118/callback"),
                "{entry} must not port-relax into cleartext"
            );
        }

        let private_entry = parse_allowlist("cursor://localhost/callback", "TEST").unwrap();

        assert!(!is_allowed_redirect_uri(
            &private_entry,
            "http://localhost:9999/callback"
        ));
        assert!(is_allowed_redirect_uri(
            &private_entry,
            "cursor://localhost/callback"
        ));
    }

    /// The exact set the deployment ships, parsed as one env value.
    #[test]
    fn deployed_allowlist_parses() {
        let raw = "https://claude.ai/api/mcp/auth_callback,\
                   https://claude.com/api/mcp/auth_callback,\
                   https://www.cursor.com/agents/mcp/oauth/callback,\
                   cursor://anysphere.cursor-mcp/oauth/callback,\
                   grokbot://mcp/oauth/callback,\
                   http://localhost:8787/callback,\
                   claude://claude.ai/oauth/callback,\
                   claude://oauth/callback,\
                   cowork://oauth/callback";
        let allowed = parse_allowlist(raw, ENV_OAUTH_REDIRECT_URIS).unwrap();
        assert_eq!(allowed.len(), 9);
    }
}
