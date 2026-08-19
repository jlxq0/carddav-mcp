//! Process-level configuration.
//!
//! Config construction is split into a pure constructor (`Config::new`)
//! and an env-var wrapper (`Config::from_env`). Tests build Config directly
//! and never touch process-global env state — Rust 2024 makes `set_var`
//! unsafe (correctly: it's racy under multi-threaded test harnesses), and
//! we forbid `unsafe_code` at the crate root, so this split is the clean
//! way to keep both invariants.

use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::{Context, Result};

use crate::oauth_redirect;

/// Public URL of this MCP server, used as the OAuth `resource` identifier
/// (RFC 8707) and as the origin the `resource` field in the
/// protected-resource metadata document (RFC 9728) is derived from. Also the
/// audience carddav-mcp requires on inbound Logto access tokens.
const ENV_RESOURCE_URL: &str = "CARDDAV_MCP_RESOURCE_URL";
/// Issuer URL of the authorization server (Logto) that mints tokens for this
/// resource, e.g. `https://login.kampong.social/oidc`.
const ENV_AUTH_SERVER_URL: &str = "CARDDAV_MCP_AUTHORIZATION_SERVER";
/// Base URL of the Stalwart server serving `CardDAV`, e.g.
/// `https://dav.kampong.social`. Discovery starts at
/// `{base}/.well-known/carddav` (307 → `/dav/card`).
const ENV_STALWART_DAV_BASE_URL: &str = "CARDDAV_MCP_STALWART_DAV_BASE_URL";
/// Bind address, defaults to `0.0.0.0:3000` for container deployment.
const ENV_BIND_ADDR: &str = "CARDDAV_MCP_BIND_ADDR";
/// Separate bind for the cluster-internal `/metrics` endpoint. Never binds
/// `0.0.0.0` unless an operator explicitly sets this var. See
/// [`resolve_metrics_bind_addr`].
const ENV_METRICS_BIND_ADDR: &str = "CARDDAV_MCP_METRICS_BIND_ADDR";
/// Kubernetes downward-API pod IP. Injected via `fieldRef: status.podIP`.
/// Used to derive the metrics bind address.
const ENV_POD_IP: &str = "POD_IP";

/// Pre-provisioned Logto `client_id` handed back by the RFC 7591 dynamic client
/// registration shim. Logto has no DCR endpoint, so claude.ai (which only
/// onboards via DCR) gets this static public-SPA client. When unset, the
/// `/register` endpoint and `registration_endpoint` advertisement are disabled.
const ENV_DCR_CLIENT_ID: &str = "CARDDAV_MCP_DCR_CLIENT_ID";
/// Per-identity read quota (per minute).
const ENV_RATE_LIMIT_READS: &str = "CARDDAV_MCP_RATE_LIMIT_READS_PER_MIN";
/// Per-identity write quota (per minute).
const ENV_RATE_LIMIT_WRITES: &str = "CARDDAV_MCP_RATE_LIMIT_WRITES_PER_MIN";
/// Maximum bytes a single `CardDAV` response body may occupy. Bounds the memory
/// one `addressbook-query` REPORT over a huge address book can pin. Default
/// 8 MiB.
const ENV_DAV_MAX_RESPONSE_BYTES: &str = "CARDDAV_MCP_DAV_MAX_RESPONSE_BYTES";
/// Number of trusted proxies in front of carddav-mcp. Default 1 (the shared
/// web Gateway behind the edge Caddy).
const ENV_TRUSTED_PROXY_HOPS: &str = "CARDDAV_MCP_TRUSTED_PROXY_HOPS";
/// Optional IP to connect to when reaching the Stalwart DAV host, overriding
/// DNS. Keeps `Host`/SNI = the public hostname while dialling a specific IP.
const ENV_STALWART_CONNECT_IP: &str = "CARDDAV_MCP_STALWART_CONNECT_IP";
/// JWT `aud` Stalwart's OIDC directory requires (`requireAudience`).
/// Must match a **registered Logto API resource indicator** — Logto answers
/// `invalid_target` at `/authorize` for anything it does not know.
const ENV_STALWART_AUDIENCE: &str = "CARDDAV_MCP_STALWART_AUDIENCE";

const DEFAULT_RATE_LIMIT_READS: u32 = 60;
const DEFAULT_RATE_LIMIT_WRITES: u32 = 30;
const DEFAULT_DAV_MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const DEFAULT_TRUSTED_PROXY_HOPS: usize = 1;

#[derive(Debug, Clone)]
pub struct Config {
    /// Our own public URL (e.g. `https://carddav-mcp.kampong.social`). Never
    /// trailing-slashed — RFC 8707 resource indicators are compared as
    /// strings.
    pub resource_url: String,
    /// Authorization server (Logto OIDC issuer). No trailing slash.
    pub authorization_server: String,
    /// Stalwart base URL for `CardDAV`. No trailing slash.
    pub stalwart_dav_base_url: String,
    /// TCP bind address for the public API (rmcp + health + .well-known).
    pub bind_addr: SocketAddr,
    /// TCP bind for the cluster-internal metrics endpoint.
    pub metrics_bind_addr: SocketAddr,
    /// Per-minute read quota. 0 is rejected at parse time.
    pub rate_limit_reads_per_min: u32,
    /// Per-minute write quota. 0 is rejected at parse time.
    pub rate_limit_writes_per_min: u32,
    /// Maximum `CardDAV` response body size (bytes).
    pub dav_max_response_bytes: u64,
    /// Number of trusted proxies in front of carddav-mcp (X-Forwarded-For).
    pub trusted_proxy_hops: usize,
    /// Optional IP to dial for the Stalwart DAV host (DNS override). `None` =
    /// use normal DNS resolution.
    pub stalwart_connect_ip: Option<String>,
    /// Optional static Logto `client_id` returned by the DCR shim (`/register`).
    /// `None` disables dynamic client registration advertisement.
    pub dcr_client_id: Option<String>,
    /// Exact OAuth redirect URIs accepted by the proxy and DCR shim.
    pub oauth_redirect_uris: Vec<String>,
    /// Absolute-URI JWT audience Stalwart's OIDC directory requires, and the
    /// RFC 8707 `resource` the OAuth proxy sends to Logto.
    ///
    /// **This must name a Logto API resource that actually exists.** Logto
    /// rejects an unregistered indicator at `/authorize` with
    /// `error=invalid_target` before the user ever sees a login screen — the
    /// connector then dead-ends with no usable diagnostic. Defaults to
    /// `resource_url`; override when the deployment must borrow a sibling
    /// MCP's already-registered API resource.
    pub stalwart_audience: String,
}

impl Config {
    /// Pure constructor. Validates URLs are absolute http(s) and strips
    /// trailing slashes. Used directly by tests; `from_env` wraps it.
    pub fn new(
        resource_url: impl Into<String>,
        authorization_server: impl Into<String>,
        stalwart_dav_base_url: impl Into<String>,
        bind_addr: SocketAddr,
    ) -> Result<Self> {
        let resource_url = strip_trailing_slash(resource_url.into());
        let authorization_server = strip_trailing_slash(authorization_server.into());
        let stalwart_dav_base_url = strip_trailing_slash(stalwart_dav_base_url.into());
        validate_url(&resource_url, ENV_RESOURCE_URL)?;
        validate_url(&authorization_server, ENV_AUTH_SERVER_URL)?;
        validate_url(&stalwart_dav_base_url, ENV_STALWART_DAV_BASE_URL)?;
        Ok(Self {
            resource_url: resource_url.clone(),
            authorization_server,
            stalwart_dav_base_url,
            bind_addr,
            metrics_bind_addr: SocketAddr::from(([127, 0, 0, 1], 9090)),
            rate_limit_reads_per_min: DEFAULT_RATE_LIMIT_READS,
            rate_limit_writes_per_min: DEFAULT_RATE_LIMIT_WRITES,
            dav_max_response_bytes: DEFAULT_DAV_MAX_RESPONSE_BYTES,
            trusted_proxy_hops: DEFAULT_TRUSTED_PROXY_HOPS,
            stalwart_connect_ip: None,
            dcr_client_id: None,
            oauth_redirect_uris: Vec::new(),
            stalwart_audience: resource_url,
        })
    }

    /// Audiences we accept on inbound Logto access tokens: the origin
    /// (`CARDDAV_MCP_RESOURCE_URL`), `{origin}/mcp` (the RFC 9728 resource,
    /// which Grok Bot puts in `aud` instead of the origin), and
    /// `stalwart_audience` (the absolute URI actually sent to Logto).
    pub fn accepted_token_audiences(&self) -> Vec<String> {
        let mut v = vec![
            self.resource_url.clone(),
            crate::oauth_metadata::mcp_resource(&self.resource_url),
            self.stalwart_audience.clone(),
        ];
        v.sort();
        v.dedup();
        v
    }

    /// Load from environment variables. Missing required vars are fatal at
    /// startup — we refuse to boot rather than silently fall back to a
    /// development default in production.
    pub fn from_env() -> Result<Self> {
        let resource_url = require_env(ENV_RESOURCE_URL)?;
        let authorization_server = require_env(ENV_AUTH_SERVER_URL)?;
        let stalwart_dav_base_url = require_env(ENV_STALWART_DAV_BASE_URL)?;
        let bind_addr_str = std::env::var(ENV_BIND_ADDR).unwrap_or_else(|_| "0.0.0.0:3000".into());
        let bind_addr = SocketAddr::from_str(&bind_addr_str)
            .with_context(|| format!("invalid {ENV_BIND_ADDR}: {bind_addr_str}"))?;
        let explicit_addr = std::env::var(ENV_METRICS_BIND_ADDR).ok();
        let pod_ip = std::env::var(ENV_POD_IP).ok();
        let metrics_bind_addr =
            resolve_metrics_bind_addr(explicit_addr.as_deref(), pod_ip.as_deref())?;

        let mut cfg = Self::new(
            resource_url,
            authorization_server,
            stalwart_dav_base_url,
            bind_addr,
        )?;
        cfg.metrics_bind_addr = metrics_bind_addr;
        cfg.rate_limit_reads_per_min =
            parse_rate_limit(ENV_RATE_LIMIT_READS, DEFAULT_RATE_LIMIT_READS)?;
        cfg.rate_limit_writes_per_min =
            parse_rate_limit(ENV_RATE_LIMIT_WRITES, DEFAULT_RATE_LIMIT_WRITES)?;
        cfg.dav_max_response_bytes =
            parse_u64_env(ENV_DAV_MAX_RESPONSE_BYTES, DEFAULT_DAV_MAX_RESPONSE_BYTES)?;
        cfg.trusted_proxy_hops = parse_trusted_proxy_hops()?;
        cfg.stalwart_connect_ip = std::env::var(ENV_STALWART_CONNECT_IP)
            .ok()
            .filter(|s| !s.trim().is_empty());
        cfg.dcr_client_id = std::env::var(ENV_DCR_CLIENT_ID)
            .ok()
            .filter(|s| !s.trim().is_empty());
        cfg.oauth_redirect_uris = parse_redirect_uris_env()?;
        cfg.stalwart_audience = match std::env::var(ENV_STALWART_AUDIENCE)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
        {
            Some(raw) => {
                // RFC 8707: Logto rejects a non-URI resource with invalid_target.
                // `stalwart` is the Logto API *name*, not an indicator — never
                // send it.
                if raw == "stalwart" || !is_absolute_http_uri(&raw) {
                    anyhow::bail!(
                        "{ENV_STALWART_AUDIENCE} must be an absolute http(s) URI (RFC 8707 resource indicator); got {raw:?}. Do not use the bare string \"stalwart\"."
                    );
                }
                strip_trailing_slash(raw)
            }
            None => cfg.resource_url.clone(),
        };
        Ok(cfg)
    }
}

/// Resolve the metrics listener bind address. Priority: explicit env →
/// `{POD_IP}:9090` → `127.0.0.1:9090`. Never returns `0.0.0.0` by default.
fn resolve_metrics_bind_addr(
    explicit_addr: Option<&str>,
    pod_ip: Option<&str>,
) -> Result<SocketAddr> {
    let addr_str: String = explicit_addr.map_or_else(
        || pod_ip.map_or_else(|| "127.0.0.1:9090".to_owned(), |ip| format!("{ip}:9090")),
        str::to_owned,
    );
    SocketAddr::from_str(&addr_str)
        .with_context(|| format!("invalid {ENV_METRICS_BIND_ADDR}: {addr_str}"))
}

fn require_env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("required env var {key} is not set"))
}

fn validate_url(url: &str, key: &str) -> Result<()> {
    if !is_absolute_http_uri(url) {
        anyhow::bail!("{key} must be an absolute http(s) URL, got: {url}");
    }
    let parsed = url::Url::parse(url).with_context(|| format!("invalid {key}: {url}"))?;
    if parsed.scheme() == "http" && !is_loopback_host(parsed.host_str().unwrap_or_default()) {
        anyhow::bail!("{key} must use https except for loopback development URLs, got: {url}");
    }
    Ok(())
}

/// RFC 8707 resource indicator: absolute http(s) URI. Rejects bare tokens
/// such as `stalwart` that Logto answers with `invalid_target`.
pub fn is_absolute_http_uri(url: &str) -> bool {
    if url.trim() != url || url.chars().any(char::is_whitespace) {
        return false;
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    matches!(parsed.scheme(), "https" | "http")
        && parsed.host_str().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.fragment().is_none()
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn parse_rate_limit(key: &str, default: u32) -> Result<u32> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) => {
            let v: u32 = raw
                .trim()
                .parse()
                .with_context(|| format!("{key} must be a positive integer, got: {raw}"))?;
            if v == 0 {
                anyhow::bail!("{key} must be > 0");
            }
            Ok(v)
        }
    }
}

fn parse_u64_env(key: &str, default: u64) -> Result<u64> {
    std::env::var(key).map_or_else(
        |_| Ok(default),
        |raw| {
            raw.trim()
                .parse()
                .with_context(|| format!("{key} must be a non-negative integer, got: {raw}"))
        },
    )
}

fn parse_redirect_uris_env() -> Result<Vec<String>> {
    match std::env::var(oauth_redirect::ENV_OAUTH_REDIRECT_URIS) {
        Ok(raw) => oauth_redirect::parse_allowlist(&raw, oauth_redirect::ENV_OAUTH_REDIRECT_URIS),
        Err(std::env::VarError::NotPresent) => Ok(Vec::new()),
        Err(e) => {
            Err(e).with_context(|| format!("invalid {}", oauth_redirect::ENV_OAUTH_REDIRECT_URIS))
        }
    }
}

fn parse_trusted_proxy_hops() -> Result<usize> {
    std::env::var(ENV_TRUSTED_PROXY_HOPS).map_or_else(
        |_| Ok(DEFAULT_TRUSTED_PROXY_HOPS),
        |raw| {
            raw.trim().parse().with_context(|| {
                format!("{ENV_TRUSTED_PROXY_HOPS} must be a non-negative integer, got: {raw}")
            })
        },
    )
}

fn strip_trailing_slash(mut s: String) -> String {
    while s.ends_with('/') {
        s.pop();
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::new(
            "https://carddav-mcp.example.test/",
            "https://login.example.test/oidc",
            "https://dav.example.test",
            SocketAddr::from(([0, 0, 0, 0], 3000)),
        )
        .unwrap()
    }

    #[test]
    fn strips_trailing_slash_on_resource_url() {
        assert_eq!(cfg().resource_url, "https://carddav-mcp.example.test");
    }

    #[test]
    fn rejects_non_http_url() {
        let err = Config::new(
            "carddav-mcp.example.test",
            "https://login.example.test",
            "https://dav.example.test",
            SocketAddr::from(([0, 0, 0, 0], 3000)),
        );
        assert!(err.is_err());
    }

    #[test]
    fn rejects_cleartext_non_loopback_service_urls() {
        let err = Config::new(
            "http://carddav-mcp.example.test",
            "https://login.example.test",
            "https://dav.example.test",
            SocketAddr::from(([0, 0, 0, 0], 3000)),
        );
        assert!(err.is_err());
    }

    #[test]
    fn allows_cleartext_loopback_urls_for_local_development() {
        let config = Config::new(
            "http://localhost:3000",
            "http://127.0.0.1:4000/oidc",
            "http://[::1]:8080",
            SocketAddr::from(([127, 0, 0, 1], 3000)),
        )
        .unwrap();
        assert_eq!(config.resource_url, "http://localhost:3000");
    }

    #[test]
    fn accepted_audiences_include_origin_and_mcp_path() {
        let a = cfg().accepted_token_audiences();
        assert!(a.contains(&"https://carddav-mcp.example.test".to_owned()));
        assert!(a.contains(&"https://carddav-mcp.example.test/mcp".to_owned()));
        assert!(!a.iter().any(|x| x == "stalwart"));
        assert_eq!(cfg().stalwart_audience, "https://carddav-mcp.example.test");
    }

    /// A deployment that borrows a sibling MCP's registered Logto API
    /// resource must still accept its own origin and `{origin}/mcp` in `aud`
    /// — different MCP clients put different values there.
    #[test]
    fn accepted_audiences_include_a_borrowed_stalwart_audience() {
        let mut c = cfg();
        c.stalwart_audience = "https://jmap-mcp.example.test".to_owned();
        let a = c.accepted_token_audiences();
        assert!(a.contains(&"https://carddav-mcp.example.test".to_owned()));
        assert!(a.contains(&"https://carddav-mcp.example.test/mcp".to_owned()));
        assert!(a.contains(&"https://jmap-mcp.example.test".to_owned()));
    }

    #[test]
    fn rejects_bare_stalwart_as_rfc8707_resource() {
        assert!(!is_absolute_http_uri("stalwart"));
        assert!(!is_absolute_http_uri(""));
        assert!(!is_absolute_http_uri("carddav-mcp.kampong.social"));
        assert!(is_absolute_http_uri("https://carddav-mcp.kampong.social"));
        assert!(is_absolute_http_uri("https://dav.kampong.social"));
    }

    #[test]
    fn metrics_bind_prefers_explicit_then_pod_ip_then_localhost() {
        assert_eq!(
            resolve_metrics_bind_addr(Some("0.0.0.0:1234"), Some("10.0.0.5"))
                .unwrap()
                .to_string(),
            "0.0.0.0:1234"
        );
        assert_eq!(
            resolve_metrics_bind_addr(None, Some("10.0.0.5"))
                .unwrap()
                .to_string(),
            "10.0.0.5:9090"
        );
        assert_eq!(
            resolve_metrics_bind_addr(None, None).unwrap().to_string(),
            "127.0.0.1:9090"
        );
    }
}
