//! Logto access-token validation via JWKS + RS256.
//!
//! carddav-mcp validates Logto access tokens *locally*: fetch the
//! issuer's JWKS once, cache the decoding keys, and verify the JWT's
//! signature + `aud` + `exp` per request. This is a self-contained check
//! with no per-request round-trip.
//!
//! Pass-through model: the same validated JWT is then forwarded verbatim to
//! Stalwart as the `CardDAV` `Authorization: Bearer`. Stalwart validates it
//! against the same Logto issuer via its OIDC directory.
//!
//! Token must be a JWT issued for *our* resource indicator (the audience
//! check enforces RFC 8707 binding). Opaque tokens (no JWT header) are
//! rejected — Logto issues JWT access tokens for registered API resources,
//! which is how carddav-mcp's protected-resource metadata steers claude.ai.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, warn};

/// Maximum age of a cached positive validation. Bounded so a token
/// revocation (Logto session end) propagates in at most this window even
/// though local JWT verification can't see revocations directly.
#[allow(unknown_lints, clippy::duration_suboptimal_units)]
const MAX_CACHE_TTL: Duration = Duration::from_secs(60);

/// Hard cap on the validation cache size; sweep expired entries before
/// evicting the entry nearest expiry.
const CACHE_CAP: usize = 256;

/// JWKS cache lifetime. Refetched on unknown `kid` regardless (key rotation).
/// `from_secs` not `from_hours`: the unit constructors are unstable on 1.93.
#[allow(unknown_lints, clippy::duration_suboptimal_units)]
const JWKS_TTL: Duration = Duration::from_secs(3600);
/// Minimum interval between outbound JWKS refresh attempts. Unknown attacker-
/// controlled `kid` values must not turn one unauthenticated request into one
/// `IdP` request. A short interval still discovers legitimate key rotation
/// promptly.
const JWKS_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// Claims we read off a Logto access token. Logto always emits `sub`, `aud`,
/// `iss`, `exp`, `iat`. `email`/`name`/`username` are present only when the
/// resource/app is configured to include user claims in the access token;
/// they're best-effort here and enriched from the DAV principal elsewhere.
#[derive(Debug, Deserialize, Clone)]
struct LogtoAccessTokenClaims {
    sub: String,
    aud: AudField,
    exp: i64,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

/// `aud` can be a single string or an array. We check membership, not
/// equality.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum AudField {
    Single(String),
    Multi(Vec<String>),
}

impl AudField {
    fn matches(&self, expected: &str) -> bool {
        match self {
            Self::Single(s) => s == expected,
            Self::Multi(xs) => xs.iter().any(|s| s == expected),
        }
    }
}

/// What the auth layer hands to the rest of the application after a
/// successful validation.
#[derive(Debug, Clone)]
pub struct AuthenticatedIdentity {
    /// Stable Logto user id (`sub`). Ownership/cache key.
    pub user_id: String,
    /// Users email, when the token carries it. Enriched from the DAV
    /// session's `username` for display when absent.
    pub email: Option<String>,
    /// Display name, when present.
    pub name: Option<String>,
    /// Token expiry (Unix epoch seconds). Surfaced via `/token/introspect`.
    pub exp: Option<i64>,
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("JWKS fetch/transport error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JWKS endpoint returned non-2xx: {status}")]
    JwksUpstream { status: u16 },
}

#[derive(Clone)]
pub struct LogtoValidationClient {
    http: reqwest::Client,
    jwks_url: String,
    expected_audiences: Vec<String>,
    expected_issuer: String,
    jwks: Arc<RwLock<JwksCache>>,
    jwks_refresh_gate: Arc<tokio::sync::Mutex<()>>,
    cache: Arc<RwLock<HashMap<[u8; 32], CacheEntry>>>,
}

#[allow(clippy::missing_fields_in_debug)] // intentionally redacts cached token/JWKS state
impl std::fmt::Debug for LogtoValidationClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogtoValidationClient")
            .field("jwks_url", &self.jwks_url)
            .field("expected_audiences", &self.expected_audiences)
            .finish()
    }
}

#[derive(Default)]
struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
    last_refresh_attempt: Option<Instant>,
}

#[derive(Clone)]
struct CacheEntry {
    identity: AuthenticatedIdentity,
    expires_at: Instant,
}

impl LogtoValidationClient {
    /// Build a validation client. `authorization_server` is the Logto OIDC
    /// issuer base (`https://login.kampong.social/oidc`); the JWKS lives at
    /// `{issuer}/jwks` and the `iss` claim equals the issuer base exactly.
    pub fn new(authorization_server: &str, expected_audiences: Vec<String>) -> Result<Self> {
        anyhow::ensure!(
            !expected_audiences.is_empty(),
            "at least one expected JWT audience is required"
        );
        let issuer = authorization_server.trim_end_matches('/').to_owned();
        let jwks_url = format!("{issuer}/jwks");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent(concat!("carddav-mcp/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            http,
            jwks_url,
            expected_audiences,
            expected_issuer: issuer,
            jwks: Arc::new(RwLock::new(JwksCache::default())),
            jwks_refresh_gate: Arc::new(tokio::sync::Mutex::new(())),
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Validate a bearer token. `Ok(Some(identity))` on a valid JWT for our
    /// audience; `Ok(None)` if the token is expired, malformed, opaque, has
    /// the wrong audience/issuer, or fails signature verification. `Err`
    /// only for JWKS-fetch transport failures.
    pub async fn validate_token(
        &self,
        token: &str,
    ) -> Result<Option<AuthenticatedIdentity>, ValidationError> {
        let key = hash_token(token);
        if let Some(hit) = self.cache_lookup(&key) {
            debug!("token validation cache hit");
            return Ok(Some(hit));
        }

        let Ok(header) = decode_header(token) else {
            warn!("bearer is not a JWT (opaque token?); rejecting");
            return Ok(None);
        };
        let Some(kid) = header.kid.clone() else {
            warn!("JWT missing `kid`; rejecting");
            return Ok(None);
        };

        let Some(decoding_key) = self.decoding_key_for(&kid).await? else {
            warn!(%kid, "no JWKS key matched token kid; rejecting");
            return Ok(None);
        };

        // jsonwebtoken requires every entry in `validation.algorithms` to
        // share the key's family (mixing EC + RSA errors out), so we can't
        // hardcode a cross-family list. Use the token header's declared `alg`
        // — but only after allow-listing it to the asymmetric algorithms we
        // accept (rejects `none`/HMAC and blocks alg-confusion). The key is
        // already pinned by `kid` from the trusted JWKS and the signature is
        // verified against it below, and jsonwebtoken enforces key.family ==
        // alg.family, so a forged cross-family `alg` cannot validate.
        if !matches!(
            header.alg,
            Algorithm::ES384
                | Algorithm::ES256
                | Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::EdDSA
        ) {
            warn!(alg = ?header.alg, "unsupported token signing algorithm; rejecting");
            return Ok(None);
        }
        let mut validation = Validation::new(header.alg);
        let audiences: Vec<&str> = self.expected_audiences.iter().map(String::as_str).collect();
        validation.set_audience(&audiences);
        validation.set_issuer(&[&self.expected_issuer]);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);

        let claims = match decode::<LogtoAccessTokenClaims>(token, &decoding_key, &validation) {
            Ok(data) => data.claims,
            Err(e) => {
                debug!(error = %e, "JWT validation failed; rejecting");
                return Ok(None);
            }
        };

        // Defence in depth: jsonwebtoken already enforced aud via Validation,
        // but re-check membership explicitly to be robust against future
        // Validation default changes.
        if !self
            .expected_audiences
            .iter()
            .any(|expected| claims.aud.matches(expected))
        {
            warn!("token audience does not include a recognised resource; rejecting");
            return Ok(None);
        }

        let identity = AuthenticatedIdentity {
            user_id: claims.sub.clone(),
            email: claims.email.clone().or_else(|| claims.username.clone()),
            name: claims.name.clone(),
            exp: Some(claims.exp),
        };
        let _ = claims.scope; // currently unused; reserved for scope gating.

        self.cache_insert(key, &identity, Some(claims.exp));
        Ok(Some(identity))
    }

    /// Drop a cached positive validation, forcing re-verification on the
    /// next presentation of this token (used when Stalwart reports the
    /// token is no longer good).
    pub fn drop_token(&self, token: &str) {
        let key = hash_token(token);
        if let Ok(mut g) = self.cache.write() {
            g.remove(&key);
        }
    }

    async fn decoding_key_for(&self, kid: &str) -> Result<Option<DecodingKey>, ValidationError> {
        // Fast path: cached key, JWKS still fresh.
        if let Ok(g) = self.jwks.read() {
            let fresh = g.fetched_at.is_some_and(|t| t.elapsed() < JWKS_TTL);
            if fresh && let Some(k) = g.keys.get(kid) {
                return Ok(Some(k.clone()));
            }
        }

        // Slow path: serialize refreshes, then re-check because another task
        // may have populated the key while this task waited. Without the gate,
        // a burst of attacker-chosen unknown kids causes a matching burst of
        // outbound JWKS requests.
        let _refresh_guard = self.jwks_refresh_gate.lock().await;
        if let Ok(g) = self.jwks.read() {
            let fresh = g.fetched_at.is_some_and(|t| t.elapsed() < JWKS_TTL);
            if fresh && let Some(k) = g.keys.get(kid) {
                return Ok(Some(k.clone()));
            }
            if g.last_refresh_attempt
                .is_some_and(|t| t.elapsed() < JWKS_MIN_REFRESH_INTERVAL)
            {
                // During the cooldown, a previously known stale key remains a
                // safe verification key; an unknown kid fails closed.
                return Ok(g.keys.get(kid).cloned());
            }
        }

        if let Ok(mut g) = self.jwks.write() {
            // Record before the network await so failures are rate-limited too.
            g.last_refresh_attempt = Some(Instant::now());
        }
        self.refresh_jwks().await?;
        Ok(self.jwks.read().ok().and_then(|g| g.keys.get(kid).cloned()))
    }

    async fn refresh_jwks(&self) -> Result<(), ValidationError> {
        let resp = self.http.get(&self.jwks_url).send().await?;
        if !resp.status().is_success() {
            return Err(ValidationError::JwksUpstream {
                status: resp.status().as_u16(),
            });
        }
        let set: JwkSet = resp.json().await?;
        let mut keys = HashMap::new();
        for jwk in &set.keys {
            if let Some(kid) = jwk.common.key_id.clone()
                && let Ok(key) = DecodingKey::from_jwk(jwk)
            {
                keys.insert(kid, key);
            }
        }
        if let Ok(mut g) = self.jwks.write() {
            g.keys = keys;
            g.fetched_at = Some(Instant::now());
        }
        Ok(())
    }

    fn cache_lookup(&self, key: &[u8; 32]) -> Option<AuthenticatedIdentity> {
        let guard = self.cache.read().ok()?;
        let result = guard
            .get(key)
            .and_then(|e| (e.expires_at > Instant::now()).then(|| e.identity.clone()));
        drop(guard);
        result
    }

    fn cache_insert(&self, key: [u8; 32], identity: &AuthenticatedIdentity, exp: Option<i64>) {
        let ttl = exp.map_or(MAX_CACHE_TTL, |exp| {
            let now = now_unix();
            let remaining = u64::try_from((exp - now).max(0)).unwrap_or(0);
            Duration::from_secs(remaining).min(MAX_CACHE_TTL)
        });
        let entry = CacheEntry {
            identity: identity.clone(),
            expires_at: Instant::now() + ttl,
        };
        let Ok(mut guard) = self.cache.write() else {
            return;
        };
        if guard.len() >= CACHE_CAP {
            let now = Instant::now();
            guard.retain(|_, e| e.expires_at > now);
        }
        if guard.len() >= CACHE_CAP
            && !guard.contains_key(&key)
            && let Some(expiring_key) = guard
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| *key)
        {
            guard.remove(&expiring_key);
        }
        guard.insert(key, entry);
    }
}

fn hash_token(token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.finalize().into()
}

fn now_unix() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(i64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    #[test]
    fn aud_single_and_multi_membership() {
        assert!(AudField::Single("https://x".into()).matches("https://x"));
        assert!(!AudField::Single("https://x".into()).matches("https://y"));
        let m = AudField::Multi(vec!["https://x".into(), "https://y".into()]);
        assert!(m.matches("https://y"));
        assert!(!m.matches("https://z"));
    }

    #[test]
    fn jwks_url_derived_from_issuer() {
        let c = LogtoValidationClient::new(
            "https://login.example.test/oidc/",
            vec!["https://res".into()],
        )
        .unwrap();
        assert_eq!(c.jwks_url, "https://login.example.test/oidc/jwks");
        assert_eq!(c.expected_issuer, "https://login.example.test/oidc");
    }

    #[tokio::test]
    async fn opaque_token_rejected() {
        let c = LogtoValidationClient::new(
            "https://login.example.test/oidc",
            vec!["https://res".into()],
        )
        .unwrap();
        // Not a JWT — decode_header fails, no network touched.
        assert!(c.validate_token("opaque-abc123").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn unknown_kids_share_one_rate_limited_jwks_refresh() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = LogtoValidationClient::new(&server.uri(), vec!["https://res".into()]).unwrap();

        let results = futures::future::join_all((0..20).map(|index| {
            let client = client.clone();
            async move {
                client
                    .decoding_key_for(&format!("attacker-kid-{index}"))
                    .await
                    .unwrap()
            }
        }))
        .await;
        assert!(results.into_iter().all(|key| key.is_none()));
    }

    #[tokio::test]
    async fn refresh_cooldown_keeps_a_previously_known_key_usable() {
        let client = LogtoValidationClient::new(
            "https://login.example.test/oidc",
            vec!["https://res".into()],
        )
        .unwrap();
        {
            let mut cache = client.jwks.write().unwrap();
            cache.keys.insert(
                "known".to_owned(),
                DecodingKey::from_secret(b"test-only-key"),
            );
            cache.fetched_at = Some(
                Instant::now()
                    .checked_sub(JWKS_TTL + Duration::from_secs(1))
                    .unwrap(),
            );
            cache.last_refresh_attempt = Some(Instant::now());
        }

        assert!(client.decoding_key_for("known").await.unwrap().is_some());
    }

    #[test]
    fn positive_validation_cache_never_exceeds_its_hard_cap() {
        let client = LogtoValidationClient::new(
            "https://login.example.test/oidc",
            vec!["https://res".into()],
        )
        .unwrap();
        let identity = AuthenticatedIdentity {
            user_id: "user".to_owned(),
            email: None,
            name: None,
            exp: None,
        };
        for index in 0..(CACHE_CAP + 10) {
            let mut key = [0_u8; 32];
            key[..8].copy_from_slice(&u64::try_from(index).unwrap().to_be_bytes());
            client.cache_insert(key, &identity, None);
        }
        assert_eq!(client.cache.read().unwrap().len(), CACHE_CAP);
    }
}
