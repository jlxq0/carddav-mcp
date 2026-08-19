//! Per-identity rate limiting (Phase 6.1).
//!
//! ## Why two keys
//!
//! Each tool call is checked against two independent token buckets:
//!
//! 1. `sha256(bearer)[..16]` — protects Stalwart from a leaked token:
//!    even if the same `sub` has multiple active tokens, a compromised
//!    one can only burn its own bucket before being denied.
//! 2. Logto `sub` — protects against the same user spinning up many
//!    tokens (e.g. claude.ai issuing a fresh one per session) and using
//!    the union of their per-token allowances to flood Stalwart.
//!
//! Either bucket exceeded → request denied. Both must allow.
//!
//! When `sub` is unavailable, only the bearer-hash bucket applies.
//!
//! ## Why two quotas
//!
//! Reads (`whoami`, `list_address_books`, `list_contacts`,
//! `search_contacts`) are cheap and idempotent — high default quota.
//! `search_contacts` can fan out one REPORT per address book, so the
//! read quota is not unbounded either. Writes (`create_contact`,
//! `update_contact`, `delete_contact`) mutate the user's address book;
//! tighter default.
//!
//! ## Memory bound
//!
//! Each bearer/subject map has a hard cardinality cap. When full, idle buckets
//! are removed first and then the least-recently-seen remaining bucket is
//! evicted. This keeps deliberate token/account churn from turning the limiter
//! itself into a process-lifetime memory leak.
//!
//! ## Quota knobs
//!
//! Configured at startup; no per-request override. Read from env in
//! `config.rs`:
//!
//! - `CARDDAV_MCP_RATE_LIMIT_READS_PER_MIN` (default 60)
//! - `CARDDAV_MCP_RATE_LIMIT_WRITES_PER_MIN` (default 30)

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};

/// Maximum number of fresh MCP sessions a single bearer token or Logto
/// subject may open in a short burst. Legitimate Claude usage normally
/// needs one or two live sessions; this leaves headroom for reconnects
/// while preventing one authenticated identity from filling the global
/// session pool (`session::MAX_SESSIONS`).
pub const MAX_INITIALIZES_PER_IDENTITY: u32 = 8;
/// Maximum identities retained in any one rate-limit map.
const MAX_BUCKETS_PER_MAP: usize = 4096;
/// Idle buckets older than this are discarded first when a map reaches its cap.
#[allow(clippy::duration_suboptimal_units)]
const BUCKET_IDLE_TTL: Duration = Duration::from_secs(3600);

/// Limiter type alias — `governor`'s direct (non-keyed) variant; we
/// build one per identity and hand it out keyed by bearer-hash or sub.
type Bucket = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

#[derive(Debug)]
struct BucketEntry {
    bucket: Arc<Bucket>,
    last_seen: Instant,
}

type BucketMap = RwLock<HashMap<String, BucketEntry>>;

/// What kind of MCP tool this call is. Drives which quota applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Read,
    Write,
}

/// Returned when a request would exceed the configured quota.
#[derive(Debug, Clone, Copy)]
pub struct RateLimited;

#[derive(Debug)]
pub struct Limiter {
    reads_per_min: NonZeroU32,
    writes_per_min: NonZeroU32,
    bearer_read: BucketMap,
    bearer_write: BucketMap,
    sub_read: BucketMap,
    sub_write: BucketMap,
}

impl Limiter {
    /// New limiter with the given per-minute quotas. `0` quotas are
    /// rejected (`None`) — use a large quota to "effectively disable",
    /// don't pass `0`.
    #[must_use]
    pub fn new(reads_per_min: u32, writes_per_min: u32) -> Option<Self> {
        Some(Self {
            reads_per_min: NonZeroU32::new(reads_per_min)?,
            writes_per_min: NonZeroU32::new(writes_per_min)?,
            bearer_read: RwLock::new(HashMap::new()),
            bearer_write: RwLock::new(HashMap::new()),
            sub_read: RwLock::new(HashMap::new()),
            sub_write: RwLock::new(HashMap::new()),
        })
    }

    /// Check both per-bearer-hash and per-sub buckets. Returns `Ok(())`
    /// if both allow, `Err(RateLimited)` if either denies.
    pub fn check(
        &self,
        bearer_hash: &str,
        sub: Option<&str>,
        category: Category,
    ) -> Result<(), RateLimited> {
        let (bearer_map, sub_map, quota) = match category {
            Category::Read => (&self.bearer_read, &self.sub_read, self.reads_per_min),
            Category::Write => (&self.bearer_write, &self.sub_write, self.writes_per_min),
        };
        let bearer_bucket = get_or_insert(bearer_map, bearer_hash, quota);
        if bearer_bucket.check().is_err() {
            return Err(RateLimited);
        }
        if let Some(s) = sub {
            let sub_bucket = get_or_insert(sub_map, s, quota);
            if sub_bucket.check().is_err() {
                return Err(RateLimited);
            }
        }
        Ok(())
    }
}

fn get_or_insert(map: &BucketMap, key: &str, quota: NonZeroU32) -> Arc<Bucket> {
    // `governor::Quota::per_minute(n)` translates to one token every
    // (60/n) seconds with a burst of `n`.
    get_or_insert_with_quota(map, key, Quota::per_minute(quota))
}

fn get_or_insert_with_quota(map: &BucketMap, key: &str, quota: Quota) -> Arc<Bucket> {
    let mut guard = match map.write() {
        Ok(g) => g,
        // RwLock poisoning is unrecoverable here. A poisoned lock means a
        // panic happened while holding the lock — the safe thing is to
        // fall through to "no rate-limiting for this caller right now"
        // rather than panic again and tear down the server. Logged
        // upstream via tracing in the call site if it ever fires.
        Err(p) => p.into_inner(),
    };
    let now = Instant::now();
    if let Some(entry) = guard.get_mut(key) {
        entry.last_seen = now;
        return Arc::clone(&entry.bucket);
    }

    if guard.len() >= MAX_BUCKETS_PER_MAP {
        guard.retain(|_, entry| now.duration_since(entry.last_seen) < BUCKET_IDLE_TTL);
    }
    if guard.len() >= MAX_BUCKETS_PER_MAP
        && let Some(oldest_key) = guard
            .iter()
            .min_by_key(|(_, entry)| entry.last_seen)
            .map(|(key, _)| key.clone())
    {
        guard.remove(&oldest_key);
    }

    let bucket = Arc::new(RateLimiter::direct(quota));
    guard.insert(
        key.to_owned(),
        BucketEntry {
            bucket: Arc::clone(&bucket),
            last_seen: now,
        },
    );
    bucket
}

/// Rate limiter dedicated to fresh MCP session creation (the
/// `initialize` request without an `mcp-session-id` header). Tool-call
/// rate limits do not protect this path because rmcp allocates the
/// session before any tool handler runs, so the per-bucket charge
/// inside [`Limiter::check`] never fires for the initialize request.
///
/// Keyed by bearer-hash AND Logto subject the same way [`Limiter`] is:
/// a stolen token can't fan out more sessions than the bucket allows,
/// and the same `sub` can't accumulate sessions across rotated tokens
/// either.
#[derive(Debug)]
pub struct InitializeLimiter {
    quota: Quota,
    bearer: BucketMap,
    sub: BucketMap,
}

impl InitializeLimiter {
    /// New limiter that allows up to `burst` initialize calls back-to-back
    /// and then refills one token every `replenish_1_per`. Pairing the
    /// refill period with `session::SESSION_KEEP_ALIVE` means once an
    /// attacker has filled their slots they can only open a new one as
    /// fast as their existing ones idle out — exactly the timescale of
    /// the global session-pool cap.
    #[must_use]
    pub fn new(replenish_1_per: Duration, burst: u32) -> Self {
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::with_period(replenish_1_per)
            .unwrap_or_else(|| Quota::per_minute(NonZeroU32::MIN))
            .allow_burst(burst);
        Self {
            quota,
            bearer: RwLock::new(HashMap::new()),
            sub: RwLock::new(HashMap::new()),
        }
    }

    /// Check both per-bearer-hash and per-sub initialize buckets.
    pub fn check(&self, bearer_hash: &str, sub: Option<&str>) -> Result<(), RateLimited> {
        let bearer_bucket = get_or_insert_with_quota(&self.bearer, bearer_hash, self.quota);
        if bearer_bucket.check().is_err() {
            return Err(RateLimited);
        }
        if let Some(s) = sub {
            let sub_bucket = get_or_insert_with_quota(&self.sub, s, self.quota);
            if sub_bucket.check().is_err() {
                return Err(RateLimited);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::duration_suboptimal_units)]
mod tests {
    use super::*;

    #[test]
    fn zero_quota_rejected() {
        assert!(Limiter::new(0, 1).is_none());
        assert!(Limiter::new(1, 0).is_none());
    }

    #[test]
    fn reads_and_writes_have_independent_buckets() {
        let l = Limiter::new(2, 2).unwrap();
        // Burn the read bucket.
        l.check("h", Some("s"), Category::Read).unwrap();
        l.check("h", Some("s"), Category::Read).unwrap();
        assert!(l.check("h", Some("s"), Category::Read).is_err());
        // Writes are unaffected.
        l.check("h", Some("s"), Category::Write).unwrap();
        l.check("h", Some("s"), Category::Write).unwrap();
        assert!(l.check("h", Some("s"), Category::Write).is_err());
    }

    #[test]
    fn distinct_bearers_dont_share_a_bucket() {
        let l = Limiter::new(1, 1).unwrap();
        l.check("h1", None, Category::Read).unwrap();
        // Same identity at the bearer-hash level → denied.
        assert!(l.check("h1", None, Category::Read).is_err());
        // Different bearer → fresh bucket.
        l.check("h2", None, Category::Read).unwrap();
    }

    #[test]
    fn sub_bucket_denies_across_bearers_for_same_user() {
        let l = Limiter::new(1, 1).unwrap();
        l.check("h1", Some("user-A"), Category::Read).unwrap();
        // Different bearer, same sub → sub bucket exhausted.
        assert!(l.check("h2", Some("user-A"), Category::Read).is_err());
    }

    #[test]
    fn no_sub_means_bearer_only() {
        let l = Limiter::new(1, 1).unwrap();
        // Without sub, the sub bucket is skipped; only bearer-hash
        // applies.
        l.check("h1", None, Category::Read).unwrap();
        assert!(l.check("h1", None, Category::Read).is_err());
        l.check("h2", None, Category::Read).unwrap();
    }

    #[test]
    fn initialize_limiter_denies_after_burst_on_bearer() {
        let l = InitializeLimiter::new(Duration::from_secs(60), 2);
        l.check("h", Some("s")).unwrap();
        l.check("h", Some("s")).unwrap();
        assert!(l.check("h", Some("s")).is_err());
    }

    #[test]
    fn initialize_limiter_denies_across_bearers_for_same_sub() {
        let l = InitializeLimiter::new(Duration::from_secs(60), 1);
        l.check("h1", Some("s")).unwrap();
        // Different bearer, same sub → sub bucket exhausted.
        assert!(l.check("h2", Some("s")).is_err());
    }

    #[test]
    fn initialize_limiter_no_sub_uses_bearer_only() {
        let l = InitializeLimiter::new(Duration::from_secs(60), 1);
        l.check("h", None).unwrap();
        assert!(l.check("h", None).is_err());
        // Different bearer → fresh bucket.
        l.check("h2", None).unwrap();
    }

    #[test]
    fn bearer_maps_remain_bounded_under_token_churn() {
        let limiter = Limiter::new(100_000, 1).unwrap();
        for index in 0..(MAX_BUCKETS_PER_MAP + 100) {
            limiter
                .check(&format!("bearer-{index}"), None, Category::Read)
                .unwrap();
        }
        assert_eq!(
            limiter.bearer_read.read().unwrap().len(),
            MAX_BUCKETS_PER_MAP
        );
    }

    #[test]
    fn initialize_maps_remain_bounded_under_token_churn() {
        let limiter = InitializeLimiter::new(Duration::from_secs(60), 1);
        for index in 0..(MAX_BUCKETS_PER_MAP + 100) {
            limiter.check(&format!("bearer-{index}"), None).unwrap();
        }
        assert_eq!(limiter.bearer.read().unwrap().len(), MAX_BUCKETS_PER_MAP);
    }
}
