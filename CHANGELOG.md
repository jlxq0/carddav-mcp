# Changelog

This project follows semantic versioning.

## [0.1.6] - 2026-08-29

### Added

- `upcoming_birthdays`: contacts whose birthday falls within the next N days,
  across one or all address books, in **one call**. Answering this by paging
  `list_contacts` and parsing vCards cost four calls and 5.39 MB of vCard for a
  one-line question, because the address book holds 366 cards against a limit of
  100. The window is inclusive at both ends, today is day 0, and results are
  sorted by days remaining.
- `birthday` on `ContactSummary`, so a caller never parses a vCard for one date.

### Fixed

- `BDAY` was parsed nowhere in the service. `parse_vcard` now reads it, and
  `birthday.rs` handles every ISO form vCard 3.0 and 4.0 permit: `YYYY-MM-DD`,
  `YYYYMMDD`, `--MM-DD`, `--MMDD`, each with an optional discarded time part. A
  value it cannot parse is skipped and counted in `unparseable_birthdays` rather
  than failing the call.

## [0.1.5] - 2026-08-28

### Fixed

- Stop the initialize rate limiter livelocking the fleet. A refused request
  charged the per-bearer bucket before testing the per-subject bucket, so every
  rejection still spent a token; with clients retrying, each refill was consumed
  by a first request whose second was refused, and the bucket never reached the
  two tokens one connection needs. `check` now charges exactly one bucket: the
  per-subject one when the token carries a subject, the per-bearer one when it
  does not.
- Size the burst for this deployment. Every mounting session authenticates as
  the same Logto subject, so the per-subject bucket is one bucket for every
  agent at once, and one client connection costs two charges because
  `claude-code` posts twice without an `mcp-session-id` about 30 ms apart. A
  burst of 8 was four connections for the whole fleet. It is now 32, one
  full-fleet restart plus a retry round, and still an eighth of `MAX_SESSIONS`.
- Decouple the refill from `SESSION_KEEP_ALIVE`. One token per 30 minutes meant
  recovering a single connection took an hour of total fleet silence. It is now
  one per minute, which bounds a stolen bearer to 60 attempts an hour against a
  live-session cap of 256.

### Added

- `carddav_mcp_initialize_rejected_total{bucket}` and a `warn` line on every
  refused initialize, carrying the bucket, the token hash, the burst and the
  replenish period. Refusals previously left no server-side record of any kind:
  the 2026-08-28 outage had to be reconstructed from which requests succeeded
  and from the silence after them. The `bucket` label separates one client
  exhausting its own quota from the shared bucket being too small for the fleet.

## [0.1.4] - 2026-08-27

### Fixed

- Record the real client address in the last-used audit field. The trusted
  proxy chain in front of this pod is `client -> Caddy edge -> Cilium gateway`,
  two `X-Forwarded-For` entries, and `CARDDAV_MCP_TRUSTED_PROXY_HOPS` defaulted
  to 1. `parse_client_ip` counts in from the right, so every authenticated
  request recorded the edge's address as the gateway saw it: a well-formed
  address identifying the wrong party, in the field an operator reads during an
  incident. The default is now 2, with the topology and the reason recorded
  beside the constant.

### Added

- One `info` line per authenticated request carrying `xff_entries`,
  `trusted_proxy_hops` and `client_ip_resolved` — the **count** of
  `X-Forwarded-For` entries and never the entries. Without it the hop count was
  unfalsifiable from outside the deployment, and the value above had to be
  taken from sibling services rather than measured here.

## [0.1.3] - 2026-08-25

### Fixed

- Accept any port on an allowlisted cleartext loopback `redirect_uri`, as
  RFC 8252 §7.3 requires. Exact string matching locked out every native client
  that binds an ephemeral local port, including the Claude Code CLI, whose
  Dynamic Client Registration was rejected as `unregistered redirect_uri`.
  Scheme, host, path and query still match exactly, on both the request and the
  allowlist entry, so `https` and private-use callbacks keep byte-for-byte
  matching and no entry can be relaxed into cleartext.

## [0.1.2] - 2026-08-19

### Fixed

- Use standalone BuildKit's Dockerfile frontend options for provenance and SBOM
  attestations so tagged container publication completes successfully.

## [0.1.1] - 2026-08-19

### Security

- Bound streamable-HTTP request bodies and all identity-keyed in-memory state.
- Coalesce and rate-limit JWKS refresh attempts for unknown JWT key IDs.
- Restore OAuth token-response anti-caching headers.
- Require HTTPS for public service dependencies and update the vulnerable `h2`
  dependency.
- Refresh the pinned distroless runtime and gate releases on high/critical
  container findings.

### Added

- Claude Desktop and Cowork redirect-URI examples.
- Versioned JSON health responses.
- Self-hosting, Kubernetes, security, and contribution documentation.
- CI secret scanning, SBOM generation, and container vulnerability scanning.

## [0.1.0] - 2026-08-17

- Initial Stalwart CardDAV MCP release with OAuth, DCR, JWT pass-through,
  streamable HTTP, seven contact tools, metrics, audit events, and a non-root
  distroless container.
