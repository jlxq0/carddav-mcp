# Changelog

This project follows semantic versioning.

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
