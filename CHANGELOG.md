# Changelog

This project follows semantic versioning.

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
