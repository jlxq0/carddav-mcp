# Changelog

This project follows semantic versioning.

## [0.1.1] - 2026-08-19

### Security

- Bound streamable-HTTP request bodies and all identity-keyed in-memory state.
- Coalesce and rate-limit JWKS refresh attempts for unknown JWT key IDs.
- Restore OAuth token-response anti-caching headers.
- Require HTTPS for public service dependencies and update the vulnerable `h2`
  dependency.

### Added

- Claude Desktop and Cowork redirect-URI examples.
- Versioned JSON health responses.
- Self-hosting, Kubernetes, security, and contribution documentation.
- CI secret scanning, SBOM generation, and container vulnerability scanning.

## [0.1.0] - 2026-08-17

- Initial Stalwart CardDAV MCP release with OAuth, DCR, JWT pass-through,
  streamable HTTP, seven contact tools, metrics, audit events, and a non-root
  distroless container.
