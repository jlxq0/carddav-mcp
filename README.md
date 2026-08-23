# carddav-mcp

`carddav-mcp` is a self-hosted, streamable-HTTP MCP server for per-user
address books on [Stalwart](https://stalw.art/) CardDAV. It validates a user's
JWT with a Logto-compatible identity provider and forwards that same bearer to
Stalwart. It never accepts or stores Basic credentials or app passwords.

The public MCP endpoint is `https://your-host.example/mcp`.

## Tools

- `whoami`
- `list_address_books`
- `list_contacts`
- `search_contacts`
- `create_contact`
- `update_contact`
- `delete_contact`

Read and write tools carry MCP annotations so compatible clients can distinguish
read-only, destructive, and idempotent operations.

## Security model

The MCP server, identity provider, Stalwart, and MCP client are all inside the
trust boundary. The server validates JWT signature, issuer, audience, and
expiry before opening an MCP session. It forwards the bearer to Stalwart only
over HTTPS and never logs or persists the token. CardDAV URLs are confined to
the configured DAV origin, response and request bodies are bounded, and
identity-keyed in-memory state has hard cardinality limits.

Anyone operating an instance can access its process and traffic. Self-host it
with an identity provider and Stalwart installation that you control. See
[SECURITY.md](SECURITY.md) for supported versions and private reporting.

## Prerequisites

- A public HTTPS hostname for this service.
- Stalwart CardDAV configured to accept JWT bearers from the same issuer.
- A Logto API resource whose indicator equals the MCP server origin.
- A public PKCE client in Logto containing `<origin>/oauth/callback`.
- An MCP client supporting streamable HTTP and OAuth 2.1.

This release is **Logto-compatible**, not arbitrary-OIDC compatible. The
authorization-server base must expose `/auth`, `/token`, `/jwks`, and `/me` in
Logto's layout. Supporting unrelated providers requires standards-based OIDC
discovery that is not implemented yet.

## Quick start with Docker Compose

The published container is Linux AMD64.

```sh
git clone https://forge.oddie.app/jlxq0/carddav-mcp.git
cd carddav-mcp
cp .env.example .env
# Edit .env for your IdP, Stalwart, public hostname, and client redirects.
docker compose up -d
curl http://127.0.0.1:3000/health
```

Terminate TLS in a reverse proxy and preserve streaming responses. For Caddy,
use `flush_interval -1` on the `reverse_proxy` transport.

Connect the MCP client to `https://your-host.example/mcp`. The server publishes
RFC 9728 protected-resource metadata at
`/.well-known/oauth-protected-resource/mcp` and an RFC 8414 authorization-server
document at `/.well-known/oauth-authorization-server`.

## Configuration

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `CARDDAV_MCP_RESOURCE_URL` | yes | — | Public origin without `/mcp`; also the JWT audience. |
| `CARDDAV_MCP_AUTHORIZATION_SERVER` | yes | — | Logto OIDC issuer base. |
| `CARDDAV_MCP_STALWART_DAV_BASE_URL` | yes | — | Public HTTPS origin serving Stalwart DAV. |
| `CARDDAV_MCP_DCR_CLIENT_ID` | recommended | — | Pre-provisioned public PKCE client returned by the DCR shim. |
| `CARDDAV_MCP_OAUTH_REDIRECT_URIS` | yes when DCR is enabled | — | Exact comma-separated MCP-client redirect allowlist. |
| `CARDDAV_MCP_STALWART_AUDIENCE` | no | resource URL | Resource indicator Stalwart accepts. Keep it service-specific where possible. |
| `CARDDAV_MCP_BIND_ADDR` | no | `0.0.0.0:3000` | Public HTTP listener. |
| `CARDDAV_MCP_METRICS_BIND_ADDR` | no | `127.0.0.1:9090` or `POD_IP:9090` | Internal Prometheus listener. |
| `CARDDAV_MCP_RATE_LIMIT_READS_PER_MIN` | no | `60` | Per-token and per-subject read quota. |
| `CARDDAV_MCP_RATE_LIMIT_WRITES_PER_MIN` | no | `30` | Per-token and per-subject write quota. |
| `CARDDAV_MCP_DAV_MAX_RESPONSE_BYTES` | no | `8388608` | Maximum accepted DAV response body. |
| `CARDDAV_MCP_TRUSTED_PROXY_HOPS` | no | `1` | Trusted rightmost `X-Forwarded-For` hops. |
| `CARDDAV_MCP_STALWART_CONNECT_IP` | no | DNS | Optional DAV DNS override while retaining Host/SNI. |
| `CARDDAV_MCP_LOG_FORMAT` | no | text | Set to `json` for structured logs. |
| `RUST_LOG` | no | application default | Tracing filter. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | disabled | Enables OTLP tracing export. |

Public resource, IdP, and DAV URLs must use HTTPS. Plain HTTP is accepted only
for loopback development URLs. Redirect URIs are exact matches; HTTP callbacks
are limited to loopback hosts.

## Logto and Stalwart setup

1. Create a Logto API resource with an indicator exactly equal to
   `CARDDAV_MCP_RESOURCE_URL`.
2. Create or reuse a public SPA/PKCE client and add
   `<CARDDAV_MCP_RESOURCE_URL>/oauth/callback` to its redirects.
3. Put that client ID in `CARDDAV_MCP_DCR_CLIENT_ID`.
4. Configure Stalwart's OIDC directory to trust the same issuer and accept the
   resource audience.
5. Put only the MCP clients' exact callback URIs in
   `CARDDAV_MCP_OAUTH_REDIRECT_URIS`; never add wildcards.

The service returns its static Logto client through a constrained DCR shim.
It proxies authorization and token requests on its own origin because remote
MCP clients require same-origin OAuth metadata. It does not mint tokens.

## Deployment

- [`compose.yaml`](compose.yaml) is the smallest local/self-hosted example.
- [`docs/kubernetes.yaml`](docs/kubernetes.yaml) is a restricted, non-root
  Kubernetes starting point. Add your ingress, TLS, and namespace-specific
  NetworkPolicy.
- `/health` is unauthenticated and returns JSON containing status and version.
- `/metrics` is served on a separate listener; do not expose it publicly.

Pin production images by both tag and digest. The official deployment uses a
read-only root filesystem, drops every Linux capability, and allows egress only
to DNS and HTTPS dependencies.

Forgejo Actions runs formatting, Clippy, tests, dependency and secret checks,
then builds and scans a Linux AMD64 OCI image. A `v*` tag publishes the versioned
image and `latest` to `forge.oddie.app/jlxq0/carddav-mcp`, with CycloneDX,
SPDX, and SLSA metadata. The production cluster is updated separately through
the `oddie-apps/platform` GitOps repository; Renovate proposes the digest change
and Argo CD applies it after that platform change is merged. This repository
does not deploy directly to Kubernetes.

## Development

Rust 1.93+ with edition 2024:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo audit
cargo deny check advisories bans licenses sources
gitleaks detect --source . --no-banner
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a change and
[CHANGELOG.md](CHANGELOG.md) for release notes.

## License

[MIT](LICENSE).
