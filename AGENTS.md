# carddav-mcp

Rust (`axum` + `rmcp`) streamable-HTTP MCP server for Stalwart CardDAV.
Reuse the jmap-mcp HTTP/OAuth/DCR/streamable-HTTP shell. Replace the JMAP
client with CardDAV. Do not ship Node/Go. Do not invent a third auth story.
Do not wrap third-party CardDAV MCP servers.

## Public auth contract

- Self-host. Public URL is `https://carddav-mcp.your-domain.example/mcp`.
- Streamable HTTP. `initialize` creates a durable session.
- RFC 9728 resource = `{origin}/mcp`. Metadata at
  `/.well-known/oauth-protected-resource/mcp`.
- `RESOURCE_URL` env = origin **without** `/mcp`.
- Bring your own IdP (Logto or another OIDC provider).
- Validate inbound JWT (JWKS), forward that bearer verbatim to Stalwart.
- Never accept or store Basic credentials or app passwords.
- Never log tokens.

## Environment

```text
CARDDAV_MCP_RESOURCE_URL=https://carddav-mcp.your-domain.example
CARDDAV_MCP_AUTHORIZATION_SERVER=https://login.your-domain.example/oidc
CARDDAV_MCP_STALWART_DAV_BASE_URL=https://dav.your-domain.example
CARDDAV_MCP_DCR_CLIENT_ID=<your-dcr-client-id>
```

## Scope

- `whoami`
- list address books
- list/search contacts
- create / update / delete contacts

Keep the HTTP/OAuth/session/Dockerfile/CI identical in shape; only the backend
client + tool list change. Self-contained repo (no third shared-crate repo).

## Verification

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```

## Known pitfalls

- Forgejo Actions can fail during `Set up job` when an immutable action commit
  is no longer advertised by the action mirror. Verify every pinned revision
  with `git ls-remote` and update the pin rather than retrying unchanged.
- Forgejo Runner does not apply the `default: stable` input declared by
  `dtolnay/rust-toolchain`. Always pass `toolchain: stable` explicitly.
- Stalwart `requireAudience` may accept only one resource indicator. Set
  `CARDDAV_MCP_STALWART_AUDIENCE` to the audience the DAV server actually
  accepts, and keep RFC 9728 `resource` as `{origin}/mcp`.
- Unknown JWT `kid` values are attacker-controlled before authentication.
  Serialize and rate-limit JWKS refresh attempts so they cannot amplify one
  public request into one IdP request.
- A retain-only cleanup pass is not a memory cap. OAuth state, token-bucket,
  and other identity-keyed maps must enforce a hard maximum after expiry or
  idle eviction.
- `rmcp` 1.x collects streamable-HTTP JSON bodies before deserializing them.
  Keep an outer `RequestBodyLimitLayer` on `/mcp`; tool-level field limits run
  too late to protect process memory.
- Reconstructed OAuth token responses must explicitly restore
  `Cache-Control: no-store` and `Pragma: no-cache`; forwarding only the body
  and content type drops the upstream credential-caching protection.
- Public IdP, resource, and DAV URLs must use HTTPS. Permit cleartext HTTP only
  for loopback development endpoints.
- RustSec advisories can appear between an initial audit and final verification.
  Always rerun `cargo audit` against the finished lockfile; do not rely on an
  earlier clean result.
- `CARDDAV_MCP_AUTHORIZATION_SERVER` is currently Logto-shaped: the code derives
  `/auth`, `/token`, `/jwks`, and `/me` directly. Do not advertise arbitrary
  OIDC-provider compatibility until discovery metadata drives those endpoints.
- OAuth client redirects are deployment configuration, not compiled defaults.
  Adding a URI to `deployed_allowlist_parses` does not enable it at runtime;
  update the deployed `CARDDAV_MCP_OAUTH_REDIRECT_URIS` value and public examples
  in the same change.
