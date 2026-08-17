# carddav-mcp

Rust streamable-HTTP MCP server for per-user address books on Stalwart CardDAV.
It validates inbound JWTs from your IdP (Logto or another OIDC provider),
then forwards the same bearer verbatim to Stalwart. It never accepts or
stores Basic credentials or app passwords.

Self-host the `/mcp` endpoint on your own domain.

## Tools

- whoami
- list_address_books
- list_contacts
- search_contacts
- create_contact
- update_contact
- delete_contact

## Required environment

```text
CARDDAV_MCP_RESOURCE_URL=https://carddav-mcp.your-domain.example
CARDDAV_MCP_AUTHORIZATION_SERVER=https://login.your-domain.example/oidc
CARDDAV_MCP_STALWART_DAV_BASE_URL=https://dav.your-domain.example
CARDDAV_MCP_DCR_CLIENT_ID=<your-dcr-client-id>
CARDDAV_MCP_OAUTH_REDIRECT_URIS=https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback,https://www.cursor.com/agents/mcp/oauth/callback,cursor://anysphere.cursor-mcp/oauth/callback,grokbot://mcp/oauth/callback,http://localhost:8787/callback
```

The public MCP endpoint is `https://carddav-mcp.your-domain.example/mcp`.

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
```
