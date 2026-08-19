# Security policy

## Supported versions

Only the newest tagged release receives security fixes. Versions older than
`0.1.1` are unsupported because they lack request-amplification and memory-bound
protections added after the initial release.

## Reporting a vulnerability

Do not open a public issue for a vulnerability or include credentials, tokens,
personal contacts, or production host details in a report. Email
`julian@lindner.earth` with:

- the affected version or commit;
- the attack preconditions and security impact;
- a minimal reproduction that does not target the public instance; and
- any suggested mitigation.

You should receive an acknowledgement within seven days. Coordinated disclosure
is preferred; a fix and release timeline depends on severity and reproducibility.

## Security boundaries

`carddav-mcp` deliberately grants an authenticated MCP client access to the
user's CardDAV address books. The operator, MCP client, identity provider, and
Stalwart server are trusted. Unauthenticated callers, bearer-token holders from
another audience, DAV response content, redirects, and network input are not.

The server must never accept Basic credentials, store app passwords, log bearer
tokens, follow DAV URLs off the configured origin, or expose `/metrics` on the
public listener. Production service URLs must use HTTPS.
