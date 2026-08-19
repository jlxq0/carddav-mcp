# Contributing

Issues and pull requests are welcome at
<https://forge.oddie.app/jlxq0/carddav-mcp>.

## Development workflow

1. Create a focused branch from `main`.
2. Add regression tests for behavior changes and security boundaries.
3. Run the complete verification suite:

   ```sh
   cargo fmt --all --check
   cargo clippy --all-targets --all-features --locked -- -D warnings
   cargo test --all-features --locked
   cargo audit
   cargo deny check advisories bans licenses sources
   gitleaks detect --source . --no-banner
   ```

4. Use a conventional commit such as `fix(auth): reject expired state`.

Keep changes self-contained in this Rust repository. Do not introduce Basic
authentication, app-password storage, token logging, or a second authentication
story. Never put real contacts, credentials, public customer addresses, or
production tokens in tests and fixtures.

Security reports belong in the private channel documented in
[SECURITY.md](SECURITY.md), not in public issues.
