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
- Bring your own Logto instance. `/auth`, `/token`, `/jwks` and `/me` are
  derived from the issuer, so arbitrary OIDC providers are not supported;
  see the discovery-metadata pitfall below.
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
- upcoming birthdays
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
  No test observes the deployed allowlist, and none can from this repository;
  update the deployed `CARDDAV_MCP_OAUTH_REDIRECT_URIS` value and public examples
  in the same change.
- A clean RustSec audit does not cover the distroless runtime packages. Scan the
  finished OCI image with Trivy, refresh the digest when fixes exist, and permit
  an unfixed CVE only with a narrow reachability argument plus a dated review.
- Trivy 0.74 expects an OCI image layout directory for `image --input`; it does
  not auto-extract a BuildKit `type=oci` tar archive. Extract the archive before
  scanning it, while retaining the tar for tools such as Syft that accept
  `oci-archive:` inputs.
- Standalone `buildctl` does not implement Buildx's `--attest` flag. Request
  provenance and SBOMs through Dockerfile frontend options instead:
  `--opt attest:provenance=mode=max` and `--opt attest:sbom=`.
- A merge and its release tag can run concurrently. Do not let both jobs export
  to the same registry cache reference: main owns cache export; tag builds only
  import that cache before publishing the immutable release image.
- **Run all five gates on a comment-only diff.** `clippy::doc_markdown` rejects
  an un-backticked CamelCase identifier in a doc comment, so prose naming
  another system's objects fails the build with no code changed: `MetalLB`,
  `BGPAdvertisement` and `HTTPRoute` cost a cycle here and the same three cost
  `jmap-mcp` one. Every pitfall in this file that names an external system is a
  candidate, which makes documentation changes the likeliest place to meet this
  lint rather than the safest.
- Latest-stable Clippy can add lints that fire only on code generated by `rmcp`
  attribute macros. Verify with the same stable toolchain as Forgejo Actions;
  when the generated code is the false positive, allow only that lint at the
  macro site and pair it with `unknown_lints` for the minimum supported Rust.
- `main` is protected: no direct push, admins included, `required_approvals: 0`,
  and `CI / cargo*` must be green. The glob is load-bearing, because a branch
  push posts `CI / cargo (push)` and a pull-request head posts
  `CI / cargo (pull_request)` — two context names for one job.
- **`CI / docker` is excluded from the required contexts on purpose. Do not add
  it back.** It declares `needs: cargo`, and a job skipped because its
  dependency failed still posts `success` to the commit status. Measured on five
  commits in this repository — `9b9a0515`, `a70d6a8c`, `e2168769`, `419fd6bf`,
  `b8aa2894` — each showing `CI / cargo` failure and `CI / docker` success one to
  two seconds later, with no docker task in the run at all. Requiring it would
  build a gate that a commit where nothing was built satisfies, and the rule
  itself records only what is required, never why the obvious second entry is
  missing.
- **Whether that required context can ever go green is decided in
  `.forgejo/workflows/ci.yml`, not in the protection rule.** `on.pull_request`
  is bare today — no `paths:`, no `branches:` — so every pull-request head
  produces `CI / cargo (pull_request)`. Add a filter and any PR the filter
  excludes produces no `cargo` context at all, and the required context can
  never report success: the gate turns from "requires green" into "cannot be
  satisfied", with nothing in the protection settings having changed and
  nothing in the rule pointing at the file that changed it. A docs-only PR
  under a `paths:` filter is the likely first casualty. Answer this from the
  `on:` block. Green PR contexts on past commits are corroboration after the
  fact, and a repository with no pull-request history has none available at
  all, while the `on:` block still answers.
- **A constant encoding another system's behaviour has to name that system
  beside it, and be measurable from this one.** `DEFAULT_TRUSTED_PROXY_HOPS`
  was 1 against a chain of 2 (`client -> Caddy edge -> Cilium gateway -> pod`),
  so every authenticated request wrote the edge's address into the last-used
  audit field as though it were the client's. Nothing failed, nothing was red,
  and the value was well formed — an absent field is recoverable and a
  confident wrong one in an audit record is not.
- It is only correct while the **edge replaces** `X-Forwarded-For` rather than
  appending. Do not treat a larger hop count as the safer choice: with one
  appending proxy and a client that sends its own header, a count of 2 selects
  the attacker's string, because the `len < hops` guard never fires. Re-derive
  the number and the edge's `trusted_proxies` setting together or not at all.
- **A hop count with no request-level log is unfalsifiable from outside the
  deployment.** Log the *count* of `X-Forwarded-For` entries and never the
  entries. Log it as a structured field: these logs are JSON, so
  `grep 'trusted_proxy_hops=[0-9]'` matches nothing and reads exactly like a
  service that logs nothing at all.
- The suite can be strong and still aimed one layer inside the value the
  deployment uses. Every `parse_client_ip` test passed a hop count explicitly,
  so all of them stayed green at any default. A test that asserts the default
  must construct through the real path and take the number from the config, and
  it has to be checked in **both** directions — reverting to 1 and to 3 — or it
  is a tautology on the constant.
- **Two log lines emitted microseconds apart are adjacent, not joined**, and
  the gap that makes adjacency look safe is a property of the traffic rather
  than of the code. The `introspect` audit line and the chain-length line are 8
  to 30 us apart while consecutive requests are 1.5 to 26 ms apart, measured
  2026-08-27 — a 50x margin produced by one serial client, which two concurrent
  requests erase.
- **`token_hash` would not fix that pairing here.** Every session mounting this
  server presents the same bearer: 7 chain-length lines and 8 audit lines on
  one pod resolved to **one** `token_hash` and one user. It identifies a
  credential and never a client, so adding it to a second line buys the
  appearance of attribution and none of the substance. A per-request
  correlation id, or folding the field into the audit event, is the fix if one
  is ever needed.
- **When comparing a source literal against a live value, the fault will be in
  the extraction, and its two outcomes cost differently.** Reading the
  allowlist literal with `sed -n 'start,+9p'` swallowed the following
  statement, so the comparison printed `DIFFER` against a deployed value that
  was byte-identical. Bound the extraction to the literal — match
  `let raw = "(.*?)";` and unescape the line continuations — rather than to a
  line count that the next edit invalidates.
- The mechanism is symmetric and the consequence is not: the same fault
  printing `IDENTICAL` is never questioned, while `DIFFER` sends someone to
  look and the fault surfaces in a minute. So the check has to be shown both
  answers before it is believed — feed it a known-identical input and confirm
  it says so, then a known-different one and confirm it disagrees. Reporting
  each side's entry count beside the verdict is what made the first one
  legible.
- **The hop count's safety rests on a `parentRef` in `oddie-apps/platform`, and
  nothing here can assert it.** Each of the eight MCP HTTPRoutes has exactly one
  `parentRef`, `gateway/web`. Adding `gateway/home` makes that backend
  LAN-reachable in one line with nothing else changing, and then a caller who
  skips the edge has a real chain depth of 1 and can forge the leftmost
  `X-Forwarded-For` entry. Today it costs code running inside the cluster:
  measured 2026-08-27, the gateway answers 401 from a pod and times out from
  the house LAN, because MetalLB advertises `203.24.209.5/32` over BGP to `sgp`,
  `lax` and `zrh` while the L2 pool is a different address.
- **If that ever changes, 2 is worse than 1 rather than merely wrong.** A hop
  count of 1 selects an infrastructure address, incorrect and inert. A hop
  count of 2 on a one-deep chain selects whatever the caller typed. The value
  that fixes the ordinary path is the value that makes the bypass path
  caller-controlled, so "set it to the edge-inclusive depth" reads as complete
  and is not.
- **`MAX_INITIALIZES_PER_IDENTITY` is reconnect headroom, not the flood
  defence.** `session::MAX_SESSIONS` caps live sessions at 256 and is the real
  control, so sizing the initialize burst for the fleet gives nothing away. Its
  original comment assumed "one or two live sessions", which is a single-client
  assumption that this deployment has never matched.
- **Every mounting session authenticates as one Logto subject, so a per-subject
  limit is a fleet limit.** Six distinct bearer hashes in 12 hours all carried
  one `sub`. Raising the burst moves the cliff and does not make the limit
  per-agent, because there is no per-agent identity to key on: that is an
  identity problem rather than a rate-limiting one.
- **One client connection costs two charges.** `claude-code` posts twice
  without an `mcp-session-id` about 30 ms apart, creating two sessions, and only
  the second reaches `Service initialized as server`. Measured 2026-08-28: 16
  charged creates produced 5 usable sessions. Any capacity stated in
  connections is half the number in the constant.
- **A refused request must spend nothing.** Charging one bucket before testing
  another turns a queue into a livelock: retries consume every refill without
  completing a connection, and the fleet never converges. Pinned by
  `a_refused_initialize_spends_nothing`.
- **A rejection with no log line and no counter is invisible.** For the hours
  the fleet was locked out, this server recorded nothing at all, and the cause
  had to be reconstructed from which requests succeeded and from the silence
  after them. Any refusal path needs its own counter before it needs tuning.
- **`kubectl port-forward` cannot reach this service's metrics listener and
  reports `connection refused`.** The listener binds `POD_IP:9090`, and
  port-forward dials `127.0.0.1` inside the pod's namespace where nothing is
  listening. Verified 2026-08-28 against a healthy pod that Alloy was scraping
  normally. Use the log line, query what Alloy ships to, or curl the pod IP from
  inside the cluster; a port-forward that returns nothing is evidence about
  port-forward.
- The same run shows why to dry-run a check before it matters: grepping the
  forwarded endpoint for a **new** counter returned 0, which was indistinguishable
  from the counter being absent, because the known-good counter beside it also
  returned nothing. Ask a check for a value you already know before asking it
  the one you do not.
- **A field acceptance of an initialize-limit change cannot discriminate here,
  so do not try.** Three sessions in the whole fleet hold a `carddav` mount
  (`lucy`, `mantis`, `penny`, measured 2026-08-28 from their configs and
  confirmed by each). Three connections is six charges, under every burst this
  service has shipped, and a pod replacement resets the buckets either way. The
  `v0.1.5` acceptance ran clean and **would have passed on `v0.1.4` too**: zero
  rejections means the changed code never executed. Distinguishing the versions
  needs five simultaneous connections or a drained bucket observed recovering,
  neither of which exists in the field. Use mutation, and say which kind of
  evidence you have.
- The way that happened is worth as much as the fact: **each step that made the
  test more rigorous made it less discriminating**, and each was right on its
  own. Insisting on simultaneous reconnects was correct against a failure mode
  that was not the problem. Then correcting the population from an unvalidated
  eight to a measured three was also correct, and it is what removed the only
  condition under which the window could have failed. Ask what result would
  falsify the check, and ask it again after every correction to the check.
- **A client that connected before a rollout advertises the old tool list until
  something forces it to reconnect**, and `ToolSearch` finding nothing is
  indistinguishable from a tool that was never shipped. Measured 2026-08-29 on
  the `v0.1.6` rollout: `upcoming_birthdays` was missing from a mounting
  session's tool list twice, and appeared immediately after any call on that
  mount re-initialized it. **Have the session make one call first, then look
  again**, before reporting a new tool absent. A correct deployment reads as a
  negative result otherwise.
- **Ask a log for a field name you have already seen before concluding a field
  is absent.** The tool audit writes `event="tool_call"` with `method=<tool>`,
  not `tool=<tool>`. Grepping for `"tool":` returned zero on a pod that had just
  served the call, which is the same silence as a tool never having run. Two of
  the three checks written in this repo on 2026-08-28 and 29 failed this way.
- **`contacts_scanned` counts every address book unless one is named.** This
  service has two (`Contacts`, 366 cards, and `Trusted Senders`, 8), so a count
  taken against `default/` alone is 366 and the tool's default answer is 374. A
  raw `addressbook-query` used to predict a tool's output has to query the same
  set the tool will.
- **A test that reimplements a comparison tests its own copy and leaves the
  call site uncovered.** The birthday fixture filtered with
  `days_until(b, today) <= days` while `upcoming_birthdays` compared
  `days_until > params.days` inline. Flipping the tool's `>` to `>=` drops a
  birthday exactly `days` away, turns the live 30-day answer from 3 into 2, and
  **left all 107 tests green**. The helper was thoroughly covered and the
  decision that uses it was covered by nothing.
- The repair is one predicate both sides call, not another test:
  `birthday::within_window`. `days_until` is **private** so a call site cannot
  compare against a raw day count at all — reintroducing the drift now fails to
  compile rather than passing quietly. Extraction alone would not have done it,
  since an inline comparison beside the predicate is still green.
- **This image is single-platform, and it is still an index.** Measured on
  `v0.1.6`: the OCI index holds `linux/amd64` plus one `unknown/unknown`
  attestation manifest, so `docker manifest inspect -v` returns an **array**
  because of the attestation rather than because of architectures. Do not read
  that array as multi-arch; there is no arm64 image, which is #10.
- **The index digest is what answers.** The pod's `imageID`
  (`sha256:7ecc9b4d…` for `v0.1.6`) is the index digest, and it is exactly what
  `clusters/fondue/carddav-mcp` pins as `tag@digest`. Neither child digest
  appears anywhere a pod or a manifest reports, so comparing against one of them
  produces a confident mismatch on a correctly deployed image.
- **Pull requests are gated by the director before merge**, agreed 2026-08-29
  after a surviving mutation reached production. The exception is an incident,
  meaning something currently broken for a user or the fleet: ship it, **leave
  the PR open**, and send one line saying it was an incident and what was
  broken. A defect found in review or by a mutation is not an incident however
  real. Closing an unreviewed incident fix is what turns a debt into a fact.
- Loopback redirect URIs cannot be matched by exact string equality. A native
  client binds a random ephemeral port per session, and RFC 8252 §7.3 requires
  the server to accept any port for a loopback entry. Relax the port only for
  cleartext `http` on a loopback host; scheme, host, path and query stay exact,
  and `https` / private-use entries keep exact matching including the port.
