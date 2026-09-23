# web-access

Browser-based RDP with no third party in the session. The RDP client runs in the browser as
WebAssembly; the server side is a WebSocket-to-TCP proxy that never decodes the stream.

Design record: `docs/architecture.md`.

## Shape

    browser (ironrdp-web, WASM)  ──WebSocket/TLS──>  proxy  ──TCP 3389──>  Windows target
            ^ the RDP client                          ^ auth + RDCleanPath, no decoding

| Piece | Source | Status |
|---|---|---|
| RDP client in the browser | `ironrdp-web`, Apache-2.0 | reuse |
| RDCleanPath, both ends | `ironrdp-rdcleanpath` | reuse |
| WebSocket-to-TCP proxy | this repo | written; compiles, 12 tests pass |
| Authentication in front of the proxy | this repo | trait plus a development stub; the identity provider is undecided |

## Build

    cargo check --all-targets
    cargo test
    cargo run -- config.toml

`config.example.toml` is the starting point. There is no default for `tls.verify`; state it.

VERIFICATION STATE, 2026-09-23: the crate compiles on Rust 1.98.1 and its 12 tests pass. It has NOT
been run against a real RDP server, so the handshake is correct against the published RDCleanPath
types and unproven against Windows. The first live connection is the test that matters.

## Why not the obvious things

| Ruled out | Reason |
|---|---|
| Cloudflare Access browser RDP | external dependency; the estate this targets is internal only |
| Apache Guacamole | the Java webapp, database and extension framework are most of it, and none of it is wanted |
| Microsoft RD Web Client | RDS role infrastructure and CALs |
| Teleport | a platform where a component was wanted |
| MeshCentral, Devolutions Gateway as a product | agent-based reach, not the shape being built |

## Settled

- The RDP client runs CLIENT-SIDE in WASM, not server-side.
- RDCleanPath is acceptable. Session confidentiality from the proxy is not a requirement on an
  internal network.
- DIRECT REACH. The proxy opens TCP to the target. No agents, no connectors, nothing installed on
  any target, so appliances and vendor-supported nodes are in scope.
- PASS-THROUGH credentials. The user's own Windows account authenticates to the target and the proxy
  stores nothing.
- Apache-2.0 upstream, so the licence question is closed.

All four are Lewis's, 2026-09-23.

## Open

- Identity provider for authenticating the user to the proxy.
- Target list source; static config is enough to start.
- Session recording, which conflicts with the architecture rather than extending it.

## Conventions

- No credential, host address or site detail belongs in this repository. It is a general tool and
  the network it might be deployed into is not described here.
- Upstream is `Devolutions/IronRDP`, Apache-2.0. Reuse the crates. Do not vendor a fork without
  writing down why, in `docs/architecture.md`.
- Commit subjects are declarative sentences, no prefixes.
- LF only.
- Record what was OBSERVED. "Not yet tested" goes false silently and nobody goes back to edit it, so
  date it and say what would change it, or write the positive observation instead.

## Licence

MIT. See `LICENSE`.
