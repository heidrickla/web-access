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
| WebSocket-to-TCP proxy | this repo | to write |
| Authentication in front of the proxy | this repo | to write, mechanism undecided |

## Why not the obvious things

| Ruled out | Reason |
|---|---|
| Cloudflare Access browser RDP | external dependency; the estate this targets is internal only |
| Apache Guacamole | the Java webapp, database and extension framework are most of it, and none of it is wanted |
| Microsoft RD Web Client | RDS role infrastructure and CALs |
| Teleport | a platform where a component was wanted |
| MeshCentral, Devolutions Gateway as a product | agent-based reach, not the shape being built |

## Settled

- The RDP client runs CLIENT-SIDE in WASM, not server-side. The proxy moves bytes and cannot read
  them unless RDCleanPath strips the inner TLS.
- RDCleanPath is acceptable. Session confidentiality from the proxy is not a requirement on an
  internal network (Lewis, 2026-09-23).
- Apache-2.0 upstream, so the licence question is closed.

## Open

- Whether targets are reached directly by the proxy, or dial out to it in a reverse tunnel.
- Authentication mechanism.
- Where the proxy sits relative to the network zones it serves.

## Licence

MIT. See `LICENSE`.
