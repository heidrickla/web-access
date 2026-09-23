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

The dependency tree is VENDORED, so this builds with no network at all. `vendor/` holds 106 crates
and `.cargo/config.toml` points Cargo at it; `Cargo.lock` is committed, because vendoring without a
lockfile pins nothing. Nothing is fetched from crates.io.

Two settings exist to keep that true and both were measured, not assumed:

| Setting | Without it |
|---|---|
| `!vendor/**` in `.gitignore` | the `*.pem` and `*.key` rules silently drop 15 of 5451 files, and Cargo's per-file checksums then fail on a fresh clone, reading as a corrupt vendor tree |
| `vendor/** -text` in `.gitattributes` | `eol=lf` rewrites 38 upstream CRLF files, changing the bytes `.cargo-checksum.json` is computed over, with the same symptom |

Verified 2026-09-23 the only way that means anything: cloned fresh, with the crate cache emptied,
then `cargo build --offline` and `cargo test --offline`. Build succeeded, 12 tests passed.

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

## Windows installer

`installer/` builds an MSI. MSI rather than a self-extracting exe because it is deployable the way an
organisation already deploys things — GPO, SCCM, Intune — with a real uninstall and upgrade path.

    # 1. produce the binary (cross-compiled from Linux, or natively on Windows)
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
        cargo build --release --target x86_64-pc-windows-gnu
    # 2. drop it in installer/payload/, then
    pwsh installer/build.ps1

What the MSI does, verified by reading the built package's tables rather than by intending it:

| | |
|---|---|
| Installs | `%ProgramFiles%\web-access\web-access-proxy.exe`, config to `%ProgramData%\web-access\config.toml` |
| Service | `WebAccessProxy`, auto-start, running as `NT AUTHORITY\LocalService` |
| Service arguments | `--service "[ProgramData]\web-access\config.toml"` |
| Service control | start on install, stop and delete on uninstall (event 163) |
| Firewall | one exception scoped to the PROGRAM, not a port, because the port comes from a config an administrator edits |
| Upgrades | major-upgrade path registered; the config is `NeverOverwrite`, so an upgrade cannot reset the allowlist |

LocalService, not LocalSystem: the proxy opens sockets and reads one file, and never authenticates as
itself to anything, because credentials pass through to the target untouched.

WiX v5 SPECIFICALLY. v6 and v7 require accepting the Open Source Maintenance Fee EULA, which is a
licensing decision with a fee attached for commercial use. v5 is the last version without that gate
and uses the same schema. The Firewall extension must be version-pinned to match the toolset.

NOT YET INSTALLED ANYWHERE as of 2026-09-23. The package builds and its contents are verified; no
machine has run it, so the service's ability to read the config as LocalService and bind its port is
unproven.

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
