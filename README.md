# web-access

Browser-based RDP with no third party in the session. The RDP client runs in the browser as
WebAssembly; the server side is a WebSocket-to-TCP proxy that never decodes the stream.

Design record: `docs/architecture.md`.

## Shape

    browser (ironrdp-web, WASM)  ──WebSocket──>  proxy  ──TCP 3389──>  Windows target
            ^ the RDP client                      ^ auth + RDCleanPath, no decoding

| Piece | Source | Notes |
|---|---|---|
| RDP client in the browser | `ironrdp-web`, Apache-2.0 | built to WASM and EMBEDDED in the proxy binary |
| RDCleanPath, both ends | `ironrdp-rdcleanpath` | reused |
| WebSocket-to-TCP proxy | this repo | `src/` |
| Authentication in front of the proxy | this repo | `src/auth.rs`; an identity provider plugs in at `identify()` |

## Build

    cargo check --all-targets
    cargo test
    cargo run -- config.toml

The dependency tree is VENDORED, so this builds with no network at all. `.cargo/config.toml` points
Cargo at `vendor/`; `Cargo.lock` is committed, because vendoring without a lockfile pins nothing.

Two settings keep the vendored tree intact:

| Setting | Without it |
|---|---|
| `!vendor/**` in `.gitignore` | the `*.pem` and `*.key` rules drop vendored files, and Cargo's per-file checksums fail on a fresh clone |
| `vendor/** -text` in `.gitattributes` | `eol=lf` rewrites upstream CRLF files, changing the bytes `.cargo-checksum.json` covers |

After changing dependencies: `cargo vendor`, then `cargo build --offline` and `cargo test --offline`
from a fresh clone with the crate cache emptied.

`config.example.toml` is the starting point. There is no default for `tls.verify`; state it.

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

## Roadmap

Future additions. RDP comes first. Design for each is in `docs/architecture.md`.

| Addition | What it takes |
|---|---|
| Identity provider | plugs in at `auth.rs::identify()` |
| Target list source | a source other than the static config |
| TLS on the listener | a certificate and a TLS acceptor in front of the existing listener. Also what the browser credential manager needs, being secure-origin only |
| Proxy-side encrypted credential store | the identity provider first |
| Linux desktops | EGFX in `ironrdp-web`, which GNOME Remote Desktop, built into Ubuntu, requires. xrdp is the fallback |
| SSH | a raw-forward proxy mode; Go's SSH client compiled to WASM, on xterm.js |
| VNC | the same raw-forward mode; noVNC |
| Telnet | the same raw-forward mode; xterm.js plus option negotiation |
| Kerberos for RDP | a KDC proxy endpoint; `ironrdp-web` already takes the URL |
| HTTP(S) web interfaces | a reverse proxy: a new component, not a relay mode |

## Windows installer

`installer/` builds an MSI. MSI rather than a self-extracting exe because it is deployable the way an
organisation already deploys things — GPO, SCCM, Intune — with a real uninstall and upgrade path.

    # 1. produce the binary (cross-compiled from Linux, or natively on Windows)
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
        cargo build --release --target x86_64-pc-windows-gnu
    # 2. drop it in installer/payload/, then
    pwsh installer/build.ps1

What the MSI does:

| | |
|---|---|
| Installs | `%ProgramFiles%\web-access\web-access-proxy.exe`, config to `%ProgramData%\web-access\config.toml` |
| Service | `WebAccessProxy`, auto-start, running as `NT AUTHORITY\LocalService` |
| Service arguments | `--service "[ProgramData]\web-access\config.toml"` |
| Service control | stop on reinstall, stop and delete on uninstall (event 162). NOT started by the installer |
| Firewall | one exception scoped to the PROGRAM, not a port, because the port comes from a config an administrator edits |
| Upgrades | major-upgrade path registered; the config is `NeverOverwrite`, so an upgrade cannot reset the allowlist |

LocalService, not LocalSystem: the proxy opens sockets and reads one file, and never authenticates as
itself to anything, because credentials pass through to the target untouched.

### Installing

From an ELEVATED prompt. The installer does not start the service, by design — see below.

    msiexec /i web-access-proxy.msi /l*v install.log     # or /qn to run silent

Then configure it, because an unconfigured gateway will not run:

1. Edit `C:\ProgramData\web-access\config.toml`: set `listen`, author the `[[target]]` allowlist and
   the `[[policy]]` grants, and set `tls.verify`. There is no default for `verify`.
2. If `verify = "ca"`, put the CA bundle where `ca_bundle` points.
3. `Start-Service WebAccessProxy`, then browse to `http://<host>:<port>/`. The proxy serves the
   client itself — there is nothing to install on the machine you browse from, which was the point.
4. `Get-Service WebAccessProxy` should read Running. If it does not, the reason is in the config:
   the service refuses to start rather than run against something it cannot validate.

Uninstall with `msiexec /x web-access-proxy.msi`, which stops and removes the service. The config in
`ProgramData` is left behind on purpose; an allowlist someone authored is not the installer's to
delete.

WHY IT DOES NOT AUTO-START: the shipped config names example hosts and a CA bundle path, so it runs
only once someone has written a real configuration. Start type is still `auto`, so once it is
configured and started it survives reboots.

WiX v5 SPECIFICALLY. v6 and v7 require accepting the Open Source Maintenance Fee EULA, which is a
licensing decision with a fee attached for commercial use. v5 is the last version without that gate
and uses the same schema. The Firewall extension must be version-pinned to match the toolset.

## The browser client

"Clientless" means nothing is INSTALLED on the accessing machine, not that no client exists. The RDP
client is `ironrdp-web` compiled to WebAssembly and delivered per session by the proxy itself.

| | |
|---|---|
| `web/ironrdp_web_bg.wasm` | built with `wasm-pack build --target web --release` |
| `web/ironrdp_web.js` | wasm-bindgen glue |
| `web/index.html` | the page: launcher tiles, sign-in dialog, canvas, session rail |
| `web/app.css`, `web/app.js` | separate files, NOT inlined: the proxy sends `default-src 'self'`, which drops an inline `<style>` and blocks an inline `<script>`. A test asserts the page inlines nothing the CSP forbids |

All three are committed and embedded with `include_bytes!`, so the deployment stays one MSI, one
service, browse to it. There is no web root to install and no way for the served client to drift
from the proxy it talks to.

One listener carries both. The request path is PEEKED without consuming, so a WebSocket upgrade
still reaches the handshake intact; `/ws` is the socket and everything else is a static asset.
Routing is by request line rather than by the `Upgrade` header because a header block can be split
across segments and a request line essentially never is.

The client's API maps straight onto the proxy's design, which is the check that the architecture was
right: `SessionBuilder.destination()` carries the TARGET ID, `authToken()` is what the proxy
authenticates, and `username()`/`password()` pass through to Windows untouched.

Keyboard: printable keys go through `unicodePressed`, non-printable ones through a scancode table. A
key in neither is dropped rather than guessed at.

## Conventions

- No credential, host address or site detail belongs in this repository. It is a general tool and
  the network it might be deployed into is not described here.
- Upstream is `Devolutions/IronRDP`, Apache-2.0. Reuse the crates. Do not vendor a fork without
  writing down why, in `docs/architecture.md`.
- Commit subjects are declarative sentences, no prefixes.
- LF only.
- Docs describe design, build and use. What is broken, missing, untested or weak goes stale within
  hours on a moving project, so it does not go in these files.

## Licence

MIT. See `LICENSE`.
