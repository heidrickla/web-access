# Architecture

Design record, 2026-09-23, settled in one conversation after building the Cloudflare version of the
same thing and taking it apart.

## The problem

Reach a Windows desktop from a browser, with nothing installed on the accessing machine, on an
internal network with no third party in the path.

## Why a browser cannot do this by itself

RDP is binary over TCP 3389 with its own TLS and CredSSP handshake. A browser exposes no raw TCP
socket API. So something must be a real RDP client, and the only question is WHERE that client runs.

| Client location | Consequence |
|---|---|
| Server-side | the gateway decodes RDP and re-emits drawing operations. Every channel must be re-implemented by hand. Apache Guacamole |
| Client-side, WASM | the browser IS the RDP client; the server is a byte relay. Cloudflare |

This repository takes the second.

## What Cloudflare actually does, since it was the reference

Measured, not assumed — their engineering blog, "RDP without the risk", 2025-03-21:

- The client is IronRDP compiled to WebAssembly, running in the browser. The post names Apache
  Guacamole as the alternative they rejected, for being Java.
- The client wraps the RDP session in a WebSocket, because browsers cannot speak TCP.
- `RDCleanPath` eliminates the inner RDP TLS, on the grounds that the WebSocket is already TLS to
  Cloudflare. That is what makes the session readable inside their network.
- Their server half is Cloudflare-specific: a Workers-based WebSocket proxy handing off to an
  internal routing service, then out through Cloudflare Tunnel. None of it is replicable and none of
  it is needed.

AN EARLIER READING OF THIS WAS WRONG AND IS KEPT HERE because it is an easy mistake to repeat: from
the feature limits alone — no audio, 500 KB text-only clipboard, PDF-only printing, file transfer as
a separate panel — it looks exactly like a server-side re-encoding design, because those are the
symptoms of having to bridge every channel by hand. It is not. Those limits are product decisions.
`ironrdp-rdpsnd` and `ironrdp-rdpdr` exist in the upstream tree, so audio and drive redirection are
implemented in the library and simply not exposed. A limitation list is evidence about a product, not
about its architecture.

## What is reused

Upstream is `Devolutions/IronRDP`, Apache-2.0, 67 crates. The ones that matter here:

| Crate | Role |
|---|---|
| `ironrdp-web` | the WASM browser build; the client half |
| `ironrdp-rdcleanpath` | the protocol between browser and proxy, both ends |
| `ironrdp-connector`, `ironrdp-tls`, `ironrdp-tokio` | connection sequence and transport for the proxy |
| `ironrdp-rdpsnd`, `ironrdp-rdpdr`, `ironrdp-cliprdr` | audio, drives, clipboard — available if wanted |

Devolutions Gateway is the reference implementation of the proxy half and is worth reading before
writing this one.

## What is written here

A WebSocket-to-TCP proxy:

1. Terminate the WebSocket and authenticate the user.
2. Decide which target that identity may reach.
3. Read the RDCleanPath request, open TCP to the target, perform the TLS handshake on the client's
   behalf, return the server's response.
4. Pipe bytes until the session ends.

The proxy never decodes RDP. It is the enforcement point for identity and target selection, and
nothing else, which is what keeps it small enough to review.

## Decisions

| Decision | State |
|---|---|
| Client-side WASM rather than server-side rendering | settled |
| RDCleanPath, accepting that the proxy can read the stream | settled: internal network, not a concern (Lewis, 2026-09-23) |
| DIRECT REACH: the proxy opens TCP to the target, no agents anywhere | settled (Lewis, 2026-09-23) |
| PASS-THROUGH: the user's own Windows credentials go to the target; the proxy stores none | settled (Lewis, 2026-09-23) |
| Identity provider for authenticating the USER to the proxy | OPEN |
| WHERE SAVED CREDENTIALS LIVE | OPEN, and the answer changes the architecture. See below |
| Target list source | OPEN; static config is enough to start |
| THE CLIENT SENDS A TARGET ID, NEVER AN ADDRESS | settled by design. Cloudflare's `/rdp/<vnet>/<ip>/<port>` lets the browser name the destination, so the allowlist is all that stands between a crafted request and an unlisted host. An opaque id makes "reach an arbitrary host" inexpressible rather than merely forbidden |
| RESOLVE BY NAME, not by address | settled (Lewis, 2026-09-23) |
| Verify the target's certificate against an internal CA | OPEN, and coupled to the row above |
| Session recording | OPEN, and it conflicts with client-side RDP: a proxy that cannot decode the stream cannot record it. If recording is required, it has to come from the target or from a decoding gateway, and that reopens the architecture |

### Resolving by name puts DNS in the trust chain

The target entry carries a hostname and the proxy resolves it at CONNECTION time, not at startup, so
a re-addressed host is picked up without a restart. DNS decides which machine a target id reaches.

Name resolution answers WHERE. Certificate validation answers WHO. The certificate row above is the
other half of this control.

Rules:

- Log the name AND the address it resolved to at that moment.
- Fail closed on resolution failure. No silent fallback to a cached address.
- A name resolving to several addresses is refused rather than picked from.

Agent identity is no longer a decision. Direct reach means there are no agents to authenticate.

### What direct reach makes load-bearing

With no agents, nothing outside the proxy constrains which hosts it can open a socket to except
network policy. SO THE TARGET ALLOWLIST IN THE PROXY IS A SECURITY CONTROL, not a convenience
feature: default-deny, explicit, and reviewable. A bug that lets an identity reach an unlisted target
is a boundary failure, and it should be tested as one.

### Where saved credentials live

| | Where | Scope |
|---|---|---|
| Browser `localStorage` | the browser profile | per browser; no server work |
| Browser credential manager | the Credential Management API | per browser; requires a secure origin |
| PROXY-SIDE ENCRYPTED STORE | a database the proxy owns, the Guacamole model | per user or per connection, any machine |

The third is the direction this grows into, because it is what makes a multi-user gateway possible:

- Credentials follow the USER, not the browser.
- An administrator can attach credentials to a CONNECTION rather than a person, so an operator clicks
  a system and is in without knowing the Windows password, and a credential rotates without telling
  anyone.
- One place to audit, revoke and rotate.

Design consequences:

- The proxy then holds credentials, which reverses pass-through rather than extending it.
- Per-user storage keeps the proxy log and the Windows event log naming the same person;
  per-connection storage makes the event log name the connection's account instead.
- Key management decides the design. Candidates, strongest first:
  1. Derived from the authenticated user's own session, so a row decrypts only while that user is
     signed in. Requires the identity provider.
  2. Windows DPAPI under the service account, binding the store to the machine.
  3. A key in the config file. Rejected.

It follows the identity provider, because option 1 needs identities to key against.

### What pass-through makes true

- The proxy holds no secrets.
- The Windows event log names the actual person, so the proxy's log and the target's log correlate.
  That correlation is the audit story.
- CredSSP has to work from a browser-hosted client. This is the historically awkward part of
  client-side RDP, and it is known to work: Cloudflare's implementation is pass-through and states
  that it manages no credentials on the Windows server.

## The capability note

Every limitation of the Cloudflare implementation is a choice made for a multi-tenant edge. On an
internal network none of those reasons apply, so audio, drive redirection and a full clipboard are
all available from the same upstream crates. The stripped-down build does not have to be the
stripped-down experience.

## Other connection types

Roadmap; RDP comes first (Lewis, 2026-09-23).

The proxy never decodes, so any protocol with a browser-side client fits. Proxy changes shared by
VNC, SSH and Telnet:

- `Target` gains `protocol`; the port defaults by protocol (3389, 5900, 22, 23).
- A raw-forward mode: authenticate, resolve, connect, pipe. The RDP path minus the RDCleanPath step.
- The mode must match the target's protocol. Protocol and port come from config, never the request,
  so the target-id rule carries over unchanged.
- Each client bundle passes the same CSP test as the RDP page.

| Protocol | Browser client | Licence |
|---|---|---|
| VNC | noVNC; needs only a WebSocket-to-TCP relay | MPL-2.0 (mainly) |
| SSH | `golang.org/x/crypto/ssh` compiled to WASM, on xterm.js. `c2FmZQ/sshterm` and `hullarb/ssheasy` (adds SFTP) use this shape | BSD-3 / MIT |
| Telnet | xterm.js plus option negotiation, written here | MIT |
| HTTP(S) | the browser itself; needs a reverse proxy that parses HTTP, a new component rather than a relay mode | n/a |

- SSH host keys belong in the target entry, checked in the browser: SSH's form of the certificate
  row in Decisions.
- Credentials pass through for all of them.

### Linux desktops

Ubuntu's GNOME desktop ships an RDP server, GNOME Remote Desktop. Nothing is installed on the
target, so direct reach holds.

| Ubuntu | GNOME | Built-in RDP |
|---|---|---|
| 22.04 | 42 | Desktop Sharing: mirrors the console session |
| 24.04 | 46 | Desktop Sharing, and Remote Login: login screen, own session |
| 26.04 | 50 | as 24.04 |

- GNOME Remote Desktop requires the graphics pipeline (EGFX) from GNOME 44; GNOME 47 removed the
  older path (gnome-remote-desktop MR !274). The client side is EGFX in `ironrdp-web`, the browser
  counterpart of IronRDP #1462. GNOME uses RemoteFX Progressive for a client without H.264.
- Remote Login takes two credentials: one shared RDP credential per machine
  (`grdctl --system rdp set-credentials`), then the user's own login at the GNOME login screen. The
  shared one is a per-connection credential, the case the proxy-side store is for.
- xrdp is the alternative: an installed package, but a listening service rather than an agent. It
  logs in real Linux accounts through PAM, so pass-through holds. It needs an X11 desktop, which
  GNOME no longer provides from Ubuntu 26.04, so there it pairs with one such as Xfce.

### Kerberos for RDP

`ironrdp-web` accepts a `kdc_proxy_url` through `extension()`; the proxy would add a KDC proxy
endpoint. Needed where the domain restricts NTLM.
