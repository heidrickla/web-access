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
| Target list source | OPEN; static config is enough to start |
| Session recording | OPEN, and it conflicts with client-side RDP: a proxy that cannot decode the stream cannot record it. If recording is required, it has to come from the target or from a decoding gateway, and that reopens the architecture |

Agent identity is no longer a decision. Direct reach means there are no agents to authenticate.

### What direct reach makes load-bearing

With no agents, nothing outside the proxy constrains which hosts it can open a socket to except
network policy. SO THE TARGET ALLOWLIST IN THE PROXY IS A SECURITY CONTROL, not a convenience
feature: default-deny, explicit, and reviewable. A bug that lets an identity reach an unlisted target
is a boundary failure, and it should be tested as one.

### What pass-through makes true

- The proxy holds no secrets, so compromising it yields reach but not credentials.
- The Windows event log names the actual person, so the proxy's log and the target's log correlate.
  That correlation is the audit story; stored credentials would have destroyed it permanently.
- CredSSP has to work from a browser-hosted client. This is the historically awkward part of
  client-side RDP, and it is known to work: Cloudflare's implementation is pass-through and states
  that it manages no credentials on the Windows server.

## The capability note

Every limitation of the Cloudflare implementation is a choice made for a multi-tenant edge. On an
internal network none of those reasons apply, so audio, drive redirection and a full clipboard are
all available from the same upstream crates. The stripped-down build does not have to be the
stripped-down experience.
