# Architecture

Design record, settled 2026-09-23 after building the Cloudflare version of the same thing and taking it apart, with the decisions made since.

## The problem

Reach a Windows desktop from a browser, with nothing installed on the accessing machine, on an internal network with no third party in the path.

## Why a browser cannot do this by itself

RDP is binary over TCP 3389 with its own TLS and CredSSP handshake. A browser exposes no raw TCP socket API. So something must be a real RDP client, and the only question is where that client runs.

| Client location | Consequence |
|---|---|
| Server-side | the gateway decodes RDP and re-emits drawing operations; every channel is re-implemented by hand (Apache Guacamole) |
| Client-side, WASM | the browser is the RDP client; the server is a byte relay (Cloudflare) |

This repository takes the second.

## What Cloudflare does, since it was the reference

From their engineering blog, "RDP without the risk", 2025-03-21:

- The client is IronRDP compiled to WebAssembly, running in the browser. The post names Apache Guacamole as the alternative they rejected, for being Java.
- The client wraps the RDP session in a WebSocket, because browsers cannot speak TCP.
- `RDCleanPath` removes the inner RDP TLS, on the grounds that the WebSocket is already TLS to Cloudflare. That is what makes the session readable inside their network.
- Their server half is Cloudflare-specific: a Workers-based WebSocket proxy handing off to an internal routing service, then out through Cloudflare Tunnel. None of it is needed here.

Their feature limits (no audio, a 500 KB text-only clipboard, PDF-only printing, file transfer as a separate panel) look like the symptoms of a server-side re-encoding design. They are product decisions: `ironrdp-rdpsnd` and `ironrdp-rdpdr` exist upstream, so audio and drive redirection are implemented in the library and not exposed. A limitation list is evidence about a product, not about its architecture.

## What is reused

Upstream is `Devolutions/IronRDP`, Apache-2.0.

| Crate | Role |
|---|---|
| `ironrdp-web` | the WASM browser build; the client half, served by the proxy |
| `ironrdp-rdcleanpath` | the protocol between browser and proxy; the only IronRDP crate the proxy links |
| `ironrdp-rdpsnd`, `ironrdp-rdpdr`, `ironrdp-cliprdr` | audio, drives, clipboard in the client, available if wanted |

The proxy's own transport is tokio, `tokio-rustls` for TLS to the target and on the listener, and `tokio-tungstenite` for the WebSocket. Devolutions Gateway is the reference implementation of the proxy half.

## What is written here

A gateway with a relay at its centre:

1. Sign the user in against Active Directory and keep that sign-in for a shift.
2. Show the user the servers assigned to them.
3. On a click, mint a single-use ticket for that user and that server, and hand the user's saved credential, if any, to their browser.
4. Take the WebSocket, check the cookie and the ticket, read the RDCleanPath request, open TCP to the server, send the client's X.224 request, perform the TLS handshake on the client's behalf, return the server's confirm and certificate chain.
5. Pipe bytes until the session ends.

The proxy never decodes RDP. It decides who may reach which server, and relays.

## Decisions

| Decision | State |
|---|---|
| Client-side WASM rather than server-side rendering | settled |
| RDCleanPath, accepting that the proxy can read the stream | settled: internal network, not a concern (Lewis, 2026-09-23) |
| Direct reach: the proxy opens TCP to the target, no agents anywhere | settled (Lewis, 2026-09-23) |
| Pass-through unless the user saves: the user's own credentials go to the server; a user may save them on the proxy, per server | settled (Lewis, 2026-09-23); saving reverses pass-through for that user and server only |
| Sign-in: Active Directory over LDAPS, a simple bind as the user; the proxy host is not domain-joined | settled (Lewis, 2026-09-23) |
| Sign in as the logged-on Windows user | roadmap: Kerberos via an SPN and keytab, accepted with `sspi` |
| Local accounts for testing: an Argon2id hash in the database, created on the command line, signing in only with `allow_local_accounts = true`; the directory section becomes optional | settled (Lewis, 2026-09-24) |
| Saved credentials live in a proxy-side encrypted store, per user and per server | settled (Lewis, 2026-09-23); see below |
| Server lists are maintained by hand on the proxy, per user; IT revokes access by disabling the account | settled (Lewis, 2026-09-23) |
| A sign-in lasts 24 hours and survives a browser restart; opening a server with under 18 hours left asks for the password again | settled: shifts run 9 to 18 hours (Lewis, 2026-09-23 and 2026-09-29) |
| Migration: saved credentials move with the database, by export and import in the admin pages | settled: about 3000 users and 4 administrators, so re-entry is not an option (Lewis, 2026-09-23) |
| The client sends a target id, never an address | settled by design. Cloudflare's `/rdp/<vnet>/<ip>/<port>` lets the browser name the destination, so the allowlist is all that stands between a crafted request and an unlisted host. An opaque id makes reaching an arbitrary host inexpressible rather than forbidden |
| Resolve by name, not by address | settled (Lewis, 2026-09-23) |
| Verify the target's certificate against an internal CA | per deployment: `tls.verify`, which has no default, and is coupled to the row above |
| Session recording | outside the proxy: a proxy that does not decode the stream cannot record it, so recording comes from the target or from a gateway that decodes RDP |

### Resolving by name puts DNS in the trust chain

The target entry carries a host name and the proxy resolves it at connection time, not at startup, so a re-addressed host is picked up without a restart. DNS decides which machine a target id reaches. Name resolution answers where; certificate validation answers who, which is why the certificate row is the other half of this control.

- The name and the address it resolved to are logged together.
- A resolution failure fails the connection; there is no cached address to fall back to.
- A name resolving to several addresses is refused rather than picked from.

### What direct reach makes load-bearing

With no agents, nothing outside the proxy constrains which hosts it opens a socket to except network policy. So a user's assignments are a security control: default-deny, explicit and reviewable. `policy::resolve` and `policy::permitted` share one predicate, an assignment row, so the list a user sees and the connections they can open cannot disagree.

### Sign-in and sessions

- A password sign-in is an LDAPS simple bind as the user. A name with a domain in it (`CORP\jdoe`, `john.doe@example.com`) is bound exactly as typed; a bare name binds as `NETBIOS\name`, or `name@domain` without `netbios`. An empty password is refused before the bind: LDAP treats it as an anonymous bind.
- After the bind, LDAP WhoAmI names the account the password was checked for, and that account is the one signed in. With `netbios` set, an account in another domain is refused.
- Active Directory refuses the bind for a disabled, expired, locked or restricted account, or one whose password must change. The `data <code>` in its answer is read: codes it returns only for the right password (532, 773, 530, 531, 533, 701) are named to the user; a lockout (775) is returned whatever password was typed, so it is logged and reported as an ordinary refusal.
- A sign-in finds its row by username, then by SID, so an account renamed in the directory keeps its row, servers and saved credentials. The SID is bound at first sign-in; a different account arriving under a bound username is refused and flagged to administrators, so a reused username inherits nothing.
- The session is a random token in an `HttpOnly; SameSite=Strict` cookie, persistent for 24 hours. The database keeps its SHA-256, so sessions survive a service restart and move with an export. `/api/me` reports the seconds left, counted on the proxy.
- With a service account configured, signed-in accounts are re-checked every `check_interval_secs`. An account that is disabled, expired, gone or re-created loses its sessions and its live RDP connections. A lookup that fails skips that account only; a pass that cannot run revokes nothing. The last pass's outcome is kept for the Migration tab, and the Activity log records when checks start failing and when they recover. The domain controller that last answered is tried first.
- A click mints a connect ticket: 60 seconds, single use, bound to the user and the server. The WebSocket must also carry the session cookie of the same user and a same-origin `Origin`. The browser takes its ticket after the credentials dialog closes, immediately before connecting.
- A connection is registered at upgrade, before anything is read, and belongs to the sign-in it was opened under. Admission re-checks that sign-in, the ticket and the assignment. Revocation, sign-out, the sign-in expiring, the assignment or server being removed, or an import ends it at any stage, setting up or established. Each setup stage has a deadline.

### Imports and freezes

Requests hold a shared gate; an import and a freezing export hold it exclusively. An import waits for requests in flight, swaps the database and its key together, and ends every connection, since their identities came from the database it replaced. A freezing export freezes and snapshots with no request in flight, so nothing acknowledged is missing from it.

| Rule | Why |
|---|---|
| Slow work runs outside the gate: sign-in's password hash or directory bind, the directory checks behind Add User and the service-account password, the periodic account check | a slow directory never holds up an import, or every request queued behind it |
| Work that left the gate re-reads the database generation when it returns, and discards its result if an import replaced the database meanwhile | a result is only applied to the database it was computed from |
| Routes that take the gate themselves re-check the caller's session and administrator status once they hold it | authorization comes from the database as it is when the work runs |
| Import and export run in a task of their own that the request awaits. A request that ends before the task has the gate abandons it; once the task has the gate, it runs to the end | the gate is never released partway through a swap |
| An export verifies the passphrase against the recovery wrap inside its own snapshot | the archive always opens with the passphrase it was made under |
| Exports run one at a time. One that fails, or whose archive is not delivered, lifts only a freeze it set, and only in the database it set it in | a failed export cannot undo another export's freeze |
| A connection records the database generation it was admitted under. Its opening and its end are recorded only in that database | identities from a replaced database never land on another user's history |
| User, server and group ids are never reused (`AUTOINCREMENT`, schemas 4 and 5) | an id kept anywhere, in a session, a live connection or an admin page, names that row or nothing |
| Every response carries `X-Data-Instance`, a value an import changes. A change must carry the instance the page loaded from, except sign-out and the routes under `/api/admin/migration/` (recovery passphrase, unlock, reset, export, freeze, import), which act on the database as a whole rather than on rows by id. A page that sees another instance reloads | an import brings back the ids its archive had, so a page loaded before it cannot act on rows that took them since |
| An account is bound to the directory SID of its first sign-in, and the binding is written only if the row is unbound or bound to that SID | two first sign-ins from different directory accounts cannot share one row |
| Each user and server row carries a random incarnation set on insert. A sign-in records its login and creates its session only on the row it authenticated, by id and incarnation; a connection's end is written only if its user and server rows still carry the incarnations seen at admission | a row that ever arrived on an old id would still be told apart |
| The serving process reads its configuration once, locks `serving.lock` in that data directory before it builds its runtime or opens the database, and releases it after the runtime has shut down and its blocking work has finished. A second serving process on the same data directory is refused; command-line tools do not take the lock | one database has one server, the directory locked is the directory served, and no second process settles state the first is still using |
| A freeze an export set travels with its archive: an archive dropped before the response takes it lifts the freeze, and the next export waits until it has | a cancelled export leaves no freeze, whichever step it was cancelled at, and cannot take a later export's freeze with it |
| A freeze an export set is marked pending in the database until the archive is handed over; a pending freeze found when the service starts is lifted. Command-line tools leave it alone | a stop, crash or power loss mid-export does not leave the proxy frozen, and a tool run during an export cannot lift its freeze |
| An import swaps the file only when no other process has the database open (no write-ahead log left once its own connection closes) | another process's log would otherwise be replayed onto the new file |

### Storage

SQLite in WAL mode, one connection behind a mutex for requests. A reader and the writer do not block each other, so an export's snapshot (`VACUUM INTO`, on a connection of its own) or a command-line export in another process runs while sign-ins and edits go on. The write-ahead log and shared-memory files sit beside the database while it is open; a clean stop removes them.

| What | Kept |
|---|---|
| Activity log | `audit_days` (400), pruned hourly, 1000 rows per batch |
| Service log | one file per UTC day, the newest 30 |
| Import backups | the newest 5 |
| Schema backup | one per upgrade that changes the schema |
| Uploaded imports awaiting confirmation | at most 2, each for 30 minutes |
| Sign-in sessions | until they expire, purged every 30 seconds |

### Connections

The listener closes connections beyond `max_connections` on accept, and a TLS handshake not finished within 10 seconds. A WebSocket keeps its connection's place under the limit until its RDP session is established or it ends. Headers must arrive within 30 seconds and a request complete within 2 minutes; exports, import uploads and import confirmations get 30 minutes. Both legs of a relay use TCP keepalive (60 seconds idle, then every 10) and no-delay; each write to the target is flushed.

At most four password hashes run at once (64 MiB each). A local account that fails five sign-ins within five minutes is refused without its password being checked until the oldest failure is five minutes old. Sessions are purged and orphaned connections closed every 30 seconds, independently of the directory check.

The HTTPS certificate is served through a resolver whose key pair is replaced when the certificate or key file changes (checked every minute). A pair that does not load is refused and the previous one kept.

When the target cannot be reached, the proxy answers the RDCleanPath request with the Windows socket error (`WSAECONNREFUSED`, `WSAETIMEDOUT`, `WSAHOST_NOT_FOUND` and so on); when the target's certificate is refused, with the TLS alert (48 unknown CA, 45 expired, 44 revoked, 42 otherwise). The page names both, so an unreachable server does not read as a wrong password.

### Where saved credentials live

| | Where | Scope |
|---|---|---|
| Browser `localStorage` | the browser profile | per browser |
| Browser credential manager | the Credential Management API | per browser; requires a secure origin |
| Proxy-side encrypted store (chosen) | the proxy's database, the Guacamole model | per user and per server, any machine |

The proxy store is what makes a multi-user gateway possible: credentials follow the user, not the browser, and there is one place to audit and revoke them. Storage is per user and per server, so the proxy log and the Windows event log still name the same person.

The RDP client performs NLA in the browser, so a saved password goes to its owner's browser for the connection it was requested for, and is saved only after the server has accepted it. A saved credential that the server refuses is asked for again; one that fails for another reason (the server unreachable) is not.

| Layer | What |
|---|---|
| Record | AES-256-GCM, fresh nonce per write, associated data binding the record to the user's SID and the server id |
| Master key | 256 random bits, one per database |
| Local wrap | DPAPI, machine scope, so the service starts unattended |
| Recovery wrap | Argon2id (64 MiB, 3 passes) of an administrator's passphrase, so the key can move to a new host |

A key derived from the user's own sign-in was the stronger candidate in the abstract and was not chosen: sign-in as the logged-on user (roadmap) supplies no password to derive from, and a key that only a signed-in user can open could not move with an export. A key in the config file was rejected.

A database whose local wrap does not open on the host it finds itself on starts locked; the recovery passphrase unlocks it and re-wraps the key for that host. A lost passphrase is replaced from the host that holds the key (`set-secret recovery --replace`). With neither, the credential store is reset: a new key, every saved credential and the service account's password deleted, users, servers and assignments kept.

### Migration

An export is a zip holding `manifest.json` (format, schema, source host, time, counts, SHA-256 of the data) and `data.db.enc`, a `VACUUM INTO` snapshot encrypted under the recovery passphrase. The export refuses a passphrase that does not open the database's recovery wrap, so an export can always be imported by whoever holds that passphrase. An export opens only with the passphrase set when it was made; changing the passphrase does not re-key earlier exports.

Import checks the manifest and checksum, decrypts, opens the result (migrating an older schema forward, refusing a newer one), runs SQLite's integrity check, re-wraps the master key for this host, backs up the current database, and swaps the file in while running. A host holding data needs its own name typed to confirm.

"Export and freeze" leaves the old host carrying sign-ins and sessions while refusing saves and admin edits, so nothing made after the export is lost at cutover.

### What pass-through makes true, for credentials that are not saved

- The proxy holds nothing for them.
- The Windows event log names the actual person, so the proxy's log and the target's log correlate.
- CredSSP works from a browser-hosted client: Cloudflare's implementation is pass-through and states that it manages no credentials on the Windows server.

## The capability note

Every limitation of the Cloudflare implementation is a choice made for a multi-tenant edge. On an internal network none of those reasons apply, so audio, drive redirection and a full clipboard are all available from the same upstream crates.

## Other connection types

Roadmap; RDP comes first (Lewis, 2026-09-23).

The proxy never decodes, so any protocol with a browser-side client fits. Proxy changes shared by VNC, SSH and Telnet:

- A server gains a protocol; the port defaults by protocol (3389, 5900, 22, 23).
- A raw-forward mode: authenticate, resolve, connect, pipe. The RDP path minus the RDCleanPath step.
- The mode must match the server's protocol. Protocol and port come from the proxy's data, never the request, so the target-id rule carries over unchanged.
- Each client bundle passes the same CSP test as the RDP page.

| Protocol | Browser client | Licence |
|---|---|---|
| VNC | noVNC; needs only a WebSocket-to-TCP relay | MPL-2.0 (mainly) |
| SSH | `golang.org/x/crypto/ssh` compiled to WASM, on xterm.js; `c2FmZQ/sshterm` and `hullarb/ssheasy` (adds SFTP) use this shape | BSD-3 / MIT |
| Telnet | xterm.js plus option negotiation, written here | MIT |
| HTTP(S) | the browser itself; needs a reverse proxy that parses HTTP, a new component rather than a relay mode | n/a |

- SSH host keys belong in the server entry, checked in the browser: SSH's form of the certificate row in Decisions.
- Credentials pass through for all of them.

### Linux desktops

Ubuntu's GNOME desktop ships an RDP server, GNOME Remote Desktop. Nothing is installed on the target, so direct reach holds.

| Ubuntu | GNOME | Built-in RDP |
|---|---|---|
| 22.04 | 42 | Desktop Sharing: mirrors the console session |
| 24.04 | 46 | Desktop Sharing, and Remote Login: login screen, own session |
| 26.04 | 50 | as 24.04 |

- GNOME Remote Desktop requires the graphics pipeline (EGFX) from GNOME 44; GNOME 47 removed the older path (gnome-remote-desktop MR !274). The client side is EGFX in `ironrdp-web`, the browser counterpart of IronRDP #1462. GNOME uses RemoteFX Progressive for a client without H.264.
- Remote Login takes two credentials: one shared RDP credential per machine (`grdctl --system rdp set-credentials`), then the user's own login at the GNOME login screen. The shared one is a per-connection credential, the case the proxy-side store is for.
- xrdp is the alternative: an installed package, but a listening service rather than an agent. It logs in real Linux accounts through PAM, so pass-through holds. It needs an X11 desktop, which GNOME no longer provides from Ubuntu 26.04, so there it pairs with one such as Xfce.

### Kerberos for RDP

`ironrdp-web` accepts a `kdc_proxy_url` through `extension()`; the proxy would add a KDC proxy endpoint. Needed where the domain restricts NTLM.
