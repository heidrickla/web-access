# web-access

Browser-based RDP with no third party in the session. Users sign in with their Active Directory
account, see the servers an administrator assigned to them, and click one to get its desktop. The RDP
client runs in the browser as WebAssembly; the proxy signs users in, keeps the server lists and saved
credentials, and relays sessions without decoding them.

Design record: `docs/architecture.md`.

## Shape

    browser (ironrdp-web, WASM)  ──HTTPS / WebSocket──>  proxy  ──TCP 3389──>  Windows servers
                                                           │
                                                           └──LDAPS──>  Active Directory

| Piece | Source | Notes |
|---|---|---|
| RDP client in the browser | `ironrdp-web`, Apache-2.0 | built to WASM and EMBEDDED in the proxy binary |
| RDCleanPath, both ends | `ironrdp-rdcleanpath` | reused |
| Sign-in | `src/directory.rs` | LDAPS simple bind as the user; the proxy host need not be domain-joined |
| Sessions and connect tickets | `src/auth.rs` | 24-hour persistent sign-in; single-use ticket per connection |
| Server lists, assignments | `src/store.rs`, `src/policy.rs` | SQLite; a user reaches exactly the servers assigned to them |
| Saved credentials | `src/vault.rs` | AES-256-GCM under a master key wrapped by DPAPI and by a recovery passphrase |
| Admin pages | `src/admin.rs`, `web/admin.*` | users, servers, groups, activity, migration |
| Export and import | `src/migrate.rs` | a zip that moves everything, saved credentials included, to a new host |
| Relay | `src/proxy.rs` | RDCleanPath handshake, then bytes |

## Using it

1. Browse to the proxy and sign in with a network account. Closing the browser does not sign out;
   the sign-in lasts 24 hours.
2. The server list shows the servers assigned to you, in the administrator's groups. Groups collapse
   and expand; the filter matches names and hosts.
3. Click a server's name. Enter its credentials, and tick "Save credentials" to be connected in one
   click next time. Credentials are saved only after the server accepts them.
4. The desktop fills the window. The rail at the left edge carries clipboard, file transfer,
   Ctrl+Alt+Del, fullscreen and Disconnect.
5. Disconnecting, or closing the browser, leaves the desktop running on the server. The list marks it
   Reconnect; clicking the server again returns to the same desktop.

## Administering it

`https://<proxy>/admin`, for the accounts listed in `admins` in `config.toml` and anyone they grant
the administrator flag.

| Tab | Does |
|---|---|
| Users | add users by network username; tick the servers each one gets, with select-all per group and copy-from-user; grant administrator; remove |
| Servers | add, edit and delete servers; bulk import from CSV (`name,host,port,group`) |
| Groups | create, rename, order and delete the groups users see |
| Activity | sign-ins, refusals, sessions opened, credential saves, every admin change |
| Migration | recovery passphrase, export, import, freeze; the directory service account's password |

A user signs in, but sees no servers until an administrator assigns them. Disabling the account in
Active Directory stops sign-in; with a service account configured, it also ends that user's sessions
at the next check.

## Moving to new hardware

Everything moves in one zip: users, groups, servers, assignments, saved credentials and sign-in
sessions. Users stay signed in across the cutover and keep their saved credentials.

1. Install the MSI on the new host. Copy `config.toml` and the HTTPS certificate for the same name.
2. Old host, Migration tab: enter the recovery passphrase, tick "Freeze", Export. The zip downloads.
   Frozen, the old host keeps carrying sessions but refuses changes, so nothing made after the
   export is lost.
3. New host, Migration tab: upload the zip, check the counts it shows, enter the passphrase, Import.
   A host that already holds data asks for its own name first, and keeps its database as a backup.
4. Move the DNS name.

The recovery passphrase is set once on the Migration tab. Without it an export cannot be imported
anywhere, so it belongs with the proxy's documentation. The same zip is a backup: importing last
night's export restores a host.

## Command line

    web-access-proxy.exe config.toml                               run in the foreground
    web-access-proxy.exe --service config.toml                     run as the Windows service
    web-access-proxy.exe export config.toml out.zip                write an export, for scheduled backups
    web-access-proxy.exe import config.toml in.zip [--replace]     apply an export, service stopped
    web-access-proxy.exe set-secret recovery config.toml           set or change the recovery passphrase
    web-access-proxy.exe set-secret directory config.toml          set the service account's password
    web-access-proxy.exe local-account config.toml <name> [--admin]   create a local account, or reset its password

## Local accounts

For testing, and for a proxy with no directory to reach. A local account signs in with a password
kept on the proxy (Argon2id hash), never checked against Active Directory, and only while the config
has `allow_local_accounts = true`. Create one from an elevated prompt on the proxy host:

    web-access-proxy.exe local-account C:\ProgramData\web-access\config.toml devtest --admin

With `allow_local_accounts = true`, the `[directory]` section may be left out entirely; then only
local accounts can sign in. A local account cannot share a name with a directory user. The Users tab
marks local accounts, and removing one there deletes it. The directory's periodic account check
skips them.

## Configuration

`config.example.toml` is the starting point and is installed as `%ProgramData%\web-access\config.toml`.

| Key | |
|---|---|
| `listen` | address and port |
| `admins` | accounts that are always administrators |
| `data_dir` | database location; defaults to the directory holding the config |
| `[https]` | PEM certificate chain and key |
| `[tls]` | how RDP servers' certificates are checked: `verify = "ca"` with `ca_bundle`, or `"insecure"`. No default |
| `[directory]` | `domain`, optional `netbios`, `urls` (ldaps only), `ca_bundle`, optional `service_account` and `check_interval_secs`. Optional when local accounts are allowed |
| `allow_local_accounts` | let local accounts sign in; default false |

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
- Users sign in with their Active Directory accounts; the proxy host is not domain-joined.
- Each user's server list is maintained by hand on the proxy, per user.
- Credentials pass through to the server unless the user saves them; saved ones are kept encrypted
  on the proxy, per user and per server, and move with an export.
- Apache-2.0 upstream, so the licence question is closed.

All Lewis's, 2026-09-23.

## Roadmap

Future additions. RDP comes first. Design for each is in `docs/architecture.md`.

| Addition | What it takes |
|---|---|
| Sign in as the logged-on Windows user | an SPN and keytab for the proxy's name; Kerberos acceptance via `sspi`; the proxy's URL in the browsers' intranet zone |
| Linux desktops | EGFX in `ironrdp-web`, which GNOME Remote Desktop, built into Ubuntu, requires. xrdp is the alternative |
| SSH | a raw-forward proxy mode; Go's SSH client compiled to WASM, on xterm.js |
| VNC | the same raw-forward mode; noVNC |
| Telnet | the same raw-forward mode; xterm.js plus option negotiation |
| Kerberos for RDP | a KDC proxy endpoint; `ironrdp-web` already takes the URL |
| HTTP(S) web interfaces | a reverse proxy: a new component, not a relay mode |

## Windows installer

`installer/` builds an MSI, deployable the way an organisation already deploys things (GPO, SCCM,
Intune) with a real uninstall and upgrade path.

    # 1. produce the binary (cross-compiled from Linux, or natively on Windows)
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
        cargo build --release --target x86_64-pc-windows-gnu
    # 2. drop it in installer/payload/, then
    pwsh installer/build.ps1

| | |
|---|---|
| Installs | `%ProgramFiles%\web-access\web-access-proxy.exe`, config to `%ProgramData%\web-access\config.toml` |
| Data directory | `%ProgramData%\web-access`: SYSTEM and Administrators full control, the service modify, no one else. Kept on uninstall |
| Service | `WebAccessProxy`, auto-start, running as `NT AUTHORITY\LocalService` |
| Service arguments | `--service "[ProgramData]\web-access\config.toml"` |
| Service control | stop on reinstall, stop and delete on uninstall (event 162). NOT started by the installer |
| Firewall | one exception scoped to the PROGRAM, not a port, because the port comes from the config |
| Upgrades | major-upgrade path registered; the config is `NeverOverwrite` |

### Installing

From an ELEVATED prompt:

    msiexec /i web-access-proxy.msi /l*v install.log     # or /qn to run silent

Then:

1. Edit `C:\ProgramData\web-access\config.toml`: `listen`, `admins`, `[https]`, `[tls]` and
   `[directory]`. Put the certificates where the config points.
2. `Start-Service WebAccessProxy` and browse to `https://<host>/`. Sign in as one of the `admins`.
3. On the Migration tab, set the recovery passphrase, and the service account's password if one is
   configured.
4. Add servers and users on the admin pages.

The service refuses to start against a config it cannot validate; the reason is in
`C:\ProgramData\web-access\web-access-proxy.log`.

Upgrading from 0.1: the `[[target]]` entries are imported once into an "Imported" group; `[[policy]]`
is no longer read. Add `[directory]`, `admins` and `[https]` before starting the service.

WiX v5 SPECIFICALLY. v6 and v7 require accepting the Open Source Maintenance Fee EULA, which is a
licensing decision with a fee attached for commercial use. v5 is the last version without that gate
and uses the same schema. The Firewall extension must be version-pinned to match the toolset.

## The browser client

"Clientless" means nothing is INSTALLED on the accessing machine, not that no client exists. The RDP
client is `ironrdp-web` compiled to WebAssembly and delivered by the proxy itself.

| | |
|---|---|
| `web/ironrdp_web_bg.wasm` | built with `wasm-pack build --target web --release` |
| `web/ironrdp_web.js` | wasm-bindgen glue |
| `web/index.html`, `web/app.js` | sign-in, the server list, the session |
| `web/admin.html`, `web/admin.js` | the admin pages |
| `web/app.css` | both pages |

Every page asset is a separate file: the proxy sends `default-src 'self'`, which forbids inline
`<style>`, `<script>`, style attributes and event handlers. A test asserts no page carries one. All
are embedded with `include_bytes!`, so a deployment is one MSI and one service, and the served client
cannot drift from the proxy it talks to.

The client's API maps onto the proxy's design: `SessionBuilder.destination()` carries the SERVER ID,
never an address, and `authToken()` carries the single-use connect ticket.

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
