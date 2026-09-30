# web-access

Browser-based RDP with no third party in the session. Users sign in with their Active Directory account, see the servers an administrator assigned to them, and click one to get its desktop. The RDP client runs in the browser as WebAssembly; the proxy signs users in, keeps the server lists and saved credentials, and relays sessions without decoding them.

Design record: `docs/architecture.md`.

## Shape

    browser (ironrdp-web, WASM)  ──HTTPS / WebSocket──>  proxy  ──TCP 3389──>  Windows servers
                                                           │
                                                           └──LDAPS──>  Active Directory

| Piece | Source | Notes |
|---|---|---|
| RDP client in the browser | `ironrdp-web`, Apache-2.0 | built to WASM and embedded in the proxy binary |
| RDCleanPath, both ends | `ironrdp-rdcleanpath` | reused |
| Sign-in | `src/directory.rs` | LDAPS simple bind as the user; the proxy host need not be domain-joined |
| Sessions and connect tickets | `src/auth.rs` | 24-hour persistent sign-in; single-use ticket per connection |
| Server lists, assignments | `src/store.rs`, `src/policy.rs` | SQLite; a user reaches exactly the servers assigned to them |
| Saved credentials | `src/vault.rs` | AES-256-GCM under a master key wrapped by DPAPI and by a recovery passphrase |
| Admin pages | `src/admin.rs`, `web/admin.*` | users, servers, groups, activity, migration |
| Export and import | `src/migrate.rs` | a zip that moves everything, saved credentials included, to a new host |
| Relay | `src/proxy.rs` | RDCleanPath handshake, then bytes |

## Using it

1. Browse to the proxy and sign in with a network account: `jdoe`, `CORP\jdoe` or the account's sign-in name such as `john.doe@example.com`. Closing the browser does not sign out; the sign-in lasts 24 hours. Opening a server with less than 18 hours left asks for the password again first.
2. The server list shows the servers assigned to you, in the administrator's groups. Groups collapse and expand; the filter matches names and hosts.
3. Click a server. Enter its credentials, and tick "Save credentials" to be connected in one click next time. Credentials are saved only after the server accepts them.
4. The desktop fills the window. The rail at the left edge carries clipboard, file transfer, Ctrl+Alt+Del, fullscreen and Disconnect. Files dropped on the desktop go to the remote clipboard.
5. Disconnecting, or closing the browser, leaves the desktop running on the server. The list marks it Reconnect; clicking the server again returns to the same desktop.

The pages are dark by default; the button beside Sign out switches to a light theme, remembered per browser.

## Administering it

`https://<proxy>/admin`, for the accounts listed in `admins` in `config.toml` and anyone they grant the administrator flag.

| Tab | Does |
|---|---|
| Users | add users by network username; tick the servers each one gets, with select-all per group and copy-from-user; grant administrator; remove |
| Servers | add, edit and delete servers; bulk import from CSV (`name,host,port,group`) |
| Groups | create, rename, order and delete the groups users see |
| Activity | sign-ins, refusals, sessions opened, credential saves, every admin change; kept `audit_days` (400) |
| Migration | this proxy's version and counts; recovery passphrase; unlock or reset the credential store; export, import, freeze; the directory service account's password and how its account checks last went |

A user signs in, but sees no servers until an administrator assigns them. Disabling the account in Active Directory stops sign-in; with a service account configured, it also ends that user's sessions at the next check. An account renamed in Active Directory keeps its servers and saved credentials: the proxy follows the account's SID to its row and renames it at the next sign-in.

The account checks run every `check_interval_secs`. When they cannot run (no domain controller answers, the service account is refused), nothing is revoked; the Migration tab says so in red and the Activity tab records `revocation.failing` once, then `revocation.restored`. An account whose lookup fails is skipped and named on the Migration tab; the others are still checked. The domain controller that last answered is tried first.

## Moving to new hardware

Everything moves in one zip: users, groups, servers, assignments, saved credentials and sign-in sessions. Users stay signed in across the cutover and keep their saved credentials.

1. Install the MSI on the new host. Copy `config.toml`, the HTTPS certificate and key, and every CA bundle the config names (`[tls] ca_bundle`, `[directory] ca_bundle`), to the same paths.
2. `Start-Service WebAccessProxy` on the new host and sign in there as one of the `admins`.
3. Old host, Migration tab: enter the recovery passphrase, tick "Freeze", Export. The zip downloads. Frozen, the old host keeps carrying sessions but refuses changes, so nothing made after the export is lost.
4. New host, Migration tab: upload the zip, check the counts it shows, enter the passphrase, Import. A host that already holds data asks for its own name first, and keeps its database as a backup.
5. Move the DNS name.

## Backups

An export is also the backup: importing last night's export restores a host. Each export opens only with the recovery passphrase that was set when it was made, so keep the passphrase history with the exports.

For a scheduled backup, a task running as SYSTEM with the passphrase in a file only SYSTEM and Administrators can read:

    web-access-proxy.exe export C:\ProgramData\web-access\config.toml D:\Backups\web-access-nightly.zip --passphrase-file C:\ProgramData\web-access\backup-passphrase.txt

The export is written beside the target, read back, and only then renamed over it, so a full disk or a dropped share keeps the previous night's file. Rotate the files with the task, for example by putting the date in the file name.

An import keeps the database it replaces as `backup-<time>.db` in the data directory; the newest five are kept. A schema upgrade keeps the database as it was as `backup-schema<N>-<time>.db`. To restore either: stop the service, delete `web-access.db-wal` and `web-access.db-shm` if they are there, rename the backup to `web-access.db`, start the service. It carries this host's key, so it opens unlocked. The two files are the write-ahead log of the database being replaced; left beside a restored copy, they would be applied to it.

## The recovery passphrase

The recovery passphrase is set once on the Migration tab. It encrypts exports and lets saved credentials move to a new host.

| Situation | Way out |
|---|---|
| Passphrase known, to be changed | Migration tab, with the current one |
| Passphrase lost, store unlocked on this host | `web-access-proxy.exe set-secret recovery C:\ProgramData\web-access\config.toml --replace`, from an elevated prompt: a new passphrase for the key this host holds. Exports made before it open only with the old one |
| Database moved here from another host, passphrase known | Migration tab, Unlock the credential store, or `web-access-proxy.exe unlock <config>` |
| Store locked and nobody has the passphrase | Migration tab, Reset the credential store, or `web-access-proxy.exe reset-credentials <config>`: a new key; every saved credential and the directory service account's password are deleted; users, servers and assignments stay |

## Command line

From an elevated prompt in `C:\Program Files\web-access`, with `<config>` usually `C:\ProgramData\web-access\config.toml`:

| Command | Does |
|---|---|
| `web-access-proxy.exe --version` | the version and the source revision it was built from |
| `web-access-proxy.exe <config>` | run in the foreground; Ctrl+C stops |
| `web-access-proxy.exe export <config> <out.zip> [--passphrase-file <path>]` | write an export |
| `web-access-proxy.exe import <config> <in.zip> [--replace] [--passphrase-file <path>]` | apply an export, service stopped |
| `web-access-proxy.exe set-secret recovery <config> [--replace]` | set or change the recovery passphrase; `--replace` for a lost one |
| `web-access-proxy.exe set-secret directory <config>` | set the service account's password |
| `web-access-proxy.exe unlock <config>` | unlock a credential store moved here from another host |
| `web-access-proxy.exe reset-credentials <config>` | start a credential store nothing can open over |
| `web-access-proxy.exe local-account <config> <name> [--admin]` | create a local account, or reset its password |

The Windows service runs `web-access-proxy.exe --service <config>`.

## Local accounts

For testing, and for a proxy with no directory to reach. A local account signs in with a password kept on the proxy (Argon2id hash), never checked against Active Directory, and only while the config has `allow_local_accounts = true`. Create one from an elevated prompt on the proxy host:

    web-access-proxy.exe local-account C:\ProgramData\web-access\config.toml devtest --admin

With `allow_local_accounts = true`, the `[directory]` section may be left out entirely; then only local accounts can sign in. A local account cannot share a name with a directory user. The Users tab marks local accounts, and removing one there deletes it. The directory's periodic account check skips them. After five failed sign-ins within five minutes, the account is refused until the oldest of those failures is five minutes old.

## Configuration

`config.example.toml` is the starting point and is installed as `%ProgramData%\web-access\config.toml`. The service reads it at start; restart the service after changing it. A key the proxy does not read, such as a misspelt `service_acount`, is named in the log at start.

| Key | |
|---|---|
| `listen` | address and port, such as `0.0.0.0:443` |
| `admins` | accounts that are always administrators |
| `data_dir` | database location; defaults to the directory holding the config |
| `allow_local_accounts` | let local accounts sign in; default false |
| `max_connections` | connections served at once, default 1024; a WebSocket counts until its RDP session is connected |
| `audit_days` | days the activity log keeps an entry, default 400 |
| `[https]` | `cert` (PEM, the server certificate first, then its chain) and `key` (PEM, unencrypted) |
| `[tls]` | how RDP servers' certificates are checked: `verify = "ca"` with `ca_bundle`, or `"insecure"`. No default |
| `[directory]` | `domain`; `netbios`; `urls` (ldaps only); optional `ca_bundle` (the Windows certificate store when omitted), `base_dn` (derived from `domain` when omitted), `service_account`, `check_interval_secs` (default 600) and `timeout_secs` (default 10). Optional when local accounts are allowed |

Set `netbios` to the domain's NetBIOS name: the proxy then refuses a password accepted for an account in another domain. A sign-in name with a domain in it (`CORP\jdoe`, `john.doe@example.com`) is checked exactly as typed, and the account signed in is the one Active Directory says the password was checked for.

## HTTPS certificate

`[https]` takes PEM files. The certificate file holds the server certificate first, then any intermediates; the key file holds the unencrypted private key. From a PFX, with OpenSSL:

    openssl pkcs12 -in proxy.pfx -clcerts -nokeys -out proxy-cert.pem
    openssl pkcs12 -in proxy.pfx -cacerts -nokeys -out chain.pem
    openssl pkcs12 -in proxy.pfx -nocerts -nodes -out proxy-key.pem

Append `chain.pem` to `proxy-cert.pem`. Keep the key file in the data directory, whose permissions admit only SYSTEM, Administrators and the service.

A renewal needs no restart: the files are read again within a minute of changing, and new connections get the new certificate. A pair that does not load (a key that does not match, a half-written file) is refused with an error in the log and the previous certificate stays in use. The log gives the certificate's expiry at start and at each reload, and warns once a day from 30 days before it. A browser that refuses the certificate shows in the log as `TLS handshake failed`, at most one line a minute.

## Build

    cargo check --all-targets
    cargo test
    cargo run -- config.toml

The dependency tree is vendored, so this builds with no network at all. `.cargo/config.toml` points Cargo at `vendor/`; `Cargo.lock` is committed, because vendoring without a lockfile pins nothing.

Two settings keep the vendored tree intact:

| Setting | Without it |
|---|---|
| `!vendor/**` in `.gitignore` | the `*.pem` and `*.key` rules drop vendored files, and Cargo's per-file checksums fail on a fresh clone |
| `vendor/** -text` in `.gitattributes` | `eol=lf` rewrites upstream CRLF files, changing the bytes `.cargo-checksum.json` covers |

After changing dependencies: `cargo vendor`, then `cargo build --offline` and `cargo test --offline` from a fresh clone with the crate cache emptied.

Gates before a push:

| Gate | Command |
|---|---|
| format | `cargo fmt --check` |
| lint | `cargo clippy --offline --all-targets -- -D warnings`; for the Linux cfg from Windows, `cargo-zigbuild clippy --offline --target x86_64-unknown-linux-musl --all-targets -- -D warnings` |
| test | `cargo nextest run --offline` |
| page scripts | `bash tests/js/run.sh` |
| dependencies | `cargo deny check` (advisories, licenses, bans, sources; `deny.toml`) |
| mutation | `cargo mutants --in-diff <diff>` for the lines a change touches |

## Why not the obvious things

| Ruled out | Reason |
|---|---|
| Cloudflare Access browser RDP | external dependency; the estate this targets is internal only |
| Apache Guacamole | the Java webapp, database and extension framework are most of it, and none of it is wanted |
| Microsoft RD Web Client | RDS role infrastructure and CALs |
| Teleport | a platform where a component was wanted |
| MeshCentral, Devolutions Gateway as a product | agent-based reach, not the shape being built |

## Settled

- The RDP client runs client-side in WASM, not server-side.
- RDCleanPath is acceptable. Session confidentiality from the proxy is not a requirement on an internal network.
- Direct reach. The proxy opens TCP to the target. No agents, no connectors, nothing installed on any target, so appliances and vendor-supported nodes are in scope.
- Users sign in with their Active Directory accounts; the proxy host is not domain-joined.
- Each user's server list is maintained by hand on the proxy, per user.
- Credentials pass through to the server unless the user saves them; saved ones are kept encrypted on the proxy, per user and per server, and move with an export.
- Apache-2.0 upstream, so the licence question is closed.

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

`installer/` builds an MSI, deployable the way an organisation already deploys things (GPO, SCCM, Intune) with a real uninstall and upgrade path. On a Windows host with the Rust MSVC toolchain and the .NET SDK:

    pwsh installer/build.ps1

It builds the proxy, takes the version from `Cargo.toml`, stamps the source revision into the binary, and writes `installer/web-access-proxy-<version>.msi`. It refuses a tree with uncommitted changes unless given `-Dev`. A release is built from its tag, `v<version>`.

| | |
|---|---|
| Installs | `%ProgramFiles%\web-access\web-access-proxy.exe`, config to `%ProgramData%\web-access\config.toml` |
| Data directory | `%ProgramData%\web-access`: SYSTEM and Administrators full control, the service modify, no one else. Each install applies this list again. Kept on uninstall |
| Config | never replaced by an install or an upgrade, and kept on uninstall |
| Service | `WebAccessProxy`, auto-start, running as `NT AUTHORITY\LocalService`, restarted a minute after the process ends unexpectedly |
| Service arguments | `--service "[ProgramData]\web-access\config.toml"` |
| First install | the service is not started: the config has to be written first |
| Upgrade | the service is stopped, replaced and started again |
| Firewall | one exception for the program, not a port, because the port comes from the config. Remote addresses from `REMOTE_ADDRESSES`: any by default, or a comma-separated list of addresses and subnets; remembered for upgrades |

### Installing

From an elevated prompt:

    msiexec /i web-access-proxy-0.3.0.msi /l*v install.log

Silent, admitting only two subnets:

    msiexec /i web-access-proxy-0.3.0.msi /qn REMOTE_ADDRESSES="10.20.0.0/16,10.30.0.0/16" /l*v install.log

Then:

1. Edit `C:\ProgramData\web-access\config.toml`: `listen`, `admins`, `[https]`, `[tls]` and `[directory]`. Put the certificates where the config points.
2. `Start-Service WebAccessProxy` and browse to `https://<host>/`. Sign in as one of the `admins`.
3. On the Migration tab, set the recovery passphrase, and the service account's password if one is configured.
4. Add servers and users on the admin pages.

The service reports running only once it has read the config, opened the database and bound its port; a start that cannot do all three fails where it was started. The reason is in `C:\ProgramData\web-access\web-access-proxy-<yyyy>-<mm>-<dd>.log`, one file per UTC day; the newest 30 are kept.

### Upgrading

1. On the Migration tab, export (or stop the service and copy `C:\ProgramData\web-access`).
2. `msiexec /i web-access-proxy-<new version>.msi /qn /l*v upgrade.log`. The service is stopped, replaced and started again. A newer schema is applied at its first start, and the database as it was is kept as `backup-schema<N>-<time>.db`.
3. Check the log for the `listening` line and the version on the Migration tab.

To go back: uninstall, install the previous MSI, stop the service, delete `web-access.db-wal` and `web-access.db-shm` if they are there, rename the `backup-schema<N>-<time>.db` copy to `web-access.db`, and start the service. A database migrated by a newer version is refused by an older one.

Upgrading from 0.1: the `[[target]]` entries are imported once into an "Imported" group; `[[policy]]` is no longer read. Add `[directory]`, `admins` and `[https]` before starting the service.

WiX v5 specifically. v6 and v7 require accepting the Open Source Maintenance Fee EULA, which is a licensing decision with a fee attached for commercial use. v5 is the last version without that gate and uses the same schema. The Firewall and Util extensions must be version-pinned to match the toolset.

## The browser client

"Clientless" means nothing is installed on the accessing machine, not that no client exists. The RDP client is `ironrdp-web` compiled to WebAssembly and delivered by the proxy itself.

| | |
|---|---|
| `web/ironrdp_web_bg.wasm` | built with `wasm-pack build --target web --release` |
| `web/ironrdp_web.js` | wasm-bindgen glue |
| `web/index.html`, `web/app.js` | sign-in, the server list, the session |
| `web/admin.html`, `web/admin.js` | the admin pages |
| `web/app.css` | both pages; dark by default, with a light theme |
| `web/theme.js` | both pages: applies the stored theme before the page paints, and the header's theme button |

Every page asset is a separate file: the proxy sends `default-src 'self'`, which forbids inline `<style>`, `<script>`, style attributes and event handlers. A test asserts no page carries one. All are embedded with `include_bytes!`, so a deployment is one MSI and one service, and the served client cannot drift from the proxy it talks to.

`build.rs` gzips each asset and names it by a hash of its content. The proxy sends the gzip to a browser that accepts it (the 7.4 MB client goes as 1.8 MB), with an ETag and `Cache-Control: no-cache`: every load asks again, so an upgrade is picked up at once, and an unchanged asset costs a 304. API answers are `no-store`.

The client's API maps onto the proxy's design: `SessionBuilder.destination()` carries the server id, never an address, and `authToken()` carries the single-use connect ticket.

Keyboard: a character typed alone goes through `unicodePressed`, so the remote's layout does not matter. A shortcut (Ctrl, Alt or Meta held, without AltGr) and every non-printable key go by scancode from the key's position, and a key is released by the route that pressed it. Lock keys are synchronised on the first key after the desktop takes focus. Fullscreen requests keyboard lock, so Esc and Windows-key shortcuts reach the remote. A key in no table is dropped rather than guessed at.

Errors: the proxy reports a server it could not reach as the Windows socket error and a refused certificate as its TLS alert, over RDCleanPath; the page names both. The proxy log carries the full reason.

## Conventions

- No credential, host address or site detail belongs in this repository. It is a general tool and the network it might be deployed into is not described here.
- Upstream is `Devolutions/IronRDP`, Apache-2.0. Reuse the crates. Do not vendor a fork without writing down why, in `docs/architecture.md`.
- Commit subjects are declarative sentences, no prefixes.
- LF only.
- Docs describe design, build and use. What is broken, missing, untested or weak goes stale within hours on a moving project, so it does not go in these files.

## Licence

MIT. See `LICENSE`.
