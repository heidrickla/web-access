# web-access

Browser-based RDP with no third party in the session. Users sign in with their Active Directory account, see the servers an administrator assigned to them, and click one to get its desktop. The RDP client runs in the browser as WebAssembly; the proxy signs users in, keeps the server lists and saved credentials, and relays sessions. Files crossing the clipboard are held on the proxy until the anti-malware product registered with Windows has scanned them.

Design record: `docs/architecture.md`.

## Shape

    browser (ironrdp-web, WASM)  ──HTTPS / WebSocket──>  proxy  ──TCP 3389──>  Windows servers
                                                           │
                                                           └──LDAPS──>  Active Directory

| Piece | Source | Notes |
|---|---|---|
| RDP client in the browser | `ironrdp-web`, MIT OR Apache-2.0 | built to WASM and embedded in the proxy binary |
| RDCleanPath, both ends | `ironrdp-rdcleanpath` | reused |
| Sign-in | `src/directory.rs` | LDAPS simple bind as the user; the proxy host need not be domain-joined |
| Single sign-on | `src/saml.rs`, `src/sso.rs` | SAML 2.0 service provider for the site's identity provider; the account is found by the SID it sends |
| Sessions and connect tickets | `src/auth.rs` | 24-hour persistent sign-in; single-use ticket per connection |
| Server lists, assignments | `src/store.rs`, `src/policy.rs` | SQLite; a user reaches exactly the servers assigned to them |
| Saved credentials | `src/vault.rs` | AES-256-GCM under a master key wrapped by DPAPI and by a recovery passphrase |
| Admin pages | `src/admin.rs`, `web/admin.*` | users, servers, groups, activity, migration |
| Export and import | `src/migrate.rs` | a zip that moves everything, saved credentials included, to a new host |
| Relay | `src/proxy.rs` | RDCleanPath handshake, then bytes |
| File scanning | `src/scan/` | files on the clipboard channel held until AMSI (Trellix, Defender) or a scanner command calls them clean |

## Using it

1. Browse to the proxy and sign in with a network account: `jdoe`, `CORP\jdoe` or the account's sign-in name such as `john.doe@example.com`, or with single sign-on where it is offered. Closing the browser does not sign out; the sign-in lasts 24 hours. Opening a server with less than 18 hours left asks to renew the sign-in first, by password or single sign-on. Both are set on the Settings tab.
2. The server list shows the servers assigned to you, in the administrator's groups. Groups collapse and expand; the filter matches names and hosts.
3. Click a server. Enter its credentials, and tick "Save credentials" to be connected in one click next time. Credentials are saved only after the server accepts them. The domain starts as the server's default, when an administrator set one.
4. The desktop fills the window. The rail at the left edge carries clipboard, file transfer, Ctrl+Alt+Del, fullscreen and Disconnect. Files dropped on the desktop go to the remote clipboard. A file larger than the limit on the Settings tab is refused, both ways; a drop holding one sends nothing. Every file is scanned on the proxy on the way, both ways, and the rail says when it passed or why it was refused.
5. Disconnecting, or closing the browser, leaves the desktop running on the server. The list marks it Reconnect; clicking the server again returns to the same desktop.

The pages are dark by default; the button beside Sign out switches to a light theme, remembered per browser.

## Administering it

`https://<proxy>/admin`, for the accounts listed in `admins` in `config.toml` and anyone they grant the administrator flag.

| Tab | Does |
|---|---|
| Users | add users by network username; tick the servers each one gets, with select-all per group and copy-from-user; grant administrator; remove |
| Servers | add, edit and delete servers, each with an optional default domain for its sign-in; bulk import from CSV (`name,host,port,group,domain`) |
| Groups | create, rename, order and delete the groups users see |
| Activity | sign-ins, refusals, sessions opened, credential saves, every admin change; kept `audit_days` (400) |
| Settings | how long a sign-in lasts (24 h) and when opening a server asks for the password again (under 18 h left; 0 never asks); the largest file sent or fetched (0, no limit). Kept in the database, so they move with an export |
| Migration | this proxy's version and counts; recovery passphrase; unlock or reset the credential store; export, import, freeze; the directory service account's password and how its account checks last went; the file scanner and its last check |

A user signs in, but sees no servers until an administrator assigns them. Disabling the account in Active Directory stops sign-in; with a service account configured, it also ends that user's sessions at the next check. An account renamed in Active Directory keeps its servers and saved credentials: the proxy follows the account's SID to its row and renames it at the next sign-in.

The account checks run every `check_interval_secs`. When they cannot run (no domain controller answers, the service account is refused), nothing is revoked; the Migration tab says so in red and the Activity tab records `revocation.failing` once, then `revocation.restored`. An account whose lookup fails is skipped and named on the Migration tab; the others are still checked. The domain controller that last answered is tried first.

Files are scanned by the anti-malware product registered with Windows (AMSI) unless `[scan]` says otherwise. The scanner is shown the EICAR test file and a harmless file at start and hourly; while the last check failed, or is over two hours ten minutes old, every file is refused. The Migration tab shows the scanner, named by its AMSI provider (Trellix registers `MfeAntimalwareProvider Class`), and its last check; the Activity tab records `scan.failing` and `scan.restored`, and one `file.upload` or `file.download` entry per file passed or refused. Each hourly check shows in the anti-malware product's own log as an EICAR detection by `web-access-proxy.exe`, under the name `web-access-check.com`.

## Moving to new hardware

Everything moves in one zip: users, groups, servers, assignments, saved credentials and sign-in sessions. Users signed in before the export stay signed in across the cutover and keep their saved credentials.

1. Install the MSI on the new host. Copy `config.toml`, the HTTPS certificate and key, and every CA bundle the config names (`[tls] ca_bundle`, `[directory] ca_bundle`), to the same paths.
2. `Start-Service WebAccessProxy` on the new host and sign in there as one of the `admins`.
3. Old host, Migration tab: enter the recovery passphrase, tick "Freeze", Export. The zip downloads. Frozen, the old host keeps signing users in and carrying sessions but refuses saved credentials and admin changes, so none of those made after the export is lost. Sign-ins after the export exist only on the old host.
4. New host, Migration tab: upload the zip, check the counts it shows, enter the passphrase, Import. A host that already holds data asks for its own name first, and keeps its database as a backup.
5. Move the DNS name.

## Backups

An export is also the backup: importing last night's export restores a host. Each export opens only with the recovery passphrase that was set when it was made, so keep the passphrase history with the exports.

For a scheduled backup, a task running as SYSTEM with the passphrase in a file SYSTEM and Administrators can read (in the data directory, as below, LocalService can read it too):

    web-access-proxy.exe export C:\ProgramData\web-access\config.toml D:\Backups\web-access-nightly.zip --passphrase-file C:\ProgramData\web-access\backup-passphrase.txt

The export is written beside the target, read back, and only then renamed over it, so a full disk or a dropped share keeps the previous night's file. Rotate the files with the task, for example by putting the date in the file name.

An import keeps the database it replaces as `backup-<time>.db` in the data directory; the newest five are kept. A schema upgrade keeps the database as it was as `backup-schema<N>-<time>.db`. To restore either: stop the service, move `web-access.db`, `web-access.db-wal` and `web-access.db-shm` out of the data directory together, rename the backup to `web-access.db`, start the service. It carries this host's key, so it opens unlocked. The `-wal` and `-shm` files are the write-ahead log of the database being replaced; left beside a restored copy, they would be applied to it.

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
| `[scan]` | `scanner`: `"amsi"` (default on Windows), `"command"` or `"off"`; `timeout_secs` (120), `max_staged_mb` (2048), `check_every_mins` (60); for `"command"`, `command` with `{file}`, `clean_exit_codes` and `detected_exit_codes` |
| `[directory]` | `domain`; `urls` (ldaps only); optional `netbios`, `ca_bundle` (the Windows certificate store when omitted), `base_dn` (derived from `domain` when omitted), `service_account`, `check_interval_secs` (default 600) and `timeout_secs` (default 10). Optional when local accounts are allowed |
| `[saml]` | single sign-on: `url` (the https address users open), `idp_metadata` (the identity provider's metadata file); optional `entity_id` (default `<url>/api/saml/metadata`), `sid_attribute` (default ADFS's Primary SID claim) and `clock_skew_secs` (default 180, at most 300). Needs `[directory]` with `service_account` |

Set `netbios` to the domain's NetBIOS name. A sign-in name with a domain in it (`CORP\jdoe`, `john.doe@example.com`) is then checked exactly as typed, a password accepted for an account in another domain is refused, and the account signed in is the one Active Directory says the password was checked for. Without `netbios`, every sign-in name binds as `name@domain`.

## Single sign-on

With `[saml]` configured, the sign-in page offers "Sign in with single sign-on" beside the password. The proxy is a SAML 2.0 service provider for the site's identity provider (ADFS, Entra ID): the browser goes to the identity provider and comes back signed in, without typing a password where the identity provider's own session holds. The account signed in is the directory account whose objectSid the assertion's SID attribute names, read with the service account, so the service account's password must be set (Migration tab).

| IT sets, on the identity provider | |
|---|---|
| Relying party | imported from `https://<proxy>/api/saml/metadata`; identifier `<url>/api/saml/metadata`, assertion consumer `<url>/api/saml/acs`, HTTP-POST |
| SID attribute | ADFS: a claim rule passing Primary SID (`http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid`). Entra ID: a claim from `user.onpremisessecurityidentifier`, whose name goes in `sid_attribute` |
| Signing | the assertion signed with SHA-256 or stronger; the response may be signed as well |
| Encryption | off for this relying party |

Then export the identity provider's metadata (ADFS: `https://<adfs>/FederationMetadata/2007-06/FederationMetadata.xml`; Entra ID: the enterprise application's Federation Metadata XML), save it where `idp_metadata` names, and restart the service. The metadata is read at start: after the identity provider adds or changes a signing certificate, export it again and restart. During a certificate rollover both certificates are trusted.

The renewal dialog offers single sign-on too; it leaves the page, and the server is opened again after. A refused single sign-on shows why, and the Activity tab records it as `signin.refused`.

## HTTPS certificate

`[https]` takes PEM files. The certificate file holds the server certificate first, then any intermediates; the key file holds the unencrypted private key. From a PFX, with OpenSSL:

    openssl pkcs12 -in proxy.pfx -clcerts -nokeys -out proxy-cert.pem
    openssl pkcs12 -in proxy.pfx -cacerts -nokeys -out chain.pem
    openssl pkcs12 -in proxy.pfx -nocerts -nodes -out proxy-key.pem

Append `chain.pem` to `proxy-cert.pem`. Keep the key file in the data directory, whose permissions admit only SYSTEM, Administrators and LocalService, the account the service runs as.

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

CI (`.github/workflows/ci.yml`) runs format, lint, test, page scripts and dependencies on Linux, and lint and test on Windows where the host has a Windows runner (GitHub).

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
- Users sign in with their Active Directory accounts, by password or through the site's SAML identity provider; the proxy host is not domain-joined.
- Each user's server list is maintained by hand on the proxy, per user.
- Credentials pass through to the server unless the user saves them; saved ones are kept encrypted on the proxy, per user and per server, and move with an export.
- Files crossing the clipboard are scanned on the proxy, inline, by the anti-malware product registered with Windows; only a clean verdict passes.
- MIT OR Apache-2.0 upstream, so the licence question is closed.

## Roadmap

Future additions. RDP comes first. Design for each is in `docs/architecture.md`.

| Addition | What it takes |
|---|---|
| Linux desktops | EGFX in `ironrdp-web`, which GNOME Remote Desktop, built into Ubuntu, requires. xrdp is the alternative |
| SSH | a raw-forward proxy mode; Go's SSH client compiled to WASM, on xterm.js |
| VNC | the same raw-forward mode; noVNC |
| Telnet | the same raw-forward mode; xterm.js plus option negotiation |
| Kerberos for RDP | a KDC proxy endpoint; `ironrdp-web` already takes the URL |
| HTTP(S) web interfaces | a reverse proxy: a new component, not a relay mode |

## Windows installer

`installer/` builds an MSI, deployable the way an organisation already deploys things (GPO, SCCM, Intune) with a real uninstall and upgrade path. On a Windows host with the Rust MSVC toolchain and the .NET SDK:

    powershell -ExecutionPolicy Bypass -File installer/build.ps1

It builds the proxy, takes the version from `Cargo.toml`, stamps the source revision into the binary, and writes `installer/web-access-proxy-<version>.msi`. It refuses a tree with uncommitted changes unless given `-Dev`. A release is built from its tag, `v<version>`.

`installer/upgrade-test.ps1` checks a package on a clean Windows Server: the upgrade from 0.2.0 with the service running, a rebuild of the same version over a broken config, uninstall, and `REMOTE_ADDRESSES`. Its header names the files it expects in `C:\wa`.

| | |
|---|---|
| Installs | `%ProgramFiles%\web-access\web-access-proxy.exe`, config to `%ProgramData%\web-access\config.toml` |
| Data directory | `%ProgramData%\web-access`: SYSTEM and Administrators full control, LocalService (the account the service runs as) modify, inherited by the files in it. Each install applies this list again. Kept on uninstall |
| Config | never replaced by an install or an upgrade, and kept on uninstall |
| Runtime | nothing to install: the C runtime is linked into the exe |
| Service | `WebAccessProxy`, auto-start, running as `NT AUTHORITY\LocalService`, restarted a minute after the process ends unexpectedly |
| Service arguments | `--service "[ProgramData]\web-access\config.toml"` |
| First install | the service is not started: the config has to be written first |
| Upgrade | the new version is installed, then the old one removed; the service is stopped, replaced and started again. A start that fails (a config still to be edited) is in the service log and does not fail the upgrade; an upgrade that fails leaves the old version installed |
| Firewall | one exception, `web-access RDP proxy`, for `web-access-proxy.exe`, not a port, because the port comes from the config. An upgrade keeps it; the upgrade from 0.2 removes 0.2's rule, `web-access proxy`. Remote addresses from `REMOTE_ADDRESSES`: any by default, or a comma-separated list of addresses and subnets; remembered for upgrades and kept on uninstall, so a reinstall uses it too |

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
2. `msiexec /i web-access-proxy-<new version>.msi /qn /l*v upgrade.log`. The new version is installed, the old one removed, and the service started again. A newer schema is applied at its first start, and the database as it was is kept as `backup-schema<N>-<time>.db`.
3. Check the log for the `listening` line and the version on the Migration tab.

To go back: uninstall, install the previous MSI, stop the service, move `web-access.db`, `web-access.db-wal` and `web-access.db-shm` out of the data directory together, rename the `backup-schema<N>-<time>.db` copy to `web-access.db`, and start the service. A database migrated by a newer version is refused by an older one.

Upgrading from 0.2 or earlier keeps `config.toml`: those packages registered the same config component. The program moves from `C:\Program Files (x86)\web-access` to `C:\Program Files\web-access`, so a scheduled task that names the old path needs the new one. From 0.1, add `[directory]`, `admins` and `[https]` to it after the upgrade, then `Start-Service WebAccessProxy`; its `[[target]]` entries are imported once into an "Imported" group, and `[[policy]]` is no longer read.

WiX v5 specifically. v6 and v7 require accepting the Open Source Maintenance Fee EULA, which is a licensing decision with a fee attached for commercial use. v5 is the last version without that gate and uses the same schema. The Firewall and Util extensions must be version-pinned to match the toolset.

## The browser client

"Clientless" means nothing is installed on the accessing machine, not that no client exists. The RDP client is `ironrdp-web` compiled to WebAssembly and delivered by the proxy itself.

| | |
|---|---|
| `web/ironrdp_web_bg.wasm` | the client, built by `scripts/build-client.sh` |
| `web/ironrdp_web.js` | wasm-bindgen glue |
| `web/index.html`, `web/app.js` | sign-in, the server list, the session |
| `web/admin.html`, `web/admin.js` | the admin pages |
| `web/app.css` | every page; dark by default, with a light theme |
| `web/theme.js` | every page: applies the stored theme before the page paints, and the header's theme button |
| `web/notices.html`, `web/notices-client.html` | third-party licences of the proxy and of the client, served at `/notices` and `/notices-client` and installed beside the binary |

The client is built from a pinned IronRDP commit, and the build is reproducible: a clean clone gives the same bytes. A test checks the committed files against these digests.

| | |
|---|---|
| IronRDP | `9b151c4c2e47c6014e1e8e55909d4180aa8bdb99` (2026-09-22), crate `ironrdp-web` |
| Toolchain | Rust 1.98.1, target `wasm32-unknown-unknown`, wasm-pack 0.13.1 (`--target web --release`, with its wasm-opt pass) |
| `ironrdp_web_bg.wasm` | sha256 `e34898c6ba5cbc72bf4b313e5d8085b55ddb60bf65b55177b4f6632f2f090996` |
| `ironrdp_web.js` | sha256 `00544efdca030a0284d66ba021743deb49c9277260034f80da7f7aeda89bde3f` |

`scripts/build-client.sh` (Linux, with cargo-deny and cargo-about) clones that commit, checks the client's wasm32 dependency graph against `deny-client.toml`, builds it, copies it into `web/`, and writes `web/notices-client.html`. `scripts/notices.sh` writes `web/notices.html` from this crate's graph; run it after changing dependencies.

Every page asset is a separate file: the proxy sends `default-src 'self'`, which forbids inline `<style>`, `<script>`, style attributes and event handlers. A test asserts no page carries one. All are embedded with `include_bytes!`, so a deployment is one MSI and one service, and the served client cannot drift from the proxy it talks to.

`build.rs` gzips each asset and names it by a hash of its content. The proxy sends the gzip to a browser that accepts it, with an ETag and `Cache-Control: no-cache`: every load asks again, so an upgrade is picked up at once, and an unchanged asset costs a 304. API answers are `no-store`.

The client's API maps onto the proxy's design: `SessionBuilder.destination()` carries the server id, never an address, and `authToken()` carries the single-use connect ticket.

Keyboard: a character typed alone goes through `unicodePressed`, so the remote's layout does not matter. A shortcut (Ctrl, Alt or Meta held, without AltGr) and every non-printable key go by scancode from the key's position, and a key is released by the route that pressed it. Lock keys are synchronised on the first key after the desktop takes focus. Fullscreen requests keyboard lock, so Esc and Windows-key shortcuts reach the remote. A key in no table is dropped rather than guessed at.

Errors: the proxy reports a server it could not reach as the Windows socket error and a refused certificate as its TLS alert, over RDCleanPath; the page names both. The proxy log carries the full reason.

## Conventions

- No credential, host address or site detail belongs in this repository. It is a general tool and the network it might be deployed into is not described here.
- Upstream is `Devolutions/IronRDP`, MIT OR Apache-2.0. Reuse the crates. Do not vendor a fork without writing down why, in `docs/architecture.md`.
- Commit subjects are declarative sentences, no prefixes.
- LF only.
- Docs describe design, build and use. What is broken, missing, untested or weak goes stale within hours on a moving project, so it does not go in these files.

## Licence

MIT. See `LICENSE`.
