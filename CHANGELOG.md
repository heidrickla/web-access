# Changelog

Notable changes, newest first. Versions follow semantic versioning; the MSI and the binary carry the same version, and a release is tagged `v<version>`.

## [0.3.0] - Unreleased

### Added

- A light theme beside the dark default, a phone layout, server tiles whose whole area opens the server, and a refreshed look on both pages.
- `--version`, and the version with its source revision in the log's first line and on the Migration tab.
- Recovery without the passphrase: `set-secret recovery --replace` gives the key this host holds a new passphrase, and Reset the credential store (Migration tab, or `reset-credentials`) starts a store nothing can open over. `unlock` on the command line.
- `--passphrase-file` for `export` and `import`, so a scheduled task can take backups.
- The MSI's firewall rule takes its remote addresses from `REMOTE_ADDRESSES`, any by default, and remembers them for upgrades.
- The service is restarted a minute after the process ends unexpectedly.
- Opening a server when the sign-in has less than 18 hours left asks for the password again, so a desktop is not cut off mid-shift.
- Mouse-wheel scrolling on the desktop. Files dropped on the desktop go to the remote clipboard.
- A page that cannot reach the proxy says so and tries again every ten seconds.

### Changed

- A sign-in is checked under the name as typed when it names a domain, and the account signed in is the one Active Directory says the password was checked for. With `netbios` set, a password accepted for an account in another domain is refused.
- An account renamed in Active Directory keeps its row, servers and saved credentials.
- The service reports running only after it has read its config, opened the database and bound its port, and reports stopping while it drains.
- An upgrade starts the service again; a first install still leaves it stopped.
- A schema upgrade keeps the database as it was, as `backup-schema<N>-<time>.db`.
- A command-line export is written beside its target, read back and renamed over it.
- The newest five import backups are kept; temporary files an interrupted export or import left are removed at service start.
- The installer builds the proxy itself and takes its version from `Cargo.toml`.
- The page names why a server could not be reached (unknown name, refused, timed out, unreachable) or why its certificate was refused (untrusted issuer, expired, revoked).
- Active Directory refusals are named once the password is proven: password expired or must change, restricted hours or workstation, disabled, expired. A lockout is logged and reported as an ordinary refusal.
- Shortcuts reach the remote by key position, so Ctrl+C is Ctrl+C whatever the layouts. Lock keys are synchronised when the desktop takes focus, and fullscreen captures Esc and Windows-key shortcuts.
- The desktop renders at the screen's pixel density.
- A refresh does not replace a message said in the last eight seconds; an error wraps rather than being cut off; during a session the rail repeats messages and its button marks a new one.
- Saved credentials are asked for again only when the server refused them.
- Admin user rows are selectable from the keyboard.

### Fixed

- An upgrade or an uninstall no longer deletes `config.toml`.
- A damaged or truncated export is reported as damaged instead of as a server error.
- A database that does not reopen after an import's swap stops the service instead of serving an empty one.
- Pressing a server tile outside its name opened nothing; opening a server said nothing while the client loaded.
- Enter in the server sign-in dialog cancelled it instead of connecting.
- The server password field and the rail's clipboard text are cleared when their dialog or session ends; signing out reloads the page.

## [0.2.0] - 2026-09-24

Directory sign-in, per-user server lists, saved credentials, admin pages, export and import, and the MSI.

## [0.1.0] - 2026-09-23

The relay, a fixed list of targets, and the first MSI.
