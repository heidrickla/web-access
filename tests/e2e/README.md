# End-to-end tests

A throwaway Samba AD domain controller and an xrdp server in containers, one or two proxies built
from this tree, and headless Chromium driving the real pages. Linux host with Docker and sudo (for an
`/etc/hosts` entry). Fixture passwords are generated into `fixtures.env` and never printed.

| Step | Command | Covers |
|---|---|---|
| Fixtures | `./up.sh` | domain `CORP.TEST` on `ldaps://dc1.corp.test:1636` with its own CA; users `jdoe`, `boss`, `asmith`, disabled `gone`, service account `svc-webaccess`; xrdp on `127.0.0.1:13389`, user `ops` |
| Build | `cargo build --release` at the repo root | |
| Proxy | `./proxy.sh start 1` | `proxy1.toml` on `127.0.0.1:8443`, bootstrap admin `boss` |
| API | `./smoke.sh` | sign-in refusals, both username forms, service account, adding users, CSV import, assignments, recovery passphrase, tickets, non-admin and cross-origin refusals |
| Browser 1 | `./run-e2e.sh e2e1` | sign-in page, grouped list, filter, collapsed state, connect and save, one-click reconnect, browser restart and reattach, forget, admin tabs, non-admin denial |
| Browser 2 and 3 | `./phases23.sh` | disabling the account ends the live session and the sign-in; export and freeze, frozen refusals, import on a second proxy, the user still signed in with the saved credential after cutover |
| Local accounts | `./smoke-local.sh` | a proxy with no directory (`proxy3.toml`): `local-account` on the command line, sign-in, admin, assignment, connect ticket |
| Guards | `./mutate.sh` | breaks each guard in a scratch copy and expects its unit test to fail |

xrdp is not an NLA server and the browser client does not send autologon, so the browser tests type
the fixture password into xrdp's own login box. xrdp's `/var/log/xrdp-sesman.log` in the `wa-rdp`
container records `reconnected session` when a reconnect returns to the same desktop.

Screenshots land in `shots/`. `docker rm -f wa-dc wa-rdp` removes the fixtures.
