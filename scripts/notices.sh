#!/usr/bin/env bash
# Writes web/notices.html, the licences of the crates the proxy is built from. Run after changing
# dependencies; the browser client's page comes from scripts/build-client.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo about generate --offline -c about.toml about.hbs > web/notices.html.part
sed -e "s|@TITLE@|Third-party licences: the proxy|" \
    -e "s|@INTRO@|The crates the proxy service is built from.|" \
    -e "s|@OTHER_HREF@|./notices-client.html|" \
    -e "s|@OTHER_LABEL@|The browser client's licences|" \
    web/notices.html.part | tr -d '\r' > web/notices.html
rm web/notices.html.part
echo "web/notices.html: $(grep -c '<section class="card notice">' web/notices.html) licence texts"
