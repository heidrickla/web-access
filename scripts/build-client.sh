#!/usr/bin/env bash
# Rebuilds the browser client (web/ironrdp_web.js, web/ironrdp_web_bg.wasm) from IronRDP at the
# pinned commit, checks its wasm32 dependency graph against deny-client.toml, and writes its
# licence page (web/notices-client.html). Linux, with rustup, wasm-pack 0.13.1, cargo-deny 0.20.2
# and cargo-about 0.9.2 on the PATH. The build is reproducible: the same inputs give the digests
# recorded in README.md, which a test checks against the committed files.
set -euo pipefail
IRONRDP_COMMIT=9b151c4c2e47c6014e1e8e55909d4180aa8bdb99
export RUSTUP_TOOLCHAIN=1.98.1

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

git clone -q https://github.com/Devolutions/IronRDP "$work/ironrdp"
git -C "$work/ironrdp" checkout -q "$IRONRDP_COMMIT"
cd "$work/ironrdp/crates/ironrdp-web"

rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal --target wasm32-unknown-unknown
cargo deny --manifest-path Cargo.toml --config "$repo/deny-client.toml" check
wasm-pack build --target web --release

cp pkg/ironrdp_web.js pkg/ironrdp_web_bg.wasm pkg/ironrdp_web.d.ts "$repo/web/"
sed 's/^targets = .*/targets = ["wasm32-unknown-unknown"]/' "$repo/about.toml" > "$work/about-client.toml"
cargo about generate --manifest-path Cargo.toml -c "$work/about-client.toml" "$repo/about.hbs" > "$work/notices.part"
sed -e "s|@TITLE@|Third-party licences: the browser client|" \
    -e "s|@INTRO@|The crates the RDP client in the page is built from: IronRDP $IRONRDP_COMMIT.|" \
    -e "s|@OTHER_HREF@|./notices.html|" \
    -e "s|@OTHER_LABEL@|The proxy's licences|" \
    "$work/notices.part" | tr -d '\r' > "$repo/web/notices-client.html"

cd "$repo/web"
sha256sum ironrdp_web_bg.wasm ironrdp_web.js
