# Uppsala - Pure Rust XML Library
default:
    @just --list

# Run all tests
test:
    cargo test

# Run focused parser/scanner/namespace tests
test-core:
    cargo check
    cargo test --lib simd::tests
    cargo test --lib parser::tests
    cargo test --test namespace_conformance

# Run unit tests only
unit:
    cargo test --lib

# Run XML 1.0 conformance tests (68 tests)
test-xml:
    cargo test --test xml_conformance

# Run namespace conformance tests (16 tests)
test-ns:
    cargo test --test namespace_conformance

# Run XPath 1.0 conformance tests (66 tests)
test-xpath:
    cargo test --test xpath_conformance

# Run XSD conformance tests (38 tests)
test-xsd:
    cargo test --test xsd_conformance

# Run serialization conformance tests (68 tests)
test-serial:
    cargo test --test serialization_conformance

# Run range conformance tests
test-range:
    cargo test --test range_conformance

# Run pull-parser differential regression tests
test-pull:
    cargo test --test pull_differential

# Run W3C XML Conformance Suite (~1208 tests)
test-w3c-xml:
    cargo test --test w3c_xmlconf -- --nocapture

# Run W3C XML Schema Test Suite - all suites (~20156 tests)
test-w3c-xsd:
    cargo test --test w3c_xsts -- --nocapture

# Run NIST Datatypes tests (~19217 tests)
test-nist:
    cargo test --test w3c_xsts xsts_nist_datatypes -- --nocapture

# Run MS DataTypes tests (~1213 tests)
test-ms:
    cargo test --test w3c_xsts xsts_ms_datatypes -- --nocapture

# Run Sun Combined tests (~199 tests)
test-sun:
    cargo test --test w3c_xsts xsts_sun_combined -- --nocapture

# Run all hand-crafted test suites
test-handcrafted: test-xml test-ns test-xpath test-xsd test-serial test-range test-pull

# Run all W3C conformance suites
test-w3c: test-w3c-xml test-w3c-xsd

# Check the project compiles without errors
check:
    cargo check

# Build in release mode
build:
    cargo build --release

# Build the performance comparison harness
build-perf:
    cargo build --release --manifest-path performance-harness/Cargo.toml

# Build libxml2 + native harness, then print the full libxml2 comparison table
bench-libxml2 samples="301":
    #!/usr/bin/env bash
    set -euo pipefail
    libxml2_dir="${LIBXML2_DIR:-../libxml2}"
    if [[ ! -d "$libxml2_dir" ]]; then
        echo "missing libxml2 checkout at $libxml2_dir" >&2
        echo "set LIBXML2_DIR=/path/to/libxml2 to use a different checkout" >&2
        exit 1
    fi
    libxml2_dir="$(cd "$libxml2_dir" && pwd)"
    libxml2_build="${LIBXML2_LIB_DIR:-$libxml2_dir/build-uppsala-release}"
    case "$libxml2_build" in
      /*) ;;
      *) libxml2_build="$(pwd)/$libxml2_build" ;;
    esac
    export LIBXML2_DIR="$libxml2_dir"
    export LIBXML2_LIB_DIR="$libxml2_build"
    cmake -S "$libxml2_dir" -B "$libxml2_build" -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=OFF \
      -DLIBXML2_WITH_PROGRAMS=OFF \
      -DLIBXML2_WITH_TESTS=OFF \
      -DLIBXML2_WITH_ZLIB=OFF \
      -DLIBXML2_WITH_ICONV=OFF \
      -DLIBXML2_WITH_ICU=OFF \
      -DLIBXML2_WITH_MODULES=OFF \
      -DLIBXML2_WITH_PYTHON=OFF \
      -DCMAKE_C_FLAGS_RELEASE='-O3 -DNDEBUG -fno-semantic-interposition -march=native' >&2
    cmake --build "$libxml2_build" >&2
    RUSTFLAGS='-C target-cpu=native' CARGO_TARGET_DIR=target/perf-native \
      cargo build --release --manifest-path performance-harness/Cargo.toml >&2
    if command -v taskset >/dev/null 2>&1; then
        taskset -c 0 target/perf-native/release/uppsala-performance-harness libxml2-report {{samples}}
    else
        target/perf-native/release/uppsala-performance-harness libxml2-report {{samples}}
    fi

# Run generated SAML-shaped parser comparison inputs
perf-saml samples="101":
    cargo run --release --manifest-path performance-harness/Cargo.toml -- saml {{samples}}

# Run the fixed benchmark input suite from a directory
perf-suite dir samples="101":
    cargo run --release --manifest-path performance-harness/Cargo.toml -- suite {{dir}} {{samples}}

# Run one XML file through the performance comparison harness
perf-file file samples="101":
    cargo run --release --manifest-path performance-harness/Cargo.toml -- file {{file}} {{samples}}

# ─── Fuzzing (audit/fuzz, cargo-fuzz + libFuzzer) ───

# Install the fuzzing toolchain (nightly + cargo-fuzz). Run once per machine.
fuzz-setup:
    rustup toolchain install nightly
    rustup component add llvm-tools-preview --toolchain nightly
    sfw cargo install cargo-fuzz

# Build every fuzz target once (ASan on; the SIMD scanners are `unsafe`).
fuzz-build:
    ./audit/fuzz/scripts/build.sh

# Fuzz ALL targets in a detached tmux session (remote-friendly: run over SSH,
# log out, it keeps going; `just fuzz-attach` to reattach, arg=seconds, 0=forever)
fuzz seconds="0":
    ./audit/fuzz/scripts/fuzz-all.sh {{seconds}}

# Fuzz a single target in the foreground, all cores via fork mode.
# e.g. `just fuzz-one fuzz_roundtrip 3600`
fuzz-one target seconds="0":
    ./audit/fuzz/scripts/run.sh {{target}} {{seconds}}

# Reattach to the running fuzz session.
fuzz-attach:
    tmux attach -t uppsala-fuzz

# Stop all fuzzing (kills the tmux session).
fuzz-stop:
    tmux kill-session -t uppsala-fuzz || true

# List any crash/timeout/oom artifacts found so far.
fuzz-crashes:
    @find audit/fuzz/artifacts -type f 2>/dev/null | sort || echo "no artifacts yet"

# Reproduce a crash: `just fuzz-repro fuzz_parse audit/fuzz/artifacts/fuzz_parse/crash-abc`
fuzz-repro target artifact:
    ./audit/fuzz/scripts/repro.sh {{target}} {{artifact}}

# HTML line-coverage report for a target's corpus.
fuzz-coverage target:
    ./audit/fuzz/scripts/coverage.sh {{target}}

# Minimize a target's corpus (drop redundant inputs).
fuzz-cmin target:
    ./audit/fuzz/scripts/minimize.sh {{target}}

# Run clippy lints
clippy:
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt

# Check formatting without modifying files
fmt-check:
    cargo fmt -- --check
