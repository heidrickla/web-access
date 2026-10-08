# Performance

Uppsala uses accelerated byte scanning for parser hot loops:

- SSE2 delimiter scanning on x86_64 for text content and attribute values.
- SSE2 ASCII XML-name continuation scanning for element and attribute names.
- SSE2 single-byte search for reference parsing.
- Scalar reference implementations on non-x86_64 and for SIMD tail bytes.

Parsing throughput depends heavily on document shape. Long plain-text spans,
large attribute values, and ASCII-heavy names favor the bulk scanners. Very
small documents are dominated by fixed parser and allocation overhead.

## Current libxml2 comparison

The tables below compare a native x86_64 server build of Uppsala against a
local sibling checkout of libxml2, called directly through `xmlReadMemory`.
The harness reports median parse time from in-memory strings; file I/O and
process startup are not included.

Build setup used for these numbers (`just bench-libxml2 101`):

- Uppsala: `RUSTFLAGS='-C target-cpu=native' cargo build --release`
- libxml2: static release library from `../libxml2`, built with
  `-O3 -DNDEBUG -fno-semantic-interposition -march=native`
- CPU pinning: `taskset -c 0`

The `Ratio` column is `libxml2 / Uppsala`; values above `1.0` mean Uppsala
parsed faster.

### Full libxml2 report

The report includes SAML-shaped request/response documents, larger generated
real-life-shaped XML documents, one local pyFF metadata fixture, and two larger
fixtures from the libxml2 checkout.

| Input | Size | Uppsala ns | Uppsala no-ns | libxml2 | Ratio ns | Ratio no-ns |
|---|---:|---:|---:|---:|---:|---:|
| SAML small | 3.4 KB | 9.494 us | 6.053 us | 23.435 us | 2.47x | 3.87x |
| SAML medium | 8.9 KB | 16.169 us | 19.331 us | 75.494 us | 4.67x | 3.91x |
| SAML large | 27.2 KB | 64.384 us | 39.515 us | 161.087 us | 2.50x | 4.08x |
| SAML metadata aggregate | 666.3 KB | 2.000 ms | 1.794 ms | 4.506 ms | 2.25x | 2.51x |
| Atom feed archive | 848.2 KB | 3.573 ms | 3.342 ms | 6.310 ms | 1.77x | 1.89x |
| SOAP invoice batch | 715.2 KB | 3.568 ms | 3.350 ms | 5.753 ms | 1.61x | 1.72x |
| pyFF sample metadata | 3.5 KB | 12.178 us | 10.712 us | 37.922 us | 3.11x | 3.54x |
| libxml2 `nvdcve_0.xml` | 287.4 KB | 1.442 ms | 1.385 ms | 2.571 ms | 1.78x | 1.86x |
| libxml2 `comps_0.xml` | 607.9 KB | 2.990 ms | 2.996 ms | 5.658 ms | 1.89x | 1.89x |

These are local measurements, not a universal claim. Re-run the harness on the
target server class before making capacity decisions.

## Running the performance harness

The comparison harness is checked into the repo under `performance-harness/`.
It is kept outside the main crate's targets so normal library builds and tests
do not depend on libxml2.

### One-command libxml2 benchmark

With libxml2 checked out at the default `../libxml2` location, run:

```bash
just bench-libxml2
```

This configures/builds libxml2 as a local static release library, builds the
Uppsala harness with `RUSTFLAGS='-C target-cpu=native'`, pins the run to CPU 0
when `taskset` is available, and prints one final Markdown table containing
the SAML-shaped inputs, larger generated XML shapes, and representative
local/libxml2 XML fixtures. The report includes namespace-aware DOM,
namespace-disabled DOM, pull scan-only, and explicit pull-to-DOM timings.

The default sample count is `301`. Use a larger count for steadier medians:

```bash
just bench-libxml2 1001
```

To use a different libxml2 checkout:

```bash
LIBXML2_DIR=/path/to/libxml2 just bench-libxml2
```

### Manual setup

By default, the harness expects a sibling libxml2 checkout next to the Uppsala
repo:

```text
code/
  uppsala/
    performance-harness/
  libxml2/
```

Build libxml2 locally:

```bash
cmake -S ../libxml2 -B ../libxml2/build-uppsala-release -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=OFF \
  -DLIBXML2_WITH_PROGRAMS=OFF \
  -DLIBXML2_WITH_TESTS=OFF \
  -DLIBXML2_WITH_ZLIB=OFF \
  -DLIBXML2_WITH_ICONV=OFF \
  -DLIBXML2_WITH_ICU=OFF \
  -DLIBXML2_WITH_MODULES=OFF \
  -DLIBXML2_WITH_PYTHON=OFF \
  -DCMAKE_C_FLAGS_RELEASE='-O3 -DNDEBUG -fno-semantic-interposition -march=native'
cmake --build ../libxml2/build-uppsala-release
```

The harness build script links `$LIBXML2_DIR/build-uppsala-release/libxml2.a`,
defaulting `LIBXML2_DIR` to `../libxml2`. Override the source checkout with
`LIBXML2_DIR=/path/to/libxml2`; override only the build-output directory with
`LIBXML2_LIB_DIR=/path/to/build` if needed.

### Run SAML-shaped inputs manually

```bash
RUSTFLAGS='-C target-cpu=native' cargo run --release \
  --manifest-path performance-harness/Cargo.toml -- saml 1001
```

### Run a single file manually

```bash
RUSTFLAGS='-C target-cpu=native' cargo run --release \
  --manifest-path performance-harness/Cargo.toml -- \
  file test-data/pyff-xslt/sample-metadata.xml 1001
```

The trailing number is the sample count (default `31`). Each run does a short
warmup, then reports medians in microseconds. Output is tab-separated:

```text
file  bytes  uppsala_ns_us  uppsala_no_ns_us  uppsala_pull_scan_us  uppsala_pull_dom_us  libxml2_us  ratio_ns  ratio_no_ns  ratio_pull_scan  ratio_pull_dom
```

The `ratio_ns` column corresponds to the default namespace-aware mode; SAML
users should usually care about this column. `ratio_no_ns` is Uppsala with
namespace resolution disabled. `ratio_pull_scan` is the direct pull event stream
without DOM allocation, and `ratio_pull_dom` is the explicit pull-to-DOM builder.

## Profiling

To find hot functions when optimizing the parser, build the harness and record
a profile on Linux:

```bash
RUSTFLAGS='-C target-cpu=native' cargo build --release \
  --manifest-path performance-harness/Cargo.toml
sudo perf record -g --call-graph dwarf \
  performance-harness/target/release/uppsala-performance-harness saml 1001
sudo perf report --no-children --sort=dso,symbol
```

Focus on self-time (`--no-children`) to identify the real bottleneck rather
than its callers, and use `perf annotate --symbol=<fn>` to inspect a hot loop's
per-instruction sample counts.

On this container, hardware counters such as `branch-misses` and `cycles` were
reported as unsupported even under `sudo perf stat`; use a host with PMU access
for branch-prediction measurements.
