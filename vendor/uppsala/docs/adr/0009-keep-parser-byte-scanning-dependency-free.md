# ADR 0009: Keep Parser Byte Scanning Dependency-Free

## Status

Accepted

## Context

Uppsala's main production target is SAML: namespace-heavy XML documents in the
3-30 KB range, often with signed assertions. The parser already has an x86_64
SSE2 delimiter scanner, but that SIMD path does not run on aarch64 machines such
as Apple Silicon. On non-x86_64 targets, delimiter scanning uses a scalar loop.

We evaluated adding `memchr` as a small dependency for portable byte searching.
This looked attractive because roxmltree uses `memchr`, and XML parsing performs
many searches for bytes such as `<`, `&`, `]`, `\r`, quotes, and `;`.

However, Uppsala's content and attribute scanners do more than find delimiters:
they also detect whether the scanned span needs XML-character validation. A
naive `memchr` implementation found delimiters quickly but then needed an
additional pass over the same span to detect non-ASCII and illegal control
bytes. On arm64 this regressed the main parser benchmarks and SAML-shaped inputs.

## Decision

Do not add `memchr` or any other scanning dependency for now.

Keep:

- x86_64 SSE2 scanning for content and attribute delimiter loops.
- one-pass scalar scanning on non-x86_64 targets, preserving validation flag
  computation in the same pass.
- simple dependency-free byte searches for isolated cases such as finding the
  semicolon in character references.

## Consequences

- Uppsala remains a zero-dependency crate by default.
- The current arm64 parser performance comes from algorithmic fixes, namespace
  caching, arena reservation, and one-pass scalar scanning, not from SIMD.
- `memchr` may be reconsidered later for isolated byte searches if the project
  relaxes the zero-dependency constraint, but it should not replace the main
  delimiter scans unless validation can remain single-pass.
- A future aarch64 NEON scanner remains the likely dependency-free route for
  improving delimiter scanning on Apple Silicon.
