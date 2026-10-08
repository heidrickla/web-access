# ADR 0014: SIMD/scalar parity for the byte scanners and differential fuzzing

## Status

Accepted

## Context

ADR 0002 introduced hand-written SSE2 scanners in `src/simd.rs`
(`scan_content_delimiters`, `scan_attr_delimiters`) that process 16 bytes per
iteration, with scalar fallbacks for non-x86_64 targets. A later branch added a
third `unsafe` SSE2 routine, `scan_escape_run`, to the serializer's escape path.
Each function returns a delimiter offset and, for the two scan functions, a
`needs_validation` flag; the scalar half of every function is the reference
implementation and the SSE2 half must produce identical results.

`unsafe` SIMD removes Rust's memory-safety guarantee for the parser and
serializer hot loops, which run over fully attacker-controlled input. The
dangerous failure mode is not only a crash (an out-of-bounds `_mm_loadu_si128`
at the `len % 16` tail) but a **silent behavioural divergence**: the SSE2 path
computing a different answer than the scalar reference. Such a divergence is
invisible to ordinary tests and to crash-only fuzzing, yet it is exactly the
class of bug that can turn into a parser-differential (two consumers of the same
bytes disagreeing) — a serious problem for the SAML/federation use case, where
successful validation is treated as a trust boundary.

A differential model of the two code paths surfaced a real inconsistency in the
`needs_validation` flag:

- `scan_content_sse2` accumulated the flag over the **entire 16-byte chunk**,
  including bytes *after* the first delimiter, then returned at the delimiter.
  The scalar reference walks byte-by-byte and **stops at the delimiter**.
- Result: whenever a delimiter was followed by a non-ASCII (`>= 0x80`) or invalid
  control byte within the same 16-byte window, the two paths returned the same
  offset but a different flag. Minimal witness: `"<" + 0xC3 + "a"*14` gave SSE2
  `(0, true)` vs scalar `(0, false)`. `scan_attr_sse2` had the same structure.

Severity analysis (3,000,000 randomised differential trials, plus reading the
one consumer): the parser (`parse_content` in `src/parser.rs`) uses the flag
**only** to decide whether to XML-validate the returned run `data[..pos]`. The
offset always matched; the SSE2 flag only ever *over-*reported (261k content +
144k attr divergences observed, **zero** under-reports). An over-report means the
parser validates an already-clean range — redundant work, never a skipped check.
So the divergence was **benign** (not exploitable), but a genuine cross-path
inconsistency that a future refactor could make load-bearing, and one that made a
strict differential fuzz oracle impossible.

## Decision

1. **Restore exact SSE2/scalar parity.** In `scan_content_sse2` and
   `scan_attr_sse2`, restrict the `needs_validation` lanes to bytes *before* the
   first delimiter by masking the validation bitmask with `(1 << d) - 1`, where
   `d` is the delimiter's lane index (all 16 lanes are kept when the chunk holds
   no delimiter). The SSE2 flag is now byte-identical to the scalar reference.
   The change is confined to the flag computation; the returned offset and the
   escape scanner are unchanged.

2. **Make SIMD/scalar parity a permanent, fuzzable invariant.** Add a fuzz-only
   `fuzzing` Cargo feature that exposes both halves of every scanner (and the
   serializer escaper) via `uppsala::fuzz_exports`. Two differential harnesses in
   `audit/fuzz` (`fuzz_simd_differential`, `fuzz_escape_differential`) assert
   `sse2(...) == scalar(...)` for arbitrary input — including the `quote` byte
   fuzzed across all 256 values — and, for the escaper, a reference-independent
   safety property (the output never contains a raw `<`, `>`, `\r`, or a bare
   `&`, nor a raw `"`/`\t`/`\n` in attribute context). The feature adds no
   dependencies and is compiled out of normal and release builds, preserving the
   zero-dependency and clean-public-API guarantees (ADR 0009).

3. **Pin the witness in a unit test.**
   `simd::tests::content_flag_matches_scalar_when_delim_precedes_invalid`
   asserts the historical divergence cases now agree, so the fix cannot silently
   regress even without a fuzzing run.

The scalar implementation remains the authoritative specification of scanner
behaviour; the SSE2 path is an optimisation that must match it exactly.

## Consequences

- The SSE2 scanners no longer over-report `needs_validation`, so the parser skips
  a small amount of redundant XML-character validation on chunks where an invalid
  byte follows a delimiter. Parse results are unchanged; all W3C conformance
  suites remain at 100%.
- SIMD/scalar equivalence is now checked by construction (unit test) and
  continuously (differential fuzzing): a divergence in any scanner, on any
  architecture that has an SSE2 path, is a fuzzing finding rather than a latent
  inconsistency. Both differential harnesses ran multi-million-execution
  campaigns with zero divergences after the fix.
- The library gains a `fuzzing` feature. It is fuzz-only: it exposes internal
  scan functions for the harnesses and must never be enabled by a normal
  dependant. Because it is off by default and dependency-free, it does not affect
  the published crate's API or footprint.
- Any future SIMD work — an aarch64 NEON path (foreseen in ADR 0002), AVX2, or a
  new scanner — must ship with a matching differential harness before merge, and
  keep the scalar reference as ground truth.
- Harness sources, seeds, dictionaries, and the tmux/multicore run tooling live
  under `audit/fuzz/` with their own README; the external methodology writeup is
  preserved as `audit/fuzz/FUZZING_PLAN.md`.
