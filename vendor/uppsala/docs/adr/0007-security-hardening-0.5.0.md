# Security Hardening Defaults for 0.5.0

## Status

Accepted.

## Date

2026-06-26

## Context

Uppsala is commonly used on XML that may cross trust boundaries before being
serialized, queried, or validated. A security review found several places where
the library preserved or accepted ambiguous XML state:

- DTD declarations were preserved by default during serialization, which could
  hand an XXE-capable `DOCTYPE` to downstream XML processors.
- Programmatic element and attribute names could be serialized without XML name
  validation.
- Namespace-sensitive parser, XPath, and XSD paths sometimes compared only local
  names or fell back to no-namespace declarations.
- XSD named type references could fail open when resolution failed.
- XPath axis traversal lacked allocation limits.
- DOM tree mutation accepted invalid or cyclic `NodeId` relationships.

A follow-up **differential security review** of the same release was then run and
reproduced several additional issues with compiled proof-of-concept programs.
They cluster into two root causes:

1. **Two existing limits were charged in the wrong place, so they were
   bypassable.** The XSD-regex match-step budget counted one tick per
   `match_node` entry while a single entry could do O(N) allocation work; the
   XPath 1.0 node-visit budget charged node-set *construction* but not the
   O(n·m) node-set *comparison*. Both let an attacker do super-linear work while
   staying under the configured cap.

2. **A handful of residual panics / injection / output-correctness gaps**
   survived the first pass: an unsanitized processing-instruction target, fixed
   byte-index slicing in three datetime validators, a `substring` integer
   overflow, a duplicate-namespace-declaration serialization bug, and a
   deep-linear-entity-chain stack overflow not covered by the byte budget.

A recurring lesson: **a resource limit only works if it is charged where the
cost is actually incurred.**

## Decision

Version 0.5.0 makes the secure behavior the default:

- Parsed `Document::doctype` is still preserved for inspection, but serializers
  omit it by default. Trusted callers can opt in with
  `XmlWriteOptions::with_doctype(true)`.
- DOM and `XmlWriter` serialization replace invalid structural QNames with `_`.
- Namespace-expanded attributes are checked for duplicates after namespace
  resolution.
- XPath 1.0 name tests are namespace-aware and require explicit prefix bindings.
- XPath 1.0 axis/predicate traversal is bounded by configurable defaults.
- XSD root lookup, type resolution, identity constraints, wildcard merging, and
  complex type derivation now fail closed on namespace mismatch, unresolved
  types, malformed temporal values, and derivation cycles.
- Public DOM mutation APIs no-op on invalid handles or cycle-forming moves.

### Differential-review second pass

The follow-up findings are fixed preferring corrections that *preserve behaviour
for legitimate input* (lazy allocation, charging the real cost) over blanket
rejection, and a dedicated regression suite (`tests/hardening_regressions.rs`)
pins each one. Finding labels below match the test function names.

One new limit was added, following ADR 0004's "default constant + per-type
builder" pattern:

| Constant | Value | Applies to | Builder |
|----------|-------|------------|---------|
| `parser::DEFAULT_MAX_ENTITY_DEPTH` | 256 | Entity replacement-text expansion nesting depth | (internal; bounded alongside the byte budget) |

Per-finding decisions:

- **F4 — XSD regex quadratic allocation.** `match_repetition` allocated an
  O(N) `seen` bitmap on entry, before knowing whether the repetition could
  advance. An outer repetition calling it O(N) times made that O(N²) — work the
  per-entry step budget never charged. The bitmap is now allocated **lazily**,
  only on the first productive greedy iteration, so the common
  `a*b*`-over-`aaaa…` shape stays linear and still matches correctly.

- **F5 — XPath 1.0 node-set comparison uncharged.** `=`/`!=` over node-sets is
  an O(n·m) string-value scan. It is now charged against the existing node-visit
  budget (`charge_comparison`, proportional to the operand cardinalities), so a
  comparison built from cheap child-axis operands can no longer run for minutes
  under the cap.

- **F6 — Processing-instruction target injection.** A PI target containing `?>`
  plus markup broke out of PI position. `sanitize_pi_target` now validates the
  target as an XML NCName (collapsing invalid targets to `_`) in addition to
  renaming the reserved `xml` target. Both the `XmlWriter` and DOM serializer
  share the helper.

- **F7 — Deep linear entity chain.** A non-cyclic chain `e0 → e1 → … → eN` with
  a tiny leaf expands to ~1 byte (so the byte budget never trips) yet recurses
  N frames deep. Expansion depth (`seen.len()`) is now capped at
  `DEFAULT_MAX_ENTITY_DEPTH`, failing closed with a normal error.

- **F8 — datetime multibyte panic.** `is_valid_gmonth` / `is_valid_gday` /
  `is_valid_gmonthday` sliced fixed byte ranges after only length checks,
  panicking when a multibyte character straddled a boundary. They now reject
  non-ASCII input up front (these lexical forms are entirely ASCII).

- **F10 — duplicate namespace declarations.** Two distinct invalid prefixes both
  sanitize to `_`, which emitted duplicate `xmlns:_` attributes (not
  well-formed). The serializer now disambiguates colliding prefixes (preserving
  both URIs) and skips an impossible duplicate default-namespace declaration.

- **F11 — `substring()` overflow.** `start + len` overflowed `usize` for
  `inf`/huge length arguments. It now uses `saturating_add` and clamps, so the
  result is the (clamped) substring with no panic in either build profile.

- **F12 — unknown Unicode property/block names.** The 0.5.0 change to reject
  unknown property names at compile time (so `\P{IsTypo}` cannot match every
  character) was reviewed for over-restriction. On audit the block table already
  matches the XSD 1.0 Part 2 Appendix-F **closed** list, so the fail-closed
  rejection is spec-correct, not a regression. This was resolved by
  **documentation only**: `is_known_property_name` and `match_unicode_block` now
  state that the recognized set is the XSD-defined closed list, so a future
  reader does not "loosen" it back into the bypass. No behavioural change.

## Consequences

This is a behavior change for callers that depended on automatic DTD
round-tripping, local-name-only XPath/XSD matching, or permissive invalid
programmatic names. These changes are included in the 0.5.0 release because
they close validation and serialization bypasses in security-sensitive
embeddings. Callers that intentionally round-trip trusted DTDs must opt in
explicitly at serialization time.

For the differential-review second pass:

- F4 and F5 change pathological cases from "slow success" to "fast, clean
  error", and F6/F8/F11 change pathological cases from "panic"/"injection" to a
  clean error or sanitized output. Legitimate input is unaffected — each fix
  ships with a "valid input still works" regression assertion in
  `tests/hardening_regressions.rs`.
- All W3C conformance suites remain at their prior pass rates (XML 100%, XSTS
  NIST 100%, MS 100%, Sun 100%), the library still builds with zero warnings,
  and `tests/hardening_regressions.rs` guards every finding against recurrence.
