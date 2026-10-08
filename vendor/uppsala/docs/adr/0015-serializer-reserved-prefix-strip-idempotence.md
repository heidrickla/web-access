# ADR 0015: NCName-sanitize the local name when the serializer strips a reserved prefix

## Status

Accepted

## Context

The serializer sanitizes structural names so that programmatic or leniently
parsed input cannot produce non-well-formed or namespace-changing output. Among
these rules, `plan_element_namespaces` (in `src/dom.rs`) strips the reserved
`xml` / `xmlns` prefixes from an element name when they carry no representable
namespace URI: `xml:` would re-parse into the XML namespace and `xmlns:` into the
XMLNS namespace, silently changing the element's namespace, so the planner emits
the **bare local name** instead.

The `fuzz_roundtrip` differential harness (see ADR 0014 and `audit/fuzz`), whose
oracle is that serialization is a one-pass fixpoint — `parse(s).to_xml()` must
equal `parse(parse(s).to_xml()).to_xml()` — produced 20 crash artifacts that all
reduced to a single cause:

- The parser leniently accepts multi-colon names. `<xmlns:xmlns:C/>` parses as an
  element with prefix `xmlns` and local name `xmlns:C` (split at the first
  colon). The local name itself contains a colon.
- When the planner stripped the reserved `xmlns` prefix, it emitted that local
  name verbatim, and the name was written through `safe_xml_qname`, which permits
  a single colon. So the output was `<xmlns:C/>`.
- Re-parsing `<xmlns:C/>` yields a *new* `xmlns`-prefixed element (`xmlns` + `C`),
  which serializes to `<C/>`. Serialization therefore stripped one prefix layer
  per round instead of converging in one pass: `<xmlns:xmlns:C/>` → `<xmlns:C/>`
  → `<C/>`.

The impact is a serializer canonicalization inconsistency: `to_xml()` output is
not a fixed point of parse→serialize. Severity is low — it requires a
namespace-malformed name (a reserved `xmlns`/`xml` prefix, which a conformant
document never uses, combined with an extra colon), there is no memory-safety
issue or markup injection, and the process converges in a bounded number of
passes. But a serializer that renames elements across successive serializations
is a real defect, and for a signature/canonicalization consumer any such
instability is undesirable.

## Decision

When the planner strips a reserved prefix and emits the bare local name,
sanitize that name as an **NCName** rather than letting it be written as a QName.
After a prefix is removed, the remainder is by definition a local name (an
NCName) and must not itself contain a colon. Concretely, the reserved-prefix and
XMLNS-namespace arms of `plan_element_namespaces` now emit
`safe_xml_ncname(local_name)` (which maps any colon-bearing or otherwise invalid
NCName to `_`) for both element and attribute names.

Consequences by input:

- `<xmlns:foo/>` → `<foo/>` (unchanged; `foo` is a valid NCName).
- `<xmlns:xmlns:C/>` → `<_/>` in one pass (the malformed local `xmlns:C`
  collapses to `_`), and `<_/>` is a fixed point.

The parser's leniency toward multi-colon and reserved-prefix names is left as-is;
the fix lives entirely in the serializer, consistent with the existing
`safe_xml_qname` / `safe_xml_ncname` sanitization design (the serializer, not the
parser, is responsible for emitting re-parseable, namespace-stable names).

## Consequences

- `to_xml()` output is now a one-pass fixpoint of parse→serialize for the reserved
  `xml` / `xmlns` prefix family, closing all 20 `fuzz_roundtrip` findings.
- Conformant documents are unaffected: a valid element/attribute local name is
  already a colon-free NCName, so `safe_xml_ncname` returns it unchanged.
  Namespace-malformed names that previously survived a colon collapse to `_`.
- Regression coverage: `ns_reserved_prefix_strip_is_single_pass_idempotent` in
  `tests/serialization_conformance.rs` asserts one-pass idempotence and a
  colon-free emitted name for the stacked-prefix family, alongside the existing
  `ns_xmlns_prefix_*` tests. `fuzz_roundtrip` remains the continuous guard.
- The finding is another example of the oracle-driven value described in ADR
  0014: a fixpoint assertion, not a crash, surfaced a silent serializer bug.
