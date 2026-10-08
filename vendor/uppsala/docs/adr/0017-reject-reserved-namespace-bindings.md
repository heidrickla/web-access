# ADR 0017: Reject reserved namespace bindings at parse time; undeclare the default namespace when stripping reserved element prefixes

## Status

Accepted

## Context

A `fuzz_roundtrip` campaign (oracle: `parse(s).to_xml()` must equal
`parse(parse(s).to_xml()).to_xml()`, see ADR 0014) produced 129 crash
artifacts. After the ADR 0015 fix, 104 still reproduced — and all of them
reduced to a single root-cause family. Minimal reproducer:

```xml
<r xmlns="http://www.w3.org/XML/1998/namespace"><xmlns:c/></r>
out1: <xml:r xmlns="http://www.w3.org/XML/1998/namespace"><c/></xml:r>
out2: <xml:r xmlns="http://www.w3.org/XML/1998/namespace"><xml:c/></xml:r>
```

Two defects combined:

1. **The parser accepted forbidden bindings of the reserved namespaces.**
   Namespaces in XML 1.0 (Third Edition) §3 reserves the XML namespace
   (`http://www.w3.org/XML/1998/namespace`, bound to `xml` and only `xml`,
   never the default) and the XMLNS namespace (`http://www.w3.org/2000/xmlns/`,
   never declarable at all). The parser rejected `xmlns:xmlns=` and `xmlns:xml=`
   bound to a foreign URI, but accepted:
   - `xmlns="http://www.w3.org/XML/1998/namespace"` (and the XMLNS URI) as the
     default namespace;
   - `xmlns:foo="http://www.w3.org/XML/1998/namespace"` (another prefix bound
     to the XML namespace) and `xmlns:foo="http://www.w3.org/2000/xmlns/"`;
   - `xmlns:=` — an empty (non-NCName) declaration prefix, which was silently
     treated as a **default** namespace declaration via
     `strip_prefix("xmlns:")`, and `xmlns:a:b=`, which declared the multi-colon
     prefix `a:b`. Six of the crash inputs reached the forbidden default
     binding through `xmlns:=` alone.

2. **The serializer's reserved-prefix strip arms did not guard against
   default-namespace capture.** When `plan_element_namespaces` (src/dom.rs)
   strips a reserved `xml:`/`xmlns:` element prefix that carries no
   representable namespace (ADR 0015), the emitted bare local name is
   unprefixed and in no namespace — exactly the situation the `(None, None)`
   arm already handles by emitting `xmlns=""` when a non-empty default
   namespace is in scope. The strip arms lacked that undeclaration, so the
   bare name was captured by the in-scope default namespace on re-parse.
   With an ordinary default namespace the bytes happened to be idempotent but
   the element's namespace silently changed; with the (wrongly accepted) XML
   namespace as the default, the second serialize had to re-prefix the element
   as `xml:*` (the XML namespace is representable only through the `xml`
   prefix), breaking the byte-level fixpoint and firing the fuzz oracle.

## Decision

Fix both layers; the parser change is the spec-conformant one and kills the
whole input family, the serializer change keeps the fixpoint guarantee for
programmatically built DOMs.

**Parser (`parse_element`, src/parser.rs):** namespace declarations are now
validated against the §3 reserved-binding constraints:

- `xmlns="…"` must not bind the XML or XMLNS namespace URI;
- the prefix in `xmlns:*` must be a valid NCName (rejects `xmlns:=` and
  `xmlns:a:b=`);
- no prefix other than `xml` may bind the XML namespace URI;
- no prefix may bind the XMLNS namespace URI.

The already-legal redundant declaration `xmlns:xml="…XML/1998/namespace"`
remains accepted. All violations are `XmlError::Namespace` errors, consistent
with the existing `xmlns:xmlns=`/`xmlns:xml=` checks.

**Serializer (`plan_element_namespaces`, src/dom.rs):** the default-namespace
undeclaration logic of the `(None, None)` arm is factored into
`undeclare_default_ns` and applied in the two strip arms as well (reserved
prefix with no URI; XMLNS-namespace name), so a stripped bare name re-parses
into no namespace: `<r xmlns="urn:x"><xmlns:c/></r>` now serializes as
`<r xmlns="urn:x"><c xmlns=""/></r>`. Additionally the stored-declaration
filter drops a binding of the XML namespace to any prefix other than `xml`
(covering DOM-built documents using `declare_namespace`), and
`NamespaceResolver::declare` ignores the same binding for programmatic
resolver construction.

## Consequences

- All 129 `fuzz_roundtrip` artifacts pass: 105 are now rejected at parse time
  (they contain a forbidden reserved binding), 24 round-trip byte-identically.
- The parser is stricter, in line with the spec: documents declaring the XML
  or XMLNS namespace as the default (or binding them to an arbitrary prefix,
  or using a non-NCName declaration prefix) now fail with a namespace error.
  These documents were never namespace-well-formed; conformant parsers
  (libxml2, Xerces) reject them too. W3C conformance is unaffected: xmlconf
  not-wf/valid/invalid and XSTS NIST/MS/Sun all remain at 100%.
- Serializer output for a stripped reserved-prefix element under a non-empty
  default namespace now carries `xmlns=""`, preserving "no namespace" across
  the round-trip instead of silently rebinding the element. This closes a
  *semantic* roundtrip bug the byte-level oracle could not see.
- Regression coverage: `error_reserved_namespace_as_default`,
  `error_xml_namespace_bound_to_other_prefix`,
  `error_xmlns_declaration_prefix_must_be_ncname` and
  `xml_prefix_may_be_declared_with_its_own_uri` in
  `tests/namespace_conformance.rs`;
  `ns_reserved_prefix_strip_undeclares_default_namespace` and
  `ns_default_declaration_of_xml_namespace_is_never_emitted` in
  `tests/serialization_conformance.rs`. `fuzz_roundtrip` remains the
  continuous guard.
