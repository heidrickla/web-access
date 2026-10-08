# ADR 0012: Opt-in libxml2-compatible lenient datatype validation

## Status

Accepted

## Context

Real-world XSD toolchains are overwhelmingly built on **libxml2** (and, via it,
lxml, pyFF, and most Python/C XML stacks). libxml2 validates a few datatypes more
permissively than the letter of XSD 1.0 Part 2 / RFC 3987. Documents that those
tools accept therefore produce *spurious* datatype errors under a strict
validator, even though every other processor in the ecosystem treats them as
valid.

Two such cases surfaced while bringing the pyFF SAML-metadata schema set up under
uppsala (`swamid-2.0-test.xml`), after the `xs:import` build fix in ADR 0011:

1. **`anyURI` containing a space.** uppsala's only `anyURI` lexical check is
   "reject if the value contains a space" (a space is invalid per RFC 3987).
   libxml2 accepts it. Example: an `mdui:GeolocationHint` value
   `geo:40.6308255004333, 22.959268014038116`.

2. **An `anyURI` attribute whose value contains spaces.** A
   `RoleDescriptor`'s child `idpdisc:DiscoveryResponse` (an
   `IndexedEndpointType`) carries
   `Location="urn:…:SAML:2.0:protocol urn:…:SAML:1.1:protocol http://…/secext"`
   — three space-separated tokens in a *single* `anyURI` attribute. This is
   malformed metadata (a `Location` is one URI), but libxml2 accepts it.

Both cases are the same rule: a single `anyURI` value containing a space.
libxml2's permissive `anyURI` is what makes the document validate.

> **Note — not a list bug.** This value *looks* like SAML's
> `protocolSupportEnumeration` (a `list` of `anyURI`), which initially suggested
> the list typing was being lost across the cross-import `xsi:type` chain. It is
> not: `protocolSupportEnumeration` validates correctly per item everywhere,
> including when a `RoleDescriptor` is substituted via `xsi:type` to a WS-Fed
> type that extends the SAML base across a different imported schema. The failing
> value is a `Location` (`anyURI`), not the list attribute. List validation
> through a cross-import `xsi:type` extension chain is pinned by
> `tests/xsd_conformance.rs::cross_import_xsi_type_list_attribute_validates_per_item`.

## Decision

Add an **opt-in, libxml2-compatible lenient mode** to `XsdValidator`, default
**off** (strict, spec-faithful):

```rust
let mut v = XsdValidator::from_schema_with_base_path(&schema, Some(path))?;
v.set_lenient(true);   // match libxml2's datatype leniency
```

In lenient mode, datatype checks that are stricter than libxml2 are relaxed.
Currently this is scoped to one rule:

- **`anyURI`** accepts a value containing a space.

Mechanically, `lenient` is a field on `XsdValidator` threaded into
`validate_builtin_value`; the `BuiltInType::AnyURI` arm skips the space check when
it is set. Nothing else changes — `set_lenient(true)` does **not** weaken any
other datatype, facet, or structural check (a malformed `xs:int` is still
rejected, etc.).

### Why a mode, not a behaviour change

- Strict validation is correct and is what the W3C XML Schema Test Suite expects;
  uppsala stays 100% on NIST/MS/Sun with the default. Relaxing `anyURI`
  unconditionally would be a spec regression.
- The leniency is explicitly a *bug-compatibility* with libxml2, so it must be a
  deliberate, named opt-in — mirroring the existing
  `set_enforce_qname_length_facets` toggle (ADR 0001).

### Both cases are the same `anyURI` rule

Case 2 is the same rule as case 1: a single `anyURI` value containing a space.
There is no list-typing bug — `protocolSupportEnumeration` (a `list` of `anyURI`)
validates correctly per item, including through cross-import `xsi:type` extension
chains (verified by
`cross_import_xsi_type_list_attribute_validates_per_item`). The space-containing
value that fails is a `Location` (`anyURI`), not the list attribute. So the single
`anyURI`-accepts-spaces relaxation covers the whole corpus.

## Consequences

- pyFF's metadata validates against the composite schema with `set_lenient(true)`:
  `test01.xml` and `swamid-2.0-test.xml` are valid; `test02-invalid.xml` is still
  rejected (12 errors) — leniency does not mask structural errors.
- Default behaviour is unchanged: strict `anyURI`, W3C XSTS still 100%
  (NIST 19217/19217, MS 1212/1212, Sun 199/199).
- Regression coverage in `tests/xsd_conformance.rs`:
  `anyuri_space_strict_rejected_lenient_accepted`,
  `anyuri_multitoken_value_lenient`, and
  `lenient_mode_keeps_other_datatype_checks` (asserting leniency is scoped).
- The mode is a single switch with room to grow: if other libxml2-permissive
  datatype quirks surface, they can be folded under the same `lenient` flag with
  the rationale documented here.
- List validation across cross-import `xsi:type` extension chains is confirmed
  correct (no item-type collapse) and is regression-tested, so no separate
  strict-mode fix is needed.
