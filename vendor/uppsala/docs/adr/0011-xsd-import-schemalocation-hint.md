# ADR 0011: `xs:import` schemaLocation is a hint — skip unresolvable imports

## Status

Accepted

## Context

A composite schema that pulls a root element's declaration in via `xs:import`
could not be used to validate instances rooted at that element. Building the
composite schema aborted instead.

Concretely (see `xsd_bug.md`): pyFF builds one entry schema
(`schema.xsd`, `targetNamespace="aggregate"`) that imports ~15 schemas (SAML
metadata/assertion, dsig, xenc, ws-fed, mdui, mdrpi, shibmd, atom, xrd, …) and
validates `md:EntityDescriptor` / `md:EntitiesDescriptor` documents. Several of
those imported schemas carry **redundant import hints** whose `schemaLocation`
uppsala cannot resolve — an unsupported URI scheme such as

```
classpath:/schema/saml-schema-metadata-2.0.xsd
http://www.w3.org/2001/xml.xsd
http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd
```

for a namespace that a sibling, resolvable import already supplies.

`process_schema_composition` treated a resolution failure on `xs:import` the
same as on `xs:include`/`xs:redefine`: it propagated the error and failed the
whole build with `Cannot resolve import schemaLocation '…': absolute URI not
supported`. Because the build never completed, the root element declared in the
*resolvable* import (`EntityDescriptor`, from `sstc-saml-schema-metadata-2.0.xsd`)
was never registered, surfacing downstream as `No element declaration found for
'EntityDescriptor'`.

The bug report diagnosed this as "imported global element declarations are not
registered," but `merge_external_declarations` already copies an imported
schema's elements (alongside its types, attributes, groups). The real cause was
one level up: the unresolvable *sibling* import aborted composition before the
resolvable one's declarations could be merged.

## Decision

Treat `xs:import/@schemaLocation` as the **hint** the spec says it is, and skip
an import whose location cannot be resolved rather than aborting the build.

Per XSD 1.0 Part 1 §4.2.3, `schemaLocation` on `xs:import` is advisory: a
processor "is not *required* to" use it and may obtain the imported components by
any means (or not at all). This is unlike `xs:include`/`xs:redefine`, where the
located schema is a mandatory part of the assembled schema. So in the `import`
branch we now skip on *any* resolution failure — unsupported URI scheme, missing
file, or a path outside the base directory:

```rust
let resolved_schema = match resolve_include_path(/* … */, "import") {
    Ok(Some(p)) => p,
    Ok(None) | Err(_) => continue, // hint: ignore an unresolvable import
};
```

 `xs:include`/`xs:redefine` are unchanged: they still treat base-directory escapes and unsupported
 absolute URI schemes as hard errors (ADR 0003 relies on this for the `anyURI_a004`
 FTP-include skip).

Resolution does not parse or build the target, so this only suppresses *location*
failures. A genuinely broken schema that *does* resolve still surfaces its build
error.

## Consequences

- Composite schemas whose root element lives in an imported schema now build and
  validate correctly (pyFF's `schema.xsd` builds; `test01.xml` validates clean,
  `test02-invalid.xml` is rejected). This unblocks pyFF's `validate` pipe.
- Aligns with libxml2/Xerces, which likewise ignore unresolvable import hints
  (the namespace is typically supplied by another import or is unused).
- A redundant import that names a namespace *not* otherwise supplied is silently
  absent; references into it then fail later as ordinary "type/element not found"
  errors, which is the correct XSD outcome for an unavailable import.
- Only an *unresolvable* location is skipped. Once a hint resolves to a real,
  readable file the imported schema is genuinely present, so a malformed (not
  well-formed) or semantically broken target is surfaced as an error, not
  silently dropped.
- Regression coverage in `tests/xsd_conformance.rs`:
  `import_with_unresolvable_hint_is_skipped_and_root_resolves` (a resolvable
  `inner.xsd` declaring the root element plus a `classpath:` import hint that must
  be skipped) and `import_of_resolvable_malformed_schema_errors` (a resolvable but
  non-well-formed import must surface). Both write their fixtures to a tempdir, so
  they always run regardless of the published-crate `test-data/` exclusion.
- ADR 0003 is unaffected: `xs:include` of an unresolvable URI still fails by
  design.

## Out of scope

Two unrelated datatype differences observed while validating real metadata
(`swamid-2.0-test.xml`) are **not** addressed here and are not part of this bug:

- A list-typed attribute (`protocolSupportEnumeration`, `md:anyURIListType`)
  whose space-separated value is validated as a single `anyURI` rather than per
  item.
- An `xs:anyURI` value containing a space (`geo:40.63…, 22.95…`) being rejected,
  where libxml2 is more lenient than RFC 3986.

These belong to datatype/list-facet handling, not schema composition.
