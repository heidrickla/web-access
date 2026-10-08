# ADR 0013: Fail-closed XML stack hardening for 0.7.1

## Status

Accepted

## Context

The 0.7.0 release added the first public XSLT engine and opt-in EXSLT support on
top of the existing parser, DOM, XPath, and XSD validator. A follow-up security
scan of the repository and its downstream `bergshamra` / `gamlastan` usage
identified several places where malformed or adversarial XML could be accepted
more permissively than intended:

- XSD element and attribute references could lose namespace precision or, for
  missing element declarations, fall back to unconstrained validation.
- Some XSD facets were interpreted with unsafe string shortcuts: temporal values
  were compared lexically, invalid pattern facets were skipped, string
  enumerations could be date/time-normalized, and unbound `xs:QName` prefixes
  were accepted.
- Identity-constraint fields that selected multiple nodes were reduced to one
  value instead of failing the constraint.
- DTD content-model nesting used parser recursion without sharing the parser's
  public depth cap.
- XSLT constructors and opt-in EXSLT functions could turn data into markup or
  allocate caller-selected output.

These behaviours are dangerous because downstream callers often treat successful
schema validation or transformation as a trust boundary. Accepting unexpected
structure at this layer can make policy checks in downstream applications reason
about a different document than the one an attacker supplied.

## Decision

Adopt a fail-closed hardening rule for XML security boundaries:

- Missing schema declarations are validation errors, not `anyType` fallbacks.
- Attribute declarations, attribute wildcards, identity constraints, and QName
  values compare expanded names, including namespace URIs.
- Invalid schema facets are validation errors.
- Date/time facets are compared as normalized temporal values when the base type
  is temporal, and non-temporal enumerations keep ordinary lexical comparison.
  Temporal comparisons fail closed when either operand (including a raw facet
  bound such as `minInclusive`/`maxInclusive`) is out of range.
- Parser-controlled recursion limits also apply to DTD content models.
- XSLT-generated comments and processing instructions reject data that cannot be
  represented safely as those node kinds.
- Opt-in EXSLT string padding has a fixed output cap.

This keeps the library strict by default. The existing `XsdValidator::set_lenient`
mode from ADR 0012 remains narrowly scoped to libxml2-compatible `xs:anyURI`
space handling and does not weaken these security checks.

## Consequences

- Some documents that were previously accepted because of unresolved imports,
  malformed schema facets, unbound QName prefixes, or ambiguous identity fields
  now produce validation errors.
- XSLT stylesheets that attempt to construct invalid comments or processing
  instructions now return `XmlError` instead of serializing unsafe XML.
- Extremely large EXSLT `str:padding()` calls now return an XPath error once the
  requested length exceeds the cap.
- Regression coverage for these behaviours lives in
  `tests/security_regressions.rs` and exercises the public parser, XSD, XSLT,
  and EXSLT APIs.
