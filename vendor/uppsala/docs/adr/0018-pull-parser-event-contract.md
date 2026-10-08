# ADR 0018: Treat the pull parser as the XML event contract

## Status

Accepted

## Context

Uppsala now exposes a pull parser that separates XML token/event parsing from
DOM construction. The public `Parser::parse` API remains the stable DOM entry
point, but internally it builds the document by consuming `PullParser` events
with `document_from_pull`.

That refactor gives callers a lower-allocation API for streaming integrations
and gives the Python bindings a path to build only active subtrees for
`iterparse`. It also changes the shape of parser coverage. Existing DOM tests
exercise most pull-parser logic indirectly because the DOM parser delegates to
the pull parser, but they do not explicitly pin the public event-derived DOM
entry point or the parser-option wiring on that path.

## Decision

`PullParser` is the parser event contract. DOM construction is one consumer of
that contract, and tests must cover both the stable DOM API and the explicit
pull-to-DOM API.

The public `next_event()` API is fused after any parse error: once an error is
returned, later calls return `Ok(None)`. This keeps direct pull-parser consumers
from accidentally looping forever on an unchanged failing cursor state.

Add differential fixture tests that parse the same regression-oriented XML
corpus two ways:

1. `Parser::parse`, representing the stable DOM API.
2. `document_from_pull(input, PullParser::...)`, representing a DOM built from
   the pull event stream.

The comparison checks serialized output, XML declaration metadata, DOCTYPE
metadata, and document-element source ranges. Invalid fixtures are also parsed
through both entry points and must fail with the same error text. The corpus
covers representative existing parser regressions: namespaces, comments, PIs,
CDATA, entity expansion, DOCTYPE preservation and hardening options, depth
limits, duplicate attributes, reserved namespace bindings, and real SAML/Atom
fixtures used by higher-level tests.

When a future parser, serializer, or security regression adds a new XML input,
the minimized input should be added to the pull differential corpus unless the
regression is unrelated to parsing or DOM construction.

Do not retain inactive copies of the old recursive DOM parser loops beside the
pull implementation. Shared token, DTD, entity, and scanner helpers remain in
`parser.rs`, but element/content/prolog DOM construction should have one active
implementation.

## Consequences

- The public pull API is covered directly, not just as an implementation detail
  of `Parser::parse`.
- Parser knobs (`namespace_aware`, `max_depth`, `max_entity_expansion`,
  `forbid_dtd`, and `forbid_entities`) are verified on both paths.
- The tests are differential, not an independent oracle. Since the current DOM
  parser is intentionally implemented on top of the pull parser, a shared bug
  can still pass these tests. W3C conformance, fuzzing, serializer round-trip
  tests, and targeted event-order unit tests remain required.
- The differential corpus is intentionally small enough for normal CI. Large
  performance or resource-exhaustion proofs stay in their existing tests and
  benchmarks, with minimized equivalents used here where possible.
