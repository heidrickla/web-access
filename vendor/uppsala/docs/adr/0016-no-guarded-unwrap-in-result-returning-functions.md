# ADR 0016: No `unwrap`/`expect` in functions that return `Result`, even when guarded

## Status

Accepted

## Context

Running the Trail of Bits Semgrep ruleset over the crate flagged two blocking
findings from `panic-in-function-returning-result` in `src/xsd_regex.rs`, in the
recursive-descent pattern parser:

```rust
// parse_alternation
if branches.len() == 1 { Ok(branches.pop().unwrap()) } else { ... }
// parse_sequence
if items.len() == 1 { Ok(items.pop().unwrap()) } else { ... }
```

Both `unwrap`s are unreachable in practice — each is guarded by a `len() == 1`
check, so `pop()` always returns `Some`. They are true positives on *form*, not
on a reachable panic: a function whose signature promises `Result` should route
failure through `Err`, and a reader (or a future edit that weakens the guard)
cannot see the invariant that makes the `unwrap` safe. The XSD regex engine also
parses attacker-controlled schema patterns, so "provably can't panic today" is a
weaker guarantee than "cannot panic by construction".

Two ways to clear the finding: suppress the rule at those lines, or remove the
`unwrap` so the code is panic-free structurally. Suppression hides the pattern
from future scans and normalises guarded `unwrap` in fallible code; the crate's
standing posture is fail-closed and warning-free (see ADR 0013), so a structural
fix is preferred.

## Decision

Functions that return `Result` (or otherwise model failure) do not call
`unwrap`/`expect`, even when a local invariant proves the call safe. Prefer a
construct that cannot panic and expresses the same intent.

For the "collapse a one-element vector, else wrap it" shape in the regex parser,
the fix is to match on the length and use `Vec::remove(0)` on the length-1 arm:

```rust
Ok(match branches.len() {
    1 => branches.remove(0),          // in-bounds by the arm's guard
    _ => RegexNode::Alternation(branches),
})
```

`remove(0)` carries no `unwrap`/`expect`, is in-bounds by the arm it sits in, and
preserves the exact previous behaviour (a single branch/item collapses to itself
instead of being wrapped in an `Alternation`/`Sequence` node; zero items stay an
empty `Sequence`). No suppression comment is added.

This convention applies to library code paths reachable from untrusted input
(parsers, validators, the serializer). Test code (`#[cfg(test)]`, which returns
`()` and where a panic *is* the failure signal) is out of scope and keeps using
`unwrap`.

## Consequences

- The two `panic-in-function-returning-result` findings are resolved
  structurally; a re-scan reports them clean without any inline suppression.
- Behaviour is unchanged: `xsd_regex` unit tests, `xsd_conformance`, and the
  pattern-heavy `w3c_xsts` suite pass byte-for-byte; `clippy -D warnings` stays
  clean.
- The convention is now on record for future contributions: reach for a
  panic-free construct (`match` on the shape, `remove`, `if let`, `?`) rather than
  a guarded `unwrap` in fallible code, and never silence the finding with a
  suppression. This complements the fail-closed hardening posture of ADR 0013.
