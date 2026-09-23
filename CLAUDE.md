# CLAUDE.md

Operating context for `D:\PersonalProjects\web-access`. Estate rules live in
`D:\PersonalProjects\ha-management\CLAUDE.md` and apply here too.

## What this is

Browser-based RDP with the client in the browser as WASM and a proxy that moves bytes without
decoding them. `docs/architecture.md` is the design record and carries the decisions, the settled
ones and the open ones. READ IT BEFORE PROPOSING A DESIGN — five alternatives were considered and
rejected with reasons, and re-proposing one of them wastes a turn.

## Boundaries

- Forge `gitea` only, `git push gitea main`. Private. Not published.
- Upstream is `Devolutions/IronRDP`, Apache-2.0. Reuse the crates; do not vendor a fork without a
  reason written down.
- No credential, host address or estate detail belongs in this repo. It is a general tool, and the
  environment it might be deployed into is not this one.

## Conventions

- Commit subjects are declarative sentences. No conventional-commit prefixes, no attribution
  trailers, no self-attribution.
- LF only.
- Condensed documentation: tables over paragraphs, one fact per sentence, no process narration.
- Record what was OBSERVED. "Not yet tested" goes false silently; date it and say what would change
  it, or write the positive observation instead.

## Traps already paid for

- A limitation list is evidence about a PRODUCT, not about its architecture. Cloudflare's missing
  audio and capped clipboard read exactly like server-side re-encoding and are nothing of the kind;
  the upstream crates implement both. See the correction in `docs/architecture.md`.
- Session recording and a non-decoding proxy are mutually exclusive. If recording becomes a
  requirement, the architecture reopens rather than the proxy growing a feature.
