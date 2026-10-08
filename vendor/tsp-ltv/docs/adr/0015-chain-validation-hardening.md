# 15. Chain-validation hardening: AIA SSRF, critical extensions, leaf purpose, name constraints, delegated OCSP responders

Date: 2026-06-22

## Status

Accepted

## Context

A Stage-3 review of the X.509 trust/chain, OCSP, CRL, and trust-store paths
found five fail-open / under-enforced behaviours (B1–B5 / M2–M4, M7 in the stack
comparison). Each lets attacker-influenced input weaken a trust decision:

- **B1 — AIA chain-builder SSRF.** `ChainBuilder::fetch_certificate`
  (`ltv/chain.rs`) GETs `caIssuers` URLs taken from the (attacker-influenced)
  certificate under validation, with no scheme allowlist, no resolved-IP
  filtering, and no response-size cap. The CRL fetch path was already hardened
  (ADR-0010); the AIA path was not.
- **B4 / M3 — unrecognized critical extensions ignored.** Chain verification
  never consulted `Extension.critical`, violating RFC 5280 §4.2 ("MUST reject a
  certificate with a critical extension it does not recognize or cannot
  process").
- **B3 / M4 — leaf purpose not bound.** `TrustStore::verify_chain` validated the
  intermediates' CA profile and the anchor, but never the **leaf**'s
  purpose (EKU/keyUsage). A certificate that chains to an anchor but is not
  authorised for the role at hand (e.g. a TLS cert presented as an OCSP-signing
  or timestamping cert) was accepted.
- **M2 — name constraints not enforced.** RFC 5280 §4.2.1.10 `NameConstraints`
  (`2.5.29.30`) was not processed, so a constrained sub-CA was silently
  un-enforced.
- **B2 / M7 — OCSP `id-pkix-ocsp-nocheck` / delegated responder.** The nocheck
  extension was parsed but never consulted; a delegated responder's own
  revocation status was never checked, and the response's `responderID` was not
  bound to the signing certificate.
- **B5 — trust-store load failures swallowed.** `from_pem_directory` did
  `let _ = add_pem_data(...)`, silently shrinking the trust-anchor set when an
  anchor file was malformed.

## Decision

**Shared SSRF helper (`net.rs`).** The SSRF controls originally embedded in
`ltv/crl.rs` (address classifier `is_disallowed_ip`, hardened redirect client,
and pre-egress `validate_fetch_url`) are extracted into a new `crate::net`
module. Both `crl.rs` and `chain.rs` now use the **same** implementation rather
than duplicating it. `fetch_certificate` validates each AIA URL before egress
(scheme allowlist + resolved-IP filtering) and streams the body under a 1 MiB
cap. The residual DNS-rebinding / redirect-to-internal-hostname limitation from
ADR-0010 carries over and is documented in `net.rs`.

**Reject unknown critical extensions.** `verify_chain` now checks every
certificate (leaf, intermediates, and anchor) and rejects any that asserts a
*critical* extension whose OID is not in a fixed recognised set
(basicConstraints, keyUsage, extendedKeyUsage, subjectAltName,
cRLDistributionPoints, authorityInfoAccess, and — only under `ltv` —
nameConstraints). A tsp-only build, which cannot enforce name constraints, keeps
a critical `nameConstraints` **fail-closed** by *not* recognising it.

**Bind the leaf to a purpose.** A new `verify_chain_for_purpose(chain, time,
purpose: CertRole)` runs `validate_extensions_for_role` on `chain[0]`. The
existing `verify_chain` is preserved unchanged (it delegates with no leaf
purpose) so external callers in other crates are unaffected; callers that know
the required role use the new method.

**Name constraints (`name_constraints.rs`).** A real processor for the common
GeneralName types — dNSName, rfc822Name, iPAddress (CIDR), and directoryName
(RDN-prefix) — enforces permitted/excluded subtrees, accumulating constraints
top-down from the anchor. A `NameConstraints` extension constraining a
GeneralName type that is **not** implemented (x400Address, URI, otherName, ...)
is rejected as unsupported — **fail closed**, never silently ignored.

**OCSP responder hardening.** `validate_responder_trust` now binds the responder
certificate to the response's `responderID` (byName subject match / byKeyHash
SHA-1 match) and returns whether the responder's own revocation status must
still be checked. A *delegated* responder (issued by the CA with
`id-kp-OCSPSigning`) **without** `id-pkix-ocsp-nocheck` is reported via the new
`check_revocation_detailed` → `OcspCheckOutcome.delegated_responder`; the async
orchestrator then checks that responder's revocation (bounded by
`max_ocsp_recursion`) and fails closed (`Invalid`) if it is revoked.

**Surface trust-store load failures.** `from_pem_directory` now **fails closed**
on any unreadable/unparseable candidate file, naming the offending file. A new
`from_pem_directory_lenient` returns `(store, skipped)` for explicit best-effort
use, reporting (never silently dropping) the skipped files.

## Consequences

- A crafted certificate can no longer turn the AIA chain-builder into an SSRF
  gadget or force unbounded memory use; the CRL and AIA paths share one audited
  control.
- A certificate asserting an unrecognized critical extension, a leaf used for the
  wrong purpose, a name-constraint violation, a substituted OCSP responder, or a
  revoked delegated responder is now rejected rather than accepted.
- `verify_chain`'s public signature is unchanged (backward compatible); the
  purpose-binding behaviour is opt-in via `verify_chain_for_purpose`.
- Name-constraint enforcement covers the four common GeneralName types; an
  unsupported constraint type is refused rather than bypassed.
- `from_pem_directory` is now fail-closed; operators relying on best-effort
  loading must switch to `from_pem_directory_lenient` and inspect the returned
  skip list.

## Related

- ADR 0010 — CRL fetch hardening (the SSRF controls this ADR generalises).
- ADR 0007 — pathLenConstraint enforcement; ADR 0012 — intermediate CA extension
  validation (the adjacent chain-validation hardening this builds on).
- ADR 0008 — OCSP responder certificate validity (the adjacent responder check
  this extends with responderID binding and nocheck consultation).
