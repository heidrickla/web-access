# Uppsala Security-Audit PoCs

Each file in this directory is a minimal input that reproduces a finding
in `../../SECURITY_AUDIT.md`. The Rust regression tests in
`../../tests/security_audit.rs` consume these files; the fixed findings now
assert the hardened (fail-closed) behavior, so a green run is the evidence
the bug stays fixed.

Run them with:

```bash
cargo test --test security_audit --no-fail-fast
# process-fatal reproducers are #[ignore]d by default:
cargo test --test security_audit -- --ignored
```

Related regression coverage lives in `../../tests/hardening_regressions.rs`
and `../../tests/security_regressions.rs`, and the corpus-driven suite
`../../tests/security_corpus.rs` (entity-expansion DoS, XXE, round-trip;
populate its inputs with `scripts/fetch_corpus.sh`).

Continuous adversarial coverage of the same surfaces is provided by the
fuzz harnesses in `../fuzz/` — see that README's "Extended corpus" and
"Mapping to SECURITY_AUDIT findings" sections.
