Deep-nesting PoC is generated at test-time rather than stored as a
multi-megabyte file. See tests/security_audit.rs::deep_nesting_parser
and ::deep_nesting_xpath — each builds an input of ~100k levels and
proves the parser recurses without a depth cap (stack overflow aborts
the test binary on Linux with the default 8 MiB stack).
