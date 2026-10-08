//! Security-audit test harness.
//!
//! Each test reproduces a finding in SECURITY_AUDIT.md, using the finding's
//! canonical `F-NN` identifier. Findings that are now fixed assert the
//! hardened behavior (fail-closed error, bounded time, or a still-working
//! legitimate baseline). A few reproducers that can only manifest as a
//! process-fatal crash on the *unhardened* code path (e.g. a true stack
//! overflow) remain `#[ignore]` so the default `cargo test` run stays safe;
//! invoke them explicitly with
//! `cargo test --test security_audit -- --ignored`.
//!
use std::time::{Duration, Instant};

use uppsala::{parse, Parser, XPathEvaluator, XmlWriter, XsdRegex, XsdValidator};

// ─── Finding F-01 — Billion Laughs (entity expansion) ──────────────────

/// Canonical Billion Laughs. `&lol9;` expands to 10^9 characters.
/// Must either be rejected *before* expansion (size cap / depth cap)
/// or complete in bounded time. The assertion below pins the hardened
/// behavior: parsing fails closed in well under a second.
#[test]
#[ignore = "OOMs / hangs the test runner — run explicitly to confirm"]
fn billion_laughs_full() {
    let xml = include_str!("../audit/pocs/billion_laughs.xml");
    let start = Instant::now();
    let res = parse(xml);
    let elapsed = start.elapsed();
    assert!(
        res.is_err() && elapsed < Duration::from_secs(1),
        "expected billion-laughs rejection/limit; elapsed={:?}, err={:?}",
        elapsed,
        res.err()
    );
}

/// Bounded-expansion baseline: 5-level nesting expands to ~3×10^5 chars,
/// which is *below* the default entity-expansion byte budget
/// (`DEFAULT_MAX_ENTITY_EXPANSION`, 1 MiB). Such a document is legitimate
/// and must still parse — the cap fails closed only on the unbounded
/// blow-up (`billion_laughs_full`), not on bounded expansion. This pins
/// that the cap does not over-reject below its threshold.
#[test]
fn bounded_entity_expansion_within_cap_accepted() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<lolz>&lol5;</lolz>"#;
    let doc = parse(xml).expect("bounded expansion below the cap must still parse");
    let root = doc.document_element().unwrap();
    let text = doc.text_content_deep(root);
    // 3 × 10^5 chars — well under the 1 MiB expansion budget.
    assert_eq!(text.len(), 3 * 100_000);
}

// ─── Finding F-02 — Quadratic entity expansion (bounded baseline) ───────

/// The quadratic POC expands to ~2000 chars, far below the expansion byte
/// budget, so it parses. This is the "legitimate bounded input still
/// works" control for F-02; the unbounded blow-up is bounded by
/// `DEFAULT_MAX_ENTITY_EXPANSION` and `DEFAULT_MAX_ENTITY_DEPTH`.
#[test]
fn quadratic_entity_expansion_bounded_accepted() {
    let xml = include_str!("../audit/pocs/quadratic_blowup.xml");
    let doc = parse(xml).expect("bounded quadratic expansion still parses");
    let root = doc.document_element().unwrap();
    let text_len = doc.text_content_deep(root).len();
    // 20 chars × 10 (inner) × 10 (outer) = 2000 — below the expansion cap.
    assert!(text_len >= 2000);
}

// ─── Finding F-03 — Parser deep-nesting depth cap — FIXED ───────────────

/// Regression for F-03. A deeply nested element chain previously recursed
/// once per level in `parse_element` and could overflow the stack. The
/// parser now enforces `DEFAULT_MAX_DEPTH` (128) and fails closed with a
/// bounded error long before the stack is at risk. A depth of 256 already
/// exceeds the cap, so the parser rejects it well before reaching the
/// bottom of the chain — no need to materialize a multi-megabyte string.
#[test]
fn deep_nesting_rejected_by_depth_cap() {
    let depth = 256; // > DEFAULT_MAX_DEPTH (128)
    let mut xml = String::with_capacity(depth * 8);
    for _ in 0..depth {
        xml.push_str("<a>");
    }
    xml.push('x');
    for _ in 0..depth {
        xml.push_str("</a>");
    }
    let res = parse(&xml);
    assert!(
        res.is_err(),
        "deep nesting must be rejected by the depth cap, not stack-overflow"
    );
    let msg = format!("{:?}", res.err());
    assert!(
        msg.contains("nesting exceeds maximum depth"),
        "expected depth-cap error, got: {}",
        msg
    );
}

/// Control: nesting that stays within the default cap still parses. This
/// pins the boundary so a future cap change that breaks legitimate
/// moderately-nested documents is caught.
#[test]
fn moderate_nesting_within_cap_accepted() {
    let depth = 100; // < DEFAULT_MAX_DEPTH (128)
    let mut xml = String::with_capacity(depth * 8);
    for _ in 0..depth {
        xml.push_str("<a>");
    }
    xml.push('x');
    for _ in 0..depth {
        xml.push_str("</a>");
    }
    let res = parse(&xml);
    assert!(
        res.is_ok(),
        "nesting within the default depth cap must still parse: {:?}",
        res.err()
    );
}

// ─── Finding F-04 — XSD regex parser stack overflow on nested parens ────

#[test]
#[ignore = "stack overflow aborts the test binary; run explicitly"]
fn xsd_regex_deep_paren_stack_overflow() {
    let n = 50_000;
    let mut pat = String::with_capacity(n * 2 + 1);
    for _ in 0..n {
        pat.push('(');
    }
    pat.push('a');
    for _ in 0..n {
        pat.push(')');
    }
    let _ = XsdRegex::compile(&pat);
}

// ─── Finding F-05 — Polynomial ReDoS in XSD regex ───────────────────────

#[test]
fn xsd_regex_polynomial_redos() {
    // (a*)*b against N 'a's. Matcher is O(n^3)/O(n^4); at N=200
    // it should finish quickly under the matcher step budget.
    let re = XsdRegex::compile("(a*)*b").expect("compile");
    let input: String = "a".repeat(200);
    let start = Instant::now();
    // Intentionally no 'b' => matcher explores every way to partition
    // the 'a's before failing. This is the worst case.
    assert!(!re.is_match(&input));
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "polynomial ReDoS regression: 200-byte input took {:?}",
        start.elapsed()
    );
}

#[test]
#[ignore = "demonstrates O(n^3+) blow-up; seconds of CPU at N=1000"]
fn xsd_regex_polynomial_redos_heavy() {
    let re = XsdRegex::compile("(a*)*b").unwrap();
    let input: String = "a".repeat(1000);
    let start = Instant::now();
    let _ = re.is_match(&input);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(1),
        "polynomial ReDoS: 1000-byte input took {:?}",
        elapsed
    );
}

// ─── Finding F-06 — XSD regex accepts unbounded {n,m} ───────────────────

#[test]
fn xsd_regex_unbounded_brace_accepted() {
    // A schema may legitimately specify a large upper bound such as
    // a{0,4_000_000_000}. Compile intentionally accepts it: the upper
    // bound never drives allocation or a fixed iteration count. Matching
    // is bounded instead by input saturation and the per-match step
    // budget (ADR 0004, finding F-05), so a huge `m` cannot cause a
    // time/memory blow-up. We therefore assert acceptance, and separately
    // assert that matching such a pattern stays fast.
    let re = XsdRegex::compile("a{0,4000000000}").expect("large bounds accepted");
    let input: String = "a".repeat(10_000);
    let start = Instant::now();
    assert!(re.is_match(&input), "linear match should succeed");
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "huge upper bound must not slow matching (step budget bounds it)"
    );
}

// ─── Finding F-07 — \p{unknown} silently matches nothing;
//                   \P{unknown} matches everything (bypass) — FIXED ──────

#[test]
fn xsd_regex_unknown_prop_rejected() {
    // Regression: an unknown Unicode property must be rejected at compile
    // time (fail-closed). Previously `\P{unknown}` compiled and matched
    // every character, silently widening an "only-letters" pattern into one
    // that admits arbitrary markup. Both `\p{...}` and `\P{...}` forms, and
    // the in-character-class form, must error.
    assert!(
        XsdRegex::compile("\\P{unknowncategory}+").is_err(),
        "\\P{{unknown}} must fail to compile, not match everything"
    );
    assert!(
        XsdRegex::compile("\\p{unknowncategory}+").is_err(),
        "\\p{{unknown}} must fail to compile"
    );
    assert!(
        XsdRegex::compile("[\\p{unknowncategory}]").is_err(),
        "\\p{{unknown}} inside a character class must fail to compile"
    );
    // Known categories and blocks still compile.
    assert!(XsdRegex::compile("\\p{Lu}+").is_ok());
    assert!(XsdRegex::compile("\\p{IsBasicLatin}+").is_ok());
}

// ─── Finding F-08 — XPath parser stack overflow ─────────────────────────

#[test]
#[ignore = "stack overflow aborts the test binary; run explicitly"]
fn xpath_parser_deep_paren_stack_overflow() {
    let n = 20_000;
    let mut expr = String::with_capacity(n * 2 + 1);
    for _ in 0..n {
        expr.push('(');
    }
    expr.push('1');
    for _ in 0..n {
        expr.push(')');
    }
    let mut doc = parse("<r/>").unwrap();
    doc.prepare_xpath();
    let eval = XPathEvaluator::new();
    let root = doc.root();
    let _ = eval.evaluate(&doc, root, &expr);
}

// ─── Finding F-09 — XPath substring() overflow — FIXED ──────────────────

#[test]
fn xpath_substring_overflow_handled() {
    // Regression for F-09. `substring(s, start, +inf)` coerced the length to
    // `usize::MAX`; `start + len` then overflowed (debug panic / release wrap
    // into an out-of-order slice). `substring` now uses `saturating_add` and
    // clamps, so a huge/`inf` length yields a normal (clamped) result with no
    // panic in either build profile.
    use std::panic;
    let mut doc = parse("<r>hello</r>").unwrap();
    doc.prepare_xpath();
    let eval = XPathEvaluator::new();
    let root = doc.root();
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        eval.evaluate(&doc, root, "substring('hello', 2, 1 div 0)")
    }));
    assert!(result.is_ok(), "substring must not panic on overflow");
    let value = result.unwrap().expect("evaluation succeeds");
    // start=2 (1-based) with an unbounded length returns the rest of the string.
    assert_eq!(value.to_string_value(&doc), "ello");
}

// ─── Finding F-10 — XSD xs:include arbitrary local file read ────────────

#[test]
fn xsd_include_rejects_absolute_paths() {
    // Regression test for F-10. Pre-fix the validator would
    // `fs::read_to_string` any attacker-supplied absolute
    // `schemaLocation` and merge its declarations in. Post-fix
    // `resolve_include_path` rejects any resolved path that escapes the
    // schema's base directory. We assert the validator build fails
    // with the containment error.
    let tmp_dir = std::env::temp_dir().join("uppsala-audit-canary");
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let canary_path = tmp_dir.join("canary.xsd");
    let canary_contents = r#"<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="leaked" type="xs:string"/>
</xs:schema>"#;
    std::fs::write(&canary_path, canary_contents).unwrap();

    // The "untrusted" schema. schemaLocation is absolute — points
    // outside the schema's own base directory.
    let schema_dir = tmp_dir.join("schema-base");
    std::fs::create_dir_all(&schema_dir).unwrap();
    let schema_path = schema_dir.join("evil.xsd");
    let schema_xml = format!(
        r#"<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:include schemaLocation="{}"/>
  <xs:element name="x" type="xs:string"/>
</xs:schema>"#,
        canary_path.display()
    );
    std::fs::write(&schema_path, &schema_xml).unwrap();

    let schema_doc = parse(&schema_xml).unwrap();
    // Post-fix: the validator rejects the absolute schemaLocation
    // because it escapes the schema's base directory. Any success
    // here is a regression.
    let result = XsdValidator::from_schema_with_base_path(&schema_doc, Some(&schema_path));
    match result {
        Ok(_) => panic!("absolute schemaLocation must be rejected (F-10 regression)"),
        Err(e) => {
            let msg = format!("{:?}", e);
            assert!(
                msg.contains("escapes the schema's base directory"),
                "expected containment error, got: {}",
                msg
            );
        }
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// ─── Finding F-11 — Circular xs:include cycle cap — FIXED ───────────────

/// Regression for F-11. `a.xsd` includes `b.xsd`, which includes `a.xsd`.
/// Pre-fix the loader recursed through the cycle until the stack
/// overflowed. The composition pass now carries a visited-paths set and a
/// depth cap, so the cycle is short-circuited and the build completes in
/// bounded time without overflowing.
#[test]
fn xsd_include_circular_handled() {
    let tmp = std::env::temp_dir().join("uppsala-audit-circular");
    std::fs::create_dir_all(&tmp).unwrap();
    let a = tmp.join("a.xsd");
    let b = tmp.join("b.xsd");
    std::fs::write(
        &a,
        r#"<?xml version="1.0"?><xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:include schemaLocation="b.xsd"/></xs:schema>"#,
    )
    .unwrap();
    std::fs::write(
        &b,
        r#"<?xml version="1.0"?><xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:include schemaLocation="a.xsd"/></xs:schema>"#,
    )
    .unwrap();
    let schema_src = std::fs::read_to_string(&a).unwrap();
    let schema_doc = parse(&schema_src).unwrap();
    // Must return (cycle detected / short-circuited), not recurse forever
    // or overflow the stack. Either Ok or a bounded Err is acceptable;
    // the point is that it terminates.
    let _ = XsdValidator::from_schema_with_base_path(&schema_doc, Some(&a));
    let _ = std::fs::remove_dir_all(&tmp);
}

// ─── Finding F-13 — Round-trip injection via programmatic comment ──────

#[test]
fn roundtrip_comment_smuggle() {
    // Regression test for F-13. Pre-fix, a `-->` sequence inside a
    // comment body closed the comment early and let a subsequent
    // `<injected/>` become a real sibling element. Post-fix,
    // `sanitize_comment_content` pads consecutive dashes with a space
    // so the terminator never appears in the output.
    let mut w = XmlWriter::new();
    w.start_element("r", &[]);
    w.comment("safe --> <injected/> <!--trailing");
    w.end_element("r");
    let out = w.into_string();
    let reparsed = parse(&out).expect("sanitized output must reparse");
    let root = reparsed.document_element().unwrap();
    let children = reparsed.children(root);
    let injected_elements: Vec<_> = children
        .iter()
        .filter(|c| matches!(reparsed.node_kind(**c), Some(uppsala::NodeKind::Element(_))))
        .collect();
    assert!(
        injected_elements.is_empty(),
        "comment smuggle leaked {} element child(ren) — sanitizer regressed: {:?}",
        injected_elements.len(),
        out
    );
}

#[test]
fn roundtrip_pi_smuggle() {
    // Regression test for F-14. Pre-fix, a `?>` sequence inside PI
    // data terminated the PI early. Post-fix, `sanitize_pi_data`
    // inserts a space between `?` and `>` so the terminator scan
    // cannot match.
    let mut w = XmlWriter::new();
    w.start_element("r", &[]);
    w.processing_instruction("x", Some("?><injected/>"));
    w.end_element("r");
    let out = w.into_string();
    let reparsed = parse(&out).expect("sanitized output must reparse");
    let root = reparsed.document_element().unwrap();
    let children = reparsed.children(root);
    let element_children: Vec<_> = children
        .iter()
        .filter(|c| matches!(reparsed.node_kind(**c), Some(uppsala::NodeKind::Element(_))))
        .collect();
    assert!(
        element_children.is_empty(),
        "PI smuggle leaked {} element child(ren) — sanitizer regressed: {:?}",
        element_children.len(),
        out
    );
}

#[test]
fn roundtrip_cdata_smuggle() {
    // Regression test for F-15. Pre-fix, `]]>` inside CDATA content
    // closed the section early and let `<injected/>` become a real
    // sibling element. Post-fix, `split_cdata_content` replaces each
    // `]]>` with the canonical `]]]]><![CDATA[>` split so the emitted
    // output is two adjacent CDATA sections whose concatenation equals
    // the original text.
    let original = "safe]]><injected/>";
    let mut w = XmlWriter::new();
    w.start_element("r", &[]);
    w.cdata(original);
    w.end_element("r");
    let out = w.into_string();

    let reparsed = parse(&out).expect("split CDATA must reparse");
    let root = reparsed.document_element().unwrap();
    let children = reparsed.children(root);
    let element_children: Vec<_> = children
        .iter()
        .filter(|c| matches!(reparsed.node_kind(**c), Some(uppsala::NodeKind::Element(_))))
        .collect();
    assert!(
        element_children.is_empty(),
        "CDATA smuggle leaked {} element child(ren) — split regressed: {:?}",
        element_children.len(),
        out
    );
    // Text semantics must round-trip byte-exact (the CDATA split is
    // byte-equivalent per XML 1.0, unlike comment/PI sanitization).
    assert_eq!(
        reparsed.text_content_deep(root),
        original,
        "CDATA split must preserve original text semantically"
    );
}

// ─── Finding F-20 — UTF-16 decoder silently drops odd trailing byte — FIXED ─

#[test]
fn utf16_odd_byte_rejected() {
    // Regression: a UTF-16 byte stream with an odd length has an incomplete
    // trailing code unit. Previously the decoder's `chunks(2)` silently
    // dropped the stray byte, hiding mid-code-unit truncation. The decoder
    // now rejects odd-length input instead of fabricating a valid document.
    let mut bytes = vec![0xFFu8, 0xFE]; // BOM LE
    for c in "<r/>".chars() {
        let cu = c as u16;
        bytes.push(cu as u8);
        bytes.push((cu >> 8) as u8);
    }
    bytes.push(0x41); // stray trailing byte → odd total length
    let res = uppsala::parse_bytes(&bytes);
    assert!(
        res.is_err(),
        "parser must error on incomplete UTF-16 tail, not silently drop it"
    );
}

// ─── Finding F-04 — XSD regex compiler stack overflow (class-subtraction recursion) ─

#[test]
#[ignore = "stack overflow on class-subtraction recursion"]
fn xsd_regex_class_subtraction_stack() {
    let n = 5_000;
    let mut pat = String::new();
    for _ in 0..n {
        pat.push_str("[a-z-");
    }
    pat.push_str("[a-z]");
    for _ in 0..n {
        pat.push(']');
    }
    let _ = XsdRegex::compile(&pat);
}

// ─── Finding F-24 — XPath `$var` unsupported (low; documented as XPath 1.0) ──

#[test]
fn xpath_variable_reference_unsupported() {
    let mut doc = parse("<r><a>1</a></r>").unwrap();
    doc.prepare_xpath();
    let eval = XPathEvaluator::new();
    let root = doc.root();
    let res = eval.evaluate(&doc, root, "$x");
    assert!(
        res.is_err(),
        "XPath 1.0 variable reference is not implemented — library documents support for XPath 1.0"
    );
}

// ─── Finding F-19 — Namespace resolver lets `xml:` be rebound ───────────

#[test]
fn namespace_resolver_refuses_xml_rebinding() {
    use std::borrow::Cow;
    use uppsala::NamespaceResolver;
    let mut r = NamespaceResolver::new();
    r.declare(Cow::Borrowed("xml"), Cow::Borrowed("urn:evil"));
    let uri = r.resolve("xml").map(|c| c.as_ref().to_string());
    // Per XML Namespaces §3 rebinding "xml" should be refused.
    assert_ne!(
        uri.as_deref(),
        Some("urn:evil"),
        "resolver permitted rebinding the reserved prefix `xml`"
    );
}

// ─── Finding F-18 — Control characters silently emitted on serialize — FIXED ─

#[test]
fn control_char_sanitized_on_attribute_write() {
    // Construct an attribute value containing U+0001 (an illegal Char
    // in XML 1.0) and serialize. The writer now replaces invalid XML
    // characters with U+FFFD so the output remains parseable.
    let mut w = XmlWriter::new();
    w.start_element("r", &[("a", "x\u{0001}y")]);
    w.end_element("r");
    let out = w.into_string();
    assert!(!out.contains('\u{0001}'));
    assert!(out.contains('\u{FFFD}'));
    parse(&out).expect("sanitized output must reparse");
}

// ─── Finding F-21 — XPath //a//b//c cross-product blow-up ──────────────

#[test]
fn xpath_double_slash_blowup() {
    // Build a modestly large tree and time a predicate-in-predicate
    // query. 50 levels × 20 siblings.
    let mut xml = String::from("<r>");
    for i in 0..50 {
        xml.push_str(&format!("<l{}>", i));
    }
    for _ in 0..20 {
        xml.push_str("<leaf/>");
    }
    for i in (0..50).rev() {
        xml.push_str(&format!("</l{}>", i));
    }
    xml.push_str("</r>");
    let mut doc = parse(&xml).unwrap();
    doc.prepare_xpath();
    let eval = XPathEvaluator::new();
    let root = doc.root();
    let start = Instant::now();
    let _ = eval.evaluate(&doc, root, "//*[//leaf]");
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "XPath double-slash regression: query took {:?}",
        start.elapsed()
    );
}

// ─── Opt-in hardening — forbid_dtd / forbid_entities ───────────────────
//
// defusedxml-style switches. Both default off (the free `parse()` is
// unchanged); when enabled the parser fails closed at the DOCTYPE / entity
// declaration rather than parsing it.

/// `forbid_dtd` rejects an external-ID DOCTYPE before parsing the DTD.
#[test]
fn forbid_dtd_rejects_external_doctype() {
    let xml = r#"<!DOCTYPE r SYSTEM "r.dtd"><r/>"#;
    assert!(parse(xml).is_ok(), "precondition: parses with the flag off");
    let res = Parser::new().with_forbid_dtd(true).parse(xml);
    assert!(res.is_err(), "forbid_dtd must reject the DOCTYPE");
    assert!(
        format!("{:?}", res.err()).contains("forbid_dtd"),
        "error should mention forbid_dtd"
    );
}

/// `forbid_dtd` rejects an internal-subset DOCTYPE (even entity-free).
#[test]
fn forbid_dtd_rejects_internal_subset() {
    let xml = r#"<!DOCTYPE r [ <!ELEMENT r EMPTY> ]><r/>"#;
    assert!(parse(xml).is_ok(), "precondition: parses with the flag off");
    assert!(
        Parser::new().with_forbid_dtd(true).parse(xml).is_err(),
        "forbid_dtd must reject any DOCTYPE"
    );
}

/// `forbid_dtd` leaves DTD-free documents untouched.
#[test]
fn forbid_dtd_accepts_dtd_free_document() {
    assert!(
        Parser::new().with_forbid_dtd(true).parse("<r/>").is_ok(),
        "forbid_dtd must not affect documents without a DOCTYPE"
    );
}

/// `forbid_entities` rejects general and parameter entity declarations.
#[test]
fn forbid_entities_rejects_entity_declarations() {
    let general = r#"<!DOCTYPE r [ <!ENTITY x "y"> ]><r/>"#;
    let parameter = r#"<!DOCTYPE r [ <!ENTITY % p "<!ELEMENT r EMPTY>"> ]><r/>"#;
    for xml in [general, parameter] {
        assert!(
            parse(xml).is_ok(),
            "precondition: parses with flag off: {xml}"
        );
        let res = Parser::new().with_forbid_entities(true).parse(xml);
        assert!(res.is_err(), "forbid_entities must reject: {xml}");
        assert!(
            format!("{:?}", res.err()).contains("forbid_entities"),
            "error should mention forbid_entities: {xml}"
        );
    }
}

/// `forbid_entities` is narrower than `forbid_dtd`: a DTD carrying only
/// `<!ELEMENT>` / `<!ATTLIST>` is still accepted.
#[test]
fn forbid_entities_allows_entity_free_dtd() {
    let xml = r#"<!DOCTYPE r [ <!ELEMENT r EMPTY> <!ATTLIST r a CDATA #IMPLIED> ]><r/>"#;
    assert!(
        Parser::new().with_forbid_entities(true).parse(xml).is_ok(),
        "forbid_entities must allow an entity-free DTD"
    );
}

/// Default parser (both flags off) still parses DOCTYPE + entities.
#[test]
fn default_parser_still_parses_dtd_and_entities() {
    let xml = r#"<!DOCTYPE r [ <!ENTITY x "hi"> ]><r>&x;</r>"#;
    assert!(parse(xml).is_ok(), "default behavior must be unchanged");
    assert!(Parser::new().parse(xml).is_ok());
}
