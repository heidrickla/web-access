//! Security regression coverage for hardening shipped in the 0.5.0 cycle.
//!
//! These tests intentionally favor small, hand-written inputs over large
//! conformance fixtures. Each case captures a previously risky behavior and
//! documents the fail-closed outcome expected from the public API.

use std::borrow::Cow;
use std::fs;
use std::path::PathBuf;

use uppsala::{
    parse, parse_bytes, transform, Document, NodeId, Parser, PullParser, QName, Stylesheet,
    XPathEvaluator, XmlWriter, XsdValidator,
};

fn validate(schema: &str, instance: &str) -> Vec<String> {
    // Keep XSD assertions compact by returning display strings rather than
    // leaking validator internals into each test.
    let schema_doc = parse(schema).expect("parse schema");
    let validator = XsdValidator::from_schema(&schema_doc).expect("build validator");
    let doc = parse(instance).expect("parse instance");
    validator
        .validate(&doc)
        .into_iter()
        .map(|e| e.to_string())
        .collect()
}

fn transform_exslt(xslt: &str, xml: &str) -> uppsala::XmlResult<String> {
    let style_doc = Parser::new().parse(xslt)?;
    let stylesheet = Stylesheet::compile(&style_doc)?.with_exslt(true);
    let mut source = Parser::new().parse(xml)?;
    source.prepare_xpath();
    stylesheet.transform(&source)
}

fn mkdir_unique(label: &str) -> PathBuf {
    // XSD import/include tests need a real base path; use a process-unique
    // directory so parallel test runs do not collide.
    let dir = std::env::temp_dir().join(format!(
        "uppsala-security-{}-{}-{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

#[test]
fn parser_rejects_duplicate_expanded_attributes() {
    // Namespace-aware XML forbids duplicate attributes after expansion, even
    // when the lexical prefixes differ. Accepting both would let the same
    // logical attribute carry conflicting values.
    let err = parse(r#"<r xmlns:a="urn:x" xmlns:b="urn:x" a:id="first" b:id="second"/>"#)
        .expect_err("duplicate expanded attributes must be rejected");
    assert!(err.to_string().contains("Duplicate attribute"));
}

#[test]
fn pull_next_event_fuses_after_direct_error() {
    let mut parser = PullParser::new("<r></x><!--ok-->");
    assert!(parser.next_event().unwrap().is_some());
    let err = parser
        .next_event()
        .expect_err("mismatched end tag must fail");
    assert!(err.to_string().contains("Mismatched end tag"));
    assert!(
        parser.next_event().unwrap().is_none(),
        "direct next_event must fuse after an error"
    );

    let mut forbidden =
        PullParser::new(r#"<!DOCTYPE r [<!ENTITY e "x">]><r/>"#).with_forbid_dtd(true);
    let err = forbidden
        .next_event()
        .expect_err("forbid_dtd must reject DOCTYPE");
    assert!(err
        .to_string()
        .contains("DOCTYPE declarations are not allowed"));
    assert!(
        forbidden.next_event().unwrap().is_none(),
        "forbid_dtd errors must not repeat forever"
    );
}

#[test]
fn xslt_computed_element_name_rejects_markup_injection() {
    let xslt = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="xml" omit-xml-declaration="yes"/>
  <xsl:template match="/"><out><xsl:element name="{/r/@n}"/></out></xsl:template>
</xsl:stylesheet>"#;
    let err = transform(xslt, r#"<r n="a/&gt;&lt;evil/&gt;&lt;a"/>"#)
        .expect_err("computed element name must be a QName");
    assert!(err.to_string().contains("valid QName"));
}

#[test]
fn xslt_computed_attribute_name_rejects_markup_injection() {
    let xslt = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="xml" omit-xml-declaration="yes"/>
  <xsl:template match="/"><out><xsl:attribute name="{/r/@n}">v</xsl:attribute></out></xsl:template>
</xsl:stylesheet>"#;
    let err = transform(xslt, r#"<r n="a=&quot;x&quot; injected"/>"#)
        .expect_err("computed attribute name must be a QName");
    assert!(err.to_string().contains("valid QName"));
}

#[test]
fn xpath_public_evaluate_rejects_trailing_tokens() {
    let doc = parse("<r><a/></r>").unwrap();
    let root = doc.root();
    for expr in ["1 trailing", "1 + 2 garbage", "/r/a ]"] {
        let err = XPathEvaluator::new()
            .evaluate(&doc, root, expr)
            .expect_err("trailing XPath tokens must be rejected");
        assert!(
            err.to_string().contains("Unexpected trailing tokens"),
            "{expr:?} produced {err}"
        );
    }
}

#[test]
fn xpath_flat_operator_chains_observe_depth_limit() {
    let doc = parse("<r/>").unwrap();
    let root = doc.root();

    XPathEvaluator::new()
        .with_max_depth(1)
        .evaluate(&doc, root, "1 + 2")
        .expect("one binary operator fits depth 1");

    let expr = ["1"; 10].join(" + ");
    let err = XPathEvaluator::new()
        .with_max_depth(4)
        .evaluate(&doc, root, &expr)
        .expect_err("flat binary chain must count against max_depth");
    assert!(err
        .to_string()
        .contains("XPath expression nesting exceeds maximum depth of 4"));
}

#[test]
fn parse_bytes_normalizes_declared_encoding_for_string_output() {
    let src = r#"<?xml version="1.0" encoding="UTF-16"?><doc>plain</doc>"#;
    let doc = parse_bytes(src.as_bytes()).expect("detected UTF-8 bytes parse");
    assert_eq!(
        doc.to_xml(),
        r#"<?xml version="1.0" encoding="UTF-8"?><doc>plain</doc>"#
    );
}

#[test]
fn writer_sanitizes_structural_names() {
    // Programmatic writer callers can pass arbitrary strings as element and
    // attribute names. Invalid structural names are collapsed to a safe QName
    // instead of being emitted verbatim into markup position.
    let mut writer = XmlWriter::new();
    writer.start_element("bad name", &[("bad attr", "value")]);
    writer.end_element("bad name");
    let output = writer.into_string();

    assert_eq!(output, r#"<_ _="value"></_>"#);
    parse(&output).expect("sanitized writer output must reparse");
}

#[test]
fn writer_disambiguates_sanitized_attribute_collisions() {
    // Distinct invalid names can sanitize to the same fallback `_`. The writer
    // must make later names unique so the output remains well-formed XML.
    let mut writer = XmlWriter::new();
    writer.start_element(
        "r",
        &[("bad attr", "one"), ("bad\tattr", "two"), ("_", "three")],
    );
    writer.end_element("r");
    let output = writer.into_string();

    assert_eq!(output, r#"<r _="one" __1="two" __2="three"></r>"#);
    parse(&output).expect("collision-disambiguated writer output must reparse");
}

#[test]
fn dom_serializer_sanitizes_programmatic_names() {
    // The DOM path has the same structural-name threat model as XmlWriter:
    // names constructed in memory must not be able to break serialized XML.
    let mut doc = Document::new();
    let root = doc.root();
    let elem = doc.create_element(QName::local("bad name"));
    doc.append_child(root, elem);
    doc.element_mut(elem)
        .unwrap()
        .set_attribute(QName::local("bad attr"), Cow::Borrowed("value"));

    let output = doc.to_xml();
    assert_eq!(output, r#"<_ _="value"/>"#);
    parse(&output).expect("sanitized DOM output must reparse");
}

#[test]
fn dom_serializer_disambiguates_sanitized_attribute_collisions() {
    // DOM serialization also needs collision handling after sanitization,
    // because programmatic attributes can contain arbitrary invalid QNames.
    let mut doc = Document::new();
    let root = doc.root();
    let elem = doc.create_element(QName::local("r"));
    doc.append_child(root, elem);
    let elem = doc.element_mut(elem).unwrap();
    elem.set_attribute(QName::local("bad attr"), Cow::Borrowed("one"));
    elem.set_attribute(QName::local("bad\tattr"), Cow::Borrowed("two"));
    elem.set_attribute(QName::local("_"), Cow::Borrowed("three"));

    let output = doc.to_xml();
    assert_eq!(output, r#"<r _="one" __1="two" __2="three"/>"#);
    parse(&output).expect("collision-disambiguated DOM output must reparse");
}

#[test]
fn parse_bytes_rejects_odd_utf16_tail() {
    // A UTF-16 byte stream is a sequence of 16-bit code units. A trailing
    // orphan byte means the input is truncated and must not be silently
    // discarded by the decoder.
    let mut le = vec![0xFF, 0xFE];
    for code_unit in "<r/>".encode_utf16() {
        le.extend_from_slice(&code_unit.to_le_bytes());
    }
    le.push(0x41);
    assert!(uppsala::parse_bytes(&le).is_err());

    let mut be = vec![0xFE, 0xFF];
    for code_unit in "<r/>".encode_utf16() {
        be.extend_from_slice(&code_unit.to_be_bytes());
    }
    be.push(0x41);
    assert!(uppsala::parse_bytes(&be).is_err());
}

#[test]
fn doctype_is_omitted_unless_explicitly_requested() {
    // Parsed DOCTYPE declarations are preserved for callers that need them,
    // but serialization omits them by default to avoid handing DTDs to
    // downstream processors unintentionally.
    let xml = r#"<?xml version="1.0"?><!DOCTYPE root SYSTEM "root.dtd"><root/>"#;
    let doc = parse(xml).unwrap();

    assert_eq!(doc.to_xml(), r#"<?xml version="1.0"?><root/>"#);
    let opts = uppsala::XmlWriteOptions::compact().with_doctype(true);
    assert_eq!(doc.to_xml_with_options(&opts), xml);
}

#[test]
fn dom_mutation_rejects_invalid_and_cyclic_node_ids() {
    // Public mutation APIs accept NodeId values, so they must ignore invalid
    // IDs and ancestry cycles instead of corrupting the arena links.
    let mut doc = Document::new();
    let root = doc.root();
    let a = doc.create_element(QName::local("a"));
    let b = doc.create_element(QName::local("b"));
    doc.append_child(root, a);
    doc.append_child(a, b);

    doc.append_child(b, a);
    assert_eq!(doc.parent(a), Some(root));
    assert_eq!(doc.parent(b), Some(a));

    doc.append_child(NodeId::new(99_999), a);
    doc.insert_before(root, NodeId::new(88_888), a);
    doc.replace_child(root, NodeId::new(77_777), a);

    assert_eq!(doc.parent(a), Some(root));
    assert_eq!(doc.children(root), vec![a]);
}

#[test]
fn xpath_node_sets_follow_mutated_document_order() {
    // Arena allocation order is not necessarily document order after DOM
    // mutation. XPath node-sets must follow the current tree links.
    let mut doc = parse("<root><a/><b/><c/></root>").unwrap();
    let root = doc.document_element().unwrap();
    let children = doc.children(root);
    let a = children[0];
    let c = children[2];
    doc.insert_before(root, c, a);

    let eval = XPathEvaluator::new();
    let nodes = eval.select_nodes(&doc, root, "*").unwrap();
    let names: Vec<&str> = nodes
        .iter()
        .map(|&node| doc.element(node).unwrap().name.local_name.as_ref())
        .collect();
    assert_eq!(names, vec!["c", "a", "b"]);

    let nodes = eval.select_nodes(&doc, root, "a | b | c").unwrap();
    let names: Vec<&str> = nodes
        .iter()
        .map(|&node| doc.element(node).unwrap().name.local_name.as_ref())
        .collect();
    assert_eq!(names, vec!["c", "a", "b"]);
}

#[test]
fn xpath_name_tests_are_namespace_aware() {
    // XPath prefixes are expression bindings, not document prefix text. This
    // verifies unprefixed tests match only no-namespace nodes and unbound
    // prefixes fail closed.
    let doc = parse(r#"<r xmlns:a="urn:a"><a:item/><item/></r>"#).unwrap();
    let root = doc.document_element().unwrap();

    let eval = XPathEvaluator::new();
    let unprefixed = eval.select_nodes(&doc, root, "item").unwrap();
    assert_eq!(unprefixed.len(), 1);
    assert!(doc
        .element(unprefixed[0])
        .unwrap()
        .name
        .namespace_uri
        .is_none());

    let unbound = eval.select_nodes(&doc, root, "a:item").unwrap();
    assert!(unbound.is_empty());

    let mut bound = XPathEvaluator::new();
    bound.add_namespace("a", "urn:a");
    let prefixed = bound.select_nodes(&doc, root, "a:item").unwrap();
    assert_eq!(prefixed.len(), 1);
    assert_eq!(
        doc.element(prefixed[0])
            .unwrap()
            .name
            .namespace_uri
            .as_deref(),
        Some("urn:a")
    );
}

#[test]
fn xpath_axis_expansion_is_budgeted() {
    // Descendant-style axes can expand over the entire DOM. A low visit budget
    // must stop expansion with a stable diagnostic, while a normal budget still
    // returns the expected nodes.
    let xml = "<r><a><b/><b/><b/><b/></a></r>";
    let doc = parse(xml).unwrap();
    let root = doc.root();

    let err = XPathEvaluator::new()
        .with_max_node_visits(2)
        .select_nodes(&doc, root, "//b")
        .expect_err("low node visit budget must stop expansion");
    assert!(err.to_string().contains("maximum node visit budget of 2"));

    let nodes = XPathEvaluator::new()
        .with_max_node_visits(100)
        .select_nodes(&doc, root, "//b")
        .unwrap();
    assert_eq!(nodes.len(), 4);
}

#[test]
fn xpath_axis_budget_is_not_double_charged_after_name_test() {
    // Axis traversal already charges returned nodes. A matching name test must
    // not charge the same node again or a one-node child lookup with budget 1
    // would fail.
    let doc = parse("<r><a/></r>").unwrap();
    let root = doc.document_element().unwrap();

    let nodes = XPathEvaluator::new()
        .with_max_node_visits(1)
        .select_nodes(&doc, root, "a")
        .unwrap();
    assert_eq!(nodes.len(), 1);

    let err = XPathEvaluator::new()
        .with_max_node_visits(0)
        .select_nodes(&doc, root, "a")
        .expect_err("child axis must still charge returned nodes");
    assert!(err.to_string().contains("maximum node visit budget of 0"));
}

#[test]
fn xpath_predicate_budget_charges_candidates_once() {
    // Predicate filtering visits each candidate once. Kept nodes are a subset
    // of those candidates and must not be charged a second time.
    let doc = parse("<r><a/><b/></r>").unwrap();
    let root = doc.document_element().unwrap();

    let nodes = XPathEvaluator::new()
        .with_max_node_visits(4)
        .select_nodes(&doc, root, "*[1]")
        .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(doc.element(nodes[0]).unwrap().name.local_name, "a");

    let err = XPathEvaluator::new()
        .with_max_node_visits(3)
        .select_nodes(&doc, root, "*[1]")
        .expect_err("predicate candidates must still be budgeted");
    assert!(err.to_string().contains("maximum node visit budget of 3"));
}

#[test]
fn xpath_id_function_scan_is_budgeted() {
    // id() performs a document-wide lookup. It must consume the same visit
    // budget as axis expansion so callers can bound adversarial lookups.
    let mut xml = String::from("<r>");
    for i in 0..64 {
        xml.push_str(&format!(r#"<item id="item-{i}"/>"#));
    }
    xml.push_str(r#"<item id="target"/></r>"#);

    let doc = parse(&xml).unwrap();
    let root = doc.root();

    let err = XPathEvaluator::new()
        .with_max_node_visits(0)
        .select_nodes(&doc, root, "id('target')")
        .expect_err("low node visit budget must stop id() expansion");
    assert!(err.to_string().contains("maximum node visit budget of 0"));

    let nodes = XPathEvaluator::new()
        .with_max_node_visits(100)
        .select_nodes(&doc, root, "id('target')")
        .unwrap();
    assert_eq!(nodes.len(), 1);
}

#[test]
fn xpath_id_function_handles_deep_programmatic_dom() {
    // id() scans the whole document. It must use heap-backed traversal too,
    // because callers can build deeper DOMs than the parser accepts.
    let mut doc = Document::new();
    let mut parent = doc.root();
    for _ in 0..4096 {
        let child = doc.create_element(QName::local("n"));
        doc.append_child(parent, child);
        parent = child;
    }
    let leaf = doc.create_element(QName::local("leaf"));
    doc.element_mut(leaf)
        .unwrap()
        .set_attribute(QName::local("id"), Cow::Borrowed("target"));
    doc.append_child(parent, leaf);

    let nodes = XPathEvaluator::new()
        .with_max_node_visits(10_000)
        .select_nodes(&doc, doc.root(), "id('target')")
        .unwrap();
    assert_eq!(nodes, vec![leaf]);

    let err = XPathEvaluator::new()
        .with_max_node_visits(32)
        .select_nodes(&doc, doc.root(), "id('target')")
        .expect_err("deep id() traversal must remain budgeted");
    assert!(err.to_string().contains("maximum node visit budget of 32"));
}

#[test]
fn xpath_descendant_collection_handles_deep_programmatic_dom() {
    // Programmatic DOM construction can exceed parser depth caps. Descendant
    // axes must use heap-backed traversal so a deep chain is still budgeted.
    let mut doc = Document::new();
    let mut parent = doc.root();
    for _ in 0..4096 {
        let child = doc.create_element(QName::local("n"));
        doc.append_child(parent, child);
        parent = child;
    }
    let leaf = doc.create_element(QName::local("leaf"));
    doc.append_child(parent, leaf);

    let nodes = XPathEvaluator::new()
        .with_max_node_visits(20_000)
        .select_nodes(&doc, doc.root(), "//leaf")
        .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0], leaf);

    let err = XPathEvaluator::new()
        .with_max_node_visits(32)
        .select_nodes(&doc, doc.root(), "//leaf")
        .expect_err("deep descendant traversal must remain budgeted");
    assert!(err.to_string().contains("maximum node visit budget of 32"));
}

#[test]
fn serializers_replace_invalid_xml_characters() {
    let mut writer = XmlWriter::new();
    writer.start_element("r", &[("a", "x\u{0001}y")]);
    writer.text("t\u{0000}u");
    writer.comment("c\u{0008}d");
    writer.processing_instruction("p", Some("q\u{000C}r"));
    writer.cdata("z\u{000B}w");
    writer.end_element("r");
    let xml = writer.into_string();

    assert!(!xml.contains('\u{0000}'));
    assert!(!xml.contains('\u{0001}'));
    assert!(!xml.contains('\u{0008}'));
    assert!(!xml.contains('\u{000B}'));
    assert!(!xml.contains('\u{000C}'));
    assert!(xml.contains('\u{FFFD}'));
    parse(&xml).expect("sanitized writer output must reparse");

    let mut doc = Document::new();
    let root = doc.root();
    let elem = doc.create_element(QName::local("r"));
    doc.append_child(root, elem);
    doc.element_mut(elem)
        .unwrap()
        .set_attribute(QName::local("a"), Cow::Borrowed("x\u{0001}y"));
    let text = doc.create_text("t\u{0000}u");
    doc.append_child(elem, text);
    let output = doc.to_xml();

    assert!(!output.contains('\u{0000}'));
    assert!(!output.contains('\u{0001}'));
    assert!(output.contains('\u{FFFD}'));
    parse(&output).expect("sanitized DOM output must reparse");
}

#[test]
fn xsd_rejects_malformed_time_and_datetime_values() {
    // Timezone parsing must reject invalid offsets and malformed Unicode input
    // as validation errors. The non-ASCII cases exercise byte-boundary safety.
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="t" type="xs:time"/>
  <xs:element name="dt" type="xs:dateTime"/>
</xs:schema>"#;

    assert!(validate(schema, "<t>23:59:59Z</t>").is_empty());
    assert!(!validate(schema, "<t>12:00:00:99</t>").is_empty());
    assert!(!validate(schema, "<t>12:00:00+99:00</t>").is_empty());
    assert!(!validate(schema, "<t>24:00:01</t>").is_empty());
    assert!(!validate(schema, "<t>12:00:0é0+000</t>").is_empty());
    assert!(!validate(schema, "<dt>2024-01-01T12:00:00+99:00</dt>").is_empty());
    assert!(!validate(schema, "<dt>2024-01-01T12:00:0é0+000</dt>").is_empty());
}

#[test]
fn xsd_datetime_facet_comparison_fails_closed_on_invalid_bounds() {
    // Facet values (minInclusive/maxInclusive) are stored as raw strings and are
    // not otherwise range-checked. A lexically-parseable but out-of-range bound
    // (month 99, hour 99) must not yield a comparable ordering that silently
    // accepts an instance value; the comparison must fail closed.
    let dt_schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="dt">
    <xs:simpleType>
      <xs:restriction base="xs:dateTime">
        <xs:maxInclusive value="2024-99-01T99:00:00Z"/>
      </xs:restriction>
    </xs:simpleType>
  </xs:element>
</xs:schema>"#;
    assert!(
        !validate(dt_schema, "<dt>2024-06-01T12:00:00Z</dt>").is_empty(),
        "invalid dateTime facet bound must fail closed"
    );

    let time_schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="t">
    <xs:simpleType>
      <xs:restriction base="xs:time">
        <xs:maxInclusive value="99:99:99Z"/>
      </xs:restriction>
    </xs:simpleType>
  </xs:element>
</xs:schema>"#;
    assert!(
        !validate(time_schema, "<t>12:00:00Z</t>").is_empty(),
        "invalid time facet bound must fail closed"
    );
}

#[test]
fn xsd_date_like_types_reject_out_of_range_timezone_offsets() {
    // Date-like XSD types use the same timezone range as xs:time/dateTime:
    // offsets are limited to +/-14:00 and minutes must be 00-59.
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="date" type="xs:date"/>
  <xs:element name="gy" type="xs:gYear"/>
  <xs:element name="gym" type="xs:gYearMonth"/>
  <xs:element name="gm" type="xs:gMonth"/>
  <xs:element name="gmd" type="xs:gMonthDay"/>
  <xs:element name="gd" type="xs:gDay"/>
</xs:schema>"#;

    for invalid in [
        "<date>2024-01-01+99:99</date>",
        "<gy>2024+99:99</gy>",
        "<gym>2024-01+99:99</gym>",
        "<gm>--01+99:99</gm>",
        "<gmd>--01-01+99:99</gmd>",
        "<gd>---01+99:99</gd>",
        "<date>2024-01-01+14:01</date>",
        "<gy>2024+14:01</gy>",
        "<gym>2024-01+14:01</gym>",
        "<gm>--01+14:01</gm>",
        "<gmd>--01-01+14:01</gmd>",
        "<gd>---01+14:01</gd>",
    ] {
        let errors = validate(schema, invalid);
        assert!(!errors.is_empty(), "expected {invalid} to be invalid");
    }

    for valid in [
        "<date>2024-01-01+14:00</date>",
        "<gy>2024+14:00</gy>",
        "<gym>2024-01+14:00</gym>",
        "<gm>--01+14:00</gm>",
        "<gmd>--01-01+14:00</gmd>",
        "<gd>---01+14:00</gd>",
    ] {
        let errors = validate(schema, valid);
        assert!(
            errors.is_empty(),
            "expected {valid} to be valid, got {errors:?}"
        );
    }
}

#[test]
fn namespaced_root_does_not_fall_back_to_no_namespace_declaration() {
    // A no-namespace declaration must not validate a namespaced document root.
    // Falling back by local name would accept documents outside the schema's
    // declared namespace.
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="root" type="xs:string"/>
</xs:schema>"#;

    let errors = validate(schema, r#"<x:root xmlns:x="urn:x">ok</x:root>"#);
    assert!(
        errors.iter().any(|e| e.contains("No element declaration")),
        "expected no-declaration error, got {errors:?}"
    );
}

#[test]
fn xsd_duplicate_model_groups_fail_before_recursive_expansion() {
    // Fuzz found that repeatedly redefining the same top-level model group with
    // refs to the previous definition caused exponential Particle cloning during
    // schema build. Duplicate top-level group names are invalid, so fail before
    // parsing the replacement body.
    let mut schema = String::from(
        r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:group name="name">
    <xs:choice>
      <xs:element name="leaf" type="xs:string"/>
    </xs:choice>
  </xs:group>
"#,
    );
    for _ in 0..24 {
        schema.push_str(
            r#"  <xs:group name="name">
    <xs:choice>
      <xs:group ref="name"/>
      <xs:group ref="name"/>
      <xs:group ref="name"/>
    </xs:choice>
  </xs:group>
"#,
        );
    }
    schema.push_str("</xs:schema>");

    let schema_doc = parse(&schema).expect("parse schema");
    let err = match XsdValidator::from_schema(&schema_doc) {
        Ok(_) => panic!("duplicate model groups must fail closed"),
        Err(err) => err,
    };
    assert!(err
        .to_string()
        .contains("Duplicate model group definition: name"));
}

#[test]
fn xsd_duplicate_attribute_groups_fail_closed() {
    // The same overwrite pattern applies to top-level attribute groups. Reject
    // duplicates instead of replacing an earlier definition after it may have
    // been referenced by later schema components.
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:attributeGroup name="attrs">
    <xs:attribute name="a" type="xs:string"/>
  </xs:attributeGroup>
  <xs:attributeGroup name="attrs">
    <xs:attribute name="b" type="xs:string"/>
  </xs:attributeGroup>
</xs:schema>"#;

    let schema_doc = parse(schema).expect("parse schema");
    let err = match XsdValidator::from_schema(&schema_doc) {
        Ok(_) => panic!("duplicate attribute groups must fail closed"),
        Err(err) => err,
    };
    assert!(err
        .to_string()
        .contains("Duplicate attributeGroup definition: attrs"));
}

#[test]
fn prefixed_xsd_type_qnames_resolve_to_imported_namespace() {
    // Prefixed `type` QNames in schemas are resolved through in-scope namespace
    // declarations. This keeps imported types precise and prevents local-name
    // fallback from masking invalid values.
    let dir = mkdir_unique("prefixed-type");

    let inner = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           targetNamespace="urn:inner">
  <xs:simpleType name="Code">
    <xs:restriction base="xs:int"/>
  </xs:simpleType>
</xs:schema>"#;
    fs::write(dir.join("inner.xsd"), inner).unwrap();

    let outer = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:i="urn:inner"
           xmlns:o="urn:outer"
           targetNamespace="urn:outer"
           elementFormDefault="qualified">
  <xs:import namespace="urn:inner" schemaLocation="inner.xsd"/>
  <xs:element name="item" type="i:Code"/>
</xs:schema>"#;
    let outer_path = dir.join("outer.xsd");
    fs::write(&outer_path, outer).unwrap();

    let schema_doc = parse(outer).unwrap();
    let validator =
        XsdValidator::from_schema_with_base_path(&schema_doc, Some(&outer_path)).unwrap();
    let doc = parse(r#"<o:item xmlns:o="urn:outer">not-an-int</o:item>"#).unwrap();
    let errors: Vec<String> = validator
        .validate(&doc)
        .into_iter()
        .map(|e| e.to_string())
        .collect();

    fs::remove_dir_all(&dir).ok();
    assert!(
        errors.iter().any(|e| e.contains("not a valid int")),
        "imported int-based type should reject non-integer content, got {errors:?}"
    );
}

#[test]
fn chameleon_include_qualifies_referenced_attributes() {
    // A no-namespace module included into a target namespace (chameleon
    // include) moves its global attributes into that namespace; attribute
    // uses that reference them must follow, or namespace-aware matching
    // rejects valid instances (W3C Sun xsd024 pattern).
    let dir = mkdir_unique("chameleon-attr");

    let module = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           elementFormDefault="qualified">
  <xs:element name="root" type="rootType"/>
  <xs:complexType name="rootType">
    <xs:attributeGroup ref="attGroup"/>
  </xs:complexType>
  <xs:attributeGroup name="attGroup">
    <xs:attribute ref="att"/>
  </xs:attributeGroup>
  <xs:attribute name="att" type="xs:string"/>
</xs:schema>"#;
    fs::write(dir.join("module.xsd"), module).unwrap();

    let outer = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           targetNamespace="urn:cham"
           xmlns="urn:cham"
           elementFormDefault="qualified">
  <xs:include schemaLocation="module.xsd"/>
</xs:schema>"#;
    let outer_path = dir.join("outer.xsd");
    fs::write(&outer_path, outer).unwrap();

    let schema_doc = parse(outer).unwrap();
    let validator =
        XsdValidator::from_schema_with_base_path(&schema_doc, Some(&outer_path)).unwrap();
    let doc = parse(r#"<c:root xmlns:c="urn:cham" c:att="yes"/>"#).unwrap();
    let errors: Vec<String> = validator
        .validate(&doc)
        .into_iter()
        .map(|e| e.to_string())
        .collect();

    fs::remove_dir_all(&dir).ok();
    assert!(
        errors.is_empty(),
        "chameleon-included attribute ref must match target namespace, got {errors:?}"
    );
}

#[test]
fn unknown_named_xsd_type_fails_closed() {
    // An unresolved schema type reference must be a validation error. Treating
    // it as string-like content would silently bypass the intended constraint.
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:i="urn:inner"
           xmlns:o="urn:outer"
           targetNamespace="urn:outer"
           elementFormDefault="qualified">
  <xs:element name="item" type="i:Missing"/>
</xs:schema>"#;

    let errors = validate(schema, r#"<o:item xmlns:o="urn:outer">anything</o:item>"#);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("Type '{urn:inner}Missing' not found")),
        "expected unresolved type error, got {errors:?}"
    );
}

#[test]
fn xsd_identity_constraints_use_namespace_uris() {
    // Identity-constraint selectors and fields must compare expanded names.
    // The valid document reuses a local name in another namespace; only the
    // target namespace should participate in the key.
    let schema = r###"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:r="urn:root"
           xmlns:v="urn:vehicle"
           targetNamespace="urn:root"
           elementFormDefault="qualified">
  <xs:element name="root">
    <xs:complexType>
      <xs:sequence>
        <xs:any namespace="##any" processContents="skip" minOccurs="0" maxOccurs="unbounded"/>
      </xs:sequence>
    </xs:complexType>
    <xs:key name="vehicle_ids">
      <xs:selector xpath=".//v:vehicle"/>
      <xs:field xpath="@v:id"/>
    </xs:key>
  </xs:element>
</xs:schema>"###;

    let valid = r#"<r:root xmlns:r="urn:root" xmlns:v="urn:vehicle" xmlns:o="urn:other">
  <v:vehicle v:id="1"/>
  <o:vehicle v:id="1"/>
</r:root>"#;
    assert!(validate(schema, valid).is_empty());

    let invalid = r#"<r:root xmlns:r="urn:root" xmlns:v="urn:vehicle">
  <v:vehicle v:id="1"/>
  <v:vehicle v:id="1"/>
</r:root>"#;
    let errors = validate(schema, invalid);
    assert!(
        errors.iter().any(|e| e.contains("duplicate value")),
        "expected duplicate key error, got {errors:?}"
    );
}

#[test]
fn xsd_identity_constraint_selector_uses_local_namespace_scope() {
    // Namespace declarations on xs:selector are in scope for that XPath. If
    // ignored, the selector matches nothing and duplicate key values bypass.
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           targetNamespace="urn:v"
           elementFormDefault="qualified">
  <xs:element name="root">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="vehicle" type="xs:string" maxOccurs="unbounded"/>
      </xs:sequence>
    </xs:complexType>
    <xs:key name="vehicle_texts">
      <xs:selector xmlns:v="urn:v" xpath="v:vehicle"/>
      <xs:field xpath="."/>
    </xs:key>
  </xs:element>
</xs:schema>"#;

    let invalid = r#"<v:root xmlns:v="urn:v">
  <v:vehicle>same</v:vehicle>
  <v:vehicle>same</v:vehicle>
</v:root>"#;
    let errors = validate(schema, invalid);
    assert!(
        errors.iter().any(|e| e.contains("duplicate value")),
        "expected selector-local namespace to expose duplicate key, got {errors:?}"
    );
}

#[test]
fn xsd_identity_constraint_field_uses_local_namespace_scope() {
    // Namespace declarations on xs:field are in scope for that XPath. xs:unique
    // skips absent fields, so ignoring the local binding would accept duplicates.
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           targetNamespace="urn:v"
           elementFormDefault="qualified">
  <xs:element name="root">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="vehicle" maxOccurs="unbounded">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="id" type="xs:string"/>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
    <xs:unique xmlns:s="urn:v" name="vehicle_ids">
      <xs:selector xpath="s:vehicle"/>
      <xs:field xmlns:f="urn:v" xpath="f:id"/>
    </xs:unique>
  </xs:element>
</xs:schema>"#;

    let invalid = r#"<v:root xmlns:v="urn:v">
  <v:vehicle><v:id>same</v:id></v:vehicle>
  <v:vehicle><v:id>same</v:id></v:vehicle>
</v:root>"#;
    let errors = validate(schema, invalid);
    assert!(
        errors.iter().any(|e| e.contains("duplicate value")),
        "expected field-local namespace to expose duplicate unique value, got {errors:?}"
    );
}

#[test]
fn xsd_keyref_field_uses_local_namespace_scope() {
    // Keyref fields with locally declared prefixes must resolve before the
    // tuple lookup. Otherwise missing field values are skipped and bad refs pass.
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           targetNamespace="urn:v"
           elementFormDefault="qualified">
  <xs:element name="root">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="vehicle" maxOccurs="unbounded">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="id" type="xs:string"/>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
        <xs:element name="ref" maxOccurs="unbounded">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="id" type="xs:string"/>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
    <xs:key xmlns:s="urn:v" name="vehicle_ids">
      <xs:selector xpath="s:vehicle"/>
      <xs:field xpath="s:id"/>
    </xs:key>
    <xs:keyref xmlns:s="urn:v" name="vehicle_refs" refer="vehicle_ids">
      <xs:selector xpath="s:ref"/>
      <xs:field xmlns:f="urn:v" xpath="f:id"/>
    </xs:keyref>
  </xs:element>
</xs:schema>"#;

    let invalid = r#"<v:root xmlns:v="urn:v">
  <v:vehicle><v:id>known</v:id></v:vehicle>
  <v:ref><v:id>missing</v:id></v:ref>
</v:root>"#;
    let errors = validate(schema, invalid);
    assert!(
        errors.iter().any(|e| e.contains("no matching key value")),
        "expected field-local namespace to expose bad keyref, got {errors:?}"
    );
}

#[test]
fn xsd_identity_tuple_index_preserves_decimal_duplicate_detection() {
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="root">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="item" maxOccurs="unbounded">
          <xs:complexType>
            <xs:attribute name="id" type="xs:decimal" use="required"/>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
    <xs:unique name="item_ids">
      <xs:selector xpath="item"/>
      <xs:field xpath="@id"/>
    </xs:unique>
  </xs:element>
</xs:schema>"#;

    let errors = validate(schema, r#"<root><item id="01.0"/><item id="1.00"/></root>"#);
    assert!(
        errors.iter().any(|e| e.contains("duplicate value")),
        "expected decimal-equivalent duplicate after tuple indexing, got {errors:?}"
    );
}

#[test]
fn xsd_keyref_tuple_index_reports_missing_references() {
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="root">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="item" maxOccurs="unbounded">
          <xs:complexType>
            <xs:attribute name="code" type="xs:string" use="required"/>
          </xs:complexType>
        </xs:element>
        <xs:element name="ref" maxOccurs="unbounded">
          <xs:complexType>
            <xs:attribute name="code" type="xs:string" use="required"/>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
    <xs:key name="item_codes">
      <xs:selector xpath="item"/>
      <xs:field xpath="@code"/>
    </xs:key>
    <xs:keyref name="ref_codes" refer="item_codes">
      <xs:selector xpath="ref"/>
      <xs:field xpath="@code"/>
    </xs:keyref>
  </xs:element>
</xs:schema>"#;

    let mut instance = String::from("<root>");
    for i in 0..128 {
        instance.push_str(&format!(r#"<item code="k{i}"/>"#));
    }
    for i in 0..128 {
        instance.push_str(&format!(r#"<ref code="k{i}"/>"#));
    }
    instance.push_str(r#"<ref code="missing"/></root>"#);

    let errors = validate(schema, &instance);
    assert_eq!(
        errors
            .iter()
            .filter(|e| e.contains("no matching key value"))
            .count(),
        1,
        "expected exactly one missing keyref with indexed lookup, got {errors:?}"
    );
}

#[test]
fn xsd_identity_selector_handles_deep_programmatic_dom() {
    // `.//` identity-constraint selectors must use heap-backed traversal just
    // like XPath axes, because callers can construct deeper DOMs than the
    // parser accepts.
    let schema = r###"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:v="urn:v"
           targetNamespace="urn:v"
           elementFormDefault="qualified">
  <xs:element name="root">
    <xs:complexType>
      <xs:sequence>
        <xs:any namespace="##any" processContents="skip" minOccurs="0" maxOccurs="unbounded"/>
      </xs:sequence>
    </xs:complexType>
    <xs:key name="leaf_ids">
      <xs:selector xpath=".//v:leaf"/>
      <xs:field xpath="@id"/>
    </xs:key>
  </xs:element>
</xs:schema>"###;
    let schema_doc = parse(schema).unwrap();
    let validator = XsdValidator::from_schema(&schema_doc).unwrap();

    let mut doc = Document::new();
    let doc_root = doc.root();
    let root = doc.create_element(QName::full("v", "urn:v", "root"));
    doc.append_child(doc_root, root);

    let mut parent = root;
    for _ in 0..4096 {
        let child = doc.create_element(QName::full("v", "urn:v", "n"));
        doc.append_child(parent, child);
        parent = child;
    }

    let first = doc.create_element(QName::full("v", "urn:v", "leaf"));
    doc.element_mut(first)
        .unwrap()
        .set_attribute(QName::local("id"), Cow::Borrowed("same"));
    doc.append_child(parent, first);

    let second = doc.create_element(QName::full("v", "urn:v", "leaf"));
    doc.element_mut(second)
        .unwrap()
        .set_attribute(QName::local("id"), Cow::Borrowed("same"));
    doc.append_child(parent, second);

    let errors = validator.validate(&doc);
    assert!(
        errors.iter().any(|e| e.message.contains("duplicate value")),
        "expected deep identity selector to find duplicate key, got {errors:?}"
    );
}

#[test]
fn xsd_attribute_wildcard_union_stays_namespace_precise() {
    // Attribute wildcard extension combines namespace constraints. The union
    // should allow only the local and target namespaces configured by the
    // schema, not arbitrary foreign attributes.
    let schema = r###"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:t="urn:t"
           targetNamespace="urn:t"
           elementFormDefault="qualified">
  <xs:complexType name="Base">
    <xs:anyAttribute namespace="##local" processContents="skip"/>
  </xs:complexType>
  <xs:complexType name="Derived">
    <xs:complexContent>
      <xs:extension base="t:Base">
        <xs:anyAttribute namespace="##targetNamespace" processContents="skip"/>
      </xs:extension>
    </xs:complexContent>
  </xs:complexType>
  <xs:element name="r" type="t:Derived"/>
</xs:schema>"###;

    let valid = r#"<t:r xmlns:t="urn:t" local="ok" t:target="ok"/>"#;
    assert!(validate(schema, valid).is_empty());

    let invalid = r#"<t:r xmlns:t="urn:t" xmlns:f="urn:f" local="ok" t:target="ok" f:bad="no"/>"#;
    let errors = validate(schema, invalid);
    assert!(
        errors.iter().any(|e| e.contains("not allowed by wildcard")),
        "expected wildcard namespace error, got {errors:?}"
    );
}

#[test]
fn xsd_attribute_wildcard_union_other_plus_local_excludes_target() {
    // ##other excludes both the schema target namespace and local attributes;
    // unioning it with ##local should add local attributes without admitting
    // target-namespace attributes.
    let schema = r###"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:t="urn:t"
           targetNamespace="urn:t"
           elementFormDefault="qualified">
  <xs:complexType name="Base">
    <xs:anyAttribute namespace="##other" processContents="skip"/>
  </xs:complexType>
  <xs:complexType name="Derived">
    <xs:complexContent>
      <xs:extension base="t:Base">
        <xs:anyAttribute namespace="##local" processContents="skip"/>
      </xs:extension>
    </xs:complexContent>
  </xs:complexType>
  <xs:element name="r" type="t:Derived"/>
</xs:schema>"###;

    let valid = r#"<t:r xmlns:t="urn:t" xmlns:f="urn:f" local="ok" f:foreign="ok"/>"#;
    assert!(validate(schema, valid).is_empty());

    let invalid = r#"<t:r xmlns:t="urn:t" t:target="no"/>"#;
    let errors = validate(schema, invalid);
    assert!(
        errors.iter().any(|e| e.contains("not allowed by wildcard")),
        "expected target-namespace wildcard error, got {errors:?}"
    );
}

#[test]
fn xsd_attribute_form_default_qualified_matches_target_namespace() {
    // attributeFormDefault="qualified" puts local attribute uses in the schema
    // target namespace; namespace-aware attribute matching must accept the
    // prefixed instance attribute and reject the unqualified spelling.
    let schema = r###"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           targetNamespace="urn:t"
           elementFormDefault="qualified"
           attributeFormDefault="qualified">
  <xs:element name="r">
    <xs:complexType>
      <xs:attribute name="id" type="xs:string" use="required"/>
    </xs:complexType>
  </xs:element>
</xs:schema>"###;

    let qualified = r#"<t:r xmlns:t="urn:t" t:id="ok"/>"#;
    let errors = validate(schema, qualified);
    assert!(
        errors.is_empty(),
        "qualified local attribute must satisfy its declaration, got {errors:?}"
    );

    let unqualified = r#"<t:r xmlns:t="urn:t" id="no"/>"#;
    let errors = validate(schema, unqualified);
    assert!(
        !errors.is_empty(),
        "unqualified attribute must not satisfy a qualified declaration"
    );
}

#[test]
fn xsd_attribute_form_qualified_overrides_unqualified_default() {
    // form="qualified" on a single attribute use qualifies just that attribute
    // while sibling declarations stay in no namespace.
    let schema = r###"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           targetNamespace="urn:t"
           elementFormDefault="qualified">
  <xs:element name="r">
    <xs:complexType>
      <xs:attribute name="q" type="xs:string" use="required" form="qualified"/>
      <xs:attribute name="u" type="xs:string" use="required"/>
    </xs:complexType>
  </xs:element>
</xs:schema>"###;

    let valid = r#"<t:r xmlns:t="urn:t" t:q="ok" u="ok"/>"#;
    let errors = validate(schema, valid);
    assert!(
        errors.is_empty(),
        "form=qualified attribute must match target namespace, got {errors:?}"
    );

    let invalid = r#"<t:r xmlns:t="urn:t" q="no" u="ok"/>"#;
    let errors = validate(schema, invalid);
    assert!(
        !errors.is_empty(),
        "unqualified spelling must not satisfy a form=qualified declaration"
    );
}

#[test]
fn xsd_timezone_less_temporal_facet_comparison_fails_closed() {
    // A timezone-less facet bound and a timezoned value are only partially
    // ordered (XSD Part 2 section 3.2.7.4); a missing timezone must not be
    // silently treated as UTC.
    let schema = r###"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="t">
    <xs:simpleType>
      <xs:restriction base="xs:time">
        <xs:minInclusive value="12:00:00"/>
      </xs:restriction>
    </xs:simpleType>
  </xs:element>
</xs:schema>"###;

    // 22:00:00-12:00 is 34:00:00 UTC-normalized: more than 14 hours after the
    // timezone-less bound, so the order is determinate and the value is valid.
    let errors = validate(schema, "<t>22:00:00-12:00</t>");
    assert!(
        errors.is_empty(),
        "determinate cross-timezone comparison must validate, got {errors:?}"
    );

    // 13:00:00+05:00 is 08:00:00Z: within the +/-14:00 window of the
    // timezone-less bound, so the comparison is indeterminate and must fail
    // closed (treating the bound as UTC would wrongly accept the value).
    let errors = validate(schema, "<t>13:00:00+05:00</t>");
    assert!(
        errors.iter().any(|e| e.contains("Cannot compare")),
        "expected indeterminate comparison error, got {errors:?}"
    );

    // Both timezone-less: totally ordered, normal facet enforcement applies.
    assert!(validate(schema, "<t>12:30:00</t>").is_empty());
    assert!(!validate(schema, "<t>11:00:00</t>").is_empty());
}

#[test]
fn xsd_date_facet_comparison_uses_timeline_not_lexical_order() {
    // 2024-01-02+14:00 and 2024-01-01-10:00 denote the same instant
    // (2024-01-01T10:00:00Z); lexical comparison would reject the value as
    // greater than the bound.
    let schema = r###"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="d">
    <xs:simpleType>
      <xs:restriction base="xs:date">
        <xs:maxInclusive value="2024-01-01-10:00"/>
      </xs:restriction>
    </xs:simpleType>
  </xs:element>
</xs:schema>"###;

    let errors = validate(schema, "<d>2024-01-02+14:00</d>");
    assert!(
        errors.is_empty(),
        "timezone-normalized equal date must satisfy maxInclusive, got {errors:?}"
    );
    assert!(!validate(schema, "<d>2024-01-02-10:00</d>").is_empty());
}

#[test]
fn xsd_gyear_facet_comparison_is_numeric_not_lexical() {
    // Lexically "9999" > "10000"; on the timeline 9999 precedes 10000.
    let schema = r###"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="y">
    <xs:simpleType>
      <xs:restriction base="xs:gYear">
        <xs:maxInclusive value="10000"/>
      </xs:restriction>
    </xs:simpleType>
  </xs:element>
</xs:schema>"###;

    let errors = validate(schema, "<y>9999</y>");
    assert!(
        errors.is_empty(),
        "gYear must compare numerically, got {errors:?}"
    );
    assert!(!validate(schema, "<y>10001</y>").is_empty());
}

#[test]
fn xsd_effective_attributes_merge_by_expanded_name() {
    // A derived type adds a qualified attribute sharing the local name of the
    // base type's unqualified one; namespace-aware merging must keep both
    // (name-only merging would drop the derived declaration).
    let schema = r###"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:t="urn:t"
           targetNamespace="urn:t"
           elementFormDefault="qualified">
  <xs:complexType name="Base">
    <xs:attribute name="id" type="xs:string" use="required"/>
  </xs:complexType>
  <xs:complexType name="Derived">
    <xs:complexContent>
      <xs:extension base="t:Base">
        <xs:attribute name="id" type="xs:string" use="required" form="qualified"/>
      </xs:extension>
    </xs:complexContent>
  </xs:complexType>
  <xs:element name="r" type="t:Derived"/>
</xs:schema>"###;

    let both = r#"<t:r xmlns:t="urn:t" id="a" t:id="b"/>"#;
    let errors = validate(schema, both);
    assert!(
        errors.is_empty(),
        "both same-local-name attributes must validate, got {errors:?}"
    );

    // The qualified declaration is its own required attribute; supplying only
    // the unqualified one must not satisfy it.
    let missing = validate(schema, r#"<t:r xmlns:t="urn:t" id="a"/>"#);
    assert!(
        !missing.is_empty(),
        "missing qualified attribute must be reported"
    );
}

#[test]
fn chameleon_include_qualifies_form_qualified_local_attributes() {
    // A chameleon-included module with attributeFormDefault="qualified": its
    // local attribute uses move into the including schema's target namespace
    // along with everything else.
    let dir = mkdir_unique("chameleon-form");

    let module = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           elementFormDefault="qualified"
           attributeFormDefault="qualified">
  <xs:element name="root">
    <xs:complexType>
      <xs:attribute name="att" type="xs:string" use="required"/>
    </xs:complexType>
  </xs:element>
</xs:schema>"#;
    fs::write(dir.join("module.xsd"), module).unwrap();

    let outer = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           targetNamespace="urn:chamform"
           xmlns="urn:chamform"
           elementFormDefault="qualified">
  <xs:include schemaLocation="module.xsd"/>
</xs:schema>"#;
    let outer_path = dir.join("outer.xsd");
    fs::write(&outer_path, outer).unwrap();

    let schema_doc = parse(outer).unwrap();
    let validator =
        XsdValidator::from_schema_with_base_path(&schema_doc, Some(&outer_path)).unwrap();
    let doc = parse(r#"<c:root xmlns:c="urn:chamform" c:att="yes"/>"#).unwrap();
    let errors: Vec<String> = validator
        .validate(&doc)
        .into_iter()
        .map(|e| e.to_string())
        .collect();

    fs::remove_dir_all(&dir).ok();
    assert!(
        errors.is_empty(),
        "chameleon-included qualified local attribute must match target namespace, got {errors:?}"
    );
}

#[test]
fn xsd_unknown_attribute_form_falls_back_to_schema_default() {
    // An unrecognized form= value must not silently force the attribute to be
    // unqualified; like parse_element_decl, it falls back to the schema's
    // attributeFormDefault.
    let schema = r###"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           targetNamespace="urn:t"
           elementFormDefault="qualified"
           attributeFormDefault="qualified">
  <xs:element name="r">
    <xs:complexType>
      <xs:attribute name="id" type="xs:string" use="required" form="bogus"/>
    </xs:complexType>
  </xs:element>
</xs:schema>"###;

    let qualified = r#"<t:r xmlns:t="urn:t" t:id="ok"/>"#;
    let errors = validate(schema, qualified);
    assert!(
        errors.is_empty(),
        "unknown form must fall back to attributeFormDefault, got {errors:?}"
    );
}

#[test]
fn xsd_complex_type_derivation_cycles_are_rejected() {
    // Recursive complex-type derivation can otherwise loop while resolving the
    // effective content model. The validator should detect the cycle and report
    // it instead of recursing indefinitely.
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:t="urn:t"
           targetNamespace="urn:t"
           elementFormDefault="qualified">
  <xs:complexType name="A">
    <xs:complexContent><xs:extension base="t:B"/></xs:complexContent>
  </xs:complexType>
  <xs:complexType name="B">
    <xs:complexContent><xs:extension base="t:A"/></xs:complexContent>
  </xs:complexType>
  <xs:element name="r" type="t:A"/>
</xs:schema>"#;

    let errors = validate(schema, r#"<t:r xmlns:t="urn:t"/>"#);
    assert!(
        errors.iter().any(|e| e.contains("derivation cycle")),
        "expected derivation cycle error, got {errors:?}"
    );
}

#[test]
fn xsd_datetime_facets_compare_actual_instants() {
    // Date/time facets must compare temporal values, not lexical strings.
    // This value sorts after the minimum as text but is two hours earlier in UTC.
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="stamp">
    <xs:simpleType>
      <xs:restriction base="xs:dateTime">
        <xs:minInclusive value="2024-01-01T00:00:00Z"/>
      </xs:restriction>
    </xs:simpleType>
  </xs:element>
</xs:schema>"#;

    let invalid = validate(schema, "<stamp>2024-01-01T00:00:00+02:00</stamp>");
    assert!(
        invalid.iter().any(|e| e.contains("minInclusive")),
        "expected instant-aware minInclusive error, got {invalid:?}"
    );

    assert!(validate(schema, "<stamp>2024-01-01T02:00:00+02:00</stamp>").is_empty());

    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="stamp">
    <xs:simpleType>
      <xs:restriction base="xs:dateTime">
        <xs:minInclusive value="2024-01-01T00:00:00.0002Z"/>
      </xs:restriction>
    </xs:simpleType>
  </xs:element>
</xs:schema>"#;
    let invalid = validate(schema, "<stamp>2024-01-01T00:00:00.0001Z</stamp>");
    assert!(
        invalid.iter().any(|e| e.contains("minInclusive")),
        "expected fractional instant comparison error, got {invalid:?}"
    );
}

#[test]
fn xsd_string_enumeration_is_not_datetime_normalized() {
    // Enumeration comparison must only normalize temporal datatypes. Treating
    // every dotted string as a timestamp lets values bypass string allow-lists.
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="role">
    <xs:simpleType>
      <xs:restriction base="xs:string">
        <xs:enumeration value="admin"/>
      </xs:restriction>
    </xs:simpleType>
  </xs:element>
</xs:schema>"#;

    assert!(validate(schema, "<role>admin</role>").is_empty());
    let errors = validate(schema, "<role>admin.000</role>");
    assert!(
        errors.iter().any(|e| e.contains("allowed values")),
        "expected string enumeration rejection, got {errors:?}"
    );
}

#[test]
fn xsd_temporal_enumeration_normalizes_timezone_beyond_datetime() {
    // All timezone-bearing temporal types (not just xs:dateTime/xs:time) must
    // normalize the timezone suffix for enumeration matching, so a lexically
    // different but value-equivalent instant (`...+00:00` vs `...Z`) still
    // matches an allowed enumeration value.
    let date_schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="d">
    <xs:simpleType>
      <xs:restriction base="xs:date">
        <xs:enumeration value="2024-01-01Z"/>
      </xs:restriction>
    </xs:simpleType>
  </xs:element>
</xs:schema>"#;
    assert!(
        validate(date_schema, "<d>2024-01-01+00:00</d>").is_empty(),
        "xs:date enumeration must normalize +00:00 to Z"
    );

    let gym_schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="g">
    <xs:simpleType>
      <xs:restriction base="xs:gYearMonth">
        <xs:enumeration value="2024-01Z"/>
      </xs:restriction>
    </xs:simpleType>
  </xs:element>
</xs:schema>"#;
    assert!(
        validate(gym_schema, "<g>2024-01+00:00</g>").is_empty(),
        "xs:gYearMonth enumeration must normalize +00:00 to Z"
    );
}

#[test]
fn xsd_negative_date_rejects_extra_suffix() {
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="d" type="xs:date"/>
</xs:schema>"#;

    assert!(validate(schema, "<d>-2024-02-29</d>").is_empty());
    let errors = validate(schema, "<d>-2024-02-29-extra</d>");
    assert!(
        errors.iter().any(|e| e.contains("date")),
        "expected malformed negative date rejection, got {errors:?}"
    );
}

#[test]
fn xsd_unresolved_element_ref_fails_closed() {
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:t="urn:t"
           xmlns:i="urn:i"
           targetNamespace="urn:t"
           elementFormDefault="qualified">
  <xs:import namespace="urn:i"/>
  <xs:element name="root">
    <xs:complexType>
      <xs:sequence>
        <xs:element ref="i:child"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>"#;

    let errors = validate(
        schema,
        r#"<t:root xmlns:t="urn:t" xmlns:i="urn:i"><i:child><x/></i:child></t:root>"#,
    );
    assert!(
        errors.iter().any(|e| e.contains("Element reference")),
        "expected unresolved element reference error, got {errors:?}"
    );
}

#[test]
fn xsd_attribute_refs_match_expanded_names() {
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:t="urn:t"
           targetNamespace="urn:t"
           elementFormDefault="qualified"
           attributeFormDefault="unqualified">
  <xs:attribute name="role" type="xs:int"/>
  <xs:element name="user">
    <xs:complexType>
      <xs:attribute ref="t:role" use="required"/>
    </xs:complexType>
  </xs:element>
</xs:schema>"#;

    assert!(validate(schema, r#"<t:user xmlns:t="urn:t" t:role="123"/>"#).is_empty());
    let errors = validate(schema, r#"<t:user xmlns:t="urn:t" role="123"/>"#);
    assert!(
        errors.iter().any(|e| e.contains("Required attribute")),
        "expected required namespaced attribute rejection, got {errors:?}"
    );
}

#[test]
fn xsd_strict_any_attribute_uses_actual_attribute_namespace() {
    let schema = r###"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:t="urn:t"
           targetNamespace="urn:t"
           elementFormDefault="qualified">
  <xs:attribute name="role" type="xs:int"/>
  <xs:element name="user">
    <xs:complexType>
      <xs:anyAttribute namespace="##any" processContents="strict"/>
    </xs:complexType>
  </xs:element>
</xs:schema>"###;

    assert!(validate(schema, r#"<t:user xmlns:t="urn:t" t:role="123"/>"#).is_empty());
    let errors = validate(
        schema,
        r#"<t:user xmlns:t="urn:t" xmlns:f="urn:f" f:role="abc"/>"#,
    );
    assert!(
        errors.iter().any(|e| e.contains("no global declaration")),
        "expected exact namespace lookup for strict anyAttribute, got {errors:?}"
    );
}

#[test]
fn xsd_pattern_compile_errors_fail_closed() {
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="code">
    <xs:simpleType>
      <xs:restriction base="xs:string">
        <xs:pattern value="["/>
      </xs:restriction>
    </xs:simpleType>
  </xs:element>
</xs:schema>"#;

    let errors = validate(schema, "<code>anything</code>");
    assert!(
        errors.iter().any(|e| e.contains("could not be compiled")),
        "expected invalid pattern to reject validation, got {errors:?}"
    );
}

#[test]
fn xsd_unique_fields_must_select_at_most_one_node() {
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="root">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="item" maxOccurs="unbounded">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="code" type="xs:string" maxOccurs="unbounded"/>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
    <xs:unique name="item_code">
      <xs:selector xpath="item"/>
      <xs:field xpath="code"/>
    </xs:unique>
  </xs:element>
</xs:schema>"#;

    let errors = validate(
        schema,
        "<root><item><code>A</code><code>B</code></item></root>",
    );
    assert!(
        errors.iter().any(|e| e.contains("must select at most one")),
        "expected multi-field xs:unique rejection, got {errors:?}"
    );
}

#[test]
fn xsd_keyref_fields_must_select_at_most_one_node() {
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="root">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="item">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="code" type="xs:string"/>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
        <xs:element name="ref">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="code" type="xs:string" maxOccurs="unbounded"/>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
    <xs:key name="item_code">
      <xs:selector xpath="item"/>
      <xs:field xpath="code"/>
    </xs:key>
    <xs:keyref name="ref_code" refer="item_code">
      <xs:selector xpath="ref"/>
      <xs:field xpath="code"/>
    </xs:keyref>
  </xs:element>
</xs:schema>"#;

    let errors = validate(
        schema,
        "<root><item><code>A</code></item><ref><code>A</code><code>B</code></ref></root>",
    );
    assert!(
        errors.iter().any(|e| e.contains("must select at most one")),
        "expected multi-field xs:keyref rejection, got {errors:?}"
    );
}

#[test]
fn dtd_content_model_depth_uses_parser_limit() {
    let content_model = format!("{}a{}", "(".repeat(10), ")".repeat(10));
    let xml = format!("<!DOCTYPE r [<!ELEMENT r {content_model}><!ELEMENT a EMPTY>]><r><a/></r>");
    let err = Parser::new()
        .with_max_depth(5)
        .parse(&xml)
        .expect_err("DTD content model nesting must honor parser depth limit");
    assert!(
        err.to_string().contains("DTD content model depth limit"),
        "expected DTD depth error, got {err:?}"
    );
}

#[test]
fn xslt_comment_constructor_rejects_markup_breakout() {
    let xslt = r#"<xsl:stylesheet version="1.0"
           xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="xml" omit-xml-declaration="yes"/>
  <xsl:template match="/">
    <xsl:comment><xsl:value-of select="/r"/></xsl:comment>
  </xsl:template>
</xsl:stylesheet>"#;

    assert_eq!(
        uppsala::transform(xslt, "<r>safe</r>").unwrap(),
        "<!--safe-->"
    );
    let err = uppsala::transform(xslt, "<r>--&gt;&lt;evil/&gt;</r>")
        .expect_err("comment breakout text must be rejected");
    assert!(
        err.to_string().contains("xsl:comment content"),
        "expected xsl:comment hardening error, got {err:?}"
    );
}

#[test]
fn xslt_processing_instruction_rejects_markup_breakout() {
    let xslt = r#"<xsl:stylesheet version="1.0"
           xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="xml" omit-xml-declaration="yes"/>
  <xsl:template match="/">
    <xsl:processing-instruction name="ok"><xsl:value-of select="/r"/></xsl:processing-instruction>
  </xsl:template>
</xsl:stylesheet>"#;

    assert_eq!(
        uppsala::transform(xslt, "<r>safe</r>").unwrap(),
        "<?ok safe?>"
    );
    let err = uppsala::transform(xslt, "<r>?&gt;&lt;evil/&gt;</r>")
        .expect_err("processing-instruction breakout text must be rejected");
    assert!(
        err.to_string().contains("xsl:processing-instruction data"),
        "expected xsl:processing-instruction hardening error, got {err:?}"
    );
}

#[test]
fn xslt_processing_instruction_target_errors_are_distinct() {
    // The reserved "xml" target and a syntactically invalid NCName are
    // different failures; each gets its own diagnostic.
    let stylesheet = |name: &str| {
        format!(
            r#"<xsl:stylesheet version="1.0"
           xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="xml" omit-xml-declaration="yes"/>
  <xsl:template match="/">
    <xsl:processing-instruction name="{name}">d</xsl:processing-instruction>
  </xsl:template>
</xsl:stylesheet>"#
        )
    };

    let err = uppsala::transform(&stylesheet("xMl"), "<r/>")
        .expect_err("reserved xml PI target must be rejected");
    assert!(
        err.to_string().contains("reserved name 'xml'"),
        "expected reserved-target diagnostic, got {err:?}"
    );

    let err = uppsala::transform(&stylesheet("1bad"), "<r/>")
        .expect_err("non-NCName PI target must be rejected");
    assert!(
        err.to_string().contains("not a valid NCName"),
        "expected NCName diagnostic, got {err:?}"
    );
}

#[test]
fn xslt_processing_instruction_target_accepts_unicode_ncname() {
    // The PI target check must use the same full-Unicode NCName rule as the
    // serializer, so a legal non-ASCII target is accepted rather than rejected
    // by an ASCII-only shortcut.
    let xslt = "<xsl:stylesheet version=\"1.0\"\n\
           xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">\n\
  <xsl:output method=\"xml\" omit-xml-declaration=\"yes\"/>\n\
  <xsl:template match=\"/\">\n\
    <xsl:processing-instruction name=\"caf\u{e9}\">data</xsl:processing-instruction>\n\
  </xsl:template>\n\
</xsl:stylesheet>";

    assert_eq!(
        uppsala::transform(xslt, "<r/>").unwrap(),
        "<?caf\u{e9} data?>"
    );
}

#[test]
fn xsd_date_like_facet_comparison_fails_closed_on_invalid_bounds() {
    // compare_facet_values must fail closed for out-of-range facet bounds on all
    // date-like temporal types, not just xs:dateTime/xs:time. A raw lexical
    // comparison of an invalid bound would otherwise silently accept instances.
    let gmonth_schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="m">
    <xs:simpleType>
      <xs:restriction base="xs:gMonth">
        <xs:maxInclusive value="--99"/>
      </xs:restriction>
    </xs:simpleType>
  </xs:element>
</xs:schema>"#;
    assert!(
        !validate(gmonth_schema, "<m>--06</m>").is_empty(),
        "invalid gMonth facet bound must fail closed"
    );

    let date_schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="d">
    <xs:simpleType>
      <xs:restriction base="xs:date">
        <xs:maxInclusive value="2024-99-01"/>
      </xs:restriction>
    </xs:simpleType>
  </xs:element>
</xs:schema>"#;
    assert!(
        !validate(date_schema, "<d>2024-06-01</d>").is_empty(),
        "invalid date facet bound must fail closed"
    );
}

#[test]
fn exslt_padding_has_output_cap() {
    let xslt = r#"<xsl:stylesheet version="1.0"
           xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
           xmlns:str="http://exslt.org/strings">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:value-of select="str:padding(4, '*')"/>
  </xsl:template>
</xsl:stylesheet>"#;
    assert_eq!(transform_exslt(xslt, "<r/>").unwrap(), "****");

    let xslt = r#"<xsl:stylesheet version="1.0"
           xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
           xmlns:str="http://exslt.org/strings">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:value-of select="str:padding(1000001, 'x')"/>
  </xsl:template>
</xsl:stylesheet>"#;
    let err = transform_exslt(xslt, "<r/>").expect_err("oversized padding must fail");
    assert!(
        err.to_string().contains("str:padding length"),
        "expected EXSLT padding cap error, got {err:?}"
    );
}

#[test]
fn xsd_qname_rejects_unbound_prefix() {
    let schema = r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="q" type="xs:QName"/>
</xs:schema>"#;

    assert!(validate(schema, r#"<q xmlns:ok="urn:ok">ok:name</q>"#).is_empty());
    let errors = validate(schema, "<q>missing:name</q>");
    assert!(
        errors.iter().any(|e| e.contains("prefix 'missing'")),
        "expected unbound QName prefix rejection, got {errors:?}"
    );
}
