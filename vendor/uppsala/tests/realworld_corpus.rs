//! Real-world dialect smoke tests.
//!
//! Drives one minimal-but-valid sample per XML dialect (§4 of other_xml.md),
//! generated under `test-data/corpus/realworld/` by `scripts/fetch_corpus.sh`.
//! Each sample is table-driven, so adding a dialect is a single row.
//!
//! Per file we assert:
//!   1. it parses without error or panic;
//!   2. serialization is a fixpoint (parse→serialize→re-parse is stable);
//!   3. the root element resolves to the expected namespace URI (spot-check);
//!   4. an XPath `count()` returns the documented node count;
//!   5. if a `schema.xsd` sits next to the sample, XSD validation passes.
//!
//! The corpus is excluded from the published crate; absent → notice + pass.

use std::fs;
use std::path::PathBuf;

use uppsala::{parse, XPathEvaluator, XPathValue, XsdValidator};

/// A dialect sample and the invariants it must satisfy.
struct Case {
    /// Path relative to test-data/corpus/realworld/.
    rel: &'static str,
    /// Expected `local-name()` of the document element.
    root_local: &'static str,
    /// Expected `namespace-uri()` of the document element ("" if none).
    root_ns: &'static str,
    /// A namespace-agnostic `count()` expression (matches by local-name).
    count_expr: &'static str,
    /// The expected value of `count_expr`.
    expected_count: usize,
}

const CASES: &[Case] = &[
    Case {
        rel: "rss/rss.xml",
        root_local: "rss",
        root_ns: "",
        count_expr: "count(//*[local-name()='item'])",
        expected_count: 3,
    },
    Case {
        rel: "atom/atom.xml",
        root_local: "feed",
        root_ns: "http://www.w3.org/2005/Atom",
        count_expr: "count(//*[local-name()='entry'])",
        expected_count: 2,
    },
    Case {
        rel: "soap/soap.xml",
        root_local: "Envelope",
        root_ns: "http://www.w3.org/2003/05/soap-envelope",
        count_expr: "count(//*[local-name()='Body'])",
        expected_count: 1,
    },
    Case {
        rel: "saml/metadata.xml",
        root_local: "EntityDescriptor",
        root_ns: "urn:oasis:names:tc:SAML:2.0:metadata",
        count_expr: "count(//*[local-name()='SingleSignOnService'])",
        expected_count: 2,
    },
    Case {
        rel: "svg/shapes.svg",
        root_local: "svg",
        root_ns: "http://www.w3.org/2000/svg",
        count_expr: "count(//*[local-name()='rect'])",
        expected_count: 3,
    },
    Case {
        rel: "xhtml/page.xhtml",
        root_local: "html",
        root_ns: "http://www.w3.org/1999/xhtml",
        count_expr: "count(//*[local-name()='p'])",
        expected_count: 2,
    },
    Case {
        rel: "gpx/track.gpx",
        root_local: "gpx",
        root_ns: "http://www.topografix.com/GPX/1/1",
        count_expr: "count(//*[local-name()='trkpt'])",
        expected_count: 3,
    },
    Case {
        rel: "kml/places.kml",
        root_local: "kml",
        root_ns: "http://www.opengis.net/kml/2.2",
        count_expr: "count(//*[local-name()='Placemark'])",
        expected_count: 2,
    },
    Case {
        rel: "pom/pom.xml",
        root_local: "project",
        root_ns: "http://maven.apache.org/POM/4.0.0",
        count_expr: "count(//*[local-name()='dependency'])",
        expected_count: 2,
    },
    Case {
        rel: "plist/config.plist",
        root_local: "plist",
        root_ns: "",
        count_expr: "count(//*[local-name()='key'])",
        expected_count: 3,
    },
    Case {
        rel: "sitemap/sitemap.xml",
        root_local: "urlset",
        root_ns: "http://www.sitemaps.org/schemas/sitemap/0.9",
        count_expr: "count(//*[local-name()='url'])",
        expected_count: 4,
    },
    Case {
        rel: "junit/results.xml",
        root_local: "testsuites",
        root_ns: "",
        count_expr: "count(//*[local-name()='testcase'])",
        expected_count: 3,
    },
    Case {
        rel: "ooxml/document.xml",
        root_local: "document",
        root_ns: "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
        count_expr: "count(//*[local-name()='p'])",
        expected_count: 2,
    },
];

fn realworld_dir() -> Option<PathBuf> {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-data")
        .join("corpus")
        .join("realworld");
    if base.exists() {
        Some(base)
    } else {
        eprintln!("realworld corpus not found, skipping (run scripts/fetch_corpus.sh)");
        None
    }
}

fn eval_number(doc: &uppsala::Document<'_>, expr: &str) -> f64 {
    let eval = XPathEvaluator::new();
    match eval.evaluate(doc, doc.root(), expr) {
        Ok(XPathValue::Number(n)) => n,
        other => panic!("expected number from {expr:?}, got {other:?}"),
    }
}

fn eval_string(doc: &uppsala::Document<'_>, expr: &str) -> String {
    let eval = XPathEvaluator::new();
    match eval.evaluate(doc, doc.root(), expr) {
        Ok(XPathValue::String(s)) => s,
        other => panic!("expected string from {expr:?}, got {other:?}"),
    }
}

#[test]
fn realworld_samples_smoke() {
    let Some(base) = realworld_dir() else { return };
    let mut checked = 0usize;

    for case in CASES {
        let path = base.join(case.rel);
        assert!(
            path.exists(),
            "{}: sample missing (re-run scripts/fetch_corpus.sh)",
            case.rel
        );
        let xml = fs::read_to_string(&path).unwrap();

        // (1) parses without error.
        let mut doc = parse(&xml).unwrap_or_else(|e| panic!("{}: parse failed: {e:?}", case.rel));

        // (2) serialization fixpoint (round-trip stable).
        let ser1 = doc.to_xml();
        let ser2 = parse(&ser1)
            .unwrap_or_else(|e| panic!("{}: re-parse failed: {e:?}", case.rel))
            .to_xml();
        assert_eq!(ser1, ser2, "{}: round-trip not stable", case.rel);

        // XPath needs the document-order index prepared.
        doc.prepare_xpath();

        // (3) namespace + local-name spot-check on the document element.
        let got_local = eval_string(&doc, "local-name(/*)");
        assert_eq!(got_local, case.root_local, "{}: root local-name", case.rel);
        let got_ns = eval_string(&doc, "namespace-uri(/*)");
        assert_eq!(got_ns, case.root_ns, "{}: root namespace-uri", case.rel);

        // (4) documented node count.
        let n = eval_number(&doc, case.count_expr);
        assert_eq!(
            n as usize, case.expected_count,
            "{}: {} = {n}, expected {}",
            case.rel, case.count_expr, case.expected_count
        );

        // (5) optional XSD validation when a schema sits next to the sample.
        let schema_path = path.with_file_name("schema.xsd");
        if schema_path.exists() {
            let schema_xml = fs::read_to_string(&schema_path).unwrap();
            let schema_doc = parse(&schema_xml)
                .unwrap_or_else(|e| panic!("{}: schema parse failed: {e:?}", case.rel));
            let validator = XsdValidator::from_schema(&schema_doc)
                .unwrap_or_else(|e| panic!("{}: schema build failed: {e:?}", case.rel));
            let errors = validator.validate(&doc);
            assert!(
                errors.is_empty(),
                "{}: XSD validation errors: {errors:?}",
                case.rel
            );
            eprintln!("realworld {}: valid against schema.xsd", case.rel);
        }

        checked += 1;
        eprintln!(
            "realworld {}: ok (ns={:?}, {}={})",
            case.rel, case.root_ns, case.count_expr, case.expected_count
        );
    }

    assert_eq!(checked, CASES.len(), "not every dialect sample was checked");
    eprintln!("realworld corpus: {checked} dialects smoke-tested");
}
