//! XSLT 1.0 conformance / acceptance tests.
//!
//! Two layers:
//!
//! 1. **Synthetic feature tests** — small, self-contained `(stylesheet, source,
//!    expected)` triples exercising individual Tier A features end to end. These
//!    complement the unit tests in `src/xslt.rs` and never touch the filesystem.
//!
//! 2. **pyFF acceptance** — the seven real pyFF stylesheets vendored under
//!    `test-data/pyff-xslt/` are run against sample SAML metadata. Each must
//!    transform without error and (for the XML output method) produce
//!    well-formed, re-parseable output. The fixtures live outside the published
//!    crate (`Cargo.toml` `exclude`); if absent (a clean checkout), those tests
//!    print a notice and pass, like the W3C suites.

use std::path::Path;

use uppsala::{transform, Parser, Stylesheet};

/// Transform helper used by the synthetic tests.
fn run(xslt: &str, xml: &str) -> String {
    transform(xslt, xml).expect("transform should succeed")
}

// ─── Synthetic feature tests ──────────────────────────────

/// A literal result element wrapping `xsl:value-of` of a computed expression.
#[test]
fn value_of_expression() {
    let xslt = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:output method="xml" omit-xml-declaration="yes"/>
        <xsl:template match="/"><n><xsl:value-of select="count(/r/*)"/></n></xsl:template>
    </xsl:stylesheet>"#;
    assert_eq!(run(xslt, "<r><a/><b/></r>"), "<n>2</n>");
}

/// Metadata-shaped transform mirroring the pyFF identity/filter pattern: copy
/// everything except elements in the XML-DSig namespace (like `unsign.xsl`).
#[test]
fn strip_signature_identity() {
    let xslt = r#"<xsl:stylesheet version="1.0"
            xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <xsl:output method="xml" omit-xml-declaration="yes"/>
        <xsl:template match="ds:Signature"/>
        <xsl:template match="@*|node()"><xsl:copy><xsl:apply-templates select="@*|node()"/></xsl:copy></xsl:template>
    </xsl:stylesheet>"#;
    let xml = r#"<E xmlns="urn:x" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature>SIG</ds:Signature><child>keep</child></E>"#;
    let out = run(xslt, xml);
    // The Signature subtree is dropped; the rest of the tree is preserved.
    assert!(out.contains("<child>keep</child>"), "got {out}");
    assert!(
        !out.contains("Signature"),
        "signature should be removed: {out}"
    );
    assert!(
        !out.contains("SIG"),
        "signature content should be removed: {out}"
    );
}

/// Conditional copy gated on non-empty normalized text (mirrors tidy.xsl's
/// handling of empty OrganizationName-style elements).
#[test]
fn conditional_copy_on_nonempty() {
    let xslt = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
        <xsl:output method="xml" omit-xml-declaration="yes"/>
        <xsl:template match="/"><out><xsl:apply-templates select="r/v"/></out></xsl:template>
        <xsl:template match="v">
            <xsl:if test="normalize-space(text()) != ''"><kept><xsl:value-of select="."/></kept></xsl:if>
        </xsl:template>
    </xsl:stylesheet>"#;
    let xml = "<r><v>a</v><v>   </v><v>b</v></r>";
    // The whitespace-only <v> is skipped; only a and b are kept.
    assert_eq!(run(xslt, xml), "<out><kept>a</kept><kept>b</kept></out>");
}

// ─── pyFF acceptance ──────────────────────────────────────

const PYFF_DIR: &str = "test-data/pyff-xslt";

/// The seven live pyFF stylesheets that define Tier A.
const PYFF_STYLESHEETS: &[&str] = &[
    "tidy.xsl",
    "pp.xsl",
    "unsign.xsl",
    "atom.xsl",
    "kalmar2.xsl",
    "eidas-cleanup.xsl",
    "pubinfo.xsl",
];

/// Run every vendored pyFF stylesheet against the sample metadata. Each must
/// compile and transform without error; XML-method output must re-parse.
#[test]
fn pyff_stylesheets_transform() {
    let dir = Path::new(PYFF_DIR);
    let sample = dir.join("sample-metadata.xml");
    if !sample.exists() {
        eprintln!(
            "skipping pyFF acceptance: {} not present (vendored fixtures absent)",
            sample.display()
        );
        return;
    }
    let single = std::fs::read_to_string(&sample).expect("read sample metadata");

    // `atom.xsl` and `pubinfo.xsl` are keyed to an `md:EntitiesDescriptor`
    // aggregate root: `atom.xsl` emits an Atom feed only from entities carrying
    // `md:Extensions/atom:entry` (the single-entity sample yields an empty result
    // tree), and `pubinfo.xsl`'s `md:EntitiesDescriptor` templates only fire at an
    // aggregate root (against the single entity it would exercise just the identity
    // template). The sample fixtures are ours (not vendored from pyFF), so we keep
    // the original single-entity `sample-metadata.xml` untouched and run those two
    // stylesheets against the aggregate fixture here.
    let aggregate_path = dir.join("atom-feed-sample.xml");
    assert!(
        aggregate_path.exists(),
        "expected atom aggregate fixture missing at {}",
        aggregate_path.display()
    );
    let aggregate = std::fs::read_to_string(&aggregate_path).expect("read atom aggregate fixture");

    for name in PYFF_STYLESHEETS {
        let path = dir.join(name);
        // The sample fixture is present, so the full acceptance corpus is
        // expected too: a missing stylesheet is a failure, not a silent skip
        // (otherwise CI could pass having run only part of the corpus).
        assert!(
            path.exists(),
            "{name}: expected pyFF stylesheet fixture missing at {} (sample metadata is present, so the corpus must be complete)",
            path.display()
        );
        let xslt = std::fs::read_to_string(&path).expect("read stylesheet");

        // atom.xsl and pubinfo.xsl need the aggregate input; the rest use the
        // single-entity sample.
        let input = if matches!(*name, "atom.xsl" | "pubinfo.xsl") {
            &aggregate
        } else {
            &single
        };

        // Compile once via the reusable API, then transform.
        let style_doc = Parser::new()
            .parse(&xslt)
            .unwrap_or_else(|e| panic!("{name}: stylesheet did not parse: {e}"));
        let stylesheet = Stylesheet::compile(&style_doc)
            .unwrap_or_else(|e| panic!("{name}: stylesheet did not compile: {e}"));
        let mut source = Parser::new()
            .parse(input)
            .expect("sample metadata did not parse");
        source.prepare_xpath();
        let out = stylesheet
            .transform(&source)
            .unwrap_or_else(|e| panic!("{name}: transform failed: {e}"));

        assert!(!out.is_empty(), "{name}: produced empty output");

        // None of the vendored stylesheets declare `method="text"`, so every
        // output is XML and must be well-formed and re-parseable.
        Parser::new()
            .parse(&out)
            .unwrap_or_else(|e| panic!("{name}: output is not well-formed XML: {e}\n{out}"));
        eprintln!("  {name}: OK ({} bytes)", out.len());
    }
    eprintln!(
        "pyFF acceptance: {} stylesheets ran",
        PYFF_STYLESHEETS.len()
    );
}
