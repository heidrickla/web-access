//! Shared helpers for the conformance suites.

use uppsala::{Document, PullParser, XmlResult};

/// Parse via the stable DOM API while asserting that the scan-only pull
/// parser agrees: both surfaces must accept or reject the input, and on
/// rejection report the same error text. Used as a drop-in `parse` in the
/// hand-crafted suites so every fixture also regression-tests the pull
/// event stream.
pub fn parse(xml: &str) -> XmlResult<Document<'_>> {
    let dom = uppsala::parse(xml);
    let scan_err = PullParser::new(xml).find_map(|event| event.err());
    match (&dom, &scan_err) {
        (Ok(_), None) => {}
        (Err(dom_err), Some(pull_err)) => assert_eq!(
            dom_err.to_string(),
            pull_err.to_string(),
            "pull parser error text differs from DOM parser"
        ),
        (Ok(_), Some(pull_err)) => {
            panic!("pull parser rejected input the DOM parser accepts: {pull_err}")
        }
        (Err(dom_err), None) => {
            panic!("pull parser accepted input the DOM parser rejects: {dom_err}")
        }
    }
    dom
}
