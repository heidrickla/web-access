//! Opt-in EXSLT extension-function library.
//!
//! These implement a vetted subset of the community EXSLT extensions
//! (<http://exslt.org/>) on top of the XPath 1.0 value model, for host languages
//! (the XSLT engine) that want them. They are **opt-in**: enable the broader set
//! with [`crate::Stylesheet::with_exslt`]. The one historically-always-on
//! function, `date:date-time()`, remains available regardless (pyFF relies on
//! it) — see [`resolve`]'s handling.
//!
//! Functions are matched by the conventional EXSLT *prefix* (the engine's
//! function-resolution seam only exposes the prefix), so a stylesheet must bind
//! the usual prefixes: `date`, `math`, `str`, `set`, `exsl`. Only functions
//! representable in the XPath 1.0 data model are provided — those returning new
//! nodes (e.g. `str:tokenize`, `exsl:node-set`) are intentionally omitted.
//!
//! Implemented (when enabled):
//! - `math:` abs, sqrt, power, log, exp, sin, cos, tan, constant, min, max, highest, lowest
//! - `str:` concat, padding, align
//! - `set:` distinct, difference, intersection, has-same-node
//! - `exsl:` object-type
//! - `date:` date-time (always available)

use crate::dom::{Document, NodeId};
use crate::error::XmlResult;
use crate::xpath::{string_value_of_node, XPathValue};

pub(crate) const MAX_EXSLT_PADDING_LENGTH: usize = 1_000_000;

/// Resolve an EXSLT `prefix:local(args)` call. Returns `None` to fall through to
/// the engine's "unknown function" handling. `date:date-time()` resolves
/// regardless of `enabled`; everything else requires `enabled == true`.
pub(crate) fn resolve(
    doc: &Document<'_>,
    prefix: Option<&str>,
    local: &str,
    args: &[XPathValue],
    enabled: bool,
) -> Option<XmlResult<XPathValue>> {
    // Always-on: the EXSLT date-time the pyFF `pubinfo` stylesheet uses.
    if prefix == Some("date") && local == "date-time" {
        return Some(Ok(XPathValue::String(crate::xslt::exslt_date_time())));
    }
    if !enabled {
        return None;
    }
    match (prefix, local) {
        (Some("math"), m) => math(doc, m, args),
        (Some("str"), s) => str_fn(doc, s, args),
        (Some("set"), s) => set_fn(doc, s, args),
        (Some("exsl"), "object-type") => Some(Ok(XPathValue::String(
            object_type(args.first()).to_string(),
        ))),
        _ => None,
    }
}

/// The string-values of a node-set argument, in document order.
fn node_strings(doc: &Document<'_>, v: Option<&XPathValue>) -> Vec<String> {
    match v {
        Some(XPathValue::NodeSet(nodes)) => nodes
            .iter()
            .map(|&n| string_value_of_node(doc, n))
            .collect(),
        _ => Vec::new(),
    }
}

/// A node-set argument's nodes (empty for non-node-set values).
fn nodes_of(v: Option<&XPathValue>) -> &[NodeId] {
    match v {
        Some(XPathValue::NodeSet(nodes)) => nodes,
        _ => &[],
    }
}

fn num(doc: &Document<'_>, v: Option<&XPathValue>) -> f64 {
    v.map(|x| x.to_number(doc)).unwrap_or(f64::NAN)
}

// ─── math: ────────────────────────────────────────────────

fn math(doc: &Document<'_>, name: &str, args: &[XPathValue]) -> Option<XmlResult<XPathValue>> {
    let n = |i: usize| num(doc, args.get(i));
    let val = match name {
        "abs" => n(0).abs(),
        "sqrt" => n(0).sqrt(),
        "power" => n(0).powf(n(1)),
        "log" => n(0).ln(),
        "exp" => n(0).exp(),
        "sin" => n(0).sin(),
        "cos" => n(0).cos(),
        "tan" => n(0).tan(),
        "constant" => return Some(Ok(XPathValue::Number(math_constant(doc, args)))),
        "min" => return Some(Ok(XPathValue::Number(min_max(doc, args.first(), false)))),
        "max" => return Some(Ok(XPathValue::Number(min_max(doc, args.first(), true)))),
        "highest" => {
            return Some(Ok(XPathValue::NodeSet(extreme_nodes(
                doc,
                args.first(),
                true,
            ))))
        }
        "lowest" => {
            return Some(Ok(XPathValue::NodeSet(extreme_nodes(
                doc,
                args.first(),
                false,
            ))))
        }
        _ => return None,
    };
    Some(Ok(XPathValue::Number(val)))
}

/// EXSLT `math:constant(name, precision)` — a named constant rounded to
/// `precision` significant decimal digits.
fn math_constant(doc: &Document<'_>, args: &[XPathValue]) -> f64 {
    let name = args
        .first()
        .map(|v| v.to_string_value(doc))
        .unwrap_or_default();
    let precision = num(doc, args.get(1));
    let raw = match name.as_str() {
        "PI" => std::f64::consts::PI,
        "E" => std::f64::consts::E,
        // The EXSLT spec spells this "SQRRT2" (a long-standing typo); accept the
        // intuitive "SQRT2" as well so callers using either spelling work.
        "SQRT2" | "SQRRT2" => std::f64::consts::SQRT_2,
        "LN2" => std::f64::consts::LN_2,
        "LN10" => std::f64::consts::LN_10,
        "LOG2E" => std::f64::consts::LOG2_E,
        "SQRT1_2" => std::f64::consts::FRAC_1_SQRT_2,
        _ => return f64::NAN,
    };
    if !precision.is_finite() || precision <= 0.0 {
        return raw;
    }
    // Round to `precision` significant figures.
    let digits = precision as i32;
    if raw == 0.0 {
        return 0.0;
    }
    let magnitude = raw.abs().log10().floor() as i32;
    let factor = 10f64.powi(digits - 1 - magnitude);
    (raw * factor).round() / factor
}

fn min_max(doc: &Document<'_>, ns: Option<&XPathValue>, want_max: bool) -> f64 {
    let mut acc: Option<f64> = None;
    for s in node_strings(doc, ns) {
        let n = s.trim().parse::<f64>().unwrap_or(f64::NAN);
        if n.is_nan() {
            return f64::NAN; // EXSLT: NaN if any value is non-numeric
        }
        acc = Some(match acc {
            None => n,
            Some(a) if want_max => a.max(n),
            Some(a) => a.min(n),
        });
    }
    acc.unwrap_or(f64::NAN)
}

/// Nodes whose numeric value is the maximum (`want_max`) or minimum, in document
/// order. Returns empty if any value is non-numeric (EXSLT semantics).
fn extreme_nodes(doc: &Document<'_>, ns: Option<&XPathValue>, want_max: bool) -> Vec<NodeId> {
    let nodes = nodes_of(ns);
    let mut best: Option<f64> = None;
    for &id in nodes {
        let n = string_value_of_node(doc, id)
            .trim()
            .parse::<f64>()
            .unwrap_or(f64::NAN);
        if n.is_nan() {
            return Vec::new();
        }
        best = Some(match best {
            None => n,
            Some(b) if want_max => b.max(n),
            Some(b) => b.min(n),
        });
    }
    let Some(target) = best else {
        return Vec::new();
    };
    nodes
        .iter()
        .copied()
        .filter(|&id| {
            string_value_of_node(doc, id)
                .trim()
                .parse::<f64>()
                .map(|n| n == target)
                .unwrap_or(false)
        })
        .collect()
}

// ─── str: ─────────────────────────────────────────────────

fn str_fn(doc: &Document<'_>, name: &str, args: &[XPathValue]) -> Option<XmlResult<XPathValue>> {
    let s = match name {
        // Concatenate the string-values of a node-set, in document order.
        "concat" => node_strings(doc, args.first()).concat(),
        // A padding string of the given length built from the (repeated) pad
        // string (default a single space), truncated to length.
        "padding" => {
            let len = num(doc, args.first());
            let len = if len.is_finite() && len > 0.0 {
                len as usize
            } else {
                0
            };
            if len > MAX_EXSLT_PADDING_LENGTH {
                return Some(Err(crate::error::XmlError::xpath(format!(
                    "EXSLT str:padding length {} exceeds maximum {}",
                    len, MAX_EXSLT_PADDING_LENGTH
                ))));
            }
            let pad = args
                .get(1)
                .map(|v| v.to_string_value(doc))
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| " ".to_string());
            pad.chars().cycle().take(len).collect()
        }
        // Align `string` within a field the width of the `width` string,
        // alignment "left" (default), "right", or "center".
        "align" => {
            let text = args
                .first()
                .map(|v| v.to_string_value(doc))
                .unwrap_or_default();
            let width = args
                .get(1)
                .map(|v| v.to_string_value(doc).chars().count())
                .unwrap_or(0);
            let alignment = args
                .get(2)
                .map(|v| v.to_string_value(doc))
                .unwrap_or_else(|| "left".to_string());
            align(&text, width, &alignment)
        }
        _ => return None,
    };
    Some(Ok(XPathValue::String(s)))
}

fn align(text: &str, width: usize, alignment: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() >= width {
        // Longer than the field: EXSLT returns the leading `width` characters.
        return chars.into_iter().take(width).collect();
    }
    let pad = width - chars.len();
    match alignment {
        "right" => format!("{}{}", " ".repeat(pad), text),
        "center" => {
            let left = pad / 2;
            format!("{}{}{}", " ".repeat(left), text, " ".repeat(pad - left))
        }
        _ => format!("{}{}", text, " ".repeat(pad)), // "left"
    }
}

// ─── set: ─────────────────────────────────────────────────

fn set_fn(doc: &Document<'_>, name: &str, args: &[XPathValue]) -> Option<XmlResult<XPathValue>> {
    let a = nodes_of(args.first());
    let b = nodes_of(args.get(1));
    let val = match name {
        // Nodes of `a` with distinct string-values (first occurrence kept),
        // preserving `a`'s (document) order.
        "distinct" => {
            let mut seen = std::collections::HashSet::new();
            let nodes = a
                .iter()
                .copied()
                .filter(|&n| seen.insert(string_value_of_node(doc, n)))
                .collect();
            XPathValue::NodeSet(nodes)
        }
        // Nodes in `a` not in `b` (by node identity), in `a`'s order.
        "difference" => {
            let bset: std::collections::HashSet<NodeId> = b.iter().copied().collect();
            XPathValue::NodeSet(a.iter().copied().filter(|n| !bset.contains(n)).collect())
        }
        // Nodes in `a` also in `b` (by node identity), in `a`'s order.
        "intersection" => {
            let bset: std::collections::HashSet<NodeId> = b.iter().copied().collect();
            XPathValue::NodeSet(a.iter().copied().filter(|n| bset.contains(n)).collect())
        }
        // True if `a` and `b` share any node.
        "has-same-node" => {
            let bset: std::collections::HashSet<NodeId> = b.iter().copied().collect();
            XPathValue::Boolean(a.iter().any(|n| bset.contains(n)))
        }
        _ => return None,
    };
    Some(Ok(val))
}

// ─── exsl: ────────────────────────────────────────────────

fn object_type(v: Option<&XPathValue>) -> &'static str {
    match v {
        Some(XPathValue::NodeSet(_)) => "node-set",
        Some(XPathValue::Boolean(_)) => "boolean",
        Some(XPathValue::Number(_)) => "number",
        Some(XPathValue::String(_)) | None => "string",
    }
}
