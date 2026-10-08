//! Identity constraint evaluation for XSD validation.
//!
//! Implements xs:key, xs:unique, and xs:keyref identity constraints using
//! a restricted XPath subset for selector and field evaluation. Supports
//! `.//` descendant selectors, composite (multi-field) keys, QName
//! namespace-aware value comparison, and decimal normalization.

use std::collections::{HashMap, HashSet};

use crate::dom::{Document, NodeId, NodeKind};
use crate::error::ValidationError;

use super::types::{IdentityConstraint, IdentityConstraintKind, XsdValidator};

#[derive(Default)]
struct IdentityTable {
    tuples: Vec<Vec<String>>,
    keys: HashSet<Vec<String>>,
}

impl XsdValidator {
    /// Evaluate identity constraints declared on an element.
    /// `context_node` is the element that declares the constraints (the scope).
    pub(super) fn evaluate_identity_constraints(
        &self,
        doc: &Document,
        context_node: NodeId,
        constraints: &[IdentityConstraint],
        errors: &mut Vec<ValidationError>,
    ) {
        // Collect key/unique constraint values by constraint name, so keyrefs can look them up.
        let mut key_tables: HashMap<String, IdentityTable> = HashMap::new();

        // First pass: evaluate key and unique constraints
        for constraint in constraints {
            if constraint.kind == IdentityConstraintKind::KeyRef {
                continue; // Process keyrefs in second pass
            }

            let selected = idc_select_nodes(
                doc,
                context_node,
                &constraint.selector,
                &constraint.selector_namespaces,
            );
            debug_log!(
                "identity constraint '{}' ({:?}): selector='{}' selected {} nodes",
                constraint.name,
                constraint.kind,
                constraint.selector,
                selected.len()
            );

            let mut table = IdentityTable::default();

            for &sel_node in &selected {
                let mut field_values: Vec<Option<String>> = Vec::new();
                let mut field_source_nodes: Vec<Option<NodeId>> = Vec::new();
                let mut all_present = true;
                let mut multiplicity_error = false;

                for (field_index, field_xpath) in constraint.fields.iter().enumerate() {
                    let field_namespaces = constraint
                        .field_namespaces
                        .get(field_index)
                        .unwrap_or(&constraint.namespaces);
                    let (value, match_count, source_node) =
                        idc_evaluate_field(doc, sel_node, field_xpath, field_namespaces);
                    // For xs:key and xs:unique, if a field selects more than one node,
                    // that's an error per XSD spec §3.11.4.
                    if match_count > 1 {
                        let elem_name = doc
                            .element(sel_node)
                            .map(|e| &*e.name.local_name)
                            .unwrap_or("?");
                        let kind_str = match constraint.kind {
                            IdentityConstraintKind::Key => "Key",
                            IdentityConstraintKind::Unique => "Unique",
                            _ => "Constraint",
                        };
                        errors.push(ValidationError {
                            message: format!(
                                "{} '{}': field '{}' selects {} nodes for element '{}' (must select at most one)",
                                kind_str, constraint.name, field_xpath, match_count, elem_name
                            ),
                            line: Some(doc.node_line(sel_node)),
                            column: Some(doc.node_column(sel_node)),
                        });
                        multiplicity_error = true;
                        break;
                    }
                    if value.is_none() {
                        all_present = false;
                    }
                    field_values.push(value);
                    field_source_nodes.push(source_node);
                }

                if multiplicity_error {
                    continue;
                }

                if constraint.kind == IdentityConstraintKind::Key {
                    // For xs:key, every field must be present
                    if !all_present {
                        let elem_name = doc
                            .element(sel_node)
                            .map(|e| &*e.name.local_name)
                            .unwrap_or("?");
                        errors.push(ValidationError {
                            message: format!(
                                "Key '{}': field value missing for element '{}'",
                                constraint.name, elem_name
                            ),
                            line: Some(doc.node_line(sel_node)),
                            column: Some(doc.node_column(sel_node)),
                        });
                        continue;
                    }
                }

                // For xs:unique, skip rows where any field is absent
                if !all_present {
                    continue;
                }

                // Build tuple, normalizing QName values using namespace context
                let tuple: Vec<String> = field_values
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let val = v.unwrap();
                        // Try to normalize as QName if value contains a prefix
                        if let Some(source) = field_source_nodes[i] {
                            idc_normalize_qname(doc, source, &val)
                        } else {
                            val
                        }
                    })
                    .collect();

                let tuple_key = idc_tuple_key(&tuple);
                if !table.keys.insert(tuple_key) {
                    let kind_str = match constraint.kind {
                        IdentityConstraintKind::Key => "Key",
                        IdentityConstraintKind::Unique => "Unique",
                        _ => "Constraint",
                    };
                    errors.push(ValidationError {
                        message: format!(
                            "{} '{}': duplicate value {:?}",
                            kind_str, constraint.name, tuple
                        ),
                        line: Some(doc.node_line(sel_node)),
                        column: Some(doc.node_column(sel_node)),
                    });
                } else {
                    table.tuples.push(tuple);
                }
            }

            key_tables.insert(constraint.name.clone(), table);
        }

        // Second pass: evaluate keyref constraints
        for constraint in constraints {
            if constraint.kind != IdentityConstraintKind::KeyRef {
                continue;
            }

            let refer_name = match &constraint.refer {
                Some(name) => name,
                None => continue,
            };

            let referred_table = key_tables.get(refer_name);
            if referred_table.is_none() {
                debug_log!(
                    "keyref '{}' refers to '{}' which was not found in this scope",
                    constraint.name,
                    refer_name
                );
                continue;
            }
            let referred_table = referred_table.unwrap();

            let selected = idc_select_nodes(
                doc,
                context_node,
                &constraint.selector,
                &constraint.selector_namespaces,
            );
            debug_log!(
                "keyref '{}': selector='{}' selected {} nodes, referred key '{}' has {} tuples",
                constraint.name,
                constraint.selector,
                selected.len(),
                refer_name,
                referred_table.tuples.len()
            );

            for &sel_node in &selected {
                let mut field_values: Vec<Option<String>> = Vec::new();
                let mut field_source_nodes: Vec<Option<NodeId>> = Vec::new();
                let mut all_present = true;

                for (field_index, field_xpath) in constraint.fields.iter().enumerate() {
                    let field_namespaces = constraint
                        .field_namespaces
                        .get(field_index)
                        .unwrap_or(&constraint.namespaces);
                    let (value, match_count, source_node) =
                        idc_evaluate_field(doc, sel_node, field_xpath, field_namespaces);
                    if match_count > 1 {
                        let elem_name = doc
                            .element(sel_node)
                            .map(|e| &*e.name.local_name)
                            .unwrap_or("?");
                        errors.push(ValidationError {
                            message: format!(
                                "KeyRef '{}': field '{}' selects {} nodes for element '{}' (must select at most one)",
                                constraint.name, field_xpath, match_count, elem_name
                            ),
                            line: Some(doc.node_line(sel_node)),
                            column: Some(doc.node_column(sel_node)),
                        });
                        all_present = false;
                        break;
                    }
                    if value.is_none() {
                        all_present = false;
                    }
                    field_values.push(value);
                    field_source_nodes.push(source_node);
                }

                // KeyRef rows with missing fields are skipped
                if !all_present {
                    continue;
                }

                // Build tuple, normalizing QName values using namespace context
                let tuple: Vec<String> = field_values
                    .into_iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let val = v.unwrap();
                        if let Some(source) = field_source_nodes[i] {
                            idc_normalize_qname(doc, source, &val)
                        } else {
                            val
                        }
                    })
                    .collect();

                let tuple_key = idc_tuple_key(&tuple);
                if !referred_table.keys.contains(&tuple_key) {
                    errors.push(ValidationError {
                        message: format!(
                            "KeyRef '{}': no matching key value {:?} in referred constraint '{}'",
                            constraint.name, tuple, refer_name
                        ),
                        line: Some(doc.node_line(sel_node)),
                        column: Some(doc.node_column(sel_node)),
                    });
                }
            }
        }
    }
}

fn idc_tuple_key(tuple: &[String]) -> Vec<String> {
    tuple
        .iter()
        .map(|value| idc_parse_decimal(value).unwrap_or_else(|| value.clone()))
        .collect()
}

/// Evaluate a restricted XPath selector expression, returning selected nodes.
///
///   selector ::= path ('|' path)*
///   path     ::= ('.//') ? step ('/' step)*
///   step     ::= '.' | nametest
///   nametest ::= qname | '*'
fn idc_select_nodes(
    doc: &Document,
    context: NodeId,
    selector: &str,
    namespaces: &HashMap<String, String>,
) -> Vec<NodeId> {
    let mut results = Vec::new();
    // Track membership in O(1) instead of an O(n) `results.contains()` scan per
    // candidate; for broad selectors (e.g. `.//*` or wide unions) the linear
    // scan made selection O(n^2), a schema-driven DoS during validation. The
    // set only gates pushes, so `results` keeps its deterministic order.
    let mut seen: HashSet<NodeId> = HashSet::new();

    // Split on '|' for union
    for path_str in selector.split('|') {
        let path = path_str.trim();
        if path.is_empty() {
            continue;
        }

        let (descendant, steps) = idc_parse_path(path);

        if descendant {
            // .// prefix: select from all descendants
            let mut descendants = Vec::new();
            idc_collect_descendants(doc, context, &mut descendants);
            for desc in descendants {
                if idc_match_steps(doc, context, desc, &steps, namespaces) && seen.insert(desc) {
                    results.push(desc);
                }
            }
        } else {
            // No .// prefix: select from direct path starting at context
            let mut candidates = vec![context];
            for (i, step) in steps.iter().enumerate() {
                let mut next_candidates = Vec::new();
                for &cand in &candidates {
                    for child in doc.children(cand) {
                        if let Some(NodeKind::Element(_)) = doc.node_kind(child) {
                            if idc_step_matches(doc, child, step, namespaces) {
                                if i == steps.len() - 1 {
                                    if seen.insert(child) {
                                        results.push(child);
                                    }
                                } else {
                                    next_candidates.push(child);
                                }
                            }
                        }
                    }
                }
                candidates = next_candidates;
                if i == steps.len() - 1 {
                    break;
                }
            }
        }
    }

    results
}

/// Parse a selector path into (is_descendant, steps).
/// A step is either "*" (wildcard), "." (self), or a potentially namespace-prefixed name.
fn idc_parse_path(path: &str) -> (bool, Vec<String>) {
    let mut s = path.trim();
    let descendant = if s.starts_with(".//") {
        s = &s[3..];
        true
    } else if s.starts_with("./") {
        s = &s[2..];
        false
    } else {
        false
    };

    let steps: Vec<String> = s.split('/').map(|st| st.trim().to_string()).collect();
    (descendant, steps)
}

/// Check if a node matches a single step (name test or wildcard).
fn idc_step_matches(
    doc: &Document,
    node: NodeId,
    step: &str,
    namespaces: &HashMap<String, String>,
) -> bool {
    if step == "*" {
        // Wildcard matches any element
        return doc.element(node).is_some();
    }
    if step == "." {
        return true; // Self
    }

    if let Some(elem) = doc.element(node) {
        // Check name match. The step might have a namespace prefix.
        if let Some(colon) = step.find(':') {
            let prefix = &step[..colon];
            let local = &step[colon + 1..];
            namespaces.get(prefix).is_some_and(|expected_ns| {
                elem.name.local_name == local
                    && elem.name.namespace_uri.as_deref() == Some(expected_ns.as_str())
            })
        } else {
            elem.name.local_name == step && elem.name.namespace_uri.is_none()
        }
    } else {
        false
    }
}

/// Collect all descendant element nodes.
fn idc_collect_descendants(doc: &Document, node: NodeId, result: &mut Vec<NodeId>) {
    let mut stack = doc.children(node);
    stack.reverse();

    while let Some(current) = stack.pop() {
        if let Some(NodeKind::Element(_)) = doc.node_kind(current) {
            result.push(current);
            let mut children = doc.children(current);
            children.reverse();
            stack.extend(children);
        }
    }
}

/// Check if a descendant node matches the step path from the context.
/// For `.//` selectors, the steps represent a suffix path that can match at any depth.
/// For example, `.//v:vehicle` (1 step) matches any descendant element named `vehicle`,
/// and `.//v:state/v:vehicle` (2 steps) matches a `vehicle` whose parent is a `state`.
/// The key insight: the LAST N nodes in the path from context to target must match
/// the N steps, allowing arbitrary depth for the `.//` descendant axis.
fn idc_match_steps(
    doc: &Document,
    context: NodeId,
    target: NodeId,
    steps: &[String],
    namespaces: &HashMap<String, String>,
) -> bool {
    if steps.is_empty() {
        return false;
    }

    // Build the path from context to target by walking up from target
    let mut path_to_target = Vec::new();
    let mut current = target;
    while current != context {
        path_to_target.push(current);
        match doc.parent(current) {
            Some(parent) => current = parent,
            None => return false, // target is not a descendant of context
        }
    }
    path_to_target.reverse(); // Now: [first child, ..., target]

    // The path must be at least as long as the steps (descendant can be deeper)
    if path_to_target.len() < steps.len() {
        return false;
    }

    // Match the LAST N nodes in the path against the N steps.
    // This allows `.//v:vehicle` to match at any depth, and
    // `.//v:state/v:vehicle` to match a vehicle whose immediate parent is a state.
    let offset = path_to_target.len() - steps.len();
    for (i, step) in steps.iter().enumerate() {
        if !idc_step_matches(doc, path_to_target[offset + i], step, namespaces) {
            return false;
        }
    }

    true
}

/// Evaluate a field XPath on a selected node, returning the field value (if present),
/// the count of matching nodes (for multiplicity checking), and the NodeId of the
/// node where the value was extracted from (for namespace resolution on QName types).
///
/// Field syntax:
///   '.' -> text content of the element
///   '@attr' -> attribute value
///   'child' or 'prefix:child' -> text content of the first matching child element
///   'child1/child2/...' -> nested child path, text of the leaf
///
/// Returns (value, match_count, source_node) where match_count is the number of nodes
/// that matched the field path. For xs:key, match_count > 1 is an error.
fn idc_evaluate_field(
    doc: &Document,
    node: NodeId,
    field: &str,
    namespaces: &HashMap<String, String>,
) -> (Option<String>, usize, Option<NodeId>) {
    let field = field.trim();

    if field == "." {
        // Text content of the element itself — always exactly 1 match (the element itself)
        let text = doc.text_content_deep(node);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return (None, 1, Some(node));
        }
        return (Some(trimmed.to_string()), 1, Some(node));
    }

    if let Some(attr_name) = field.strip_prefix('@') {
        // Attribute
        // Handle pipe-separated (union) attribute fields like "@id|@id|..."
        // Take just the first one since they're all the same
        let attr_name = if let Some(pipe) = attr_name.find('|') {
            &attr_name[..pipe]
        } else {
            attr_name
        };
        if let Some(elem) = doc.element(node) {
            let mut count = 0;
            let mut value = None;
            for attr in &elem.attributes {
                if idc_attr_matches(&attr.name, attr_name, namespaces) {
                    count += 1;
                    if value.is_none() {
                        value = Some(attr.value.to_string());
                    }
                }
            }
            if count > 0 {
                return (value, count, Some(node));
            }
        }
        return (None, 0, Some(node));
    }

    // Child path: split on '/' and navigate
    let parts: Vec<&str> = field.split('/').collect();
    let mut current_nodes = vec![node];

    for part in &parts {
        let part = part.trim();
        let mut next_nodes = Vec::new();

        for &cn in &current_nodes {
            for child in doc.children(cn) {
                if let Some(NodeKind::Element(_)) = doc.node_kind(child) {
                    if idc_step_matches(doc, child, part, namespaces) {
                        next_nodes.push(child);
                    }
                }
            }
        }

        current_nodes = next_nodes;
        if current_nodes.is_empty() {
            return (None, 0, None);
        }
    }

    let match_count = current_nodes.len();

    // Return text content of the first matching node
    if let Some(&result_node) = current_nodes.first() {
        let text = doc.text_content_deep(result_node);
        let trimmed = text.trim();
        if trimmed.is_empty() {
            // For key constraint: check if element exists even if empty
            // An empty element is still a "present" field value (empty string)
            return (Some(String::new()), match_count, Some(result_node));
        }
        (Some(trimmed.to_string()), match_count, Some(result_node))
    } else {
        (None, 0, None)
    }
}

fn idc_attr_matches(
    name: &crate::dom::QName<'_>,
    test: &str,
    namespaces: &HashMap<String, String>,
) -> bool {
    if let Some(colon) = test.find(':') {
        let prefix = &test[..colon];
        let local = &test[colon + 1..];
        namespaces.get(prefix).is_some_and(|expected_ns| {
            name.local_name == local && name.namespace_uri.as_deref() == Some(expected_ns.as_str())
        })
    } else {
        name.local_name == test && name.namespace_uri.is_none()
    }
}

/// Normalize a value that might be a QName by resolving its namespace prefix.
/// If the value contains a `:` that looks like a namespace prefix, resolve the
/// prefix to a namespace URI using the in-scope namespace declarations on the
/// source element (walking up the DOM tree). Returns `{namespace_uri}local_name`
/// for prefixed QNames, or the original value if no prefix or prefix can't be resolved.
fn idc_normalize_qname(doc: &Document, source_node: NodeId, value: &str) -> String {
    let value = value.trim();
    if let Some(colon) = value.find(':') {
        let prefix = &value[..colon];
        let local = &value[colon + 1..];

        // Don't treat things with empty prefix or local as QNames
        if prefix.is_empty() || local.is_empty() {
            return value.to_string();
        }

        // Resolve the namespace prefix by walking up the DOM tree
        if let Some(ns_uri) = idc_resolve_prefix(doc, source_node, prefix) {
            return format!("{{{}}}{}", ns_uri, local);
        }
    }
    value.to_string()
}

/// Resolve a namespace prefix by checking the in-scope namespace declarations
/// on the given element and its ancestors.
fn idc_resolve_prefix(doc: &Document, node: NodeId, prefix: &str) -> Option<String> {
    let mut current = Some(node);
    while let Some(n) = current {
        if let Some(elem) = doc.element(n) {
            if let Some((_, uri)) = elem
                .namespace_declarations
                .iter()
                .find(|(p, _)| &**p == prefix)
            {
                return Some(uri.to_string());
            }
        }
        current = doc.parent(n);
    }
    None
}

/// Parse a decimal string into a normalized form for comparison.
/// Returns None if the string is not a valid decimal number.
fn idc_parse_decimal(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Check if it looks like a decimal number
    let mut chars = s.chars().peekable();
    let negative = if chars.peek() == Some(&'-') {
        chars.next();
        true
    } else if chars.peek() == Some(&'+') {
        chars.next();
        false
    } else {
        false
    };

    let remaining: String = chars.collect();
    if remaining.is_empty() {
        return None;
    }

    // Split on decimal point
    let (int_part, frac_part) = if let Some(dot_pos) = remaining.find('.') {
        (&remaining[..dot_pos], &remaining[dot_pos + 1..])
    } else {
        (remaining.as_str(), "")
    };

    // Validate: all digits
    if !int_part.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    // Normalize: strip leading zeros from integer part, strip trailing zeros from fraction
    let int_normalized = int_part.trim_start_matches('0');
    let int_normalized = if int_normalized.is_empty() {
        "0"
    } else {
        int_normalized
    };

    let frac_normalized = frac_part.trim_end_matches('0');

    // Check for zero
    if int_normalized == "0" && frac_normalized.is_empty() {
        return Some("0".to_string()); // Normalize +0 and -0 to "0"
    }

    let sign = if negative { "-" } else { "" };
    if frac_normalized.is_empty() {
        Some(format!("{}{}", sign, int_normalized))
    } else {
        Some(format!("{}{}.{}", sign, int_normalized, frac_normalized))
    }
}
