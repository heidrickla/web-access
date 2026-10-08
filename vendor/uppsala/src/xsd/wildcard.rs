//! Wildcard namespace constraint operations.
//!
//! Provides functions for checking namespace membership against wildcard
//! constraints, computing the intersection and union of namespace constraints,
//! and determining the stricter of two processContents values.
//!
//! These are used by `AttributeWildcard` methods
//! and by element wildcard validation in the validation module.

use super::types::{NamespaceConstraint, ProcessContents};

/// Check if a namespace URI matches a wildcard namespace constraint.
///
/// Works for both attribute and element wildcards. Returns `true` if the
/// given namespace (or absence thereof) is allowed by the constraint.
pub(crate) fn wildcard_allows_namespace(
    constraint: &NamespaceConstraint,
    ns: Option<&str>,
) -> bool {
    match constraint {
        NamespaceConstraint::Any => true,
        NamespaceConstraint::Other(target_ns) => {
            match ns {
                None => false, // ##other excludes no-namespace
                Some(uri) => match target_ns {
                    Some(tns) => uri != tns,
                    None => true,
                },
            }
        }
        NamespaceConstraint::Local => ns.is_none(),
        NamespaceConstraint::TargetNamespace(target_ns) => ns == target_ns.as_deref(),
        NamespaceConstraint::List(uris) => match ns {
            None => uris.iter().any(|u| u == "##local"),
            Some(uri) => uris.iter().any(|u| u == uri),
        },
        NamespaceConstraint::NotLocal => ns.is_some(),
        NamespaceConstraint::Not(excluded) => {
            matches!(ns, Some(uri) if !excluded.iter().any(|u| u == uri))
        }
        NamespaceConstraint::AnyExcept(excluded) => match ns {
            None => true,
            Some(uri) => !excluded.iter().any(|u| u == uri),
        },
    }
}

/// Return the stricter of two processContents values.
///
/// Ordering: Strict > Lax > Skip. Used when intersecting wildcards to
/// ensure the most restrictive validation mode is preserved.
pub(super) fn stricter_process_contents(
    a: &ProcessContents,
    b: &ProcessContents,
) -> ProcessContents {
    match (a, b) {
        (ProcessContents::Strict, _) | (_, ProcessContents::Strict) => ProcessContents::Strict,
        (ProcessContents::Lax, _) | (_, ProcessContents::Lax) => ProcessContents::Lax,
        _ => ProcessContents::Skip,
    }
}

/// Compute the intersection of two namespace constraints.
///
/// Returns `None` if the intersection is empty (no namespace allowed by both).
/// Used when merging attribute groups that both define wildcards — the result
/// only allows namespaces permitted by both wildcards.
pub(super) fn intersect_namespace_constraints(
    a: &NamespaceConstraint,
    b: &NamespaceConstraint,
) -> Option<NamespaceConstraint> {
    if let Some(finite) = finite_namespaces(a) {
        return intersection_from_finite(finite, b);
    }
    if let Some(finite) = finite_namespaces(b) {
        return intersection_from_finite(finite, a);
    }

    match (a, b) {
        // Any intersected with anything is that thing
        (NamespaceConstraint::Any, other) | (other, NamespaceConstraint::Any) => {
            Some(other.clone())
        }
        (NamespaceConstraint::Other(a), NamespaceConstraint::Other(b)) => {
            Some(excluding_namespaces([a.as_ref(), b.as_ref()]))
        }
        (NamespaceConstraint::Other(excluded), NamespaceConstraint::Not(other_excluded))
        | (NamespaceConstraint::Not(other_excluded), NamespaceConstraint::Other(excluded)) => {
            let mut excluded_uris = other_excluded.clone();
            if let Some(uri) = excluded {
                push_unique(&mut excluded_uris, uri.clone());
            }
            Some(not_constraint(excluded_uris))
        }
        (NamespaceConstraint::Other(excluded), NamespaceConstraint::NotLocal)
        | (NamespaceConstraint::NotLocal, NamespaceConstraint::Other(excluded)) => {
            Some(NamespaceConstraint::Other(excluded.clone()))
        }
        (NamespaceConstraint::Other(excluded), NamespaceConstraint::AnyExcept(other_excluded))
        | (NamespaceConstraint::AnyExcept(other_excluded), NamespaceConstraint::Other(excluded)) => {
            let mut excluded_uris = other_excluded.clone();
            if let Some(uri) = excluded {
                push_unique(&mut excluded_uris, uri.clone());
            }
            Some(not_constraint(excluded_uris))
        }
        (NamespaceConstraint::Not(a), NamespaceConstraint::Not(b)) => {
            let mut excluded = a.clone();
            for uri in b {
                push_unique(&mut excluded, uri.clone());
            }
            Some(not_constraint(excluded))
        }
        (NamespaceConstraint::Not(excluded), NamespaceConstraint::AnyExcept(other_excluded))
        | (NamespaceConstraint::AnyExcept(other_excluded), NamespaceConstraint::Not(excluded)) => {
            let mut excluded_uris = excluded.clone();
            for uri in other_excluded {
                push_unique(&mut excluded_uris, uri.clone());
            }
            Some(not_constraint(excluded_uris))
        }
        (NamespaceConstraint::Not(excluded), NamespaceConstraint::NotLocal)
        | (NamespaceConstraint::NotLocal, NamespaceConstraint::Not(excluded)) => {
            Some(not_constraint(excluded.clone()))
        }
        (NamespaceConstraint::NotLocal, NamespaceConstraint::AnyExcept(excluded))
        | (NamespaceConstraint::AnyExcept(excluded), NamespaceConstraint::NotLocal) => {
            Some(not_constraint(excluded.clone()))
        }
        (NamespaceConstraint::AnyExcept(a), NamespaceConstraint::AnyExcept(b)) => {
            let mut excluded = a.clone();
            for uri in b {
                push_unique(&mut excluded, uri.clone());
            }
            Some(any_except_constraint(excluded))
        }
        (NamespaceConstraint::NotLocal, NamespaceConstraint::NotLocal) => {
            Some(NamespaceConstraint::NotLocal)
        }
        _ => None,
    }
}

/// Compute the union of two namespace constraints.
///
/// Used when computing the effective wildcard for complex type extensions —
/// the derived type's wildcard is unioned with the base type's wildcard.
/// Falls back to `Any` for combinations that don't have a more specific result.
pub(super) fn union_namespace_constraints(
    a: &NamespaceConstraint,
    b: &NamespaceConstraint,
) -> NamespaceConstraint {
    if let (Some(mut finite_a), Some(finite_b)) = (finite_namespaces(a), finite_namespaces(b)) {
        for ns in finite_b {
            if !finite_a.contains(&ns) {
                finite_a.push(ns);
            }
        }
        return constraint_from_finite(finite_a).unwrap_or(NamespaceConstraint::Any);
    }
    if let Some(finite) = finite_namespaces(a) {
        match b {
            NamespaceConstraint::Other(excluded) => {
                return union_other_with_finite(excluded, finite)
            }
            NamespaceConstraint::NotLocal => return union_notlocal_with_finite(finite),
            NamespaceConstraint::Not(excluded) => return union_not_with_finite(excluded, finite),
            NamespaceConstraint::AnyExcept(excluded) => {
                return union_any_except_with_finite(excluded, finite);
            }
            _ => {}
        }
    }
    if let Some(finite) = finite_namespaces(b) {
        match a {
            NamespaceConstraint::Other(excluded) => {
                return union_other_with_finite(excluded, finite)
            }
            NamespaceConstraint::NotLocal => return union_notlocal_with_finite(finite),
            NamespaceConstraint::Not(excluded) => return union_not_with_finite(excluded, finite),
            NamespaceConstraint::AnyExcept(excluded) => {
                return union_any_except_with_finite(excluded, finite);
            }
            _ => {}
        }
    }

    match (a, b) {
        // Any union anything = Any
        (NamespaceConstraint::Any, _) | (_, NamespaceConstraint::Any) => NamespaceConstraint::Any,
        (NamespaceConstraint::AnyExcept(excluded), NamespaceConstraint::Other(other))
        | (NamespaceConstraint::Other(other), NamespaceConstraint::AnyExcept(excluded)) => {
            let common = match other {
                Some(uri) if excluded.contains(uri) => vec![uri.clone()],
                _ => Vec::new(),
            };
            any_except_constraint(common)
        }
        (NamespaceConstraint::AnyExcept(_), NamespaceConstraint::NotLocal)
        | (NamespaceConstraint::NotLocal, NamespaceConstraint::AnyExcept(_)) => {
            NamespaceConstraint::Any
        }
        (NamespaceConstraint::AnyExcept(a), NamespaceConstraint::Not(b))
        | (NamespaceConstraint::Not(b), NamespaceConstraint::AnyExcept(a)) => {
            any_except_constraint(common_exclusions(a, b))
        }
        (NamespaceConstraint::AnyExcept(a), NamespaceConstraint::AnyExcept(b)) => {
            any_except_constraint(common_exclusions(a, b))
        }
        (NamespaceConstraint::Other(a), NamespaceConstraint::Other(b)) => match (a, b) {
            (Some(left), Some(right)) if left == right => NamespaceConstraint::Other(a.clone()),
            (None, None) => NamespaceConstraint::Other(None),
            _ => NamespaceConstraint::NotLocal,
        },
        (NamespaceConstraint::NotLocal, other) | (other, NamespaceConstraint::NotLocal) => {
            if finite_includes_local(other) {
                NamespaceConstraint::Any
            } else {
                NamespaceConstraint::NotLocal
            }
        }
        (NamespaceConstraint::Other(excluded), NamespaceConstraint::TargetNamespace(Some(ns)))
        | (NamespaceConstraint::TargetNamespace(Some(ns)), NamespaceConstraint::Other(excluded)) => {
            if excluded.as_deref() == Some(ns.as_str()) {
                NamespaceConstraint::NotLocal
            } else {
                NamespaceConstraint::Other(excluded.clone())
            }
        }
        (NamespaceConstraint::Other(excluded), NamespaceConstraint::Local)
        | (NamespaceConstraint::Local, NamespaceConstraint::Other(excluded)) => match excluded {
            Some(uri) => any_except_constraint(vec![uri.clone()]),
            None => NamespaceConstraint::Any,
        },
        (NamespaceConstraint::Not(excluded), NamespaceConstraint::TargetNamespace(Some(ns)))
        | (NamespaceConstraint::TargetNamespace(Some(ns)), NamespaceConstraint::Not(excluded)) => {
            let reduced: Vec<String> = excluded.iter().filter(|u| *u != ns).cloned().collect();
            not_constraint(reduced)
        }
        (NamespaceConstraint::Not(excluded), NamespaceConstraint::Local)
        | (NamespaceConstraint::Local, NamespaceConstraint::Not(excluded)) => {
            any_except_constraint(excluded.clone())
        }
        (NamespaceConstraint::Not(a), NamespaceConstraint::Not(b)) => {
            let common: Vec<String> = a.iter().filter(|u| b.contains(u)).cloned().collect();
            not_constraint(common)
        }
        _ => NamespaceConstraint::Any,
    }
}

fn finite_namespaces(constraint: &NamespaceConstraint) -> Option<Vec<Option<String>>> {
    match constraint {
        NamespaceConstraint::Local => Some(vec![None]),
        NamespaceConstraint::TargetNamespace(ns) => Some(vec![ns.clone()]),
        NamespaceConstraint::List(uris) => {
            let mut result = Vec::new();
            for uri in uris {
                let ns = if uri == "##local" {
                    None
                } else {
                    Some(uri.clone())
                };
                if !result.contains(&ns) {
                    result.push(ns);
                }
            }
            Some(result)
        }
        _ => None,
    }
}

fn finite_includes_local(constraint: &NamespaceConstraint) -> bool {
    finite_namespaces(constraint).is_some_and(|namespaces| namespaces.contains(&None))
}

fn intersection_from_finite(
    finite: Vec<Option<String>>,
    other: &NamespaceConstraint,
) -> Option<NamespaceConstraint> {
    let kept: Vec<Option<String>> = finite
        .into_iter()
        .filter(|ns| wildcard_allows_namespace(other, ns.as_deref()))
        .collect();
    constraint_from_finite(kept)
}

fn constraint_from_finite(values: Vec<Option<String>>) -> Option<NamespaceConstraint> {
    // Sort + dedup so the result is deterministic and duplicate-free regardless
    // of input ordering. Plain `dedup` only removes *adjacent* duplicates, so a
    // non-adjacent repeat (e.g. `[a, b, a]`) would otherwise slip through.
    let mut values = values;
    values.sort();
    values.dedup();
    match values.as_slice() {
        [] => None,
        [None] => Some(NamespaceConstraint::Local),
        // A single explicit URI is just the set `{uri}`. Represent it as a
        // one-element `List`, not `TargetNamespace`: the latter carries dedicated
        // `##targetNamespace` semantics that the union/intersection arms special-
        // case, so reusing it for an arbitrary singleton can skew wildcard merges.
        [Some(uri)] => Some(NamespaceConstraint::List(vec![uri.clone()])),
        _ => {
            let mut uris = Vec::new();
            for value in values {
                match value {
                    None => push_unique(&mut uris, "##local".to_string()),
                    Some(uri) => push_unique(&mut uris, uri),
                }
            }
            Some(NamespaceConstraint::List(uris))
        }
    }
}

fn excluding_namespaces<'a>(
    exclusions: impl IntoIterator<Item = Option<&'a String>>,
) -> NamespaceConstraint {
    let mut excluded = Vec::new();
    for uri in exclusions.into_iter().flatten() {
        push_unique(&mut excluded, uri.clone());
    }
    not_constraint(excluded)
}

fn not_constraint(excluded: Vec<String>) -> NamespaceConstraint {
    if excluded.is_empty() {
        NamespaceConstraint::NotLocal
    } else {
        NamespaceConstraint::Not(excluded)
    }
}

fn any_except_constraint(excluded: Vec<String>) -> NamespaceConstraint {
    let mut deduped = Vec::new();
    for uri in excluded {
        push_unique(&mut deduped, uri);
    }
    if deduped.is_empty() {
        NamespaceConstraint::Any
    } else {
        NamespaceConstraint::AnyExcept(deduped)
    }
}

fn common_exclusions(a: &[String], b: &[String]) -> Vec<String> {
    a.iter().filter(|u| b.contains(u)).cloned().collect()
}

fn union_other_with_finite(
    excluded: &Option<String>,
    finite: Vec<Option<String>>,
) -> NamespaceConstraint {
    let includes_local = finite.contains(&None);
    match excluded {
        Some(uri) if finite.contains(&Some(uri.clone())) => {
            if includes_local {
                NamespaceConstraint::Any
            } else {
                NamespaceConstraint::NotLocal
            }
        }
        Some(uri) => {
            if includes_local {
                any_except_constraint(vec![uri.clone()])
            } else {
                NamespaceConstraint::Other(Some(uri.clone()))
            }
        }
        None => {
            if includes_local {
                NamespaceConstraint::Any
            } else {
                NamespaceConstraint::NotLocal
            }
        }
    }
}

fn union_notlocal_with_finite(finite: Vec<Option<String>>) -> NamespaceConstraint {
    if finite.contains(&None) {
        NamespaceConstraint::Any
    } else {
        NamespaceConstraint::NotLocal
    }
}

fn union_not_with_finite(excluded: &[String], finite: Vec<Option<String>>) -> NamespaceConstraint {
    let includes_local = finite.contains(&None);
    let mut reduced = excluded.to_vec();
    for ns in finite.into_iter().flatten() {
        reduced.retain(|excluded_ns| excluded_ns != &ns);
    }
    if includes_local {
        any_except_constraint(reduced)
    } else {
        not_constraint(reduced)
    }
}

fn union_any_except_with_finite(
    excluded: &[String],
    finite: Vec<Option<String>>,
) -> NamespaceConstraint {
    let mut reduced = excluded.to_vec();
    for ns in finite.into_iter().flatten() {
        reduced.retain(|excluded_ns| excluded_ns != &ns);
    }
    any_except_constraint(reduced)
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_notlocal_with_no_target_namespace_is_any() {
        // `TargetNamespace(None)` is the no-namespace case (≡ Local). Its
        // union with NotLocal must cover every name → Any, not NotLocal
        // (which would wrongly exclude no-namespace names).
        let a = NamespaceConstraint::NotLocal;
        let b = NamespaceConstraint::TargetNamespace(None);
        assert!(matches!(
            union_namespace_constraints(&a, &b),
            NamespaceConstraint::Any
        ));
        assert!(matches!(
            union_namespace_constraints(&b, &a),
            NamespaceConstraint::Any
        ));
        // The resulting constraint must admit both no-namespace and any URI.
        let result = union_namespace_constraints(&a, &b);
        assert!(wildcard_allows_namespace(&result, None));
        assert!(wildcard_allows_namespace(&result, Some("urn:x")));
    }

    #[test]
    fn union_notlocal_with_local_list_is_any() {
        let a = NamespaceConstraint::NotLocal;
        let b = NamespaceConstraint::List(vec!["##local".into(), "urn:extra".into()]);

        let result = union_namespace_constraints(&a, &b);
        assert!(matches!(result, NamespaceConstraint::Any));
        assert!(wildcard_allows_namespace(&result, None));
        assert!(wildcard_allows_namespace(&result, Some("urn:x")));

        let result = union_namespace_constraints(&b, &a);
        assert!(matches!(result, NamespaceConstraint::Any));
        assert!(wildcard_allows_namespace(&result, None));
        assert!(wildcard_allows_namespace(&result, Some("urn:x")));
    }

    #[test]
    fn union_notlocal_with_specific_target_namespace_stays_notlocal() {
        // A specific (non-empty) target namespace is itself non-local, so the
        // union with NotLocal contributes nothing new and remains NotLocal.
        let a = NamespaceConstraint::NotLocal;
        let b = NamespaceConstraint::TargetNamespace(Some("urn:x".into()));
        assert!(matches!(
            union_namespace_constraints(&a, &b),
            NamespaceConstraint::NotLocal
        ));
    }

    #[test]
    fn union_other_with_local_excludes_target_namespace() {
        let other = NamespaceConstraint::Other(Some("urn:t".into()));
        let local = NamespaceConstraint::Local;

        let result = union_namespace_constraints(&other, &local);
        assert!(wildcard_allows_namespace(&result, None));
        assert!(wildcard_allows_namespace(&result, Some("urn:f")));
        assert!(!wildcard_allows_namespace(&result, Some("urn:t")));

        let result = union_namespace_constraints(&local, &other);
        assert!(wildcard_allows_namespace(&result, None));
        assert!(wildcard_allows_namespace(&result, Some("urn:f")));
        assert!(!wildcard_allows_namespace(&result, Some("urn:t")));
    }

    #[test]
    fn union_other_with_finite_list_is_precise() {
        let other = NamespaceConstraint::Other(Some("urn:t".into()));
        let list = NamespaceConstraint::List(vec!["##local".into(), "urn:f".into()]);

        let result = union_namespace_constraints(&other, &list);
        assert!(wildcard_allows_namespace(&result, None));
        assert!(wildcard_allows_namespace(&result, Some("urn:f")));
        assert!(wildcard_allows_namespace(&result, Some("urn:g")));
        assert!(!wildcard_allows_namespace(&result, Some("urn:t")));

        let list = NamespaceConstraint::List(vec!["urn:t".into()]);
        let result = union_namespace_constraints(&other, &list);
        assert!(wildcard_allows_namespace(&result, Some("urn:t")));
        assert!(wildcard_allows_namespace(&result, Some("urn:g")));
        assert!(!wildcard_allows_namespace(&result, None));
    }
}
