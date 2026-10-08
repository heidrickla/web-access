//! List item facet resolution helpers.
//!
//! When a list type's `itemType` is a user-defined simple type (not a built-in),
//! the item type's facets must be resolved in post-processing passes after
//! initial schema parsing. These functions walk through type references, content
//! models, and particles to resolve and store item facets for later validation.

use std::collections::HashMap;

use super::types::{BuiltInType, ContentModel, Facet, Particle, ParticleKind, TypeDef, TypeRef};

/// Type alias for resolved item facets map: (namespace, local_name) -> (base_type, facets).
type ResolvedItemsMap = HashMap<(Option<String>, String), (BuiltInType, Vec<Facet>)>;

/// Type alias for named list-type info: (namespace, local_name) -> (item_type, item_facets).
/// Only contains entries for named simple types that are themselves list types,
/// so presence in the map means "the base is a list".
pub(super) type ListBasesMap = HashMap<(Option<String>, String), (Option<BuiltInType>, Vec<Facet>)>;

/// Resolve list item facets for an inline SimpleTypeDef within a TypeRef.
/// Also recurses into inline ComplexTypeDefs to resolve their content model particles.
pub(super) fn resolve_inline_list_item_facets(
    type_ref: &mut TypeRef,
    resolved_items: &ResolvedItemsMap,
    list_bases: &ListBasesMap,
    schema_ns: &Option<String>,
) {
    if let TypeRef::Inline(td) = type_ref {
        match td.as_mut() {
            TypeDef::Simple(st) => {
                // An inline `<restriction base="SomeNamedListType">` does not
                // carry `is_list` at parse time — only the base's local name.
                // If that base is a list type, inherit list-ness (and the item
                // type/facets) so length facets count items, not characters
                // (issue #12). The global named-type pass in `builder.rs`
                // handles this for named derived types; this covers anonymous
                // inline types embedded in element declarations and particles.
                if !st.is_list {
                    if let Some(base_local) = &st._base_type_local {
                        let base_key = (schema_ns.clone(), base_local.clone());
                        if let Some((item_type, item_facets)) = list_bases.get(&base_key) {
                            st.is_list = true;
                            if st.item_type.is_none() {
                                st.item_type = item_type.clone();
                            }
                            if st.item_facets.is_empty() {
                                st.item_facets = item_facets.clone();
                            }
                        }
                    }
                }
                if st.is_list {
                    if let Some(item_name) = &st._item_type_local {
                        let item_key = (schema_ns.clone(), item_name.clone());
                        if let Some((item_base, item_facets)) = resolved_items.get(&item_key) {
                            st.item_type = Some(item_base.clone());
                            st.item_facets = item_facets.clone();
                        }
                    }
                }
            }
            TypeDef::Complex(ct) => {
                resolve_content_model_list_item_facets(
                    &mut ct.content,
                    resolved_items,
                    list_bases,
                    schema_ns,
                );
            }
        }
    }
}

/// Resolve list item facets in all inline types within a content model's particles.
pub(super) fn resolve_content_model_list_item_facets(
    content: &mut ContentModel,
    resolved_items: &ResolvedItemsMap,
    list_bases: &ListBasesMap,
    schema_ns: &Option<String>,
) {
    match content {
        ContentModel::Sequence(particles, _, _) | ContentModel::Choice(particles, _, _) => {
            resolve_particles_list_item_facets(particles, resolved_items, list_bases, schema_ns);
        }
        ContentModel::All(particles) => {
            resolve_particles_list_item_facets(particles, resolved_items, list_bases, schema_ns);
        }
        _ => {}
    }
}

/// Resolve list item facets in all particles recursively.
fn resolve_particles_list_item_facets(
    particles: &mut [Particle],
    resolved_items: &ResolvedItemsMap,
    list_bases: &ListBasesMap,
    schema_ns: &Option<String>,
) {
    for particle in particles.iter_mut() {
        match &mut particle.kind {
            ParticleKind::Element(decl) => {
                resolve_inline_list_item_facets(
                    &mut decl.type_ref,
                    resolved_items,
                    list_bases,
                    schema_ns,
                );
            }
            ParticleKind::Sequence(sub) | ParticleKind::Choice(sub) => {
                resolve_particles_list_item_facets(sub, resolved_items, list_bases, schema_ns);
            }
            ParticleKind::Any { .. } => {}
        }
    }
}
