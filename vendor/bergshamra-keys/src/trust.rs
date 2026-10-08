//! Trust store management for certificate chain validation.
//!
//! This module re-exports the trust store infrastructure from the shared [`tsp_ltv`] crate,
//! following the same facade pattern used by underskrift (PDF signing).
//!
//! Provides [`TrustStore`] for holding trusted CA certificates (trust anchors),
//! [`TrustStoreSet`] for managing separate stores for different purposes,
//! and [`build_chain_from_pool`] for building ordered certificate chains.

pub use tsp_ltv::trust::*;
