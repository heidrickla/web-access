//! Cryptographic primitives for certificate and signature verification.
//!
//! Provides digest algorithms, signature verification, and OID mappings
//! used by the TSP, OCSP, CRL, and trust store modules.

pub mod algorithm;
pub mod verify;
