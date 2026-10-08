#![forbid(unsafe_code)]

//! X.509 certificate chain validation.
//!
//! Validates leaf certificates against trusted roots with optional intermediate
//! certificates. Supports time override, CRL checking, and chain building.
//!
//! This module is a facade over [`tsp_ltv`] — the shared trust/validation
//! infrastructure used across the e-signing family of crates.

use bergshamra_core::Error;
use der::Decode;
use tsp_ltv::crypto::verify::SignaturePolicy;
use tsp_ltv::trust::{build_chain_from_pool_with_policy, trust_anchor_subjects, TrustStore};
use x509_cert::Certificate;

/// The signature-algorithm policy applied to certificate-chain verification.
///
/// When bergshamra is built with the `legacy-algorithms` feature, certificate
/// signatures over weak/deprecated digests (MD5/SHA-1/SHA-224) are accepted so
/// historical XML-DSig interop material (the merlin/phaos/aleksey/xmldsig11 test
/// corpora, all SHA-1-era) validates. Without that feature the strict,
/// fail-closed tsp-ltv default is used and weak-digest certificate chains are
/// rejected. This mirrors how bergshamra already gates legacy digest/signature
/// support elsewhere behind the same feature.
fn cert_signature_policy() -> SignaturePolicy {
    #[cfg(feature = "legacy-algorithms")]
    {
        SignaturePolicy::allow_legacy()
    }
    #[cfg(not(feature = "legacy-algorithms"))]
    {
        SignaturePolicy::strict()
    }
}

/// Configuration for X.509 certificate chain validation.
pub struct CertValidationConfig<'a> {
    /// Trusted CA certificates (DER-encoded).
    pub trusted_certs: &'a [Vec<u8>],
    /// Untrusted intermediate certificates (DER-encoded).
    pub untrusted_certs: &'a [Vec<u8>],
    /// CRLs (DER-encoded).
    pub crls: &'a [Vec<u8>],
    /// Override verification time (format: "YYYY-MM-DD+HH:MM:SS").
    pub verification_time: Option<&'a str>,
    /// Skip time validity checks.
    pub skip_time_checks: bool,
}

/// Validate a certificate chain from a leaf cert to a trusted root.
///
/// `leaf_der` is the DER-encoded leaf certificate.
/// `additional_certs` are extra certs from the XML (the full x509_chain from KeyInfo).
/// Returns `Ok(())` if the chain is valid, `Err` otherwise.
pub fn validate_cert_chain(
    leaf_der: &[u8],
    additional_certs: &[Vec<u8>],
    config: &CertValidationConfig<'_>,
) -> Result<(), Error> {
    let leaf = Certificate::from_der(leaf_der)
        .map_err(|e| Error::Certificate(format!("failed to parse leaf certificate: {e}")))?;

    let sig_policy = cert_signature_policy();

    // Build a TrustStore from the trusted certificates
    let mut trust_store = TrustStore::new().with_signature_policy(sig_policy);
    for der in config.trusted_certs {
        trust_store
            .add_der_certificate(der)
            .map_err(|e| Error::Certificate(format!("failed to add trusted cert: {e}")))?;
    }

    if trust_store.is_empty() {
        return Err(Error::Certificate(
            "no trusted certificates available".into(),
        ));
    }

    // Collect all available intermediate certs for chain building:
    // additional certs from XML + untrusted intermediates
    let mut pool: Vec<Certificate> = Vec::new();
    for der in additional_certs {
        if der.as_slice() == leaf_der {
            continue; // skip the leaf itself
        }
        if let Ok(c) = Certificate::from_der(der) {
            pool.push(c);
        }
    }
    for der in config.untrusted_certs {
        if let Ok(c) = Certificate::from_der(der) {
            pool.push(c);
        }
    }

    // Resolve validation time
    let validation_time = if config.skip_time_checks {
        None
    } else {
        Some(resolve_verification_time(config.verification_time)?)
    };

    // Check if the leaf is directly a trusted cert (self-signed trusted)
    let leaf_der_owned = leaf_der.to_vec();
    if trust_store.contains_der(&leaf_der_owned) {
        // Self-signed trusted cert — verify self-signature via tsp-ltv
        tsp_ltv::crypto::verify::verify_certificate_signature_with_policy(
            &leaf,
            &leaf,
            &sig_policy,
        )
        .map_err(|e| Error::Certificate(format!("self-signature verification failed: {e}")))?;
        // Check time validity if required
        if let Some(ref time) = validation_time {
            check_cert_time_validity(&leaf, time)?;
        }
        return Ok(());
    }

    // Build an ordered chain from leaf through intermediates. The per-link
    // signature checks honour the same policy the trust store will use, so a
    // weak-but-valid link is not dropped before verify_chain runs.
    let anchor_subjects = trust_anchor_subjects(&trust_store);
    let chain =
        build_chain_from_pool_with_policy(&leaf, &pool, &anchor_subjects, None, &sig_policy)
            .map_err(|e| Error::Certificate(format!("cannot build certificate chain: {e}")))?;

    // Verify the chain against the trust store
    trust_store
        .verify_chain(&chain, validation_time)
        .map_err(|e| Error::Certificate(format!("{e}")))?;

    // Check CRLs against the leaf cert
    if !config.crls.is_empty() {
        check_crls(&leaf, config.crls, config.verification_time)?;
    }

    Ok(())
}

/// Parse a verification time string into a `der::DateTime`.
/// Format: "YYYY-MM-DD+HH:MM:SS"
fn parse_verification_time(s: &str) -> Result<der::DateTime, Error> {
    let s = s.trim();
    if s.len() < 19 {
        return Err(Error::Certificate(format!(
            "invalid verification time format: {s}"
        )));
    }

    let year: u16 = s[0..4]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid year in time: {s}")))?;
    let month: u8 = s[5..7]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid month in time: {s}")))?;
    let day: u8 = s[8..10]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid day in time: {s}")))?;

    // Separator can be '+' or 'T'
    let rest = &s[11..];
    let hour: u8 = rest[0..2]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid hour in time: {s}")))?;
    let min: u8 = rest[3..5]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid minute in time: {s}")))?;
    let sec: u8 = rest[6..8]
        .parse()
        .map_err(|_| Error::Certificate(format!("invalid second in time: {s}")))?;

    der::DateTime::new(year, month, day, hour, min, sec)
        .map_err(|e| Error::Certificate(format!("invalid verification time: {e}")))
}

/// Get the current time as a `der::DateTime`, or use the override.
fn resolve_verification_time(override_time: Option<&str>) -> Result<der::DateTime, Error> {
    if let Some(time_str) = override_time {
        return parse_verification_time(time_str);
    }

    // Use current system time
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Certificate(format!("system time error: {e}")))?;

    der::DateTime::from_unix_duration(now)
        .map_err(|e| Error::Certificate(format!("time conversion error: {e}")))
}

/// Convert an x509_cert Time to der::DateTime.
fn x509_time_to_datetime(t: &x509_cert::time::Time) -> Result<der::DateTime, Error> {
    Ok(t.to_date_time())
}

/// Check if a certificate is valid at the given time.
fn check_cert_time_validity(cert: &Certificate, verif_time: &der::DateTime) -> Result<(), Error> {
    let not_before = x509_time_to_datetime(&cert.tbs_certificate.validity.not_before)?;
    let not_after = x509_time_to_datetime(&cert.tbs_certificate.validity.not_after)?;

    if *verif_time < not_before {
        return Err(Error::Certificate(format!(
            "certificate is not yet valid (notBefore: {not_before:?})"
        )));
    }
    if *verif_time > not_after {
        return Err(Error::Certificate(format!(
            "certificate has expired (notAfter: {not_after:?})"
        )));
    }

    Ok(())
}

/// Check leaf certificate against CRLs.
///
/// Always checks all CRLs regardless of CRL time validity (skip-time behavior).
/// When a cert serial is found in a CRL, it's considered revoked only if the
/// revocation date is at or before the verification time.
fn check_crls(
    leaf: &Certificate,
    crls: &[Vec<u8>],
    verification_time_str: Option<&str>,
) -> Result<(), Error> {
    use x509_cert::crl::CertificateList;

    let leaf_serial = &leaf.tbs_certificate.serial_number;
    let verif_time = resolve_verification_time(verification_time_str)?;

    for crl_der in crls {
        let crl = CertificateList::from_der(crl_der)
            .map_err(|e| Error::Certificate(format!("failed to parse CRL: {e}")))?;

        // Check if the leaf cert's serial is in the revoked list
        if let Some(ref revoked_certs) = crl.tbs_cert_list.revoked_certificates {
            for revoked in revoked_certs {
                if revoked.serial_number == *leaf_serial {
                    // Check revocation date against verification time
                    let revocation_time = x509_time_to_datetime(&revoked.revocation_date)?;
                    if verif_time >= revocation_time {
                        return Err(Error::Certificate(
                            "certificate has been revoked (found in CRL)".into(),
                        ));
                    }
                    // Revocation date is after verification time — cert wasn't revoked yet
                }
            }
        }
    }

    Ok(())
}
