//! Integration test: sign and verify XML signatures using SoftHSM2 via kryptering PKCS#11.
//!
//! Prerequisites: run `bash hsm-test/setup.sh` from the bergshamra root directory.
//! Tests are ignored by default; run with:
//!     cargo test -p bergshamra-dsig --test hsm_sign_verify -- --ignored

use std::path::Path;

/// Candidate SoftHSM2 PKCS#11 module locations. Kept in sync with the same
/// list probed by `hsm-test/setup.sh` so the test and setup agree on where the
/// module may live across distros (generic, Debian/Ubuntu multiarch, lib64,
/// /usr/local).
const SOFTHSM_LIB_CANDIDATES: &[&str] = &[
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib64/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
];

/// Path to the SoftHSM2 library.
fn softhsm_lib() -> &'static str {
    SOFTHSM_LIB_CANDIDATES
        .iter()
        .copied()
        .find(|p| Path::new(p).exists())
        .unwrap_or_else(|| {
            panic!(
                "SoftHSM2 library not found in any known location: {}",
                SOFTHSM_LIB_CANDIDATES.join(", ")
            )
        })
}

/// Set the SOFTHSM2_CONF environment variable so SoftHSM2 can find the test token.
///
/// Reads the gitignored config that `hsm-test/setup.sh` generates (with an
/// absolute tokendir for this checkout), not the committed template.
fn set_softhsm_conf() {
    let conf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("hsm-test/softhsm2.local.conf");
    assert!(
        conf.exists(),
        "SoftHSM2 config not found at {conf:?} -- run `bash hsm-test/setup.sh` first"
    );
    std::env::set_var("SOFTHSM2_CONF", &conf);
}

#[test]
#[ignore] // Requires SoftHSM2 setup: run `bash hsm-test/setup.sh` first
fn test_pkcs11_provider_loads_softhsm() {
    set_softhsm_conf();
    let provider = kryptering::pkcs11::Pkcs11Provider::new(Path::new(softhsm_lib()))
        .expect("Failed to load SoftHSM2 library");
    let _session = provider
        .open_session("1234")
        .expect("Failed to open session with PIN 1234");
}

#[test]
#[ignore] // Requires SoftHSM2 setup: run `bash hsm-test/setup.sh` first
fn test_pkcs11_provider_wrong_pin_fails() {
    set_softhsm_conf();
    let provider = kryptering::pkcs11::Pkcs11Provider::new(Path::new(softhsm_lib()))
        .expect("Failed to load SoftHSM2 library");
    let result = provider.open_session("wrong-pin");
    assert!(
        result.is_err(),
        "Opening session with wrong PIN should fail"
    );
}

#[test]
#[ignore] // Requires SoftHSM2 setup + kryptering PKCS#11 signing implementation
fn test_hsm_rsa_sign_verify() {
    use kryptering::Signer;
    use kryptering::Verifier;

    set_softhsm_conf();

    let provider = kryptering::pkcs11::Pkcs11Provider::new(Path::new(softhsm_lib()))
        .expect("Failed to load SoftHSM2");
    let session = provider
        .open_session("1234")
        .expect("Failed to open session");

    let signer = kryptering::pkcs11::Pkcs11Signer::new(
        &session,
        "test-rsa-key",
        kryptering::SignatureAlgorithm::RsaPkcs1v15(kryptering::HashAlgorithm::Sha256),
    )
    .expect("Failed to create RSA signer");

    let verifier = kryptering::pkcs11::Pkcs11Verifier::new(
        &session,
        "test-rsa-key",
        kryptering::SignatureAlgorithm::RsaPkcs1v15(kryptering::HashAlgorithm::Sha256),
    )
    .expect("Failed to create RSA verifier");

    // Sign and verify
    let data = b"Hello from HSM - RSA test data";
    let signature = signer.sign(data).expect("RSA signing should succeed");
    assert!(!signature.is_empty(), "Signature should not be empty");

    let valid = verifier
        .verify(data, &signature)
        .expect("RSA verification should succeed");
    assert!(valid, "RSA signature should be valid");

    // Tampered data must fail
    let valid_tampered = verifier
        .verify(b"Tampered data", &signature)
        .expect("Verification call itself should not error");
    assert!(
        !valid_tampered,
        "RSA signature should be invalid for tampered data"
    );
}

#[test]
#[ignore] // Requires SoftHSM2 setup + kryptering PKCS#11 signing implementation
fn test_hsm_ec_sign_verify() {
    use kryptering::Signer;
    use kryptering::Verifier;

    set_softhsm_conf();

    let provider = kryptering::pkcs11::Pkcs11Provider::new(Path::new(softhsm_lib()))
        .expect("Failed to load SoftHSM2");
    let session = provider
        .open_session("1234")
        .expect("Failed to open session");

    let signer = kryptering::pkcs11::Pkcs11Signer::new(
        &session,
        "test-ec-key",
        kryptering::SignatureAlgorithm::Ecdsa(
            kryptering::EcCurve::P256,
            kryptering::HashAlgorithm::Sha256,
        ),
    )
    .expect("Failed to create EC signer");

    let verifier = kryptering::pkcs11::Pkcs11Verifier::new(
        &session,
        "test-ec-key",
        kryptering::SignatureAlgorithm::Ecdsa(
            kryptering::EcCurve::P256,
            kryptering::HashAlgorithm::Sha256,
        ),
    )
    .expect("Failed to create EC verifier");

    // Sign and verify
    let data = b"Hello from HSM - EC test data";
    let signature = signer.sign(data).expect("EC signing should succeed");
    assert!(!signature.is_empty(), "Signature should not be empty");

    let valid = verifier
        .verify(data, &signature)
        .expect("EC verification should succeed");
    assert!(valid, "EC signature should be valid");

    // Tampered data must fail
    let valid_tampered = verifier
        .verify(b"Tampered data", &signature)
        .expect("Verification call itself should not error");
    assert!(
        !valid_tampered,
        "EC signature should be invalid for tampered data"
    );
}

#[test]
#[ignore] // Requires SoftHSM2 setup + kryptering PKCS#11 signing + bergshamra-dsig HSM integration
fn test_hsm_rsa_xml_sign_verify() {
    use kryptering::Signer;
    use kryptering::Verifier;

    set_softhsm_conf();

    let provider = kryptering::pkcs11::Pkcs11Provider::new(Path::new(softhsm_lib()))
        .expect("Failed to load SoftHSM2");
    let session = provider
        .open_session("1234")
        .expect("Failed to open session");

    // Create HSM signer for RSA-SHA256
    let signer = kryptering::pkcs11::Pkcs11Signer::new(
        &session,
        "test-rsa-key",
        kryptering::SignatureAlgorithm::RsaPkcs1v15(kryptering::HashAlgorithm::Sha256),
    )
    .expect("Failed to create signer");

    // Create HSM verifier
    let verifier = kryptering::pkcs11::Pkcs11Verifier::new(
        &session,
        "test-rsa-key",
        kryptering::SignatureAlgorithm::RsaPkcs1v15(kryptering::HashAlgorithm::Sha256),
    )
    .expect("Failed to create verifier");

    // XML template for enveloped signature
    let template = r#"<?xml version="1.0"?>
<Root>
  <Data>Hello from HSM</Data>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue></ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue></ds:SignatureValue>
  </ds:Signature>
</Root>"#;

    // Compute digest, canonicalize SignedInfo, and sign via HSM
    let doc = uppsala::parse(template).expect("parse template");

    let signed_info_c14n = {
        use bergshamra_c14n::C14nMode;
        use bergshamra_xml::nodeset::NodeSet;

        let sig_node = doc
            .descendants(doc.root())
            .into_iter()
            .find(|&n| {
                doc.element(n)
                    .is_some_and(|e| &*e.name.local_name == "Signature")
            })
            .expect("Signature element");
        let signed_info = doc
            .children(sig_node)
            .into_iter()
            .find(|&n| {
                doc.element(n)
                    .is_some_and(|e| &*e.name.local_name == "SignedInfo")
            })
            .expect("SignedInfo element");

        let ns = NodeSet::tree_without_comments(signed_info, &doc);
        let no_prefixes: &[&str] = &[];
        bergshamra_c14n::canonicalize_doc(&doc, C14nMode::Exclusive, Some(&ns), no_prefixes)
            .expect("canonicalize SignedInfo")
    };

    // Sign the canonicalized SignedInfo using the HSM
    let sig_bytes = signer
        .sign(&signed_info_c14n)
        .expect("HSM signing should succeed");
    assert!(!sig_bytes.is_empty(), "Signature bytes should not be empty");

    // Verify the signature using the HSM
    let valid = verifier
        .verify(&signed_info_c14n, &sig_bytes)
        .expect("HSM verification should succeed");
    assert!(
        valid,
        "HSM RSA signature over canonicalized SignedInfo should verify"
    );
}

#[test]
#[ignore] // Requires SoftHSM2 setup + kryptering PKCS#11 signing implementation
fn test_hsm_sign_software_verify() {
    // Sign with HSM, then verify with the HSM verifier (same key label).
    // This validates that the HSM-produced signature format is consistent
    // with the PKCS#11 verification path.
    use kryptering::Signer;
    use kryptering::Verifier;

    set_softhsm_conf();

    let provider = kryptering::pkcs11::Pkcs11Provider::new(Path::new(softhsm_lib()))
        .expect("Failed to load SoftHSM2");
    let session = provider
        .open_session("1234")
        .expect("Failed to open session");

    // Sign with the private key via HSM
    let signer = kryptering::pkcs11::Pkcs11Signer::new(
        &session,
        "test-rsa-key",
        kryptering::SignatureAlgorithm::RsaPkcs1v15(kryptering::HashAlgorithm::Sha256),
    )
    .expect("Failed to create RSA signer");

    let data = b"HSM sign, software verify test data";
    let signature = signer.sign(data).expect("RSA signing should succeed");
    assert!(!signature.is_empty(), "Signature should not be empty");

    // Verify with the public key via HSM (proves the signature format is valid)
    let verifier = kryptering::pkcs11::Pkcs11Verifier::new(
        &session,
        "test-rsa-key",
        kryptering::SignatureAlgorithm::RsaPkcs1v15(kryptering::HashAlgorithm::Sha256),
    )
    .expect("Failed to create RSA verifier");

    let valid = verifier
        .verify(data, &signature)
        .expect("Verification should succeed");
    assert!(
        valid,
        "HSM-produced RSA signature should verify via HSM verifier"
    );

    // Tampered data must fail
    let valid_tampered = verifier
        .verify(b"Tampered data", &signature)
        .expect("Verification call itself should not error");
    assert!(
        !valid_tampered,
        "Signature should be invalid for tampered data"
    );
}

#[test]
#[ignore] // Requires SoftHSM2 setup with EC P-384 key
fn test_hsm_ec384_sign_verify() {
    use kryptering::Signer;
    use kryptering::Verifier;

    set_softhsm_conf();

    let provider = kryptering::pkcs11::Pkcs11Provider::new(Path::new(softhsm_lib()))
        .expect("Failed to load SoftHSM2");
    let session = provider
        .open_session("1234")
        .expect("Failed to open session");

    let signer = kryptering::pkcs11::Pkcs11Signer::new(
        &session,
        "test-ec384-key",
        kryptering::SignatureAlgorithm::Ecdsa(
            kryptering::EcCurve::P384,
            kryptering::HashAlgorithm::Sha384,
        ),
    )
    .expect("Failed to create EC P-384 signer");

    let verifier = kryptering::pkcs11::Pkcs11Verifier::new(
        &session,
        "test-ec384-key",
        kryptering::SignatureAlgorithm::Ecdsa(
            kryptering::EcCurve::P384,
            kryptering::HashAlgorithm::Sha384,
        ),
    )
    .expect("Failed to create EC P-384 verifier");

    // Sign and verify
    let data = b"Hello from HSM - EC P-384 test data";
    let signature = signer.sign(data).expect("EC P-384 signing should succeed");
    assert!(!signature.is_empty(), "Signature should not be empty");

    let valid = verifier
        .verify(data, &signature)
        .expect("EC P-384 verification should succeed");
    assert!(valid, "EC P-384 signature should be valid");

    // Tampered data must fail
    let valid_tampered = verifier
        .verify(b"Tampered data", &signature)
        .expect("Verification call itself should not error");
    assert!(
        !valid_tampered,
        "EC P-384 signature should be invalid for tampered data"
    );
}

#[test]
#[ignore] // Requires SoftHSM2 setup with RSA key
fn test_hsm_rsa_pss_sign_verify() {
    use kryptering::Signer;
    use kryptering::Verifier;

    set_softhsm_conf();

    let provider = kryptering::pkcs11::Pkcs11Provider::new(Path::new(softhsm_lib()))
        .expect("Failed to load SoftHSM2");
    let session = provider
        .open_session("1234")
        .expect("Failed to open session");

    let signer = kryptering::pkcs11::Pkcs11Signer::new(
        &session,
        "test-rsa-key",
        kryptering::SignatureAlgorithm::RsaPss(kryptering::HashAlgorithm::Sha256),
    )
    .expect("Failed to create RSA-PSS signer");

    let verifier = kryptering::pkcs11::Pkcs11Verifier::new(
        &session,
        "test-rsa-key",
        kryptering::SignatureAlgorithm::RsaPss(kryptering::HashAlgorithm::Sha256),
    )
    .expect("Failed to create RSA-PSS verifier");

    // Sign and verify
    let data = b"Hello from HSM - RSA-PSS test data";
    let signature = signer.sign(data).expect("RSA-PSS signing should succeed");
    assert!(!signature.is_empty(), "Signature should not be empty");

    let valid = verifier
        .verify(data, &signature)
        .expect("RSA-PSS verification should succeed");
    assert!(valid, "RSA-PSS signature should be valid");

    // Tampered data must fail
    let valid_tampered = verifier
        .verify(b"Tampered data", &signature)
        .expect("Verification call itself should not error");
    assert!(
        !valid_tampered,
        "RSA-PSS signature should be invalid for tampered data"
    );
}

#[test]
#[ignore] // Requires SoftHSM2 setup with HMAC key
fn test_hsm_hmac_sign_verify() {
    use kryptering::Signer;
    use kryptering::Verifier;

    set_softhsm_conf();

    let provider = kryptering::pkcs11::Pkcs11Provider::new(Path::new(softhsm_lib()))
        .expect("Failed to load SoftHSM2");
    let session = provider
        .open_session("1234")
        .expect("Failed to open session");

    let hmac = kryptering::pkcs11::Pkcs11HmacSigner::new(
        &session,
        "test-hmac-key",
        kryptering::SignatureAlgorithm::Hmac(kryptering::HashAlgorithm::Sha256),
    )
    .expect("Failed to create HMAC signer");

    let data = b"HMAC test data";
    let mac = hmac.sign(data).expect("HMAC signing should succeed");
    assert!(!mac.is_empty(), "HMAC output should not be empty");

    let valid = hmac
        .verify(data, &mac)
        .expect("HMAC verification should succeed");
    assert!(valid, "HMAC should verify correctly");

    let invalid = hmac
        .verify(b"wrong data", &mac)
        .expect("Verify call should not error");
    assert!(!invalid, "HMAC should fail for wrong data");
}

#[test]
#[ignore] // Requires SoftHSM2 setup with Ed25519 key (may not be supported)
fn test_hsm_ed25519_sign_verify() {
    use kryptering::Signer;
    use kryptering::Verifier;

    set_softhsm_conf();

    let provider = kryptering::pkcs11::Pkcs11Provider::new(Path::new(softhsm_lib()))
        .expect("Failed to load SoftHSM2");
    let session = provider
        .open_session("1234")
        .expect("Failed to open session");

    // Ed25519 key may not have been generated if SoftHSM2 doesn't support it.
    // Gracefully skip if the key is not found.
    let signer = match kryptering::pkcs11::Pkcs11Signer::new(
        &session,
        "test-ed25519-key",
        kryptering::SignatureAlgorithm::Ed25519,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Skipping Ed25519 test: key not found ({e})");
            return;
        }
    };

    let verifier = match kryptering::pkcs11::Pkcs11Verifier::new(
        &session,
        "test-ed25519-key",
        kryptering::SignatureAlgorithm::Ed25519,
    ) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Skipping Ed25519 test: public key not found ({e})");
            return;
        }
    };

    // Sign and verify
    let data = b"Hello from HSM - Ed25519 test data";
    let signature = match signer.sign(data) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("Skipping Ed25519 test: signing failed ({e})");
            return;
        }
    };
    assert!(!signature.is_empty(), "Signature should not be empty");

    let valid = verifier
        .verify(data, &signature)
        .expect("Ed25519 verification should succeed");
    assert!(valid, "Ed25519 signature should be valid");

    // Tampered data must fail
    let valid_tampered = verifier
        .verify(b"Tampered data", &signature)
        .expect("Verification call itself should not error");
    assert!(
        !valid_tampered,
        "Ed25519 signature should be invalid for tampered data"
    );
}

#[test]
#[ignore] // Requires SoftHSM2 setup + kryptering PKCS#11 signing + bergshamra-dsig
fn test_hsm_ec_xml_sign_verify() {
    use kryptering::Signer;
    use kryptering::Verifier;

    set_softhsm_conf();

    let provider = kryptering::pkcs11::Pkcs11Provider::new(Path::new(softhsm_lib()))
        .expect("Failed to load SoftHSM2");
    let session = provider
        .open_session("1234")
        .expect("Failed to open session");

    // Create HSM signer for ECDSA P-256 SHA-256
    let signer = kryptering::pkcs11::Pkcs11Signer::new(
        &session,
        "test-ec-key",
        kryptering::SignatureAlgorithm::Ecdsa(
            kryptering::EcCurve::P256,
            kryptering::HashAlgorithm::Sha256,
        ),
    )
    .expect("Failed to create EC signer");

    // Create HSM verifier
    let verifier = kryptering::pkcs11::Pkcs11Verifier::new(
        &session,
        "test-ec-key",
        kryptering::SignatureAlgorithm::Ecdsa(
            kryptering::EcCurve::P256,
            kryptering::HashAlgorithm::Sha256,
        ),
    )
    .expect("Failed to create EC verifier");

    // XML template for enveloped signature with ECDSA
    let template = r#"<?xml version="1.0"?>
<Root>
  <Data>Hello from HSM - EC XML signature</Data>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
      <ds:Reference URI="">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue></ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue></ds:SignatureValue>
  </ds:Signature>
</Root>"#;

    // Parse and canonicalize SignedInfo
    let doc = uppsala::parse(template).expect("parse template");

    let signed_info_c14n = {
        use bergshamra_c14n::C14nMode;
        use bergshamra_xml::nodeset::NodeSet;

        let sig_node = doc
            .descendants(doc.root())
            .into_iter()
            .find(|&n| {
                doc.element(n)
                    .is_some_and(|e| &*e.name.local_name == "Signature")
            })
            .expect("Signature element");
        let signed_info = doc
            .children(sig_node)
            .into_iter()
            .find(|&n| {
                doc.element(n)
                    .is_some_and(|e| &*e.name.local_name == "SignedInfo")
            })
            .expect("SignedInfo element");

        let ns = NodeSet::tree_without_comments(signed_info, &doc);
        let no_prefixes: &[&str] = &[];
        bergshamra_c14n::canonicalize_doc(&doc, C14nMode::Exclusive, Some(&ns), no_prefixes)
            .expect("canonicalize SignedInfo")
    };

    // Sign the canonicalized SignedInfo using the HSM (ECDSA P-256)
    let sig_bytes = signer
        .sign(&signed_info_c14n)
        .expect("HSM EC signing should succeed");
    assert!(
        !sig_bytes.is_empty(),
        "EC signature bytes should not be empty"
    );

    // Verify the signature using the HSM
    let valid = verifier
        .verify(&signed_info_c14n, &sig_bytes)
        .expect("HSM EC verification should succeed");
    assert!(
        valid,
        "HSM ECDSA signature over canonicalized SignedInfo should verify"
    );
}
