#![forbid(unsafe_code)]

//! Key Derivation Functions: ConcatKDF (NIST SP 800-56A), PBKDF2, and HKDF (RFC 5869).

use bergshamra_core::{algorithm, Error};
use kryptering::algorithm::HashAlgorithm;

/// ConcatKDF parameters from XML.
#[derive(Debug, Clone, Default)]
pub struct ConcatKdfParams {
    /// Digest algorithm URI (e.g., SHA-256)
    pub digest_uri: Option<String>,
    /// AlgorithmID — hex-encoded in the XML
    pub algorithm_id: Option<Vec<u8>>,
    /// PartyUInfo — hex-encoded in the XML
    pub party_u_info: Option<Vec<u8>>,
    /// PartyVInfo — hex-encoded in the XML
    pub party_v_info: Option<Vec<u8>>,
}

/// PBKDF2 parameters from XML.
#[derive(Debug, Clone)]
pub struct Pbkdf2Params {
    /// PRF algorithm URI (e.g., HMAC-SHA256)
    pub prf_uri: String,
    /// Salt bytes
    pub salt: Vec<u8>,
    /// Iteration count
    pub iteration_count: u32,
    /// Desired key length in bytes
    pub key_length: usize,
}

/// HKDF parameters from XML (RFC 5869).
#[derive(Debug, Clone, Default)]
pub struct HkdfParams {
    /// PRF algorithm URI (e.g., HMAC-SHA256). Defaults to HMAC-SHA256 if not set.
    pub prf_uri: Option<String>,
    /// Optional salt bytes. When `None`, HKDF uses a zero-filled salt of hash length.
    pub salt: Option<Vec<u8>>,
    /// Optional info/context bytes for the HKDF-Expand step.
    pub info: Option<Vec<u8>>,
    /// Desired output key length in bits. Converted to bytes internally.
    /// If 0 or unset, the caller must supply `key_len` to `hkdf_derive()`.
    pub key_length_bits: u32,
}

/// Map an XML digest URI to `kryptering::HashAlgorithm`.
fn digest_uri_to_hash(uri: &str) -> Result<HashAlgorithm, Error> {
    match uri {
        algorithm::SHA1 => Ok(HashAlgorithm::Sha1),
        algorithm::SHA224 => Ok(HashAlgorithm::Sha224),
        algorithm::SHA256 => Ok(HashAlgorithm::Sha256),
        algorithm::SHA384 => Ok(HashAlgorithm::Sha384),
        algorithm::SHA512 => Ok(HashAlgorithm::Sha512),
        algorithm::SHA3_224 => Ok(HashAlgorithm::Sha3_224),
        algorithm::SHA3_256 => Ok(HashAlgorithm::Sha3_256),
        algorithm::SHA3_384 => Ok(HashAlgorithm::Sha3_384),
        algorithm::SHA3_512 => Ok(HashAlgorithm::Sha3_512),
        _ => Err(Error::UnsupportedAlgorithm(format!(
            "digest algorithm: {uri}"
        ))),
    }
}

/// Map an XML HMAC PRF URI to `kryptering::HashAlgorithm`.
fn prf_uri_to_hash(uri: &str) -> Result<HashAlgorithm, Error> {
    match uri {
        algorithm::HMAC_SHA1 => Ok(HashAlgorithm::Sha1),
        algorithm::HMAC_SHA224 => Ok(HashAlgorithm::Sha224),
        algorithm::HMAC_SHA256 => Ok(HashAlgorithm::Sha256),
        algorithm::HMAC_SHA384 => Ok(HashAlgorithm::Sha384),
        algorithm::HMAC_SHA512 => Ok(HashAlgorithm::Sha512),
        _ => Err(Error::UnsupportedAlgorithm(format!("PRF: {uri}"))),
    }
}

/// Derive a key using ConcatKDF (NIST SP 800-56A, Section 5.8.1).
pub fn concat_kdf(
    shared_secret: &[u8],
    key_len: usize,
    params: &ConcatKdfParams,
) -> Result<Vec<u8>, Error> {
    let digest_uri = params.digest_uri.as_deref().unwrap_or(algorithm::SHA256);
    let hash = digest_uri_to_hash(digest_uri)
        .map_err(|_| Error::UnsupportedAlgorithm(format!("ConcatKDF digest: {digest_uri}")))?;

    let k_params = kryptering::kdf::ConcatKdfParams {
        hash,
        algorithm_id: params.algorithm_id.clone(),
        party_u_info: params.party_u_info.clone(),
        party_v_info: params.party_v_info.clone(),
    };

    kryptering::kdf::concat_kdf(shared_secret, key_len, &k_params)
        .map_err(crate::map_kryptering_err)
}

/// Derive a key using PBKDF2 (RFC 8018).
pub fn pbkdf2_derive(password: &[u8], params: &Pbkdf2Params) -> Result<Vec<u8>, Error> {
    let hash = prf_uri_to_hash(&params.prf_uri)
        .map_err(|_| Error::UnsupportedAlgorithm(format!("PBKDF2 PRF: {}", params.prf_uri)))?;

    let k_params = kryptering::kdf::Pbkdf2Params {
        hash,
        salt: params.salt.clone(),
        iteration_count: params.iteration_count,
        key_length: params.key_length,
    };

    kryptering::kdf::pbkdf2_derive(password, &k_params).map_err(crate::map_kryptering_err)
}

/// Derive a key using HKDF (RFC 5869: Extract-then-Expand).
pub fn hkdf_derive(
    shared_secret: &[u8],
    key_len: usize,
    params: &HkdfParams,
) -> Result<Vec<u8>, Error> {
    let prf_uri = params.prf_uri.as_deref().unwrap_or(algorithm::HMAC_SHA256);
    let hash = prf_uri_to_hash(prf_uri)
        .map_err(|_| Error::UnsupportedAlgorithm(format!("HKDF PRF: {prf_uri}")))?;

    let k_params = kryptering::kdf::HkdfParams {
        hash,
        salt: params.salt.clone(),
        info: params.info.clone(),
        key_length_bits: params.key_length_bits,
    };

    kryptering::kdf::hkdf_derive(shared_secret, key_len, &k_params)
        .map_err(crate::map_kryptering_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_sha256_basic() {
        // RFC 5869 Test Case 1
        let ikm = [0x0b; 22];
        let salt = hex_decode("000102030405060708090a0b0c");
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");

        let params = HkdfParams {
            prf_uri: Some(algorithm::HMAC_SHA256.to_string()),
            salt: Some(salt),
            info: Some(info),
            key_length_bits: 336, // 42 bytes
        };

        let okm = hkdf_derive(&ikm, 0, &params).unwrap();
        assert_eq!(okm.len(), 42);
        assert_eq!(
            hex_encode(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_sha256_empty_salt_and_info() {
        // RFC 5869 Test Case 3: zero-length salt and info
        let ikm = [0x0b; 22];
        let params = HkdfParams {
            prf_uri: Some(algorithm::HMAC_SHA256.to_string()),
            salt: None,
            info: None,
            key_length_bits: 336, // 42 bytes
        };

        let okm = hkdf_derive(&ikm, 0, &params).unwrap();
        assert_eq!(okm.len(), 42);
        assert_eq!(
            hex_encode(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn hkdf_default_prf_is_sha256() {
        // When prf_uri is None, should default to HMAC-SHA256
        let ikm = [0x0b; 22];
        let params_explicit = HkdfParams {
            prf_uri: Some(algorithm::HMAC_SHA256.to_string()),
            salt: None,
            info: None,
            key_length_bits: 128,
        };
        let params_default = HkdfParams {
            prf_uri: None,
            salt: None,
            info: None,
            key_length_bits: 128,
        };

        let okm1 = hkdf_derive(&ikm, 0, &params_explicit).unwrap();
        let okm2 = hkdf_derive(&ikm, 0, &params_default).unwrap();
        assert_eq!(okm1, okm2);
    }

    #[test]
    fn hkdf_key_len_fallback() {
        // key_length_bits=0 should use the key_len parameter
        let ikm = [0x0b; 22];
        let params = HkdfParams {
            prf_uri: Some(algorithm::HMAC_SHA256.to_string()),
            salt: None,
            info: None,
            key_length_bits: 0,
        };

        let okm = hkdf_derive(&ikm, 32, &params).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn hkdf_unsupported_prf() {
        let params = HkdfParams {
            prf_uri: Some("http://example.com/unsupported".to_string()),
            ..Default::default()
        };
        let err = hkdf_derive(&[0u8; 16], 16, &params).unwrap_err();
        assert!(
            err.to_string().contains("HKDF PRF"),
            "unexpected error: {err}"
        );
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
