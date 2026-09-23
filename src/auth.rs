//! Authenticating the caller to the PROXY. Nothing here touches Windows credentials.
//!
//! Pass-through is settled: the user's own Windows account authenticates to the target, carried
//! inside the RDP stream the proxy does not decode. So this module establishes only who is asking,
//! never what they will log in as.
//!
//! The identity provider is an OPEN decision, which is why this is a trait. Swapping in OIDC, SAML
//! or an LDAP bind should not touch anything outside this file.

use crate::policy::Identity;
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("no credential presented")]
    Missing,
    #[error("credential not recognised")]
    Rejected,
}

pub trait Authenticator: Send + Sync {
    /// The token arrives in RDCleanPath's `proxy_auth` field.
    fn authenticate(&self, token: &str) -> Result<Identity, AuthError>;
}

/// Development authenticator: tokens mapped to identities in a file.
///
/// NOT AN IDENTITY PROVIDER. It exists so the proxy can be exercised end to end before the IdP
/// decision lands, and it is the one piece here designed to be deleted. It holds bearer tokens,
/// which is exactly the "proxy becomes a credential store" shape the architecture avoids elsewhere.
pub struct StaticAuthenticator {
    tokens: BTreeMap<String, Identity>,
}

impl StaticAuthenticator {
    pub fn new(tokens: BTreeMap<String, Identity>) -> Self {
        Self { tokens }
    }
}

impl Authenticator for StaticAuthenticator {
    fn authenticate(&self, token: &str) -> Result<Identity, AuthError> {
        if token.is_empty() {
            return Err(AuthError::Missing);
        }
        self.tokens.get(token).cloned().ok_or(AuthError::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> StaticAuthenticator {
        let mut tokens = BTreeMap::new();
        tokens.insert(
            "dev-token".to_owned(),
            Identity {
                subject: "lewis".into(),
                groups: vec!["OT-Historian-Admins".into()],
            },
        );
        StaticAuthenticator::new(tokens)
    }

    #[test]
    fn a_known_token_yields_its_identity() {
        let id = auth().authenticate("dev-token").expect("known");
        assert_eq!(id.subject, "lewis");
        assert_eq!(id.groups, vec!["OT-Historian-Admins".to_owned()]);
    }

    #[test]
    fn an_empty_token_is_missing_not_rejected() {
        assert!(matches!(auth().authenticate(""), Err(AuthError::Missing)));
    }

    #[test]
    fn an_unknown_token_is_rejected() {
        assert!(matches!(auth().authenticate("nope"), Err(AuthError::Rejected)));
    }
}
