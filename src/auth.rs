//! Authenticating the caller to the PROXY. Nothing here touches Windows credentials.
//!
//! Pass-through is settled: the user's own Windows account authenticates to the target, carried
//! inside the RDP stream the proxy does not decode. So this module establishes only who is asking.
//!
//! THE USER NEVER TYPES A PROXY TOKEN. One is minted when the page is served and handed to it with
//! the target list; the browser sends it back on the WebSocket. It is a machine concern and it stays
//! one.
//!
//! The identity provider is an OPEN decision, which is why `identify` is the single function that
//! changes when it lands. Until then everyone who can reach the proxy is treated as permitted to
//! everything the config grants, which is a NETWORK-enforced boundary and not an identity one. That
//! is stated loudly at startup rather than hidden behind a token box that only looked like security.

use crate::policy::Identity;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// How long a minted token stays usable. Long enough to open a session from a page that has been
/// sitting on a second monitor, short enough that a leaked one is not a standing key.
const TOKEN_TTL: Duration = Duration::from_secs(8 * 60 * 60);

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("no credential presented")]
    Missing,
    #[error("credential not recognised")]
    Rejected,
    #[error("credential expired")]
    Expired,
}

struct Issued {
    identity: Identity,
    minted: Instant,
}

#[derive(Default)]
pub struct Sessions {
    issued: Mutex<HashMap<String, Issued>>,
}

impl Sessions {
    pub fn global() -> &'static Sessions {
        static SESSIONS: OnceLock<Sessions> = OnceLock::new();
        SESSIONS.get_or_init(Sessions::default)
    }

    /// Mint a token for a caller the proxy has just served a page to.
    pub fn mint(&self, identity: Identity) -> String {
        let token = random_token();
        let mut issued = self.issued.lock().expect("sessions poisoned");
        issued.retain(|_, v| v.minted.elapsed() < TOKEN_TTL);
        issued.insert(
            token.clone(),
            Issued {
                identity,
                minted: Instant::now(),
            },
        );
        token
    }

    pub fn authenticate(&self, token: &str) -> Result<Identity, AuthError> {
        if token.is_empty() {
            return Err(AuthError::Missing);
        }
        let issued = self.issued.lock().expect("sessions poisoned");
        match issued.get(token) {
            None => Err(AuthError::Rejected),
            Some(entry) if entry.minted.elapsed() >= TOKEN_TTL => Err(AuthError::Expired),
            Some(entry) => Ok(entry.identity.clone()),
        }
    }

    #[cfg(test)]
    pub fn count(&self) -> usize {
        self.issued.lock().expect("sessions poisoned").len()
    }
}

/// 256 bits from the OS, hex encoded. `ring` is already in the tree as rustls' crypto backend, so
/// this adds no dependency and does not invent its own randomness.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("the OS random source failed");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// THE POINT WHERE AN IDENTITY PROVIDER WILL PLUG IN. Everything else in this codebase is written
/// against `Identity` and does not care where it came from.
pub fn identify(all_groups: &[String]) -> Identity {
    Identity {
        subject: "anonymous".to_owned(),
        groups: all_groups.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            subject: "lewis".into(),
            groups: vec!["OT-Historian-Admins".into()],
        }
    }

    #[test]
    fn a_minted_token_authenticates_once_minted() {
        let s = Sessions::default();
        let token = s.mint(identity());
        assert_eq!(s.authenticate(&token).unwrap().subject, "lewis");
    }

    #[test]
    fn an_unminted_token_is_rejected() {
        let s = Sessions::default();
        s.mint(identity());
        assert!(matches!(s.authenticate("deadbeef"), Err(AuthError::Rejected)));
    }

    #[test]
    fn an_empty_token_is_missing() {
        let s = Sessions::default();
        assert!(matches!(s.authenticate(""), Err(AuthError::Missing)));
    }

    #[test]
    fn tokens_are_distinct_and_long() {
        let s = Sessions::default();
        let a = s.mint(identity());
        let b = s.mint(identity());
        assert_ne!(a, b);
        assert_eq!(a.len(), 64, "256 bits hex encoded");
        assert_eq!(s.count(), 2);
    }
}
