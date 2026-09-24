//! Sign-in sessions and connect tickets.
//!
//! | Credential   | Carried by          | Lifetime | Stored                          |
//! |--------------|---------------------|----------|---------------------------------|
//! | session      | `wa_session` cookie | 24 h     | SHA-256 of the token, database  |
//! | connect ticket | the RDP client's `authToken` | 60 s, one use | memory          |
//!
//! Sessions last a full shift (9 to 18 hours) and survive a browser restart and a service restart.
//! A connect ticket is minted when a user clicks a server, is bound to that user and that server,
//! and is spent by the WebSocket that carries the session.

use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Sign-in session lifetime. Work shifts run 9 to 18 hours.
pub const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// How long a connect ticket may wait for its WebSocket.
pub const TICKET_TTL: Duration = Duration::from_secs(60);
pub const COOKIE: &str = "wa_session";

/// 256 bits from the OS, hex encoded.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("the OS random source failed");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What the database keeps instead of the token.
pub fn token_hash(token: &str) -> Vec<u8> {
    digest(&SHA256, token.as_bytes()).as_ref().to_vec()
}

/// A persistent cookie, so closing the browser does not sign the user out.
pub fn session_cookie(token: &str, secure: bool) -> String {
    format!(
        "{COOKIE}={token}; Path=/; Max-Age={}; HttpOnly; SameSite=Strict{}",
        SESSION_TTL.as_secs(),
        if secure { "; Secure" } else { "" }
    )
}

pub fn clear_cookie(secure: bool) -> String {
    format!(
        "{COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict{}",
        if secure { "; Secure" } else { "" }
    )
}

/// The value of one cookie from a `Cookie` header.
pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (k, v) = pair.trim().split_once('=')?;
        (k == name && !v.is_empty()).then_some(v)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket {
    pub user_id: i64,
    pub server_id: i64,
}

struct Issued {
    ticket: Ticket,
    minted: Instant,
}

#[derive(Default)]
pub struct Tickets {
    issued: Mutex<HashMap<String, Issued>>,
}

impl Tickets {
    pub fn issue(&self, user_id: i64, server_id: i64) -> String {
        let token = random_token();
        let mut issued = self.issued.lock().unwrap_or_else(|p| p.into_inner());
        issued.retain(|_, v| v.minted.elapsed() < TICKET_TTL);
        issued.insert(
            token.clone(),
            Issued {
                ticket: Ticket { user_id, server_id },
                minted: Instant::now(),
            },
        );
        token
    }

    /// Spend a ticket. It is removed whether or not it is still valid, so it can never be tried twice.
    pub fn redeem(&self, token: &str) -> Option<Ticket> {
        self.redeem_at(token, Instant::now())
    }

    fn redeem_at(&self, token: &str, at: Instant) -> Option<Ticket> {
        let entry = self
            .issued
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(token)?;
        (at.saturating_duration_since(entry.minted) < TICKET_TTL).then_some(entry.ticket)
    }

    pub fn clear(&self) {
        self.issued.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
}

/// Failed local-account sign-ins allowed per username within the window before further attempts are
/// refused without checking the password.
pub const THROTTLE_FAILURES: usize = 5;
pub const THROTTLE_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Local accounts have no directory lockout policy behind them, so the proxy keeps its own.
#[derive(Default)]
pub struct Throttle {
    failures: Mutex<HashMap<String, Vec<Instant>>>,
}

impl Throttle {
    pub fn blocked(&self, key: &str) -> bool {
        self.blocked_at(key, Instant::now())
    }

    fn blocked_at(&self, key: &str, at: Instant) -> bool {
        let mut map = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        let Some(times) = map.get_mut(key) else {
            return false;
        };
        times.retain(|t| at.saturating_duration_since(*t) < THROTTLE_WINDOW);
        times.len() >= THROTTLE_FAILURES
    }

    pub fn fail(&self, key: &str) {
        self.fail_at(key, Instant::now());
    }

    fn fail_at(&self, key: &str, at: Instant) {
        let mut map = self.failures.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, v| v.last().is_some_and(|t| at.saturating_duration_since(*t) < THROTTLE_WINDOW));
        map.entry(key.to_owned()).or_default().push(at);
    }

    pub fn clear(&self, key: &str) {
        self.failures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(key);
    }

    #[cfg(test)]
    pub fn failures(&self, key: &str) -> usize {
        self.failures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(key)
            .map_or(0, Vec::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_throttle_blocks_after_five_failures_and_lifts_after_the_window() {
        let t = Throttle::default();
        let start = Instant::now();
        for _ in 0..THROTTLE_FAILURES - 1 {
            t.fail_at("devtest", start);
        }
        assert!(!t.blocked_at("devtest", start));
        t.fail_at("devtest", start);
        assert!(t.blocked_at("devtest", start));
        assert!(!t.blocked_at("someone-else", start));
        assert!(!t.blocked_at("devtest", start + THROTTLE_WINDOW));
        t.fail_at("devtest", start);
        t.clear("devtest");
        assert!(!t.blocked_at("devtest", start));
    }

    #[test]
    fn a_ticket_is_spent_by_its_first_use() {
        let t = Tickets::default();
        let token = t.issue(1, 2);
        assert_eq!(t.redeem(&token), Some(Ticket { user_id: 1, server_id: 2 }));
        assert_eq!(t.redeem(&token), None);
    }

    #[test]
    fn an_expired_ticket_is_refused() {
        let t = Tickets::default();
        let token = t.issue(1, 2);
        let later = Instant::now() + TICKET_TTL;
        assert_eq!(t.redeem_at(&token, later), None);
    }

    #[test]
    fn an_unknown_ticket_is_refused() {
        let t = Tickets::default();
        t.issue(1, 2);
        assert_eq!(t.redeem("deadbeef"), None);
        assert_eq!(t.redeem(""), None);
    }

    #[test]
    fn tokens_are_distinct_and_long() {
        let a = random_token();
        let b = random_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert_eq!(token_hash(&a).len(), 32);
    }

    #[test]
    fn the_session_cookie_is_persistent_for_a_day() {
        let c = session_cookie("abc", true);
        assert!(c.contains("Max-Age=86400"));
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Strict"));
        assert!(c.ends_with("; Secure"));
        assert!(!session_cookie("abc", false).contains("Secure"));
    }

    #[test]
    fn cookies_are_read_by_exact_name() {
        let h = "other=1; wa_session=tok; wa_session_x=2";
        assert_eq!(cookie_value(h, COOKIE), Some("tok"));
        assert_eq!(cookie_value("wa_sessionx=1", COOKIE), None);
        assert_eq!(cookie_value("wa_session=", COOKIE), None);
    }
}
