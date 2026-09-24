//! Every WebSocket connection carrying (or about to carry) an RDP session, from the moment it is
//! upgraded. Registered BEFORE the handshake, so a connection still setting up can be ended by
//! revocation, sign-out, assignment removal or an import just like an established one.

use std::collections::HashSet;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tokio::sync::oneshot;

struct Live {
    user_id: i64,
    /// The sign-in session the connection was opened under. It ends when that session ends.
    token_hash: Vec<u8>,
    /// Known once the connect ticket is redeemed.
    server_id: Option<i64>,
    /// True once bytes flow to the server.
    established: bool,
    cancel: Option<oneshot::Sender<()>>,
}

/// What is left of a connection when it is removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ended {
    pub user_id: i64,
    pub server_id: Option<i64>,
    pub established: bool,
}

#[derive(Default)]
pub struct LiveSessions {
    inner: Mutex<HashMap<u64, Live>>,
    next: AtomicU64,
}

impl LiveSessions {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Live>> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Register a connection at upgrade. The receiver fires when it must end.
    pub fn register(&self, user_id: i64, token_hash: Vec<u8>) -> (u64, oneshot::Receiver<()>) {
        let (tx, rx) = oneshot::channel();
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.lock().insert(
            id,
            Live {
                user_id,
                token_hash,
                server_id: None,
                established: false,
                cancel: Some(tx),
            },
        );
        (id, rx)
    }

    pub fn set_server(&self, id: u64, server_id: i64) {
        if let Some(l) = self.lock().get_mut(&id) {
            l.server_id = Some(server_id);
        }
    }

    pub fn set_established(&self, id: u64) {
        if let Some(l) = self.lock().get_mut(&id) {
            l.established = true;
        }
    }

    pub fn remove(&self, id: u64) -> Option<Ended> {
        self.lock().remove(&id).map(|l| Ended {
            user_id: l.user_id,
            server_id: l.server_id,
            established: l.established,
        })
    }

    fn end_where(&self, pred: impl Fn(&Live) -> bool) -> usize {
        let mut inner = self.lock();
        let mut n = 0;
        for live in inner.values_mut().filter(|l| pred(l)) {
            if let Some(tx) = live.cancel.take() {
                let _ = tx.send(());
                n += 1;
            }
        }
        n
    }

    /// End every connection a user has, established or not.
    pub fn end_user(&self, user_id: i64) -> usize {
        self.end_where(|l| l.user_id == user_id)
    }

    /// End a user's connections to one server, after the assignment is removed.
    pub fn end_user_server(&self, user_id: i64, server_id: i64) -> usize {
        self.end_where(|l| l.user_id == user_id && l.server_id == Some(server_id))
    }

    /// End every connection to a server, after the server is deleted.
    pub fn end_server(&self, server_id: i64) -> usize {
        self.end_where(|l| l.server_id == Some(server_id))
    }

    /// End the connections opened under one sign-in session, when it is signed out.
    pub fn end_session(&self, token_hash: &[u8]) -> usize {
        self.end_where(|l| l.token_hash == token_hash)
    }

    /// End everything, after an import has replaced the identities the connections were admitted
    /// under.
    pub fn end_all(&self) -> usize {
        self.end_where(|_| true)
    }

    /// (id, user, sign-in session) for every connection, for the session-validity check.
    pub fn connections(&self) -> Vec<(u64, i64, Vec<u8>)> {
        self.lock()
            .iter()
            .map(|(id, l)| (*id, l.user_id, l.token_hash.clone()))
            .collect()
    }

    /// End specific connections by id.
    pub fn end_ids(&self, ids: &[u64]) -> usize {
        let mut inner = self.lock();
        let mut n = 0;
        for id in ids {
            if let Some(tx) = inner.get_mut(id).and_then(|l| l.cancel.take()) {
                let _ = tx.send(());
                n += 1;
            }
        }
        n
    }

    /// Users with any connection, established or setting up.
    pub fn user_ids(&self) -> HashSet<i64> {
        self.lock().values().map(|l| l.user_id).collect()
    }

    /// Servers this user has an established session to.
    pub fn servers_for(&self, user_id: i64) -> HashSet<i64> {
        self.lock()
            .values()
            .filter(|l| l.user_id == user_id && l.established)
            .filter_map(|l| l.server_id)
            .collect()
    }

    pub fn count(&self) -> usize {
        self.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ending_a_user_signals_only_their_connections_including_pending_ones() {
        let live = LiveSessions::default();
        let (a, mut ra) = live.register(1, b"s1".to_vec());
        let (_, mut rb) = live.register(1, b"s1".to_vec()); // still setting up: no server yet
        let (_, mut rc) = live.register(2, b"s2".to_vec());
        live.set_server(a, 10);
        live.set_established(a);
        assert_eq!(live.end_user(1), 2);
        assert!(ra.try_recv().is_ok());
        assert!(rb.try_recv().is_ok(), "a pending connection is ended too");
        assert!(rc.try_recv().is_err());
    }

    #[test]
    fn signing_out_ends_only_that_sessions_connections() {
        let live = LiveSessions::default();
        let (_, mut r1) = live.register(1, b"phone".to_vec());
        let (_, mut r2) = live.register(1, b"desk".to_vec());
        assert_eq!(live.end_session(b"phone"), 1);
        assert!(r1.try_recv().is_ok());
        assert!(r2.try_recv().is_err());
    }

    #[test]
    fn only_established_sessions_count_as_connected() {
        let live = LiveSessions::default();
        let (a, _ra) = live.register(1, b"s".to_vec());
        live.set_server(a, 10);
        assert!(live.servers_for(1).is_empty());
        live.set_established(a);
        assert_eq!(live.servers_for(1), HashSet::from([10]));
        assert_eq!(
            live.remove(a),
            Some(Ended { user_id: 1, server_id: Some(10), established: true })
        );
        assert_eq!(live.count(), 0);
    }

    #[test]
    fn removing_an_assignment_ends_connections_to_that_server_only() {
        let live = LiveSessions::default();
        let (a, mut ra) = live.register(1, b"s".to_vec());
        let (b, mut rb) = live.register(1, b"s".to_vec());
        live.set_server(a, 10);
        live.set_server(b, 11);
        assert_eq!(live.end_user_server(1, 10), 1);
        assert!(ra.try_recv().is_ok());
        assert!(rb.try_recv().is_err());
    }
}
