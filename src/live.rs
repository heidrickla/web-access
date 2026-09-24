//! RDP sessions running through this proxy right now, so a revoked user's sessions can be ended and
//! a user's list can show which servers they are connected to.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tokio::sync::oneshot;

struct Live {
    user_id: i64,
    server_id: i64,
    cancel: Option<oneshot::Sender<()>>,
}

#[derive(Default)]
pub struct LiveSessions {
    inner: Mutex<HashMap<u64, Live>>,
    next: AtomicU64,
}

impl LiveSessions {
    /// Register a session. The receiver fires when the session must end.
    pub fn register(&self, user_id: i64, server_id: i64) -> (u64, oneshot::Receiver<()>) {
        let (tx, rx) = oneshot::channel();
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).insert(
            id,
            Live {
                user_id,
                server_id,
                cancel: Some(tx),
            },
        );
        (id, rx)
    }

    pub fn unregister(&self, id: u64) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).remove(&id);
    }

    /// End every session a user has open. Returns how many were signalled.
    pub fn end_user(&self, user_id: i64) -> usize {
        self.end_where(|l| l.user_id == user_id)
    }

    /// End a user's sessions to one server, after the assignment is removed.
    pub fn end_user_server(&self, user_id: i64, server_id: i64) -> usize {
        self.end_where(|l| l.user_id == user_id && l.server_id == server_id)
    }

    /// End every session to a server, after the server is deleted.
    pub fn end_server(&self, server_id: i64) -> usize {
        self.end_where(|l| l.server_id == server_id)
    }

    fn end_where(&self, pred: impl Fn(&Live) -> bool) -> usize {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut n = 0;
        for live in inner.values_mut().filter(|l| pred(l)) {
            if let Some(tx) = live.cancel.take() {
                let _ = tx.send(());
                n += 1;
            }
        }
        n
    }

    /// Servers this user has a session open to.
    pub fn servers_for(&self, user_id: i64) -> HashSet<i64> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .filter(|l| l.user_id == user_id)
            .map(|l| l.server_id)
            .collect()
    }

    pub fn count(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ending_a_user_signals_only_their_sessions() {
        let live = LiveSessions::default();
        let (_, mut a) = live.register(1, 10);
        let (_, mut b) = live.register(1, 11);
        let (_, mut c) = live.register(2, 10);
        assert_eq!(live.end_user(1), 2);
        assert!(a.try_recv().is_ok());
        assert!(b.try_recv().is_ok());
        assert!(c.try_recv().is_err());
        assert_eq!(live.servers_for(1), HashSet::from([10, 11]));
    }

    #[test]
    fn unregistering_forgets_the_session() {
        let live = LiveSessions::default();
        let (id, _) = live.register(1, 10);
        live.unregister(id);
        assert_eq!(live.count(), 0);
        assert!(live.servers_for(1).is_empty());
    }
}
