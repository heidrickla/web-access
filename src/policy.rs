//! User plus target id in, a server out, default-deny.
//!
//! A user reaches exactly the servers an administrator assigned to them. `resolve` and `permitted`
//! share the assignment predicate: a list that showed something the connection would refuse, or hid
//! something it would allow, would be a second authorization model drifting from the first.

use crate::store::{ListedServer, Server, Store, StoreError};

/// Why a request was refused. THE CLIENT IS NOT TOLD WHICH: "no such target" versus "not allowed"
/// would be an enumeration oracle. The log records the difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    NoSuchTarget,
    NotPermitted,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("refused")]
    Denied(Denied),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The client names a server by its id, never by an address.
pub fn resolve(store: &Store, user_id: i64, target_id: &str) -> Result<Server, PolicyError> {
    let id: i64 = target_id
        .parse()
        .map_err(|_| PolicyError::Denied(Denied::NoSuchTarget))?;
    let server = store
        .server_by_id(id)?
        .ok_or(PolicyError::Denied(Denied::NoSuchTarget))?;
    if store.is_assigned(user_id, server.id)? {
        Ok(server)
    } else {
        Err(PolicyError::Denied(Denied::NotPermitted))
    }
}

/// Everything this user may reach, for their list.
pub fn permitted(store: &Store, user_id: i64) -> Result<Vec<ListedServer>, PolicyError> {
    Ok(store.assigned_servers(user_id)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        store: Store,
        user: i64,
        other: i64,
        assigned: i64,
        unassigned: i64,
    }

    fn fixture() -> Fixture {
        let store = Store::open_in_memory().unwrap();
        let user = store.user_create("jdoe", None).unwrap();
        let other = store.user_create("asmith", None).unwrap();
        let assigned = store
            .server_create("historian-01", "historian-01.example", 3389, None)
            .unwrap();
        let unassigned = store
            .server_create("dc-01", "dc-01.example", 3389, None)
            .unwrap();
        store.set_assignments(user, &[assigned]).unwrap();
        Fixture {
            store,
            user,
            other,
            assigned,
            unassigned,
        }
    }

    fn denied(r: Result<Server, PolicyError>) -> Option<Denied> {
        match r {
            Err(PolicyError::Denied(d)) => Some(d),
            _ => None,
        }
    }

    #[test]
    fn an_assigned_server_is_reached() {
        let f = fixture();
        let s = resolve(&f.store, f.user, &f.assigned.to_string()).unwrap();
        assert_eq!(s.host, "historian-01.example");
        assert_eq!(s.port, 3389);
    }

    #[test]
    fn an_unassigned_server_is_refused() {
        let f = fixture();
        assert_eq!(
            denied(resolve(&f.store, f.user, &f.unassigned.to_string())),
            Some(Denied::NotPermitted)
        );
    }

    #[test]
    fn another_users_assignment_grants_nothing() {
        let f = fixture();
        assert_eq!(
            denied(resolve(&f.store, f.other, &f.assigned.to_string())),
            Some(Denied::NotPermitted)
        );
    }

    #[test]
    fn a_server_that_does_not_exist_cannot_be_named() {
        let f = fixture();
        assert_eq!(
            denied(resolve(&f.store, f.user, "999")),
            Some(Denied::NoSuchTarget)
        );
        assert_eq!(
            denied(resolve(&f.store, f.user, "dc-01.example")),
            Some(Denied::NoSuchTarget)
        );
        assert_eq!(
            denied(resolve(&f.store, f.user, "")),
            Some(Denied::NoSuchTarget)
        );
    }

    #[test]
    fn no_assignments_at_all_is_a_denial_not_a_pass() {
        let f = fixture();
        assert!(permitted(&f.store, f.other).unwrap().is_empty());
        for id in [f.assigned, f.unassigned] {
            assert!(resolve(&f.store, f.other, &id.to_string()).is_err());
        }
    }

    /// The list and the connection must agree for every server.
    #[test]
    fn the_list_and_the_connection_use_one_predicate() {
        let f = fixture();
        for user in [f.user, f.other] {
            let listed: Vec<i64> = permitted(&f.store, user)
                .unwrap()
                .iter()
                .map(|l| l.server.id)
                .collect();
            for id in [f.assigned, f.unassigned] {
                assert_eq!(
                    listed.contains(&id),
                    resolve(&f.store, user, &id.to_string()).is_ok(),
                    "user {user} server {id}"
                );
            }
        }
    }
}
