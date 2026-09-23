//! Identity plus target id in, a target out, default-deny.

use crate::config::{Config, Policy, Target};
use std::collections::BTreeMap;

/// Who the caller is, as established by the identity provider. The proxy never holds their Windows
/// credentials: those pass through to the target untouched.
#[derive(Debug, Clone)]
pub struct Identity {
    pub subject: String,
    pub groups: Vec<String>,
}

/// Why a request was refused. THE CLIENT IS NOT TOLD WHICH: distinguishing "no such target" from
/// "not allowed" hands an unauthenticated caller a target enumeration oracle. The log records the
/// difference, because an operator needs it and an attacker does not get it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    NoSuchTarget,
    NotPermitted,
}

pub struct Catalogue {
    targets: BTreeMap<String, Target>,
    policies: Vec<Policy>,
}

impl Catalogue {
    pub fn new(config: &Config) -> Self {
        Self {
            targets: config
                .target
                .iter()
                .map(|t| (t.id.clone(), t.clone()))
                .collect(),
            policies: config.policy.clone(),
        }
    }

    pub fn len(&self) -> usize {
        self.targets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// The whole authorization decision. Absence of a grant is a denial; there is no fallthrough.
    pub fn resolve(&self, identity: &Identity, target_id: &str) -> Result<&Target, Denied> {
        let target = self.targets.get(target_id).ok_or(Denied::NoSuchTarget)?;
        if self.grants(identity, target) {
            Ok(target)
        } else {
            Err(Denied::NotPermitted)
        }
    }

    /// Everything this identity may reach, for the launcher to render. SAME PREDICATE as `resolve`,
    /// deliberately: a list that showed something the connection would refuse, or hid something it
    /// would allow, would be a second authorization model drifting away from the first.
    pub fn permitted(&self, identity: &Identity) -> Vec<&Target> {
        self.targets
            .values()
            .filter(|t| self.grants(identity, t))
            .collect()
    }

    fn grants(&self, identity: &Identity, target: &Target) -> bool {
        self.policies.iter().any(|policy| {
            identity.groups.iter().any(|g| g == &policy.group)
                && policy.allow.iter().any(|tag| target.tags.contains(tag))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Tls, VerifyMode};

    fn catalogue() -> Catalogue {
        let config = Config {
            listen: "127.0.0.1:0".into(),
            tls: Tls {
                verify: VerifyMode::Insecure,
                ca_bundle: None,
            },
            target: vec![
                Target {
                    id: "historian-01".into(),
                    host: "historian-01.example".into(),
                    port: 3389,
                    tags: vec!["historian".into()],
                },
                Target {
                    id: "unreferenced".into(),
                    host: "nobody.example".into(),
                    port: 3389,
                    tags: vec!["untagged-by-any-policy".into()],
                },
            ],
            policy: vec![Policy {
                group: "OT-Historian-Admins".into(),
                allow: vec!["historian".into()],
            }],
        };
        Catalogue::new(&config)
    }

    fn identity(groups: &[&str]) -> Identity {
        Identity {
            subject: "lewis".into(),
            groups: groups.iter().map(|g| (*g).to_owned()).collect(),
        }
    }

    #[test]
    fn a_granted_group_reaches_a_tagged_target() {
        let catalogue = catalogue();
        let target = catalogue
            .resolve(&identity(&["OT-Historian-Admins"]), "historian-01")
            .expect("should be permitted");
        assert_eq!(target.host, "historian-01.example");
        assert_eq!(target.port, 3389);
    }

    #[test]
    fn a_target_no_policy_grants_is_refused_even_to_a_known_group() {
        assert_eq!(
            catalogue().resolve(&identity(&["OT-Historian-Admins"]), "unreferenced"),
            Err(Denied::NotPermitted)
        );
    }

    #[test]
    fn an_unknown_group_reaches_nothing() {
        assert_eq!(
            catalogue().resolve(&identity(&["Domain Users"]), "historian-01"),
            Err(Denied::NotPermitted)
        );
    }

    #[test]
    fn a_target_absent_from_the_allowlist_cannot_be_named() {
        assert_eq!(
            catalogue().resolve(&identity(&["OT-Historian-Admins"]), "dc-01"),
            Err(Denied::NoSuchTarget)
        );
    }

    #[test]
    fn no_groups_at_all_is_a_denial_not_a_pass() {
        assert_eq!(
            catalogue().resolve(&identity(&[]), "historian-01"),
            Err(Denied::NotPermitted)
        );
    }
}
