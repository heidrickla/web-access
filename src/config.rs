//! The target allowlist and the policy that grants access to it.
//!
//! This file is a SECURITY CONTROL, not a convenience. With direct reach and no agents, nothing
//! outside the proxy limits which hosts it may open a socket to except network policy, so an entry
//! here is the difference between reachable and not. Default-deny throughout: a target absent from
//! `[[target]]` cannot be named, and a target no `[[policy]]` grants cannot be reached.

use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Address the WebSocket listener binds to.
    pub listen: String,
    pub tls: Tls,
    #[serde(default)]
    pub target: Vec<Target>,
    #[serde(default)]
    pub policy: Vec<Policy>,
}

#[derive(Debug, Deserialize)]
pub struct Tls {
    pub verify: VerifyMode,
    /// PEM bundle of the CA that issues target certificates. Required by `VerifyMode::Ca`.
    pub ca_bundle: Option<String>,
}

/// NO DEFAULT ON PURPOSE. Whether the proxy checks who it connected to is a decision an operator
/// states, not one that happens silently. Cloudflare's implementation does not verify the origin
/// certificate; on a segmented network that trade reads differently, so it is spelled out here.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum VerifyMode {
    /// Validate the target certificate against `ca_bundle`. Name resolution says WHERE, this says WHO.
    Ca,
    /// Accept any certificate. Reachability without identity.
    Insecure,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct Target {
    /// What the client names. NEVER an address: the client cannot express a host it was not given.
    pub id: String,
    /// Resolved at connection time, not at startup, so a re-addressed host is not stale until restart.
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_port() -> u16 {
    3389
}

#[derive(Debug, Deserialize, Clone)]
pub struct Policy {
    /// A group from the identity provider.
    pub group: String,
    /// Tags this group may reach. Tags rather than host lists, so adding a target is one entry here
    /// and nobody edits access rules.
    pub allow: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("target id {0:?} is defined more than once; an ambiguous allowlist entry is refused rather than resolved")]
    DuplicateTarget(String),
    #[error("tls.verify is \"ca\" but no tls.ca_bundle was given")]
    MissingCaBundle,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let config: Config = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let mut seen = BTreeMap::new();
        for target in &self.target {
            if seen.insert(target.id.clone(), ()).is_some() {
                return Err(ConfigError::DuplicateTarget(target.id.clone()));
            }
        }
        if self.tls.verify == VerifyMode::Ca && self.tls.ca_bundle.is_none() {
            return Err(ConfigError::MissingCaBundle);
        }
        Ok(())
    }
}
