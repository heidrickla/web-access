//! Configuration: where to listen, how to reach the directory, where the data lives.
//!
//! Servers, groups, users and assignments are NOT here. They live in the database and are managed
//! from the admin pages. `[[target]]` entries are read once, to seed an empty database.

use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Address the listener binds to.
    pub listen: String,
    /// Serve HTTPS. Without it the listener speaks plain HTTP.
    #[serde(default)]
    pub https: Option<Https>,
    /// How the proxy validates RDP targets' certificates.
    pub tls: Tls,
    pub directory: DirectoryConfig,
    /// Accounts that are always administrators, so the management plane cannot lock itself out.
    #[serde(default)]
    pub admins: Vec<String>,
    /// Holds the database and, off Windows, the local key file. Defaults to the directory holding
    /// the config file.
    #[serde(default)]
    pub data_dir: Option<String>,
    /// Seeds an empty database, then ignored.
    #[serde(default)]
    pub target: Vec<Target>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Https {
    /// PEM certificate chain, leaf first.
    pub cert: String,
    /// PEM private key.
    pub key: String,
}

#[derive(Debug, Deserialize)]
pub struct Tls {
    pub verify: VerifyMode,
    /// PEM bundle of the CA that issues target certificates. Required by `VerifyMode::Ca`.
    pub ca_bundle: Option<String>,
}

/// NO DEFAULT ON PURPOSE. Whether the proxy checks which machine it connected to is a decision an
/// operator states.
#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum VerifyMode {
    /// Validate the target certificate against `ca_bundle`.
    Ca,
    /// Accept any certificate.
    Insecure,
}

/// The Active Directory users sign in against.
#[derive(Debug, Deserialize, Clone)]
pub struct DirectoryConfig {
    /// DNS domain, e.g. `corp.example.com`. Forms the bind name `user@domain` and the default base DN.
    pub domain: String,
    /// NetBIOS domain name. When set, binds use `NETBIOS\user`, which works whatever UPN suffix an
    /// account carries.
    #[serde(default)]
    pub netbios: Option<String>,
    /// Domain controllers, tried in order. `ldaps://` only.
    pub urls: Vec<String>,
    /// PEM bundle for the domain controllers' certificates. Absent: the operating system's store.
    #[serde(default)]
    pub ca_bundle: Option<String>,
    /// Search base. Absent: derived from `domain`.
    #[serde(default)]
    pub base_dn: Option<String>,
    /// Read-only account for account-state checks. Its password is set from the admin pages or
    /// with `set-secret directory`, never here.
    #[serde(default)]
    pub service_account: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// How often signed-in accounts are re-checked with the service account.
    #[serde(default = "default_check_interval")]
    pub check_interval_secs: u64,
}

fn default_timeout() -> u64 {
    10
}

fn default_check_interval() -> u64 {
    600
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct Target {
    pub id: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_port() -> u16 {
    3389
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
    #[error("target id {0:?} is defined more than once")]
    DuplicateTarget(String),
    #[error("tls.verify is \"ca\" but no tls.ca_bundle was given")]
    MissingCaBundle,
    #[error("directory: {0}")]
    Directory(String),
}

impl Config {
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(path, &text)
    }

    pub fn parse(path: &str, text: &str) -> Result<Self, ConfigError> {
        let mut config: Config = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;
        if config.data_dir.is_none() {
            let dir = std::path::Path::new(path)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            config.data_dir = Some(dir.to_string_lossy().into_owned());
        }
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let mut seen = BTreeSet::new();
        for target in &self.target {
            if !seen.insert(target.id.clone()) {
                return Err(ConfigError::DuplicateTarget(target.id.clone()));
            }
        }
        if self.tls.verify == VerifyMode::Ca && self.tls.ca_bundle.is_none() {
            return Err(ConfigError::MissingCaBundle);
        }
        let d = &self.directory;
        if d.domain.trim().is_empty() || !d.domain.contains('.') {
            return Err(ConfigError::Directory(
                "domain must be a DNS domain such as corp.example.com".into(),
            ));
        }
        if d.urls.is_empty() {
            return Err(ConfigError::Directory("urls lists no domain controller".into()));
        }
        if let Some(bad) = d.urls.iter().find(|u| !u.to_ascii_lowercase().starts_with("ldaps://")) {
            return Err(ConfigError::Directory(format!(
                "{bad}: only ldaps:// is accepted"
            )));
        }
        Ok(())
    }

    pub fn data_dir(&self) -> PathBuf {
        PathBuf::from(self.data_dir.as_deref().unwrap_or("."))
    }

    pub fn database_path(&self) -> PathBuf {
        self.data_dir().join("web-access.db")
    }

    /// Bootstrap administrators, normalised the way usernames are stored.
    pub fn is_bootstrap_admin(&self, username: &str) -> bool {
        self.admins
            .iter()
            .filter_map(|a| crate::directory::normalize_username(a))
            .any(|a| a == username)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
listen = "0.0.0.0:443"
data_dir = "/var/lib/web-access"
admins = ["CORP\\JDoe"]
[tls]
verify = "insecure"
[directory]
domain = "corp.example.com"
urls = ["ldaps://dc1.corp.example.com"]
"#;

    #[test]
    fn a_minimal_config_parses() {
        let c = Config::parse("t", GOOD).unwrap();
        assert!(c.https.is_none());
        assert_eq!(c.directory.timeout_secs, 10);
        assert!(c.is_bootstrap_admin("jdoe"));
        assert!(!c.is_bootstrap_admin("someone"));
    }

    #[test]
    fn the_data_directory_defaults_to_the_config_directory() {
        let text = GOOD.replace("data_dir = \"/var/lib/web-access\"\n", "");
        let c = Config::parse("/etc/web-access/config.toml", &text).unwrap();
        assert_eq!(c.data_dir(), PathBuf::from("/etc/web-access"));
        assert_eq!(c.database_path(), PathBuf::from("/etc/web-access/web-access.db"));
    }

    #[test]
    fn the_shipped_example_parses() {
        let c = Config::parse("config.toml", include_str!("../config.example.toml")).unwrap();
        assert!(c.https.is_some());
        assert_eq!(c.directory.urls.len(), 2);
    }

    #[test]
    fn plain_ldap_is_refused() {
        let text = GOOD.replace("ldaps://dc1", "ldap://dc1");
        assert!(matches!(Config::parse("t", &text), Err(ConfigError::Directory(_))));
    }

    #[test]
    fn ca_mode_needs_a_bundle() {
        let text = GOOD.replace("verify = \"insecure\"", "verify = \"ca\"");
        assert!(matches!(Config::parse("t", &text), Err(ConfigError::MissingCaBundle)));
    }
}
