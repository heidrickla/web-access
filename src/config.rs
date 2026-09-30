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
    /// Active Directory sign-in. Optional when local accounts are allowed.
    #[serde(default)]
    pub directory: Option<DirectoryConfig>,
    /// Accounts that are always administrators, so the management plane cannot lock itself out.
    #[serde(default)]
    pub admins: Vec<String>,
    /// Let accounts created with `local-account` sign in. They are checked against a hash in the
    /// database, never against the directory.
    #[serde(default)]
    pub allow_local_accounts: bool,
    /// Holds the database and, off Windows, the local key file. Defaults to the directory holding
    /// the config file.
    #[serde(default)]
    pub data_dir: Option<String>,
    /// Connections served at once; more are closed on accept. A WebSocket counts until its RDP
    /// session is established; established sessions are not counted.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Days the activity log keeps an entry.
    #[serde(default = "default_audit_days")]
    pub audit_days: u32,
    /// Seeds an empty database, then ignored.
    #[serde(default)]
    pub target: Vec<Target>,
    /// How files crossing the clipboard channel are scanned before they are passed on.
    #[serde(default)]
    pub scan: Scan,
    /// Keys in the file that nothing reads, such as a misspelt `service_acount`. Logged at start.
    #[serde(skip)]
    pub unknown: Vec<String>,
}

/// Every key the file may hold, by table. Anything else is reported by `unknown_keys`.
const KNOWN: &[(&str, &[&str])] = &[
    (
        "",
        &[
            "listen",
            "https",
            "tls",
            "directory",
            "admins",
            "allow_local_accounts",
            "data_dir",
            "max_connections",
            "audit_days",
            "target",
            "scan",
        ],
    ),
    (
        "scan",
        &[
            "scanner",
            "command",
            "clean_exit_codes",
            "detected_exit_codes",
            "timeout_secs",
            "max_staged_mb",
            "check_every_mins",
        ],
    ),
    ("https", &["cert", "key"]),
    ("tls", &["verify", "ca_bundle"]),
    (
        "directory",
        &[
            "domain",
            "netbios",
            "urls",
            "ca_bundle",
            "base_dn",
            "service_account",
            "timeout_secs",
            "check_interval_secs",
        ],
    ),
    ("target", &["id", "host", "port"]),
];

/// Dotted names of the keys `KNOWN` does not list.
fn unknown_keys(text: &str) -> Vec<String> {
    let Ok(root) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    let known = |table: &str| {
        KNOWN
            .iter()
            .find(|(t, _)| *t == table)
            .map_or(&[][..], |(_, keys)| *keys)
    };
    let mut found = Vec::new();
    for (key, value) in &root {
        if !known("").contains(&key.as_str()) {
            found.push(key.clone());
            continue;
        }
        let tables: Vec<&toml::Table> = match value {
            toml::Value::Table(t) => vec![t],
            toml::Value::Array(items) => items.iter().filter_map(|v| v.as_table()).collect(),
            _ => continue,
        };
        for t in tables {
            for inner in t.keys() {
                if !known(key).contains(&inner.as_str()) {
                    found.push(format!("{key}.{inner}"));
                }
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// `amsi` hands each file to the anti-malware product registered with Windows (Trellix, Defender);
/// `command` runs a scanner program on a copy; `off` passes the clipboard channel through unread.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Scanner {
    Amsi,
    Command,
    Off,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct Scan {
    pub scanner: Scanner,
    /// For `command`: the program and its arguments; `{file}` is replaced by the copy's path.
    pub command: Vec<String>,
    pub clean_exit_codes: Vec<i32>,
    pub detected_exit_codes: Vec<i32>,
    /// A file that has no verdict in this time is refused.
    pub timeout_secs: u64,
    /// Bytes held for scanning at once, across every session; a transfer past it is refused.
    pub max_staged_mb: u64,
    /// How often the scanner is shown the EICAR test file. Each check is one detection in the
    /// anti-malware product's own log.
    pub check_every_mins: u64,
}

impl Scan {
    fn check(&self) -> Result<(), String> {
        if self.scanner == Scanner::Amsi && !cfg!(windows) {
            return Err("scanner = \"amsi\" needs Windows".into());
        }
        if self.scanner == Scanner::Command {
            if self.command.is_empty() {
                return Err("scanner = \"command\" needs command = [program, args...]".into());
            }
            if !self.command.iter().any(|a| a.contains("{file}")) {
                return Err("command must pass the file as {file}".into());
            }
            if self.detected_exit_codes.is_empty() {
                return Err("detected_exit_codes lists no code".into());
            }
            if self
                .clean_exit_codes
                .iter()
                .any(|c| self.detected_exit_codes.contains(c))
            {
                return Err("an exit code cannot mean both clean and detected".into());
            }
        }
        if self.timeout_secs == 0 || self.max_staged_mb == 0 {
            return Err("timeout_secs and max_staged_mb must be at least 1".into());
        }
        if !(5..=1440).contains(&self.check_every_mins) {
            return Err("check_every_mins must be 5 to 1440".into());
        }
        Ok(())
    }
}

impl Default for Scan {
    fn default() -> Self {
        Self {
            scanner: if cfg!(windows) {
                Scanner::Amsi
            } else {
                Scanner::Off
            },
            command: Vec::new(),
            clean_exit_codes: vec![0],
            detected_exit_codes: Vec::new(),
            timeout_secs: 120,
            max_staged_mb: 2048,
            check_every_mins: 60,
        }
    }
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

fn default_max_connections() -> usize {
    1024
}

fn default_check_interval() -> u64 {
    600
}

fn default_audit_days() -> u32 {
    400
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
    #[error("audit_days must be at least 1")]
    AuditDays,
    #[error("scan: {0}")]
    Scan(String),
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
        config.unknown = unknown_keys(text);
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
        if self.audit_days == 0 {
            return Err(ConfigError::AuditDays);
        }
        self.scan.check().map_err(ConfigError::Scan)?;
        let Some(d) = &self.directory else {
            if self.allow_local_accounts {
                return Ok(());
            }
            return Err(ConfigError::Directory(
                "nobody could sign in: add a [directory] section, or allow_local_accounts = true"
                    .into(),
            ));
        };
        if d.domain.trim().is_empty() || !d.domain.contains('.') {
            return Err(ConfigError::Directory(
                "domain must be a DNS domain such as corp.example.com".into(),
            ));
        }
        if d.urls.is_empty() {
            return Err(ConfigError::Directory(
                "urls lists no domain controller".into(),
            ));
        }
        if let Some(bad) = d
            .urls
            .iter()
            .find(|u| !u.to_ascii_lowercase().starts_with("ldaps://"))
        {
            return Err(ConfigError::Directory(format!(
                "{bad}: only ldaps:// is accepted"
            )));
        }
        Ok(())
    }

    /// The service account, if a directory with one is configured.
    pub fn service_account(&self) -> Option<&str> {
        self.directory.as_ref()?.service_account.as_deref()
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
        assert_eq!(c.directory.as_ref().unwrap().timeout_secs, 10);
        assert!(!c.allow_local_accounts);
        assert!(c.is_bootstrap_admin("jdoe"));
        assert!(!c.is_bootstrap_admin("someone"));
    }

    #[test]
    fn the_data_directory_defaults_to_the_config_directory() {
        let text = GOOD.replace("data_dir = \"/var/lib/web-access\"\n", "");
        let c = Config::parse("/etc/web-access/config.toml", &text).unwrap();
        assert_eq!(c.data_dir(), PathBuf::from("/etc/web-access"));
        assert_eq!(
            c.database_path(),
            PathBuf::from("/etc/web-access/web-access.db")
        );
    }

    #[test]
    fn the_shipped_example_parses() {
        let c = Config::parse("config.toml", include_str!("../config.example.toml")).unwrap();
        assert!(c.https.is_some());
        assert_eq!(c.directory.as_ref().unwrap().urls.len(), 2);
        // As installed on Windows, files are scanned by the registered anti-malware product.
        if cfg!(windows) {
            assert_eq!(c.scan.scanner, Scanner::Amsi);
        }
    }

    #[test]
    fn a_scan_setting_that_cannot_work_is_refused() {
        for bad in [
            "[scan]\nscanner = \"command\"\ncommand = [\"scan\"]\ndetected_exit_codes = [1]\n",
            "[scan]\nscanner = \"command\"\ncommand = [\"scan\", \"{file}\"]\n",
            "[scan]\nscanner = \"command\"\ncommand = [\"scan\", \"{file}\"]\ndetected_exit_codes = [0]\n",
            "[scan]\nscanner = \"off\"\ncheck_every_mins = 1\n",
            "[scan]\nscanner = \"off\"\ntimeout_secs = 0\n",
        ] {
            let text = format!("{GOOD}\n{bad}");
            assert!(
                matches!(Config::parse("t", &text), Err(ConfigError::Scan(_))),
                "accepted: {bad}"
            );
        }
        let ok = format!(
            "{GOOD}\n[scan]\nscanner = \"command\"\ncommand = [\"scan\", \"{{file}}\"]\ndetected_exit_codes = [1]\n"
        );
        assert!(Config::parse("t", &ok).is_ok());
    }

    const LOCAL_ONLY: &str = r#"
listen = "0.0.0.0:443"
allow_local_accounts = true
[tls]
verify = "insecure"
"#;

    #[test]
    fn local_accounts_alone_need_no_directory() {
        let c = Config::parse("t", LOCAL_ONLY).unwrap();
        assert!(c.directory.is_none());
        assert!(c.service_account().is_none());
    }

    #[test]
    fn a_config_nobody_can_sign_in_with_is_refused() {
        let text = LOCAL_ONLY.replace("allow_local_accounts = true\n", "");
        assert!(matches!(
            Config::parse("t", &text),
            Err(ConfigError::Directory(_))
        ));
    }

    #[test]
    fn plain_ldap_is_refused() {
        let text = GOOD.replace("ldaps://dc1", "ldap://dc1");
        assert!(matches!(
            Config::parse("t", &text),
            Err(ConfigError::Directory(_))
        ));
    }

    #[test]
    fn a_misspelt_key_is_reported_and_every_documented_one_is_known() {
        let text = GOOD.replace("[directory]\n", "[directory]\nservice_acount = \"svc\"\n")
            + "\n[[target]]\nid = \"a\"\nhost = \"a.example\"\nprot = 3390\n";
        let c = Config::parse("t", &text).unwrap();
        assert_eq!(c.unknown, vec!["directory.service_acount", "target.prot"]);
        // The example documents every key, some commented out: all of them are known.
        let every: String = include_str!("../config.example.toml")
            .lines()
            .map(|l| {
                l.strip_prefix("# ")
                    .filter(|r| r.contains(" = "))
                    .unwrap_or(l)
            })
            .map(|l| format!("{l}\n"))
            .collect();
        // AMSI is Windows-only, and the command scanner the example also documents runs anywhere.
        let every = if cfg!(windows) {
            every
        } else {
            every.replace("scanner = \"amsi\"", "scanner = \"command\"")
        };
        let c = Config::parse("t", &every).unwrap();
        assert!(c.unknown.is_empty(), "{:?}", c.unknown);
        assert!(
            c.allow_local_accounts,
            "the commented keys were not uncommented"
        );
    }

    #[test]
    fn ca_mode_needs_a_bundle() {
        let text = GOOD.replace("verify = \"insecure\"", "verify = \"ca\"");
        assert!(matches!(
            Config::parse("t", &text),
            Err(ConfigError::MissingCaBundle)
        ));
    }
}
