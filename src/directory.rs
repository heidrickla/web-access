//! Signing users in against Active Directory over LDAPS, and checking account state.
//!
//! The proxy host is not domain-joined, so there is no Windows logon to lean on: a password
//! sign-in is a simple bind as the user. AD refuses that bind for a disabled, expired or locked
//! account, which is what makes revoking the account in AD revoke access here.

use crate::config::DirectoryConfig;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use std::sync::Arc;
use std::time::Duration;

/// LDAP result code for a failed bind.
const RC_INVALID_CREDENTIALS: u32 = 49;
const UAC_ACCOUNT_DISABLE: i64 = 0x2;

#[derive(Debug, thiserror::Error)]
pub enum DirError {
    #[error("the username or password is not correct")]
    InvalidCredentials,
    #[error("no domain controller could be reached: {0}")]
    Unreachable(String),
    #[error("directory: {0}")]
    Protocol(String),
    #[error("directory configuration: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, DirError>;

/// What the directory says about one account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub username: String,
    pub display_name: Option<String>,
    pub sid: String,
    pub disabled: bool,
    pub expired: bool,
}

impl Account {
    pub fn usable(&self) -> bool {
        !self.disabled && !self.expired
    }
}

pub struct Directory {
    cfg: DirectoryConfig,
    tls: Arc<rustls::ClientConfig>,
    base_dn: String,
}

/// `DOMAIN\user`, `user@domain` and `user` all name the same account. Returns the lowercase
/// sAMAccountName, or None for something that cannot be one.
pub fn normalize_username(input: &str) -> Option<String> {
    let s = input.trim();
    let s = s.rsplit('\\').next().unwrap_or(s);
    let s = s.split('@').next().unwrap_or(s);
    if s.is_empty() || s.chars().count() > 64 {
        return None;
    }
    const FORBIDDEN: &[char] = &['"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>', '@', '(', ')', '\0'];
    if s.chars().any(|c| c.is_control() || FORBIDDEN.contains(&c)) {
        return None;
    }
    Some(s.to_lowercase())
}

/// RFC 4515 escaping for a value placed in a search filter.
pub fn escape_filter(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            c => out.push(c),
        }
    }
    out
}

/// Binary objectSid to its `S-1-5-21-...` form.
pub fn sid_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    let revision = bytes[0];
    let count = bytes[1] as usize;
    if bytes.len() != 8 + 4 * count {
        return None;
    }
    let mut authority: u64 = 0;
    for b in &bytes[2..8] {
        authority = (authority << 8) | *b as u64;
    }
    let mut s = format!("S-{revision}-{authority}");
    for i in 0..count {
        let at = 8 + 4 * i;
        let sub = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        s.push_str(&format!("-{sub}"));
    }
    Some(s)
}

/// `accountExpires` is a FILETIME: 100 ns ticks since 1601. Zero and the maximum mean never.
fn expired(account_expires: Option<i64>, now_unix: i64) -> bool {
    match account_expires {
        None | Some(0) | Some(i64::MAX) => false,
        Some(ticks) => {
            let unix = ticks / 10_000_000 - 11_644_473_600;
            unix <= now_unix
        }
    }
}

fn base_dn_for(domain: &str) -> String {
    domain
        .split('.')
        .filter(|p| !p.is_empty())
        .map(|p| format!("DC={p}"))
        .collect::<Vec<_>>()
        .join(",")
}

impl Directory {
    pub fn new(cfg: &DirectoryConfig) -> Result<Self> {
        let roots = match &cfg.ca_bundle {
            Some(path) => {
                let pem = std::fs::read(path)
                    .map_err(|e| DirError::Config(format!("reading {path}: {e}")))?;
                let mut roots = rustls::RootCertStore::empty();
                for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
                    let cert = cert.map_err(|e| DirError::Config(format!("{path}: {e}")))?;
                    roots
                        .add(cert)
                        .map_err(|e| DirError::Config(format!("{path}: {e}")))?;
                }
                roots
            }
            None => {
                let mut roots = rustls::RootCertStore::empty();
                let found = rustls_native_certs::load_native_certs();
                for cert in found.certs {
                    let _ = roots.add(cert);
                }
                roots
            }
        };
        if roots.is_empty() {
            return Err(DirError::Config(
                "no CA certificates to validate the domain controllers against".into(),
            ));
        }
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            base_dn: cfg
                .base_dn
                .clone()
                .unwrap_or_else(|| base_dn_for(&cfg.domain)),
            cfg: cfg.clone(),
            tls: Arc::new(tls),
        })
    }

    /// For tests: never contacted, so it needs no CA bundle.
    #[cfg(test)]
    pub fn unconnected(cfg: &DirectoryConfig) -> Self {
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        Self {
            base_dn: base_dn_for(&cfg.domain),
            cfg: cfg.clone(),
            tls: Arc::new(tls),
        }
    }

    pub fn has_service_account(&self) -> bool {
        self.cfg.service_account.is_some()
    }

    /// The name an account binds as.
    fn bind_name(&self, username: &str) -> String {
        match &self.cfg.netbios {
            Some(nb) => format!("{nb}\\{username}"),
            None => format!("{username}@{}", self.cfg.domain),
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.cfg.timeout_secs.max(1))
    }

    /// Connect to the first domain controller that answers.
    async fn connect(&self) -> Result<Ldap> {
        let mut last = String::from("no domain controller configured");
        for url in &self.cfg.urls {
            let settings = LdapConnSettings::new()
                .set_conn_timeout(self.timeout())
                .set_config(Arc::clone(&self.tls));
            match LdapConnAsync::with_settings(settings, url).await {
                Ok((conn, ldap)) => {
                    ldap3::drive!(conn);
                    return Ok(ldap);
                }
                Err(e) => {
                    tracing::warn!(%url, error = %e, "domain controller unreachable");
                    last = format!("{url}: {e}");
                }
            }
        }
        Err(DirError::Unreachable(last))
    }

    async fn bind(&self, ldap: &mut Ldap, username: &str, password: &str) -> Result<()> {
        // An empty password is an UNAUTHENTICATED bind, which LDAP reports as success.
        if password.is_empty() {
            return Err(DirError::InvalidCredentials);
        }
        let result = ldap
            .with_timeout(self.timeout())
            .simple_bind(&self.bind_name(username), password)
            .await
            .map_err(|e| DirError::Protocol(e.to_string()))?;
        match result.rc {
            0 => Ok(()),
            RC_INVALID_CREDENTIALS => Err(DirError::InvalidCredentials),
            rc => Err(DirError::Protocol(format!("bind returned {rc}: {}", result.text))),
        }
    }

    async fn find(&self, ldap: &mut Ldap, username: &str) -> Result<Option<Account>> {
        let filter = format!(
            "(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))",
            escape_filter(username)
        );
        let (entries, _) = ldap
            .with_timeout(self.timeout())
            .search(
                &self.base_dn,
                Scope::Subtree,
                &filter,
                vec![
                    "objectSid",
                    "sAMAccountName",
                    "displayName",
                    "userAccountControl",
                    "accountExpires",
                ],
            )
            .await
            .map_err(|e| DirError::Protocol(e.to_string()))?
            .success()
            .map_err(|e| DirError::Protocol(e.to_string()))?;
        let entry = match entries.into_iter().next() {
            Some(e) => SearchEntry::construct(e),
            None => return Ok(None),
        };
        let first = |name: &str| entry.attrs.get(name).and_then(|v| v.first()).cloned();
        let sid = entry
            .bin_attrs
            .get("objectSid")
            .and_then(|v| v.first())
            .and_then(|b| sid_to_string(b))
            .ok_or_else(|| DirError::Protocol("the account has no readable objectSid".into()))?;
        let uac = first("userAccountControl")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        let expires = first("accountExpires").and_then(|v| v.parse::<i64>().ok());
        Ok(Some(Account {
            username: first("sAMAccountName")
                .map(|s| s.to_lowercase())
                .unwrap_or_else(|| username.to_owned()),
            display_name: first("displayName"),
            sid,
            disabled: uac & UAC_ACCOUNT_DISABLE != 0,
            expired: expired(expires, crate::store::now()),
        }))
    }

    /// Password sign-in. `username` is already normalised.
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<Account> {
        let mut ldap = self.connect().await?;
        let outcome = async {
            self.bind(&mut ldap, username, password).await?;
            // An account may read its own entry, so no service account is needed here.
            let account = self
                .find(&mut ldap, username)
                .await?
                .ok_or_else(|| DirError::Protocol("bound, but the account's entry was not found".into()))?;
            if !account.usable() {
                return Err(DirError::InvalidCredentials);
            }
            Ok(account)
        }
        .await;
        let _ = ldap.unbind().await;
        outcome
    }

    /// Look accounts up with the service account. None for an account that no longer exists.
    pub async fn lookup_many(
        &self,
        service_password: &str,
        usernames: &[String],
    ) -> Result<Vec<(String, Option<Account>)>> {
        let service = self
            .cfg
            .service_account
            .as_deref()
            .and_then(normalize_username)
            .ok_or_else(|| DirError::Config("no service_account configured".into()))?;
        let mut ldap = self.connect().await?;
        let outcome = async {
            self.bind(&mut ldap, &service, service_password)
                .await
                .map_err(|e| match e {
                    DirError::InvalidCredentials => DirError::Config(
                        "the service account's password was refused".into(),
                    ),
                    other => other,
                })?;
            let mut out = Vec::with_capacity(usernames.len());
            for name in usernames {
                out.push((name.clone(), self.find(&mut ldap, name).await?));
            }
            Ok(out)
        }
        .await;
        let _ = ldap.unbind().await;
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_normalise_from_every_form() {
        assert_eq!(normalize_username("CORP\\JDoe").as_deref(), Some("jdoe"));
        assert_eq!(normalize_username("jdoe@corp.example.com").as_deref(), Some("jdoe"));
        assert_eq!(normalize_username("  JDoe ").as_deref(), Some("jdoe"));
        assert_eq!(normalize_username(""), None);
        assert_eq!(normalize_username("a*b"), None);
        assert_eq!(normalize_username("x(y)"), None);
    }

    #[test]
    fn filter_values_are_escaped() {
        assert_eq!(escape_filter("a*(b)\\"), "a\\2a\\28b\\29\\5c");
    }

    #[test]
    fn a_sid_renders_in_its_string_form() {
        // S-1-5-21-1004336348-1177238915-682003330-512
        let bytes = [
            1u8, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 0xdc, 0xf4, 0xdc, 0x3b, 0x83, 0x3d, 0x2b, 0x46,
            0x82, 0x8b, 0xa6, 0x28, 0x00, 0x02, 0x00, 0x00,
        ];
        assert_eq!(
            sid_to_string(&bytes).as_deref(),
            Some("S-1-5-21-1004336348-1177238915-682003330-512")
        );
        assert_eq!(sid_to_string(&bytes[..10]), None);
    }

    #[test]
    fn account_expiry_reads_filetime() {
        assert!(!expired(None, 1_800_000_000));
        assert!(!expired(Some(0), 1_800_000_000));
        assert!(!expired(Some(i64::MAX), 1_800_000_000));
        // 2020-01-01T00:00:00Z as FILETIME.
        let y2020 = (1_577_836_800 + 11_644_473_600) * 10_000_000;
        assert!(expired(Some(y2020), 1_800_000_000));
        assert!(!expired(Some(y2020), 1_500_000_000));
    }

    #[test]
    fn the_base_dn_derives_from_the_domain() {
        assert_eq!(base_dn_for("corp.example.com"), "DC=corp,DC=example,DC=com");
    }
}
