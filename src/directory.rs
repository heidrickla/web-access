//! Signing users in against Active Directory over LDAPS, and checking account state.
//!
//! The proxy host is not domain-joined, so there is no Windows logon to lean on: a password
//! sign-in is a simple bind as the user. AD refuses that bind for a disabled, expired or locked
//! account, which is what makes revoking the account in AD revoke access here.

use crate::config::DirectoryConfig;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// LDAP result code for a failed bind.
const RC_INVALID_CREDENTIALS: u32 = 49;
const UAC_ACCOUNT_DISABLE: i64 = 0x2;

#[derive(Debug, thiserror::Error)]
pub enum DirError {
    #[error("the username or password is not correct")]
    InvalidCredentials,
    /// The directory refused an account it would otherwise accept, and said why.
    #[error("{0}")]
    Refused(Refusal),
    /// The password was accepted for an account outside the configured domain.
    #[error("the account {0} is not in the configured domain")]
    OtherDomain(String),
    #[error("no domain controller could be reached: {0}")]
    Unreachable(String),
    #[error("directory: {0}")]
    Protocol(String),
    #[error("directory configuration: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, DirError>;

/// Why Active Directory refused a bind whose password it may have accepted, from the `data <hex>`
/// code in its error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("the password has expired or must be changed; change it at a Windows sign-in, then sign in here")]
    PasswordMustChange,
    #[error("the account is locked; try again later or ask the helpdesk to unlock it")]
    Locked,
    #[error("the account may not sign in at this time or from here")]
    Restricted,
    #[error("the account is disabled")]
    Disabled,
    #[error("the account has expired")]
    Expired,
}

impl Refusal {
    /// The code as Active Directory writes it, for the activity log.
    pub fn code(self) -> &'static str {
        match self {
            Refusal::PasswordMustChange => "532/773",
            Refusal::Locked => "775",
            Refusal::Restricted => "530/531",
            Refusal::Disabled => "533",
            Refusal::Expired => "701",
        }
    }

    /// Whether Active Directory gives this answer only for the right password. A lockout is
    /// reported whatever password is typed, so naming it would tell anyone the account exists.
    pub fn proves_password(self) -> bool {
        !matches!(self, Refusal::Locked)
    }
}

/// The refusal named by Active Directory's `... data 775, ...` text; None for a wrong password
/// (`data 52e`) and for anything else.
fn refusal_in(text: &str) -> Option<Refusal> {
    let code = text.split("data ").nth(1)?.split([',', ' ']).next()?;
    match code.to_ascii_lowercase().as_str() {
        "532" | "773" => Some(Refusal::PasswordMustChange),
        "775" => Some(Refusal::Locked),
        "530" | "531" => Some(Refusal::Restricted),
        "533" => Some(Refusal::Disabled),
        "701" => Some(Refusal::Expired),
        _ => None,
    }
}

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
    /// The domain controller that last answered, tried first: with the first one listed down,
    /// every sign-in would otherwise wait out its timeout before reaching the next.
    preferred: AtomicUsize,
}

/// The order to try `count` controllers in: the preferred one, then the rest as configured.
fn try_order(count: usize, preferred: usize) -> Vec<usize> {
    let first = if preferred < count { preferred } else { 0 };
    std::iter::once(first)
        .chain((0..count).filter(|i| *i != first))
        .take(count)
        .collect()
}

/// The account name part of `DOMAIN\user`, `user@domain` or `user`, lowercased, or None for
/// something that cannot be one. For a local account and for the proxy's own lists; a directory
/// sign-in checks the password under the name as typed and takes the account from the directory.
pub fn normalize_username(input: &str) -> Option<String> {
    let s = input.trim();
    let s = s.rsplit('\\').next().unwrap_or(s);
    let s = s.split('@').next().unwrap_or(s);
    if s.is_empty() || s.chars().count() > 64 {
        return None;
    }
    const FORBIDDEN: &[char] = &[
        '"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>', '@', '(', ')',
        '\0',
    ];
    if s.chars().any(|c| c.is_control() || FORBIDDEN.contains(&c)) {
        return None;
    }
    Some(s.to_lowercase())
}

/// The account in a WhoAmI answer: `u:DOMAIN\user` (Active Directory, Samba) gives the domain
/// and the lowercase short name, `u:user` the short name alone. Anything else names no account.
fn parse_authzid(authzid: &str) -> Option<(Option<String>, String)> {
    let id = authzid.strip_prefix("u:")?;
    let (domain, name) = match id.rsplit_once('\\') {
        Some((d, n)) => (Some(d.to_owned()).filter(|d| !d.is_empty()), n),
        None => (None, id),
    };
    Some((domain, normalize_username(name)?))
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

/// An LDAP filter value matching a `S-1-5-21-...` SID in its binary form, each byte escaped;
/// None for anything that is not one.
pub fn sid_filter(sid: &str) -> Option<String> {
    Some(
        sid_bytes(sid)?
            .iter()
            .map(|b| format!("\\{b:02x}"))
            .collect(),
    )
}

/// A SID in the form `sid_to_string` gives, so two spellings of one SID compare equal; None for
/// anything that is not a SID.
pub fn canonical_sid(sid: &str) -> Option<String> {
    sid_to_string(&sid_bytes(sid.trim())?)
}

fn sid_bytes(sid: &str) -> Option<Vec<u8>> {
    let mut parts = sid.strip_prefix("S-")?.split('-');
    let revision: u8 = parts.next()?.parse().ok()?;
    let authority: u64 = parts.next()?.parse().ok()?;
    if authority >= 1 << 48 {
        return None;
    }
    let subs = parts
        .map(|p| p.parse::<u32>().ok())
        .collect::<Option<Vec<u32>>>()?;
    if subs.is_empty() || subs.len() > 15 {
        return None;
    }
    let mut bytes = vec![revision, subs.len() as u8];
    bytes.extend_from_slice(&authority.to_be_bytes()[2..]);
    for s in subs {
        bytes.extend_from_slice(&s.to_le_bytes());
    }
    Some(bytes)
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
                for cert in CertificateDer::pem_slice_iter(&pem) {
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
            preferred: AtomicUsize::new(0),
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
            preferred: AtomicUsize::new(0),
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

    /// The name a sign-in binds as: exactly what was typed when it names a domain, so an
    /// email-style sign-in name reaches its own account, and otherwise the configured form. As
    /// typed only with `netbios` set: that is what the domain WhoAmI reports is checked against,
    /// and without the check another domain's `jsmith` would sign in as this domain's.
    fn sign_in_name(&self, typed: &str) -> Option<String> {
        let typed = typed.trim();
        let short = normalize_username(typed)?;
        if typed.len() > 256 || typed.chars().any(char::is_control) {
            return None;
        }
        let names_a_domain = typed.contains('@') || typed.contains('\\');
        Some(if names_a_domain && self.cfg.netbios.is_some() {
            typed.to_owned()
        } else {
            self.bind_name(&short)
        })
    }

    /// Who the directory says this connection is bound as, from the WhoAmI operation (RFC 4532):
    /// the account's short name, and its NetBIOS domain where the answer carries one.
    async fn whoami(&self, ldap: &mut Ldap) -> Result<(Option<String>, String)> {
        let (exop, _) = ldap
            .with_timeout(self.timeout())
            .extended(ldap3::exop::WhoAmI)
            .await
            .map_err(|e| DirError::Protocol(e.to_string()))?
            .success()
            .map_err(|e| DirError::Protocol(format!("who-am-i: {e}")))?;
        let authzid = exop
            .val
            .as_deref()
            .and_then(|v| std::str::from_utf8(v).ok())
            .unwrap_or("");
        parse_authzid(authzid)
            .ok_or_else(|| DirError::Protocol(format!("who-am-i named no account: {authzid:?}")))
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(self.cfg.timeout_secs.max(1))
    }

    /// Connect to the first domain controller that answers, starting with the last one that did.
    async fn connect(&self) -> Result<Ldap> {
        let mut last = String::from("no domain controller configured");
        let order = try_order(self.cfg.urls.len(), self.preferred.load(Ordering::Relaxed));
        for index in order {
            let url = &self.cfg.urls[index];
            let settings = LdapConnSettings::new()
                .set_conn_timeout(self.timeout())
                .set_config(Arc::clone(&self.tls));
            match LdapConnAsync::with_settings(settings, url).await {
                Ok((conn, ldap)) => {
                    ldap3::drive!(conn);
                    self.preferred.store(index, Ordering::Relaxed);
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

    async fn bind(&self, ldap: &mut Ldap, bind_name: &str, password: &str) -> Result<()> {
        // An empty password is an UNAUTHENTICATED bind, which LDAP reports as success.
        if password.is_empty() {
            return Err(DirError::InvalidCredentials);
        }
        let result = ldap
            .with_timeout(self.timeout())
            .simple_bind(bind_name, password)
            .await
            .map_err(|e| DirError::Protocol(e.to_string()))?;
        match result.rc {
            0 => Ok(()),
            RC_INVALID_CREDENTIALS => Err(match refusal_in(&result.text) {
                Some(r) => DirError::Refused(r),
                None => DirError::InvalidCredentials,
            }),
            rc => Err(DirError::Protocol(format!(
                "bind returned {rc}: {}",
                result.text
            ))),
        }
    }

    async fn find(&self, ldap: &mut Ldap, username: &str) -> Result<Option<Account>> {
        let filter = format!(
            "(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))",
            escape_filter(username)
        );
        self.find_by(ldap, &filter, username).await
    }

    /// The account with this SID, whatever it is called now: a rename in the directory keeps
    /// the SID, so an account checked by SID is not mistaken for a deleted one.
    async fn find_sid(
        &self,
        ldap: &mut Ldap,
        sid: &str,
        username: &str,
    ) -> Result<Option<Account>> {
        let value =
            sid_filter(sid).ok_or_else(|| DirError::Protocol(format!("{sid} is not a SID")))?;
        let filter = format!("(&(objectCategory=person)(objectClass=user)(objectSid={value}))");
        self.find_by(ldap, &filter, username).await
    }

    async fn find_by(
        &self,
        ldap: &mut Ldap,
        filter: &str,
        username: &str,
    ) -> Result<Option<Account>> {
        let (entries, _) = ldap
            .with_timeout(self.timeout())
            .search(
                &self.base_dn,
                Scope::Subtree,
                filter,
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
        // A name or SID names one account. Two answers mean the filter is not what it should be,
        // and picking either would sign someone in as an account the directory did not single out.
        if entries.len() > 1 {
            return Err(DirError::Protocol(format!(
                "the directory returned {} accounts for one name",
                entries.len()
            )));
        }
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

    /// Password sign-in with the name as typed. The account signed in is the one the directory
    /// says the password was checked for, never one looked up by the typed name: AD resolves a
    /// sign-in name before a short name, so the two can be different people.
    pub async fn authenticate(&self, typed: &str, password: &str) -> Result<Account> {
        let bind_name = self
            .sign_in_name(typed)
            .ok_or(DirError::InvalidCredentials)?;
        let mut ldap = self.connect().await?;
        let outcome = async {
            self.bind(&mut ldap, &bind_name, password).await?;
            let (domain, short) = self.whoami(&mut ldap).await?;
            if let (Some(nb), Some(domain)) = (&self.cfg.netbios, &domain) {
                if !nb.eq_ignore_ascii_case(domain) {
                    return Err(DirError::OtherDomain(format!("{domain}\\{short}")));
                }
            }
            // An account may read its own entry, so no service account is needed here.
            let account = self.find(&mut ldap, &short).await?.ok_or_else(|| {
                DirError::Protocol("bound, but the account's entry was not found".into())
            })?;
            if !account.usable() {
                return Err(DirError::InvalidCredentials);
            }
            Ok(account)
        }
        .await;
        let _ = ldap.unbind().await;
        outcome
    }

    /// Look accounts up with the service account. None for an account that no longer exists. Any
    /// failure fails the whole call.
    pub async fn lookup_many(
        &self,
        service_password: &str,
        usernames: &[String],
    ) -> Result<Vec<(String, Option<Account>)>> {
        let by_name: Vec<(String, Option<String>)> =
            usernames.iter().map(|n| (n.clone(), None)).collect();
        self.lookup_each(service_password, &by_name)
            .await?
            .into_iter()
            .map(|(name, found)| found.map(|a| (name, a)))
            .collect()
    }

    /// The one account with this SID, read with the service account, for a sign-in an identity
    /// provider vouched for. None when no account in the search base has it; the SID the
    /// directory returns must be the one asked for.
    pub async fn lookup_by_sid(
        &self,
        service_password: &str,
        sid: &str,
    ) -> Result<Option<Account>> {
        let wanted =
            canonical_sid(sid).ok_or_else(|| DirError::Protocol(format!("{sid} is not a SID")))?;
        let found = self
            .lookup_each(service_password, &[(wanted.clone(), Some(wanted.clone()))])
            .await?
            .pop()
            .map(|(_, found)| found)
            .unwrap_or(Ok(None))?;
        match found {
            Some(account) if account.sid != wanted => Err(DirError::Protocol(format!(
                "asked for {wanted}, the directory answered {}",
                account.sid
            ))),
            other => Ok(other),
        }
    }

    /// As `lookup_many`, for `(username, SID)` pairs: an account with a SID is found by it, one
    /// without by name. A lookup that fails fails only its own account: one unreadable entry
    /// does not stop the checks of everyone else. Connecting and binding still fail the call.
    pub async fn lookup_each(
        &self,
        service_password: &str,
        accounts: &[(String, Option<String>)],
    ) -> Result<Vec<(String, Result<Option<Account>>)>> {
        let service = self
            .cfg
            .service_account
            .as_deref()
            .and_then(normalize_username)
            .ok_or_else(|| DirError::Config("no service_account configured".into()))?;
        let mut ldap = self.connect().await?;
        let outcome = async {
            self.bind(&mut ldap, &self.bind_name(&service), service_password)
                .await
                .map_err(|e| match e {
                    DirError::InvalidCredentials => {
                        DirError::Config("the service account's password was refused".into())
                    }
                    DirError::Refused(r) => DirError::Config(format!(
                        "the service account was refused: {r} (data {})",
                        r.code()
                    )),
                    other => other,
                })?;
            let mut out = Vec::with_capacity(accounts.len());
            for (name, sid) in accounts {
                let found = match sid {
                    Some(sid) => self.find_sid(&mut ldap, sid, name).await,
                    None => self.find(&mut ldap, name).await,
                };
                out.push((name.clone(), found));
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
        assert_eq!(
            normalize_username("jdoe@corp.example.com").as_deref(),
            Some("jdoe")
        );
        assert_eq!(normalize_username("  JDoe ").as_deref(), Some("jdoe"));
        assert_eq!(normalize_username(""), None);
        assert_eq!(normalize_username("a*b"), None);
        assert_eq!(normalize_username("x(y)"), None);
    }

    #[test]
    fn active_directory_refusal_codes_are_named() {
        let ad = |code: &str| {
            format!("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data {code}, v4563")
        };
        assert_eq!(
            refusal_in(&ad("52e")),
            None,
            "a wrong password named a reason"
        );
        assert_eq!(refusal_in(&ad("532")), Some(Refusal::PasswordMustChange));
        assert_eq!(refusal_in(&ad("773")), Some(Refusal::PasswordMustChange));
        assert_eq!(refusal_in(&ad("775")), Some(Refusal::Locked));
        assert_eq!(refusal_in(&ad("530")), Some(Refusal::Restricted));
        assert_eq!(refusal_in(&ad("531")), Some(Refusal::Restricted));
        assert_eq!(refusal_in(&ad("533")), Some(Refusal::Disabled));
        assert_eq!(refusal_in(&ad("701")), Some(Refusal::Expired));
        assert_eq!(refusal_in("Invalid credentials"), None);
    }

    #[test]
    fn a_whoami_answer_names_the_account_signed_in() {
        assert_eq!(
            parse_authzid("u:CORP\\JDoe"),
            Some((Some("CORP".into()), "jdoe".into()))
        );
        assert_eq!(parse_authzid("u:jdoe"), Some((None, "jdoe".into())));
        assert_eq!(parse_authzid("dn:CN=John,DC=corp"), None);
        assert_eq!(parse_authzid(""), None);
        assert_eq!(parse_authzid("u:CORP\\"), None);
    }

    fn config(netbios: Option<&str>) -> DirectoryConfig {
        let mut text = String::from(
            "domain = \"corp.example.com\"\nurls = [\"ldaps://dc1.corp.example.com\"]\n",
        );
        if let Some(nb) = netbios {
            text.push_str(&format!("netbios = \"{nb}\"\n"));
        }
        toml::from_str(&text).unwrap()
    }

    #[test]
    fn a_sid_becomes_the_filter_for_its_binary_form() {
        let sid = "S-1-5-21-3623811015-3361044348-30300820-1013";
        let filter = sid_filter(sid).unwrap();
        let bytes: Vec<u8> = filter
            .split('\\')
            .skip(1)
            .map(|h| u8::from_str_radix(h, 16).unwrap())
            .collect();
        assert_eq!(sid_to_string(&bytes).as_deref(), Some(sid));
        assert!(filter.starts_with("\\01\\05\\00\\00\\00\\00\\00\\05\\15\\00\\00\\00"));
        for bad in ["local:abc", "S-1-5", "S-1-x-21", "S-1-5-21-99999999999", ""] {
            assert_eq!(sid_filter(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_controller_that_last_answered_is_tried_first() {
        assert_eq!(try_order(3, 0), vec![0, 1, 2]);
        assert_eq!(try_order(3, 2), vec![2, 0, 1]);
        assert_eq!(try_order(3, 7), vec![0, 1, 2]);
        assert_eq!(try_order(0, 0), Vec::<usize>::new());
    }

    /// A real LDAPS listener stands in for the second controller; the first refuses connections.
    /// `localhost` tries ::1 first, and Windows takes about 2 s to refuse it there.
    #[tokio::test]
    async fn a_controller_that_answered_is_remembered() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = env!("CARGO_MANIFEST_DIR");
        let cert_path = format!("{dir}/tests/fixtures/server-cert.pem");
        let certs = CertificateDer::pem_file_iter(&cert_path)
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pki_types::PrivateKeyDer::from_pem_file(format!(
            "{dir}/tests/fixtures/server-key.pem"
        ))
        .unwrap();
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _held = acceptor.accept(s).await;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                });
            }
        });
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let cfg: DirectoryConfig = toml::from_str(&format!(
            "domain = \"corp.example.com\"\nurls = [\"ldaps://127.0.0.1:{closed}\", \"ldaps://localhost:{up}\"]\nca_bundle = '{cert_path}'\ntimeout_secs = 10\n"
        ))
        .unwrap();
        let d = Directory::new(&cfg).unwrap();
        assert!(d.connect().await.is_ok());
        assert_eq!(d.preferred.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_sign_in_binds_as_typed_when_it_names_a_domain() {
        let d = Directory::unconnected(&config(Some("CORP")));
        assert_eq!(d.sign_in_name("JDoe").as_deref(), Some("CORP\\jdoe"));
        assert_eq!(
            d.sign_in_name(" john.doe@company.com ").as_deref(),
            Some("john.doe@company.com")
        );
        assert_eq!(
            d.sign_in_name("OTHER\\jdoe").as_deref(),
            Some("OTHER\\jdoe")
        );
        assert_eq!(d.sign_in_name("a*b"), None);
        assert_eq!(d.sign_in_name(""), None);
        let bare = Directory::unconnected(&config(None));
        assert_eq!(
            bare.sign_in_name("jdoe").as_deref(),
            Some("jdoe@corp.example.com")
        );
        // Without netbios nothing checks the domain WhoAmI reports, so a name from another
        // domain is bound in this one.
        assert_eq!(
            bare.sign_in_name("EMEA\\jdoe").as_deref(),
            Some("jdoe@corp.example.com")
        );
        assert_eq!(
            bare.sign_in_name("jdoe@emea.example.com").as_deref(),
            Some("jdoe@corp.example.com")
        );
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
