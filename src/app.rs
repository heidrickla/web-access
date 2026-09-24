//! Everything a request handler needs, built once at start.

use crate::auth::Tickets;
use crate::config::Config;
use crate::directory::Directory;
use crate::live::LiveSessions;
use crate::migrate::PendingImport;
use crate::proxy::{tls_setup, TlsSetup};
use crate::store::{ImportRow, Store};
use crate::vault::{local_protector, Vault, VaultError};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Password hashes computed at once. Each Argon2 run holds 64 MiB.
pub const HASH_PERMITS: usize = 4;

const META_DIRECTORY_PASSWORD: &str = "directory_password";
const AAD_DIRECTORY_PASSWORD: &[u8] = b"directory service password";
pub const META_FROZEN: &str = "frozen";
/// Set with a freeze an export sets, cleared once the export hands over its archive. Found at
/// start, it marks a freeze whose export never finished.
pub const META_FREEZE_PENDING: &str = "freeze_pending";
const META_SEEDED: &str = "seeded_from_config";

pub struct App {
    pub cfg: Config,
    pub store: Store,
    pub vault: Vault,
    /// None when only local accounts sign in.
    pub directory: Option<Directory>,
    pub tickets: Tickets,
    pub live: LiveSessions,
    pub target_tls: TlsSetup,
    /// Set the cookie's Secure attribute: true when the listener speaks HTTPS.
    pub secure_cookies: bool,
    pub host_name: String,
    pub imports: Mutex<HashMap<String, PendingImport>>,
    /// Requests hold it shared; an import, and an export, hold it exclusively. So no request
    /// straddles a database swap, and no edit lands between a freeze and its snapshot.
    pub gate: tokio::sync::RwLock<()>,
    /// Bumped by every import. Work that read the database, left the gate for something slow, and
    /// came back checks it before acting on what it read.
    generation: AtomicU64,
    /// Bounds concurrent password hashing, whatever the connection count.
    pub hash_permits: Arc<tokio::sync::Semaphore>,
    /// One export at a time, so a failed export can only undo a freeze it set itself.
    pub export_lock: Arc<tokio::sync::Mutex<()>>,
    /// Failed local-account sign-ins, per username.
    pub throttle: crate::auth::Throttle,
}

impl App {
    pub fn new(cfg: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let data_dir = cfg.data_dir();
        std::fs::create_dir_all(&data_dir)?;
        let store = Store::open(&cfg.database_path())?;
        let vault = Vault::load(&store, local_protector(&data_dir)?)?;
        let directory = cfg.directory.as_ref().map(Directory::new).transpose()?;
        let target_tls = tls_setup(&cfg.tls)?;
        let secure = cfg.https.is_some();
        let app = Self::from_parts(cfg, store, vault, directory, target_tls, host_name(), secure);
        app.seed_from_config()?;
        Ok(app)
    }

    /// `new`, for the process that serves. Only it settles what an earlier run left behind:
    /// command-line tools open the same database while the service runs, and must not lift the
    /// freeze of an export still in progress.
    pub fn for_serving(cfg: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let app = Self::new(cfg)?;
        app.lift_stranded_freeze()?;
        Ok(app)
    }

    /// A freeze whose export never handed over its archive, because the service stopped, crashed
    /// or lost power mid-export, is lifted when the service starts. Returns whether one was.
    pub fn lift_stranded_freeze(&self) -> Result<bool, crate::store::StoreError> {
        if !self.store.flag(META_FREEZE_PENDING)? {
            return Ok(false);
        }
        self.store.set_flag(META_FROZEN, false)?;
        self.store.set_flag(META_FREEZE_PENDING, false)?;
        self.store.audit("system", "unfreeze", "the export that froze this proxy did not finish");
        tracing::warn!("lifted a freeze left by an export that did not finish");
        Ok(true)
    }

    pub fn from_parts(
        cfg: Config,
        store: Store,
        vault: Vault,
        directory: Option<Directory>,
        target_tls: TlsSetup,
        host_name: String,
        secure_cookies: bool,
    ) -> Self {
        Self {
            secure_cookies,
            host_name,
            cfg,
            store,
            vault,
            directory,
            tickets: Tickets::default(),
            live: LiveSessions::default(),
            target_tls,
            imports: Mutex::new(HashMap::new()),
            gate: tokio::sync::RwLock::new(()),
            generation: AtomicU64::new(0),
            hash_permits: Arc::new(tokio::sync::Semaphore::new(HASH_PERMITS)),
            export_lock: Arc::new(tokio::sync::Mutex::new(())),
            throttle: crate::auth::Throttle::default(),
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Called by an import, under the exclusive gate, once the new database is in place.
    pub fn bump_generation(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// `[[target]]` entries become servers in an "Imported" group, once, into an empty database.
    fn seed_from_config(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.cfg.target.is_empty()
            || self.store.flag(META_SEEDED)?
            || !self.store.servers_empty()?
        {
            return Ok(());
        }
        let rows: Vec<ImportRow> = self
            .cfg
            .target
            .iter()
            .map(|t| ImportRow {
                name: t.id.clone(),
                host: t.host.clone(),
                port: t.port,
                group: Some("Imported".into()),
            })
            .collect();
        let (created, _) = self.store.servers_import(&rows)?;
        self.store.set_flag(META_SEEDED, true)?;
        self.store.audit(
            "system",
            "servers.seed",
            &format!("{created} server(s) from config.toml"),
        );
        tracing::info!(created, "seeded servers from config.toml");
        Ok(())
    }

    pub fn frozen(&self) -> bool {
        self.store.flag(META_FROZEN).unwrap_or(false)
    }

    pub fn directory_password(&self) -> Result<Option<String>, VaultError> {
        match self.store.meta_get(META_DIRECTORY_PASSWORD)? {
            None => Ok(None),
            Some(blob) => {
                let plain = self.vault.open_value(AAD_DIRECTORY_PASSWORD, &blob)?;
                Ok(Some(String::from_utf8_lossy(&plain).into_owned()))
            }
        }
    }

    pub fn set_directory_password(&self, password: &str) -> Result<(), VaultError> {
        let blob = self
            .vault
            .seal_value(AAD_DIRECTORY_PASSWORD, password.as_bytes())?;
        self.store.meta_set(META_DIRECTORY_PASSWORD, &blob)?;
        Ok(())
    }

    pub fn directory_password_set(&self) -> bool {
        matches!(self.store.meta_get(META_DIRECTORY_PASSWORD), Ok(Some(_)))
    }

    pub fn is_admin(&self, user: &crate::store::User) -> bool {
        user.is_admin || self.cfg.is_bootstrap_admin(&user.username)
    }

    /// The directory, when it has a service account for lookups.
    pub fn lookup_directory(&self) -> Option<&Directory> {
        self.directory.as_ref().filter(|d| d.has_service_account())
    }
}

/// This machine's name, for export file names and the import confirmation.
pub fn host_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_owned())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "web-access".to_owned())
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_in(dir: &std::path::Path) -> Config {
        let text = format!(
            "listen = \"127.0.0.1:0\"\ndata_dir = {:?}\nadmins = [\"boss\"]\nallow_local_accounts = true\n[tls]\nverify = \"insecure\"\n",
            dir.to_string_lossy()
        );
        Config::parse("test", &text).unwrap()
    }

    /// A freeze stranded by an export that never finished (the service stopped, crashed or lost
    /// power) is lifted when the service next starts, and not by a command-line tool, which may run
    /// while the service's export is still in progress. A freeze with no export pending stays.
    #[test]
    fn a_stranded_freeze_is_lifted_when_the_service_starts_and_only_then() {
        let dir = std::env::temp_dir().join(format!("web-access-test-{}", &crate::auth::random_token()[..12]));
        let app = App::for_serving(config_in(&dir)).unwrap();
        app.store.set_flag(META_FREEZE_PENDING, true).unwrap();
        app.store.set_flag(META_FROZEN, true).unwrap();
        drop(app);
        let tool = App::new(config_in(&dir)).unwrap();
        assert!(tool.frozen(), "a command-line tool lifted a freeze whose export may still be running");
        drop(tool);
        let app = App::for_serving(config_in(&dir)).unwrap();
        assert!(!app.frozen(), "a stranded freeze survived a restart");
        app.store.set_flag(META_FROZEN, true).unwrap();
        drop(app);
        let app = App::for_serving(config_in(&dir)).unwrap();
        assert!(app.frozen(), "a freeze with no export pending was lifted at start");
    }
}
