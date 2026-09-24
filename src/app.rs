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
use std::sync::Mutex;

const META_DIRECTORY_PASSWORD: &str = "directory_password";
const AAD_DIRECTORY_PASSWORD: &[u8] = b"directory service password";
pub const META_FROZEN: &str = "frozen";
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
}

impl App {
    pub fn new(cfg: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let data_dir = cfg.data_dir();
        std::fs::create_dir_all(&data_dir)?;
        let store = Store::open(&cfg.database_path())?;
        let vault = Vault::load(&store, local_protector(&data_dir)?)?;
        let directory = cfg.directory.as_ref().map(Directory::new).transpose()?;
        let target_tls = tls_setup(&cfg.tls)?;
        let app = Self {
            secure_cookies: cfg.https.is_some(),
            host_name: host_name(),
            cfg,
            store,
            vault,
            directory,
            tickets: Tickets::default(),
            live: LiveSessions::default(),
            target_tls,
            imports: Mutex::new(HashMap::new()),
        };
        app.seed_from_config()?;
        Ok(app)
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
