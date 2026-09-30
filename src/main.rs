//! web-access proxy.
//!
//!     web-access-proxy --version                              the version and the build it came from
//!     web-access-proxy [config.toml]                          run in the foreground; Ctrl-C stops
//!     web-access-proxy --service [config.toml]                run under the Service Control Manager
//!     web-access-proxy export <config.toml> <out.zip> [--passphrase-file <path>]   write an export
//!     web-access-proxy import <config.toml> <in.zip> [--replace] [--passphrase-file <path>]
//!                                                             apply an export; service stopped
//!     web-access-proxy set-secret recovery <config.toml> [--replace]   set or change the recovery
//!                                                             passphrase; --replace for a lost one
//!     web-access-proxy set-secret directory <config.toml>     set the service account's password
//!     web-access-proxy unlock <config.toml>                   unlock a store moved from another host
//!     web-access-proxy reset-credentials <config.toml>        start a store nothing can open over
//!     web-access-proxy local-account <config.toml> <name> [--admin]   create a local account, or
//!                                                             reset its password

mod admin;
mod app;
mod auth;
mod config;
mod directory;
mod https;
mod live;
// Used by the Windows service; built and tested everywhere.
#[cfg_attr(not(windows), allow(dead_code))]
mod logfile;
mod migrate;
mod policy;
mod proxy;
mod resolve;
mod server;
mod settings;
mod store;
mod vault;
mod web;

#[cfg(windows)]
mod service;

/// A path made absolute. A Windows service starts in the system directory, so a relative path
/// would resolve against `C:\Windows\System32`.
fn absolute(given: &str) -> String {
    std::fs::canonicalize(given)
        .map(|p| p.to_string_lossy().trim_start_matches(r"\\?\").to_owned())
        .unwrap_or_else(|_| given.to_owned())
}

/// The config path for the run and service entry points: the first argument that is not a flag.
pub fn config_path_from_args() -> String {
    let given = std::env::args()
        .skip(1)
        .find(|a| !a.starts_with("--"))
        .unwrap_or_else(|| "config.toml".to_owned());
    absolute(&given)
}

/// Days of service log kept, one file a day.
#[cfg(windows)]
const LOG_DAYS: usize = 30;

/// Where a service writes its log: beside the config, because a service has no stdout.
#[cfg(windows)]
fn service_log(config_path: &str) -> std::sync::Arc<logfile::DailyLog> {
    use std::path::Path;
    let dir = Path::new(config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."));
    logfile::DailyLog::new(dir, "web-access-proxy", LOG_DAYS)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "web_access_proxy=info".into())
    };

    #[cfg(windows)]
    if std::env::args().any(|a| a == "--service") {
        let log = service_log(&config_path_from_args());
        let path = log.current_path();
        tracing_subscriber::fmt()
            .with_env_filter(filter())
            .with_ansi(false)
            .with_writer(move || logfile::Writer(std::sync::Arc::clone(&log)))
            .init();
        tracing::info!(log = %path.display(), keep_days = LOG_DAYS, "starting as a windows service");
        service::start()?;
        return Ok(());
    }

    tracing_subscriber::fmt().with_env_filter(filter()).init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let tool = args.first().map(String::as_str);
    if tool == Some("--version") {
        println!(
            "web-access-proxy {} ({})",
            env!("CARGO_PKG_VERSION"),
            option_env!("WEB_ACCESS_BUILD").unwrap_or("build unrecorded")
        );
        return Ok(());
    }
    if !matches!(
        tool,
        Some("export" | "import" | "set-secret" | "local-account" | "unlock" | "reset-credentials")
    ) {
        return server::serve_blocking(
            &config_path_from_args(),
            async {
                let _ = tokio::signal::ctrl_c().await;
            },
            || {},
        );
    }
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        server::install_crypto_provider()?;
        match args.first().map(String::as_str) {
            Some("export") => cli::export(&args[1..]),
            Some("import") => cli::import(&args[1..]),
            Some("set-secret") => cli::set_secret(&args[1..]).await,
            Some("local-account") => cli::local_account(&args[1..]),
            Some("unlock") => cli::unlock(&args[1..]),
            Some("reset-credentials") => cli::reset_credentials(&args[1..]),
            _ => Err("not a command-line tool".into()),
        }
    })
}

mod cli {
    //! The same operations as the Migration page, for scheduled backups and for a host whose web
    //! listener is not up yet.

    use super::absolute;
    use crate::app::App;
    use crate::config::Config;
    use crate::migrate;
    use crate::vault::Vault;
    use std::error::Error;

    type Result = std::result::Result<(), Box<dyn Error>>;

    fn app(config: Option<&String>) -> std::result::Result<App, Box<dyn Error>> {
        let path = config.ok_or("the config path is required")?;
        App::new(Config::load(&absolute(path))?)
    }

    /// The recovery passphrase: from `--passphrase-file <path>` for a scheduled task, which has no
    /// console, and otherwise typed. Only a trailing line ending is taken off the file's contents.
    fn passphrase(args: &[String]) -> std::result::Result<String, Box<dyn Error>> {
        match args.iter().position(|a| a == "--passphrase-file") {
            Some(i) => {
                let path = args.get(i + 1).ok_or("--passphrase-file needs a path")?;
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("reading the passphrase file {path}: {e}"))?;
                Ok(text.trim_end_matches(['\r', '\n']).to_owned())
            }
            None => Ok(prompt::secret("Recovery passphrase: ")?),
        }
    }

    /// Write `bytes` to `out` without ever leaving a partial file there: written beside it, flushed
    /// to disk, read back as an archive, then renamed over it. A full disk or a dropped share keeps
    /// the previous export at `out` intact.
    fn write_export(out: &str, bytes: &[u8]) -> Result {
        use std::io::Write;
        let part = format!("{out}.part");
        let written = (|| -> Result {
            let mut f = std::fs::File::create(&part)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            drop(f);
            migrate::read_zip(&std::fs::read(&part)?)?;
            std::fs::rename(&part, out)?;
            Ok(())
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&part);
        }
        written
    }

    pub fn export(args: &[String]) -> Result {
        let app = app(args.first())?;
        let out = args
            .get(1)
            .filter(|a| !a.starts_with("--"))
            .ok_or("usage: export <config.toml> <out.zip> [--passphrase-file <path>]")?;
        let pass = passphrase(args)?;
        let export = migrate::export(&app, &pass)?;
        write_export(out, &export.bytes)?;
        app.store.audit("console", "export", &export.file_name);
        println!(
            "wrote {out}: {} users, {} servers, {} assignments, {} saved credentials",
            export.manifest.counts.users,
            export.manifest.counts.servers,
            export.manifest.counts.assignments,
            export.manifest.counts.credentials
        );
        Ok(())
    }

    pub fn import(args: &[String]) -> Result {
        let app = app(args.first())?;
        let zip = args
            .get(1)
            .ok_or("usage: import <config.toml> <in.zip> [--replace]")?;
        let replace = args.iter().any(|a| a == "--replace");
        let (manifest, blob) = migrate::read_zip(&std::fs::read(zip)?)?;
        let current = app.store.counts()?;
        if migrate::holds_data(&current) && !replace {
            return Err(format!(
                "this proxy holds {} users and {} servers; add --replace to overwrite them",
                current.users, current.servers
            )
            .into());
        }
        println!(
            "export from {} holds {} users, {} servers, {} assignments, {} saved credentials",
            manifest.source_host,
            manifest.counts.users,
            manifest.counts.servers,
            manifest.counts.assignments,
            manifest.counts.credentials
        );
        let pass = passphrase(args)?;
        let counts = migrate::apply(&app, &blob, &pass).map_err(|e| match e {
            migrate::MigrateError::Store(s) => {
                format!("{s} (stop the WebAccessProxy service first)")
            }
            other => other.to_string(),
        })?;
        app.store.audit("console", "import", &format!("{counts:?}"));
        println!("imported; start the service");
        Ok(())
    }

    pub async fn set_secret(args: &[String]) -> Result {
        let which = args.first().map(String::as_str);
        let app = app(args.get(1))?;
        match which {
            Some("recovery") if args.iter().any(|a| a == "--replace") => {
                // A lost passphrase. The key comes from this host's own wrap instead.
                if !app.vault.is_unlocked() {
                    return Err("the credential store is locked on this host, so there is no key to wrap under a new passphrase; reset-credentials starts it over".into());
                }
                let new = prompt::secret("New recovery passphrase (12 characters or more): ")?;
                if prompt::secret("Repeat it: ")? != new {
                    return Err("the two entries differ".into());
                }
                app.vault.replace_recovery(&app.store, &new)?;
                app.store
                    .audit("console", "recovery.replaced", "without the previous passphrase");
                println!("recovery passphrase replaced; exports made before now open only with the old one");
            }
            Some("recovery") => {
                let current = if Vault::recovery_set(&app.store)? {
                    Some(prompt::secret("Current recovery passphrase: ")?)
                } else {
                    None
                };
                let new = prompt::secret("New recovery passphrase (12 characters or more): ")?;
                if prompt::secret("Repeat it: ")? != new {
                    return Err("the two entries differ".into());
                }
                app.vault
                    .set_recovery(&app.store, current.as_deref(), &new)?;
                app.store.audit("console", "recovery.set", "");
                println!("recovery passphrase set; keep it with the proxy's documentation");
            }
            Some("directory") => {
                let (Some(account), Some(directory)) =
                    (app.cfg.service_account(), app.lookup_directory())
                else {
                    return Err("no service_account is configured in config.toml".into());
                };
                let pass = prompt::secret(&format!("Password for {account}: "))?;
                let probe = crate::directory::normalize_username(account).unwrap_or_default();
                directory.lookup_many(&pass, &[probe]).await?;
                app.set_directory_password(&pass)?;
                app.store.audit("console", "directory.password", "");
                println!("service account password verified and stored");
            }
            _ => {
                return Err(
                    "usage: set-secret recovery <config.toml> [--replace] | set-secret directory <config.toml>"
                        .into(),
                )
            }
        }
        Ok(())
    }

    /// Unlock a credential store moved here from another host, with the recovery passphrase.
    pub fn unlock(args: &[String]) -> Result {
        let app = app(args.first())?;
        if app.vault.is_unlocked() {
            println!("the credential store is already unlocked on this host");
            return Ok(());
        }
        let pass = passphrase(args)?;
        app.vault.adopt(&app.store, &pass)?;
        app.store.audit("console", "vault.unlock", "");
        println!("credential store unlocked for this host");
        Ok(())
    }

    /// Start the credential store over when nothing can open it. Deletes every saved credential and
    /// the directory service account's password.
    pub fn reset_credentials(args: &[String]) -> Result {
        let app = app(args.first())?;
        println!(
            "This deletes every saved credential ({}) and the directory service account's password, and starts the credential store over.",
            app.store.counts()?.credentials
        );
        let typed = prompt::line(&format!(
            "Type this host's name, {}, to confirm: ",
            app.host_name
        ))?;
        if !typed.trim().eq_ignore_ascii_case(&app.host_name) {
            return Err("the host name did not match; nothing was changed".into());
        }
        let removed = app.reset_credential_store()?;
        app.store.audit(
            "console",
            "vault.reset",
            &format!("{removed} saved credential(s) deleted"),
        );
        println!("credential store reset; {removed} saved credential(s) deleted. Set a recovery passphrase next.");
        Ok(())
    }

    /// A local account signs in against a hash in the database, never the directory. For testing, and
    /// for a proxy with no directory at all.
    pub fn local_account(args: &[String]) -> Result {
        let app = app(args.first())?;
        let name = args
            .get(1)
            .filter(|a| !a.starts_with("--"))
            .ok_or("usage: local-account <config.toml> <name> [--admin]")?;
        let username =
            crate::directory::normalize_username(name).ok_or("that is not a valid username")?;
        let password = prompt::secret(&format!(
            "Password for {username} (12 characters or more): "
        ))?;
        crate::vault::check_strength(&password).map_err(|e| e.to_string())?;
        if prompt::secret("Repeat it: ")? != password {
            return Err("the two entries differ".into());
        }
        let hash = crate::vault::hash_password(&password)?;
        let sid = format!("local:{}", &crate::auth::random_token()[..32]);
        let id = app.store.local_account_set(&username, &hash, &sid)?;
        if args.iter().any(|a| a == "--admin") {
            app.store.user_set_admin(id, true)?;
        }
        app.store.audit("console", "local-account.set", &username);
        println!("local account {username} is ready");
        if !app.cfg.allow_local_accounts {
            println!("it cannot sign in until config.toml has allow_local_accounts = true");
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// An export that is not a readable archive never replaces the one already there, and
        /// leaves no partial file behind; a good one replaces it.
        #[test]
        fn a_failed_export_keeps_the_previous_one() {
            let dir = std::env::temp_dir().join(format!(
                "web-access-cli-export-{}",
                &crate::auth::random_token()[..12]
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let out = dir.join("nightly.zip").to_string_lossy().into_owned();
            let blob = b"ciphertext".to_vec();
            std::fs::write(&out, b"last night's export").unwrap();

            assert!(write_export(&out, b"half a zip").is_err());
            assert_eq!(std::fs::read(&out).unwrap(), b"last night's export");
            assert!(!std::path::Path::new(&format!("{out}.part")).exists());

            let good = migrate::build_zip(&migrate::test_manifest(&blob), &blob).unwrap();
            write_export(&out, &good).unwrap();
            assert_eq!(std::fs::read(&out).unwrap(), good);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    mod prompt {
        use std::io::{BufRead, Write};

        /// Read a line from the console, echoed.
        pub fn line(label: &str) -> std::io::Result<String> {
            print!("{label}");
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            Ok(line.trim_end_matches(['\r', '\n']).to_owned())
        }

        /// Read a line from the console without echoing it where the platform allows.
        pub fn secret(label: &str) -> std::io::Result<String> {
            print!("{label}");
            std::io::stdout().flush()?;
            let _echo = EchoOff::new();
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            println!();
            Ok(line.trim_end_matches(['\r', '\n']).to_owned())
        }

        #[cfg(windows)]
        struct EchoOff(Option<(windows_sys::Win32::Foundation::HANDLE, u32)>);

        #[cfg(windows)]
        impl EchoOff {
            fn new() -> Self {
                use windows_sys::Win32::System::Console::{
                    GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT,
                    STD_INPUT_HANDLE,
                };
                // SAFETY: plain console API calls on this process's standard input handle.
                unsafe {
                    let h = GetStdHandle(STD_INPUT_HANDLE);
                    let mut mode = 0u32;
                    if GetConsoleMode(h, &mut mode) == 0 {
                        return Self(None);
                    }
                    SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT);
                    Self(Some((h, mode)))
                }
            }
        }

        #[cfg(windows)]
        impl Drop for EchoOff {
            fn drop(&mut self) {
                if let Some((h, mode)) = self.0 {
                    // SAFETY: restores the mode read in new().
                    unsafe {
                        windows_sys::Win32::System::Console::SetConsoleMode(h, mode);
                    }
                }
            }
        }

        #[cfg(not(windows))]
        struct EchoOff;

        #[cfg(not(windows))]
        impl EchoOff {
            fn new() -> Self {
                EchoOff
            }
        }
    }
}
