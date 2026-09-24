//! web-access proxy.
//!
//!     web-access-proxy [config.toml]                          run in the foreground; Ctrl-C stops
//!     web-access-proxy --service [config.toml]                run under the Service Control Manager
//!     web-access-proxy export <config.toml> <out.zip>         write an export, as the admin page does
//!     web-access-proxy import <config.toml> <in.zip> [--replace]   apply an export; service stopped
//!     web-access-proxy set-secret recovery <config.toml>      set or change the recovery passphrase
//!     web-access-proxy set-secret directory <config.toml>     set the service account's password
//!     web-access-proxy local-account <config.toml> <name> [--admin]   create a local account, or
//!                                                             reset its password

mod admin;
mod app;
mod auth;
mod config;
mod directory;
mod live;
mod migrate;
mod policy;
mod proxy;
mod resolve;
mod server;
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

/// Where a service writes its log: beside the config, because a service has no stdout.
#[cfg(windows)]
fn service_log_path(config_path: &str) -> std::path::PathBuf {
    use std::path::Path;
    Path::new(config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("web-access-proxy.log")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "web_access_proxy=info".into())
    };

    #[cfg(windows)]
    if std::env::args().any(|a| a == "--service") {
        let path = service_log_path(&config_path_from_args());
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        tracing_subscriber::fmt()
            .with_env_filter(filter())
            .with_ansi(false)
            .with_writer(move || file.try_clone().expect("could not clone the log file handle"))
            .init();
        tracing::info!(log = %path.display(), "starting as a windows service");
        service::start()?;
        return Ok(());
    }

    tracing_subscriber::fmt().with_env_filter(filter()).init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        server::install_crypto_provider()?;
        match args.first().map(String::as_str) {
            Some("export") => cli::export(&args[1..]),
            Some("import") => cli::import(&args[1..]),
            Some("set-secret") => cli::set_secret(&args[1..]).await,
            Some("local-account") => cli::local_account(&args[1..]),
            _ => {
                let config_path = config_path_from_args();
                server::run(&config_path, async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await
            }
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
        Ok(App::new(Config::load(&absolute(path))?)?)
    }

    pub fn export(args: &[String]) -> Result {
        let app = app(args.first())?;
        let out = args.get(1).ok_or("usage: export <config.toml> <out.zip>")?;
        let pass = prompt::secret("Recovery passphrase: ")?;
        let export = migrate::export(&app, &pass)?;
        std::fs::write(out, &export.bytes)?;
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
        let zip = args.get(1).ok_or("usage: import <config.toml> <in.zip> [--replace]")?;
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
        let pass = prompt::secret("Recovery passphrase: ")?;
        let counts = migrate::apply(&app, &blob, &pass).map_err(|e| match e {
            migrate::MigrateError::Store(s) => format!("{s} (stop the WebAccessProxy service first)"),
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
                app.vault.set_recovery(&app.store, current.as_deref(), &new)?;
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
            _ => return Err("usage: set-secret recovery|directory <config.toml>".into()),
        }
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
        let username = crate::directory::normalize_username(name).ok_or("that is not a valid username")?;
        let password = prompt::secret(&format!("Password for {username} (12 characters or more): "))?;
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

    mod prompt {
        use std::io::{BufRead, Write};

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
                    GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
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
