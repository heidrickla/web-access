//! web-access proxy.
//!
//! Terminate a WebSocket, authenticate the caller, check the requested target id against the
//! allowlist, resolve it, open TCP, hand the RDCleanPath response back, then move bytes.
//!
//! What this deliberately does NOT do: decode RDP, store any credential, or accept an address from
//! the client. See `docs/architecture.md`.
//!
//!     web-access-proxy [config.toml]     run in the foreground, stop with Ctrl-C
//!     web-access-proxy --service [path]  run under the Windows Service Control Manager

mod auth;
mod config;
mod policy;
mod proxy;
mod resolve;
mod server;
mod web;

#[cfg(windows)]
mod service;

/// The config path, absolute. A Windows service starts with its working directory set to the system
/// directory, so a relative path would resolve against `C:\Windows\System32` rather than the install
/// directory; making it absolute here means both entry points agree on what they loaded.
pub fn config_path_from_args() -> String {
    let given = std::env::args()
        .skip(1)
        .find(|a| !a.starts_with("--"))
        .unwrap_or_else(|| "config.toml".to_owned());
    std::fs::canonicalize(&given)
        .map(|p| p.to_string_lossy().trim_start_matches(r"\\?\").to_owned())
        .unwrap_or(given)
}

/// Where a service writes its log. A service has no stdout — anything written there goes nowhere,
/// so without this the proxy is undiagnosable exactly when it matters. Beside the config, because
/// that directory already exists and the service can already read it.
#[cfg(windows)]
fn service_log_path(config_path: &str) -> std::path::PathBuf {
    std::path::Path::new(config_path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
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
            .with_ansi(false) // a log file is read in Notepad, not a terminal
            .with_writer(move || file.try_clone().expect("could not clone the log file handle"))
            .init();
        tracing::info!(log = %path.display(), "starting as a windows service");
        service::start()?;
        return Ok(());
    }

    tracing_subscriber::fmt().with_env_filter(filter()).init();

    let config_path = config_path_from_args();
    tokio::runtime::Runtime::new()?.block_on(async move {
        server::install_crypto_provider()?;
        server::run(&config_path, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    })
}
