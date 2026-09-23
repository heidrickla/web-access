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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "web_access_proxy=info".into()),
        )
        .init();

    #[cfg(windows)]
    if std::env::args().any(|a| a == "--service") {
        service::start()?;
        return Ok(());
    }

    let config_path = config_path_from_args();
    tokio::runtime::Runtime::new()?.block_on(async move {
        server::install_crypto_provider()?;
        server::run(&config_path, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    })
}
