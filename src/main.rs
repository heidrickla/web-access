//! web-access proxy.
//!
//! Terminate a WebSocket, authenticate the caller, check the requested target id against the
//! allowlist, resolve it, open TCP, hand the RDCleanPath response back, then move bytes.
//!
//! What this deliberately does NOT do: decode RDP, store any credential, or accept an address from
//! the client. See `docs/architecture.md`.

mod auth;
mod config;
mod policy;
mod proxy;
mod resolve;

use auth::{Authenticator, StaticAuthenticator};
use config::Config;
use policy::{Catalogue, Identity};
use proxy::{tls_setup, Session};

use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "web_access_proxy=info".into()),
        )
        .init();

    // The provider needs installing once per process before any TLS config is built.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "could not install the rustls crypto provider")?;

    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_owned());
    let cfg = Config::load(&path)?;
    let catalogue = Arc::new(Catalogue::new(&cfg));

    if catalogue.is_empty() {
        warn!("the allowlist is empty, so this proxy can reach nothing; that is the safe state, not a working one");
    }
    info!(
        targets = catalogue.len(),
        policies = cfg.policy.len(),
        verify = ?cfg.tls.verify,
        "loaded {path}"
    );

    // Placeholder identity source. See auth.rs: this is the piece designed to be deleted once the
    // identity provider is chosen.
    let mut tokens = BTreeMap::new();
    if let Ok(dev) = std::env::var("WEB_ACCESS_DEV_TOKEN") {
        tokens.insert(
            dev,
            Identity {
                subject: "dev".into(),
                groups: cfg.policy.iter().map(|p| p.group.clone()).collect(),
            },
        );
        warn!("WEB_ACCESS_DEV_TOKEN is set: a single static token grants every configured group. Development only.");
    }
    let authenticator: Arc<dyn Authenticator> = Arc::new(StaticAuthenticator::new(tokens));

    let tls = Arc::new(tls_setup(&cfg.tls)?);
    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    info!(listen = %cfg.listen, "accepting websocket connections");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                error!(error = %e, "accept failed");
                continue;
            }
        };

        let session = Session {
            catalogue: Arc::clone(&catalogue),
            authenticator: Arc::clone(&authenticator),
            tls: Arc::clone(&tls),
        };

        tokio::spawn(async move {
            let ws = match tokio_tungstenite::accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                    warn!(%peer, error = %e, "websocket handshake failed");
                    return;
                }
            };
            if let Err(e) = session.run(ws, peer).await {
                warn!(%peer, error = %e, "session ended");
            }
        });
    }
}
