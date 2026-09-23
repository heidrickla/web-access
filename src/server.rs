//! The accept loop, shared by the console and Windows service entry points.
//!
//! Both callers supply their own shutdown future: Ctrl-C from a terminal, the Service Control
//! Manager's stop event from a service. Nothing below knows which.

use crate::auth::{Authenticator, StaticAuthenticator};
use crate::config::Config;
use crate::policy::{Catalogue, Identity};
use crate::proxy::{tls_setup, Session};

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use tracing::{error, info, warn};

pub async fn run(
    config_path: &str,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::load(config_path)?;
    let catalogue = Arc::new(Catalogue::new(&cfg));

    if catalogue.is_empty() {
        warn!("the allowlist is empty, so this proxy can reach nothing; that is the safe state, not a working one");
    }
    info!(
        targets = catalogue.len(),
        policies = cfg.policy.len(),
        verify = ?cfg.tls.verify,
        "loaded {config_path}"
    );

    // Placeholder identity source. See auth.rs: the piece designed to be deleted once the identity
    // provider is chosen.
    let mut tokens = BTreeMap::new();
    if let Ok(dev) = std::env::var("WEB_ACCESS_DEV_TOKEN") {
        tokens.insert(
            dev,
            Identity {
                subject: "dev".into(),
                groups: cfg.policy.iter().map(|p| p.group.clone()).collect(),
            },
        );
        warn!("WEB_ACCESS_DEV_TOKEN is set: one static token grants every configured group. Development only.");
    }
    let authenticator: Arc<dyn Authenticator> = Arc::new(StaticAuthenticator::new(tokens));

    let tls = Arc::new(tls_setup(&cfg.tls)?);
    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    info!(listen = %cfg.listen, "accepting websocket connections");

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown requested; no longer accepting connections");
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
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
                    // One listener serves both the browser client and its WebSocket. The path is
                    // peeked without consuming, so a WebSocket upgrade still reaches the handshake
                    // with its bytes intact.
                    let path = match crate::web::peek_path(&stream).await {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(%peer, error = %e, "could not read the request line");
                            return;
                        }
                    };

                    if path != crate::web::WS_PATH {
                        if let Err(e) = crate::web::serve(stream, &path).await {
                            warn!(%peer, %path, error = %e, "serving the client failed");
                        }
                        return;
                    }

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
    }
}

/// Installed once per process before any TLS config is built.
pub fn install_crypto_provider() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "could not install the rustls crypto provider")?;
    Ok(())
}
