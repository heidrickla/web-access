//! The accept loop, shared by the console and Windows service entry points.
//!
//! Both callers supply their own shutdown future: Ctrl-C from a terminal, the Service Control
//! Manager's stop event from a service. Nothing below knows which.

use crate::config::Config;
use crate::policy::Catalogue;
use crate::proxy::{tls_setup, Session};

use std::future::Future;
use std::sync::Arc;
use tracing::{error, info, warn};

pub async fn run(
    config_path: &str,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::load(config_path)?;
    let catalogue = Arc::new(Catalogue::new(&cfg));
    let all_groups: Arc<Vec<String>> =
        Arc::new(cfg.policy.iter().map(|p| p.group.clone()).collect());

    if catalogue.is_empty() {
        warn!("the allowlist is empty, so this proxy can reach nothing; that is the safe state, not a working one");
    }
    info!(
        targets = catalogue.len(),
        policies = cfg.policy.len(),
        verify = ?cfg.tls.verify,
        "loaded {config_path}"
    );
    warn!("NO IDENTITY PROVIDER IS CONFIGURED: everyone who can reach this listener is served the launcher and granted every configured group. The boundary is the network, not an identity. See auth.rs::identify.");

    let tls = Arc::new(tls_setup(&cfg.tls)?);
    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    info!(listen = %cfg.listen, "serving the launcher and accepting websocket connections");

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
                    tls: Arc::clone(&tls),
                };
                let catalogue = Arc::clone(&catalogue);
                let all_groups = Arc::clone(&all_groups);

                tokio::spawn(async move {
                    // One listener serves both the launcher and its WebSocket. The path is peeked
                    // without consuming, so a WebSocket upgrade still reaches the handshake with its
                    // bytes intact.
                    let path = match crate::web::peek_path(&stream).await {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(%peer, error = %e, "could not read the request line");
                            return;
                        }
                    };

                    if path != crate::web::WS_PATH {
                        if let Err(e) = crate::web::serve(stream, &path, &catalogue, &all_groups).await {
                            warn!(%peer, %path, error = %e, "serving the launcher failed");
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
