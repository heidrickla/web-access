//! The accept loop, shared by the console and Windows service entry points, and the background
//! account checks.

use crate::app::App;
use crate::config::{Config, Https};
use crate::store::now;
use crate::web::Peer;

use axum::Router;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, error, info, warn};

pub async fn run(
    config_path: &str,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::load(config_path)?;
    let listen = cfg.listen.clone();
    let acceptor = match &cfg.https {
        Some(h) => Some(TlsAcceptor::from(Arc::new(server_tls(h)?))),
        None => {
            warn!("no [https] section: the listener serves plain HTTP");
            None
        }
    };
    let app = Arc::new(App::new(cfg)?);
    let counts = app.store.counts()?;
    info!(
        users = counts.users,
        servers = counts.servers,
        database = %app.store.path().display(),
        credential_store = if app.vault.is_unlocked() { "unlocked" } else { "LOCKED" },
        "loaded {config_path}"
    );

    tokio::spawn(checks(Arc::clone(&app)));

    let router = crate::web::router(Arc::clone(&app));
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    info!(%listen, https = acceptor.is_some(), "listening");

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
                let router = router.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor {
                        Some(acceptor) => match acceptor.accept(stream).await {
                            Ok(tls) => serve(tls, peer, router).await,
                            Err(e) => debug!(%peer, error = %e, "TLS handshake failed"),
                        },
                        None => serve(stream, peer, router).await,
                    }
                });
            }
        }
    }
}

/// HTTP/1.1 on one connection, with upgrades so the WebSocket can take it over.
async fn serve<S>(stream: S, peer: SocketAddr, router: Router)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
        req.extensions_mut().insert(Peer(peer));
        router.clone().oneshot(req.map(axum::body::Body::new))
    });
    let result = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(30))
        .serve_connection(TokioIo::new(stream), svc)
        .with_upgrades()
        .await;
    if let Err(e) = result {
        debug!(%peer, error = %e, "connection ended with an error");
    }
}

fn server_tls(h: &Https) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    let cert_pem = std::fs::read(&h.cert).map_err(|e| format!("reading {}: {e}", h.cert))?;
    let key_pem = std::fs::read(&h.key).map_err(|e| format!("reading {}: {e}", h.key))?;
    let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", h.cert))?;
    if certs.is_empty() {
        return Err(format!("{} holds no certificate", h.cert).into());
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| format!("{}: {e}", h.key))?
        .ok_or_else(|| format!("{} holds no private key", h.key))?;
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Periodic housekeeping: expired sessions go, and accounts the directory no longer allows lose
/// their sessions and live RDP connections.
async fn checks(app: Arc<App>) {
    let every = Duration::from_secs(app.cfg.directory.check_interval_secs.max(30));
    let mut tick = tokio::time::interval(every);
    loop {
        tick.tick().await;
        if let Err(e) = app.store.sessions_purge(now()) {
            warn!(error = %e, "session purge failed");
        }
        match revocation_pass(&app).await {
            Ok(0) => {}
            Ok(n) => info!(revoked = n, "revocation pass ended sessions"),
            Err(e) => warn!(error = %e, "revocation pass could not run; nothing was revoked"),
        }
    }
}

/// Check every user holding a session against the directory. A directory that cannot be reached
/// revokes nothing.
pub async fn revocation_pass(app: &App) -> Result<usize, Box<dyn std::error::Error>> {
    if !app.directory.has_service_account() {
        return Ok(0);
    }
    let Some(password) = app.directory_password()? else {
        return Ok(0);
    };
    let users = app.store.users_with_sessions(now())?;
    if users.is_empty() {
        return Ok(0);
    }
    let names: Vec<String> = users.iter().map(|u| u.username.clone()).collect();
    let found = app.directory.lookup_many(&password, &names).await?;
    let mut revoked = 0;
    for (user, (_, account)) in users.iter().zip(found) {
        let reason = match &account {
            None => Some("the account no longer exists"),
            Some(a) if a.disabled => Some("the account is disabled"),
            Some(a) if a.expired => Some("the account has expired"),
            Some(a) if user.sid.as_deref().is_some_and(|s| s != a.sid) => {
                Some("the account's SID changed")
            }
            _ => None,
        };
        if let Some(reason) = reason {
            app.store.sessions_delete_user(user.id)?;
            let ended = app.live.end_user(user.id);
            app.store.audit(
                "system",
                "revoked",
                &format!("{}: {reason}; {ended} live session(s) ended", user.username),
            );
            revoked += 1;
        }
    }
    Ok(revoked)
}

/// Installed once per process before any TLS config is built.
pub fn install_crypto_provider() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "could not install the rustls crypto provider")?;
    Ok(())
}
