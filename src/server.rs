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

    let limits = Limits {
        max_connections: app.cfg.max_connections,
        tls_handshake: TLS_HANDSHAKE,
    };
    let router = crate::web::router(Arc::clone(&app));
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    info!(%listen, https = acceptor.is_some(), max_connections = limits.max_connections, "listening");
    accept_loop(listener, acceptor, router, limits, shutdown).await;
    Ok(())
}

/// A client that has not finished its TLS handshake by now is dropped.
pub const TLS_HANDSHAKE: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// HTTP connections served at once, each from accept until its request cycle ends. A connection
    /// over the limit is closed on accept.
    pub max_connections: usize,
    pub tls_handshake: Duration,
}

pub async fn accept_loop(
    listener: tokio::net::TcpListener,
    acceptor: Option<TlsAcceptor>,
    router: Router,
    limits: Limits,
    shutdown: impl Future<Output = ()>,
) {
    let permits = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown requested; no longer accepting connections");
                return;
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        error!(error = %e, "accept failed");
                        continue;
                    }
                };
                // Admission before any work is spawned: unauthenticated clients cannot hold more
                // than the limit, whatever they send or fail to send.
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    warn!(%peer, "connection limit reached; closing");
                    drop(stream);
                    continue;
                };
                let router = router.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    match acceptor {
                        Some(acceptor) => {
                            match tokio::time::timeout(limits.tls_handshake, acceptor.accept(stream)).await {
                                Ok(Ok(tls)) => serve(tls, peer, router).await,
                                Ok(Err(e)) => debug!(%peer, error = %e, "TLS handshake failed"),
                                Err(_) => debug!(%peer, "TLS handshake timed out"),
                            }
                        }
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

/// How often connections are checked against the sign-in they were opened under.
pub const SESSION_CHECK: Duration = Duration::from_secs(30);

/// Periodic housekeeping: expired sessions go, connections whose sign-in has ended are closed, and
/// accounts the directory no longer allows lose their sessions and connections.
async fn checks(app: Arc<App>) {
    let directory_every = Duration::from_secs(
        app.cfg
            .directory
            .as_ref()
            .map_or(600, |d| d.check_interval_secs)
            .max(30),
    );
    let mut last_directory: Option<std::time::Instant> = None;
    let mut tick = tokio::time::interval(SESSION_CHECK);
    loop {
        tick.tick().await;
        // Shared hold: no pass straddles an import.
        let _shared = app.gate.read().await;
        if let Err(e) = app.store.sessions_purge(now()) {
            warn!(error = %e, "session purge failed");
        }
        let orphans = end_orphaned_connections(&app);
        if orphans > 0 {
            info!(ended = orphans, "connections ended because their sign-in ended");
        }
        if last_directory.is_none_or(|t| t.elapsed() >= directory_every) {
            last_directory = Some(std::time::Instant::now());
            match revocation_pass(&app).await {
                Ok(0) => {}
                Ok(n) => info!(revoked = n, "revocation pass ended sessions"),
                Err(e) => warn!(error = %e, "revocation pass could not run; nothing was revoked"),
            }
        }
    }
}

/// A connection lives only as long as the sign-in it was opened under: expired, signed out,
/// revoked, reset or deleted, the connection closes. A store error ends nothing.
pub fn end_orphaned_connections(app: &App) -> usize {
    let at = now();
    let stale: Vec<u64> = app
        .live
        .connections()
        .into_iter()
        .filter(|(_, user_id, hash)| match app.store.session_user(hash, at) {
            Ok(Some(u)) => u.id != *user_id,
            Ok(None) => true,
            Err(_) => false,
        })
        .map(|(id, _, _)| id)
        .collect();
    app.live.end_ids(&stale)
}

/// Directory users to re-check: everyone holding a sign-in session, and everyone with a connection.
fn users_to_check(app: &App) -> Result<Vec<crate::store::User>, Box<dyn std::error::Error>> {
    let mut users = app.store.directory_users_with_sessions(now())?;
    let mut seen: std::collections::HashSet<i64> = users.iter().map(|u| u.id).collect();
    for id in app.live.user_ids() {
        if seen.insert(id) {
            if let Some(u) = app.store.user_by_id(id)?.filter(|u| !u.local) {
                users.push(u);
            }
        }
    }
    Ok(users)
}

/// Check those users against the directory. A directory that cannot be reached revokes nothing.
pub async fn revocation_pass(app: &App) -> Result<usize, Box<dyn std::error::Error>> {
    let Some(directory) = app.lookup_directory() else {
        return Ok(0);
    };
    let Some(password) = app.directory_password()? else {
        return Ok(0);
    };
    let users = users_to_check(app)?;
    if users.is_empty() {
        return Ok(0);
    }
    let names: Vec<String> = users.iter().map(|u| u.username.clone()).collect();
    let found = directory.lookup_many(&password, &names).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::tests::{signed_in, test_app};
    use tokio::io::AsyncReadExt;

    #[test]
    fn a_connection_whose_sign_in_ended_is_closed() {
        let app = test_app();
        let (uid, cookie) = signed_in(&app, "jdoe");
        let hash = crate::auth::token_hash(cookie.split_once('=').unwrap().1);
        let (_, mut live) = app.live.register(uid, hash.clone());
        let (_, mut other) = app.live.register(uid, b"a session that never existed".to_vec());
        assert_eq!(end_orphaned_connections(&app), 1);
        assert!(other.try_recv().is_ok(), "no sign-in behind it");
        assert!(live.try_recv().is_err(), "its sign-in is live");
        app.store.session_delete(&hash).unwrap();
        assert_eq!(end_orphaned_connections(&app), 1);
        assert!(live.try_recv().is_ok(), "signed out, so closed");
    }

    #[test]
    fn users_with_a_connection_are_checked_even_without_a_sign_in_row() {
        let app = test_app();
        let uid = app.store.user_create("jdoe", None).unwrap();
        let local = app.store.local_account_set("devtest", "h", "local:1").unwrap();
        let (_a, _ra) = app.live.register(uid, b"gone".to_vec());
        let (_b, _rb) = app.live.register(local, b"gone".to_vec());
        let ids: Vec<i64> = users_to_check(&app).unwrap().iter().map(|u| u.id).collect();
        assert_eq!(ids, vec![uid], "local accounts are never checked against the directory");
    }

    async fn loopback() -> (tokio::net::TcpListener, SocketAddr) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        (l, a)
    }

    /// A PEM pair made for this test with openssl; it protects nothing.
    const TEST_CERT: &str = include_str!("../tests/fixtures/localhost-cert.pem");
    const TEST_KEY: &str = include_str!("../tests/fixtures/localhost-key.pem");

    fn test_acceptor() -> TlsAcceptor {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certs = rustls_pemfile::certs(&mut TEST_CERT.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut TEST_KEY.as_bytes()).unwrap().unwrap();
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        TlsAcceptor::from(Arc::new(cfg))
    }

    /// Connect and send nothing: the server must hang up within the handshake deadline.
    #[tokio::test]
    async fn a_silent_tls_client_is_dropped_at_the_handshake_deadline() {
        let (listener, addr) = loopback().await;
        let limits = Limits { max_connections: 8, tls_handshake: Duration::from_millis(300) };
        let router = crate::web::router(test_app());
        tokio::spawn(accept_loop(listener, Some(test_acceptor()), router, limits, std::future::pending()));
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(3), client.read(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "still open after the deadline: {read:?}");
    }

    /// Connections over the limit are closed on accept, while those within it stay open.
    #[tokio::test]
    async fn connections_over_the_limit_are_closed_on_accept() {
        let (listener, addr) = loopback().await;
        let limits = Limits { max_connections: 2, tls_handshake: Duration::from_secs(30) };
        let router = crate::web::router(test_app());
        tokio::spawn(accept_loop(listener, Some(test_acceptor()), router, limits, std::future::pending()));
        let _a = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _b = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "the third connection was not closed: {read:?}");
        let mut a = _a;
        let still = tokio::time::timeout(Duration::from_millis(300), a.read(&mut buf)).await;
        assert!(still.is_err(), "a connection within the limit was closed");
    }
}
