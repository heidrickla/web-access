//! HTTP: the pages, the user API and the WebSocket that carries RDP.
//!
//! The browser client (`ironrdp-web`, WASM) and the pages are EMBEDDED IN THE BINARY, so a
//! deployment is one MSI and one service, and the served client cannot drift from the proxy it talks
//! to.

use crate::app::App;
use crate::auth::{self, COOKIE};
use crate::directory::{normalize_username, DirError};
use crate::migrate::MigrateError;
use crate::policy::{self, PolicyError};
use crate::proxy::Session;
use crate::store::{now, StoreError, StoredCredential, User};
use crate::vault::{credential_aad, Vault, VaultError};

use axum::body::Body;
use axum::extract::{FromRequestParts, Path, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::WebSocketStream;

pub type Shared = Arc<App>;

/// The remote address of the connection a request arrived on.
#[derive(Debug, Clone, Copy)]
pub struct Peer(pub SocketAddr);

pub const CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; \
    connect-src 'self' ws: wss:; img-src 'self' data: blob:; frame-ancestors 'none'; \
    base-uri 'none'; form-action 'self'";

/// (request path, content type, bytes).
pub const ASSETS: &[(&str, &str, &[u8])] = &[
    ("/", "text/html; charset=utf-8", include_bytes!("../web/index.html")),
    ("/index.html", "text/html; charset=utf-8", include_bytes!("../web/index.html")),
    ("/admin", "text/html; charset=utf-8", include_bytes!("../web/admin.html")),
    ("/admin.html", "text/html; charset=utf-8", include_bytes!("../web/admin.html")),
    ("/app.css", "text/css; charset=utf-8", include_bytes!("../web/app.css")),
    ("/app.js", "text/javascript; charset=utf-8", include_bytes!("../web/app.js")),
    ("/admin.js", "text/javascript; charset=utf-8", include_bytes!("../web/admin.js")),
    ("/ironrdp_web.js", "text/javascript; charset=utf-8", include_bytes!("../web/ironrdp_web.js")),
    ("/ironrdp_web_bg.wasm", "application/wasm", include_bytes!("../web/ironrdp_web_bg.wasm")),
];

// ---- errors ---------------------------------------------------------------------------------

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    pub fn bad_request(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, m)
    }
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not found")
    }
    pub fn conflict(m: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, m)
    }
    pub fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, "request failed");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "the proxy could not complete that request")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound => Self::not_found(),
            StoreError::Conflict(m) => Self::conflict(m),
            StoreError::Invalid(m) => Self::bad_request(m),
            other => Self::internal(other),
        }
    }
}

impl From<VaultError> for ApiError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Locked | VaultError::NoRecovery => Self::conflict(e.to_string()),
            VaultError::WrongPassphrase | VaultError::Weak => Self::bad_request(e.to_string()),
            VaultError::Store(s) => s.into(),
            other => Self::internal(other),
        }
    }
}

impl From<MigrateError> for ApiError {
    fn from(e: MigrateError) -> Self {
        match e {
            MigrateError::NoRecovery => Self::conflict(e.to_string()),
            MigrateError::WrongPassphrase
            | MigrateError::BadArchive(_)
            | MigrateError::Newer(_)
            | MigrateError::Confirm(_)
            | MigrateError::Expired
            | MigrateError::Integrity(_) => Self::bad_request(e.to_string()),
            MigrateError::Vault(v) => v.into(),
            MigrateError::Store(s) => s.into(),
            other => Self::internal(other),
        }
    }
}

impl From<DirError> for ApiError {
    fn from(e: DirError) -> Self {
        match e {
            DirError::InvalidCredentials => Self::new(StatusCode::UNAUTHORIZED, e.to_string()),
            DirError::Unreachable(_) => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "the directory could not be reached; try again shortly",
            ),
            other => Self::internal(other),
        }
    }
}

impl From<PolicyError> for ApiError {
    fn from(e: PolicyError) -> Self {
        match e {
            // One answer for "no such server" and "not yours".
            PolicyError::Denied(_) => Self::not_found(),
            PolicyError::Store(s) => s.into(),
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

// ---- who is asking --------------------------------------------------------------------------

/// A signed-in user, from the session cookie.
pub struct CurrentUser {
    pub user: User,
    pub token_hash: Vec<u8>,
}

impl FromRequestParts<Shared> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &Shared) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|h| auth::cookie_value(h, COOKIE))
            .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "sign in"))?;
        let token_hash = auth::token_hash(token);
        let user = app
            .store
            .session_user(&token_hash, now())?
            .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "sign in"))?;
        Ok(Self { user, token_hash })
    }
}

/// A signed-in administrator.
pub struct AdminUser(pub User);

impl FromRequestParts<Shared> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &Shared) -> Result<Self, Self::Rejection> {
        let current = CurrentUser::from_request_parts(parts, app).await?;
        if app.is_admin(&current.user) {
            Ok(Self(current.user))
        } else {
            Err(ApiError::new(StatusCode::FORBIDDEN, "administrators only"))
        }
    }
}

/// Origin must name the same host the request was sent to.
pub fn same_origin(headers: &HeaderMap) -> bool {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    match (host, origin) {
        (Some(host), Some(origin)) => origin
            .split_once("://")
            .map(|(_, rest)| rest.trim_end_matches('/').eq_ignore_ascii_case(host))
            .unwrap_or(false),
        _ => false,
    }
}

/// Every state-changing request must come from a page this proxy served.
async fn origin_guard(req: Request, next: Next) -> Response {
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if safe || same_origin(req.headers()) {
        next.run(req).await
    } else {
        ApiError::new(StatusCode::FORBIDDEN, "cross-origin request refused").into_response()
    }
}

async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    res
}

// ---- router ---------------------------------------------------------------------------------

pub fn router(app: Shared) -> Router {
    Router::new()
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/me/servers", get(my_servers))
        .route("/api/connect", post(connect))
        .route(
            "/api/credentials/{server}",
            put(save_credential).delete(forget_credential),
        )
        .route("/ws", get(ws_upgrade))
        .nest("/api/admin", crate::admin::router())
        .fallback(static_asset)
        .layer(middleware::from_fn(origin_guard))
        .layer(middleware::map_response(security_headers))
        .with_state(app)
}

async fn static_asset(method: Method, uri: Uri) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method not allowed").into_response();
    }
    match ASSETS.iter().find(|(p, _, _)| *p == uri.path()) {
        Some((_, content_type, body)) => {
            ([(header::CONTENT_TYPE, *content_type)], *body).into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

// ---- sign-in --------------------------------------------------------------------------------

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct Me {
    username: String,
    display_name: Option<String>,
    is_admin: bool,
}

fn me_of(app: &App, user: &User) -> Me {
    Me {
        username: user.username.clone(),
        display_name: user.display_name.clone(),
        is_admin: app.is_admin(user),
    }
}

async fn login(State(app): State<Shared>, Json(req): Json<LoginRequest>) -> ApiResult<Response> {
    let username = normalize_username(&req.username)
        .ok_or_else(|| ApiError::bad_request("enter your username"))?;
    if req.password.len() > 1024 {
        return Err(ApiError::bad_request("that password is too long"));
    }
    let account = match app.directory.authenticate(&username, &req.password).await {
        Ok(a) => a,
        Err(DirError::InvalidCredentials) => {
            app.store.audit(&username, "signin.refused", "directory refused the credentials");
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "the username or password is not correct, or the account cannot sign in",
            ));
        }
        Err(e) => {
            tracing::warn!(%username, error = %e, "sign-in could not reach a decision");
            return Err(e.into());
        }
    };

    let user = match app.store.user_by_name(&account.username)? {
        Some(u) => u,
        None => {
            let id = app
                .store
                .user_create(&account.username, account.display_name.as_deref())?;
            app.store.user_by_id(id)?.ok_or_else(ApiError::not_found)?
        }
    };
    // A username reused by a different account never inherits the old one's list or credentials.
    if let Some(bound) = &user.sid {
        if *bound != account.sid {
            app.store.user_flag_mismatch(user.id)?;
            app.store.audit(
                &account.username,
                "signin.refused",
                &format!("account SID {} does not match the registered {bound}", account.sid),
            );
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "this account does not match the one registered here; an administrator must confirm it",
            ));
        }
    }
    app.store
        .user_record_login(user.id, &account.sid, account.display_name.as_deref())?;

    let token = auth::random_token();
    let expires = now() + auth::SESSION_TTL.as_secs() as i64;
    app.store
        .session_create(&auth::token_hash(&token), user.id, expires)?;
    let _ = app.store.sessions_purge(now());
    app.store.audit(&user.username, "signin", "");

    let user = app.store.user_by_id(user.id)?.ok_or_else(ApiError::not_found)?;
    Ok((
        [(header::SET_COOKIE, auth::session_cookie(&token, app.secure_cookies))],
        Json(me_of(&app, &user)),
    )
        .into_response())
}

async fn logout(State(app): State<Shared>, current: CurrentUser) -> ApiResult<Response> {
    app.store.session_delete(&current.token_hash)?;
    app.store.audit(&current.user.username, "signout", "");
    Ok((
        [(header::SET_COOKIE, auth::clear_cookie(app.secure_cookies))],
        StatusCode::NO_CONTENT,
    )
        .into_response())
}

async fn me(State(app): State<Shared>, current: CurrentUser) -> Json<Me> {
    Json(me_of(&app, &current.user))
}

// ---- the user's servers -----------------------------------------------------------------------

#[derive(Serialize)]
struct ListedGroup {
    name: Option<String>,
    servers: Vec<ListedServerJson>,
}

#[derive(Serialize)]
struct ListedServerJson {
    id: i64,
    name: String,
    host: String,
    saved: bool,
    connected: bool,
    reconnect: bool,
}

async fn my_servers(State(app): State<Shared>, current: CurrentUser) -> ApiResult<Json<serde_json::Value>> {
    let user = &current.user;
    let listed = policy::permitted(&app.store, user.id)?;
    let saved = app.store.saved_server_ids(user.id)?;
    let connected = app.live.servers_for(user.id);
    let recent = app
        .store
        .recent_ends(user.id, now() - auth::SESSION_TTL.as_secs() as i64)?;

    // Already ordered by group order, group name, server name.
    let mut groups: Vec<ListedGroup> = Vec::new();
    for l in listed {
        let s = &l.server;
        let item = ListedServerJson {
            id: s.id,
            name: s.name.clone(),
            host: s.host.clone(),
            saved: saved.contains(&s.id),
            connected: connected.contains(&s.id),
            reconnect: recent.contains_key(&s.id) && !connected.contains(&s.id),
        };
        match groups.last_mut() {
            Some(g) if g.name == l.group_name => g.servers.push(item),
            _ => groups.push(ListedGroup {
                name: l.group_name.clone(),
                servers: vec![item],
            }),
        }
    }
    Ok(Json(json!({ "groups": groups })))
}

#[derive(Deserialize)]
struct ConnectRequest {
    server: i64,
}

async fn connect(
    State(app): State<Shared>,
    current: CurrentUser,
    Json(req): Json<ConnectRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let user = &current.user;
    let server = policy::resolve(&app.store, user.id, &req.server.to_string())?;
    let ticket = app.tickets.issue(user.id, server.id);

    // A saved credential goes to its owner's browser for this connection only: the RDP client
    // performs NLA in the browser, so that is where the password has to be.
    let credential = match (app.store.credential_get(user.id, server.id)?, &user.sid) {
        (Some(stored), Some(sid)) if app.vault.is_unlocked() => {
            match app.vault.open(&credential_aad(sid, server.id), &stored.nonce, &stored.secret) {
                Ok(password) => Some(json!({
                    "username": stored.username,
                    "domain": stored.domain,
                    "password": String::from_utf8_lossy(&password),
                })),
                Err(e) => {
                    tracing::warn!(user = %user.username, server = %server.name, error = %e, "a saved credential did not open");
                    None
                }
            }
        }
        _ => None,
    };
    Ok(Json(json!({
        "ticket": ticket,
        "server": { "id": server.id, "name": server.name },
        "credential": credential,
    })))
}

#[derive(Deserialize)]
struct SaveCredential {
    username: String,
    #[serde(default)]
    domain: Option<String>,
    password: String,
}

/// Why saving is unavailable right now, if it is.
fn saving_blocked(app: &App) -> Option<&'static str> {
    if app.frozen() {
        return Some("saving is paused while this proxy is being migrated");
    }
    if !matches!(Vault::recovery_set(&app.store), Ok(true)) {
        return Some("saving credentials is not yet enabled on this proxy; an administrator must set the recovery passphrase");
    }
    if !app.vault.is_unlocked() {
        return Some("the credential store is locked; an administrator must unlock it");
    }
    None
}

async fn save_credential(
    State(app): State<Shared>,
    current: CurrentUser,
    Path(server_id): Path<i64>,
    Json(req): Json<SaveCredential>,
) -> ApiResult<StatusCode> {
    if let Some(why) = saving_blocked(&app) {
        return Err(ApiError::conflict(why));
    }
    let user = &current.user;
    let server = policy::resolve(&app.store, user.id, &server_id.to_string())?;
    let username = req.username.trim();
    let domain = req.domain.as_deref().map(str::trim).filter(|d| !d.is_empty());
    if username.is_empty() || username.len() > 256 || req.password.is_empty() || req.password.len() > 1024
        || domain.is_some_and(|d| d.len() > 256)
    {
        return Err(ApiError::bad_request("a username and password are required"));
    }
    let sid = user
        .sid
        .as_deref()
        .ok_or_else(|| ApiError::conflict("sign in again before saving"))?;
    let (nonce, secret) = app
        .vault
        .seal(&credential_aad(sid, server.id), req.password.as_bytes())?;
    app.store.credential_put(
        user.id,
        server.id,
        &StoredCredential {
            username: username.to_owned(),
            domain: domain.map(str::to_owned),
            nonce,
            secret,
        },
    )?;
    app.store.audit(&user.username, "credential.save", &server.name);
    Ok(StatusCode::NO_CONTENT)
}

async fn forget_credential(
    State(app): State<Shared>,
    current: CurrentUser,
    Path(server_id): Path<i64>,
) -> ApiResult<StatusCode> {
    if app.frozen() {
        return Err(ApiError::conflict("changes are paused while this proxy is being migrated"));
    }
    let user = &current.user;
    let server = policy::resolve(&app.store, user.id, &server_id.to_string())?;
    if app.store.credential_delete(user.id, server.id)? {
        app.store.audit(&user.username, "credential.forget", &server.name);
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---- the WebSocket ----------------------------------------------------------------------------

async fn ws_upgrade(
    State(app): State<Shared>,
    current: CurrentUser,
    mut req: Request,
) -> ApiResult<Response> {
    let headers = req.headers();
    // A GET, so origin_guard let it through; a WebSocket is not subject to the same-origin policy,
    // so the check is made here.
    if !same_origin(headers) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "cross-origin request refused"));
    }
    let is_upgrade = headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let key = headers
        .get(header::SEC_WEBSOCKET_KEY)
        .map(|k| derive_accept_key(k.as_bytes()));
    let (true, Some(accept)) = (is_upgrade, key) else {
        return Err(ApiError::bad_request("expected a WebSocket upgrade"));
    };
    let peer = req
        .extensions()
        .get::<Peer>()
        .map(|p| p.0)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let on_upgrade = hyper::upgrade::on(&mut req);

    let user = current.user;
    tokio::spawn(async move {
        let upgraded = match on_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!(%peer, error = %e, "websocket upgrade failed");
                return;
            }
        };
        let ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;
        let session = Session {
            app: &app,
            user: &user,
            peer,
        };
        if let Err(e) = session.run(ws, std::future::pending::<()>()).await {
            tracing::warn!(%peer, user = %user.username, error = %e, "session ended");
        }
    });

    Ok(Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, "websocket")
        .header(header::SEC_WEBSOCKET_ACCEPT, accept)
        .body(Body::empty())
        .map_err(ApiError::internal)?)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::config::Config;
    use crate::directory::Directory;
    use crate::vault::KeyFile;
    use tower::ServiceExt;

    /// A proxy with a scratch database, a key-file vault and a directory it never contacts.
    pub fn test_app() -> Shared {
        test_app_keyed([9; 32], "testhost")
    }

    /// As `test_app`, with this host's local key and name, to stand in for two different hosts.
    pub fn test_app_keyed(key: [u8; 32], host: &str) -> Shared {
        let dir = std::env::temp_dir().join(format!("web-access-test-{}", &auth::random_token()[..12]));
        std::fs::create_dir_all(&dir).unwrap();
        let text = format!(
            r#"
listen = "127.0.0.1:0"
data_dir = {:?}
admins = ["boss"]
[tls]
verify = "insecure"
[directory]
domain = "corp.example.com"
urls = ["ldaps://dc.corp.example.com"]
"#,
            dir.to_string_lossy()
        );
        let cfg = Config::parse("test", &text).unwrap();
        let store = crate::store::Store::open(&cfg.database_path()).unwrap();
        let vault = Vault::load(&store, Box::new(KeyFile::from_key(key))).unwrap();
        let directory = Directory::unconnected(&cfg.directory);
        let target_tls = crate::proxy::tls_setup(&cfg.tls).unwrap();
        Arc::new(App {
            secure_cookies: false,
            host_name: host.into(),
            store,
            vault,
            directory,
            tickets: Default::default(),
            live: Default::default(),
            target_tls,
            imports: Default::default(),
            cfg,
        })
    }

    /// Sign a user in directly, returning the cookie header value.
    pub fn signed_in(app: &App, username: &str) -> (i64, String) {
        let id = match app.store.user_by_name(username).unwrap() {
            Some(u) => u.id,
            None => app.store.user_create(username, None).unwrap(),
        };
        app.store
            .user_record_login(id, &format!("S-1-5-21-{id}"), None)
            .unwrap();
        let token = auth::random_token();
        app.store
            .session_create(&auth::token_hash(&token), id, now() + 3600)
            .unwrap();
        (id, format!("{COOKIE}={token}"))
    }

    pub async fn call(
        app: &Shared,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "proxy.test")
            .header(header::ORIGIN, "https://proxy.test");
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, c);
        }
        let req = match body {
            Some(v) => b
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let res = router(Arc::clone(app)).oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 64 << 20).await.unwrap();
        let v = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    #[tokio::test]
    async fn unauthenticated_api_calls_are_refused() {
        let app = test_app();
        for (m, p) in [("GET", "/api/me"), ("GET", "/api/me/servers"), ("POST", "/api/logout")] {
            let (s, _) = call(&app, m, p, None, None).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "{m} {p}");
        }
    }

    #[tokio::test]
    async fn a_cross_origin_post_is_refused() {
        let app = test_app();
        let (_, cookie) = signed_in(&app, "jdoe");
        let req = Request::builder()
            .method("POST")
            .uri("/api/logout")
            .header(header::HOST, "proxy.test")
            .header(header::ORIGIN, "https://evil.test")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap();
        let res = router(Arc::clone(&app)).oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn the_list_shows_only_assigned_servers_grouped() {
        let app = test_app();
        let (uid, cookie) = signed_in(&app, "jdoe");
        let g = app.store.group_create("Historians").unwrap();
        let a = app.store.server_create("hist-01", "hist-01.example", 3389, Some(g)).unwrap();
        let _b = app.store.server_create("dc-01", "dc-01.example", 3389, None).unwrap();
        let c = app.store.server_create("eng-01", "eng-01.example", 3389, None).unwrap();
        app.store.set_assignments(uid, &[a, c]).unwrap();
        let (s, v) = call(&app, "GET", "/api/me/servers", Some(&cookie), None).await;
        assert_eq!(s, StatusCode::OK);
        let groups = v["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["name"], "Historians");
        assert_eq!(groups[0]["servers"][0]["name"], "hist-01");
        assert!(groups[1]["name"].is_null());
        assert_eq!(groups[1]["servers"][0]["name"], "eng-01");
    }

    #[tokio::test]
    async fn connecting_to_an_unassigned_server_looks_like_a_missing_one() {
        let app = test_app();
        let (_, cookie) = signed_in(&app, "jdoe");
        let other = app.store.server_create("dc-01", "dc-01.example", 3389, None).unwrap();
        let (s1, v1) = call(&app, "POST", "/api/connect", Some(&cookie), Some(json!({"server": other}))).await;
        let (s2, v2) = call(&app, "POST", "/api/connect", Some(&cookie), Some(json!({"server": 9999}))).await;
        assert_eq!(s1, StatusCode::NOT_FOUND);
        assert_eq!((s1, v1), (s2, v2));
    }

    #[tokio::test]
    async fn saving_needs_a_recovery_passphrase_then_round_trips_through_connect() {
        let app = test_app();
        let (uid, cookie) = signed_in(&app, "jdoe");
        let a = app.store.server_create("hist-01", "hist-01.example", 3389, None).unwrap();
        app.store.set_assignments(uid, &[a]).unwrap();
        let cred = json!({"username": "ops", "domain": "PLANT", "password": "p@ss"});

        let (s, _) = call(&app, "PUT", &format!("/api/credentials/{a}"), Some(&cookie), Some(cred.clone())).await;
        assert_eq!(s, StatusCode::CONFLICT, "no recovery passphrase yet");

        app.vault.set_recovery(&app.store, None, "a long recovery phrase").unwrap();
        let (s, _) = call(&app, "PUT", &format!("/api/credentials/{a}"), Some(&cookie), Some(cred)).await;
        assert_eq!(s, StatusCode::NO_CONTENT);

        let (s, v) = call(&app, "POST", "/api/connect", Some(&cookie), Some(json!({"server": a}))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["credential"]["username"], "ops");
        assert_eq!(v["credential"]["domain"], "PLANT");
        assert_eq!(v["credential"]["password"], "p@ss");
        assert_eq!(v["ticket"].as_str().unwrap().len(), 64);

        let (_, list) = call(&app, "GET", "/api/me/servers", Some(&cookie), None).await;
        assert_eq!(list["groups"][0]["servers"][0]["saved"], true);

        let (s, _) = call(&app, "DELETE", &format!("/api/credentials/{a}"), Some(&cookie), None).await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        let (_, v) = call(&app, "POST", "/api/connect", Some(&cookie), Some(json!({"server": a}))).await;
        assert!(v["credential"].is_null());
    }

    #[tokio::test]
    async fn a_frozen_proxy_refuses_saves() {
        let app = test_app();
        let (uid, cookie) = signed_in(&app, "jdoe");
        let a = app.store.server_create("hist-01", "h", 3389, None).unwrap();
        app.store.set_assignments(uid, &[a]).unwrap();
        app.vault.set_recovery(&app.store, None, "a long recovery phrase").unwrap();
        app.store.set_flag(crate::app::META_FROZEN, true).unwrap();
        let (s, v) = call(&app, "PUT", &format!("/api/credentials/{a}"), Some(&cookie),
            Some(json!({"username": "ops", "password": "x"}))).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert!(v["error"].as_str().unwrap().contains("migrated"));
    }

    #[tokio::test]
    async fn a_session_lasts_a_full_day_and_no_longer() {
        let app = test_app();
        let uid = app.store.user_create("jdoe", None).unwrap();
        let start = now();
        let ttl = auth::SESSION_TTL.as_secs() as i64;
        app.store.session_create(b"h", uid, start + ttl).unwrap();
        assert!(app.store.session_user(b"h", start + ttl - 60).unwrap().is_some(), "23h59m");
        assert!(app.store.session_user(b"h", start + ttl).unwrap().is_none(), "24h");
    }

    #[tokio::test]
    async fn signing_out_ends_the_session() {
        let app = test_app();
        let (_, cookie) = signed_in(&app, "jdoe");
        let (s, _) = call(&app, "POST", "/api/logout", Some(&cookie), None).await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        let (s, _) = call(&app, "GET", "/api/me", Some(&cookie), None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }

    fn page(path: &str) -> String {
        let html = std::str::from_utf8(ASSETS.iter().find(|(p, _, _)| *p == path).unwrap().2).unwrap();
        // Comments are stripped first: a comment EXPLAINING the rule would otherwise match it.
        let mut stripped = String::with_capacity(html.len());
        let mut rest = html;
        while let Some(start) = rest.find("<!--") {
            stripped.push_str(&rest[..start]);
            rest = match rest[start..].find("-->") {
                Some(end) => &rest[start + end + 3..],
                None => "",
            };
        }
        stripped.push_str(rest);
        stripped
    }

    /// The CSP forbids inline <style>, inline <script> and inline event handlers. Inlining any of
    /// them produced a page that rendered unstyled and did nothing, with the cause visible only in
    /// the console.
    #[test]
    fn no_page_inlines_anything_the_csp_forbids() {
        for path in ["/", "/admin"] {
            let html = page(path);
            assert!(!html.contains("<style"), "{path}: inline <style>");
            assert!(!html.contains(" style=\""), "{path}: inline style attribute");
            assert!(!html.contains(" onclick="), "{path}: inline handler");
            for fragment in html.split("<script").skip(1) {
                let tag = fragment.split('>').next().unwrap_or("");
                assert!(tag.contains("src="), "{path}: inline <script{tag}>");
            }
        }
    }

    #[test]
    fn everything_the_pages_reference_is_served() {
        for (path, needles) in [("/", vec!["./app.css", "./app.js"]), ("/admin", vec!["./app.css", "./admin.js"])] {
            let html = page(path);
            for needle in needles {
                assert!(html.contains(needle), "{path} does not reference {needle}");
                let served = needle.trim_start_matches('.');
                assert!(ASSETS.iter().any(|(p, _, _)| *p == served), "{served} not served");
            }
        }
        let app = std::str::from_utf8(ASSETS.iter().find(|(p, _, _)| *p == "/app.js").unwrap().2).unwrap();
        assert!(app.contains("./ironrdp_web.js"));
    }

    #[test]
    fn origin_must_match_host() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("proxy.test:8443"));
        h.insert(header::ORIGIN, HeaderValue::from_static("https://proxy.test:8443"));
        assert!(same_origin(&h));
        h.insert(header::ORIGIN, HeaderValue::from_static("https://proxy.test"));
        assert!(!same_origin(&h));
        h.remove(header::ORIGIN);
        assert!(!same_origin(&h));
    }
}
