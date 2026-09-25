//! The management plane: users, their server lists, servers, groups, activity, migration.
//! Every route requires an administrator.

use crate::app::{META_FREEZE_PENDING, META_FROZEN};
use crate::directory::normalize_username;
use crate::migrate;
use crate::store::{ImportRow, User};
use crate::vault::Vault;
use crate::web::{revalidate_admin, AdminToken, AdminUser, ApiError, ApiResult, Shared};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Largest export accepted for import.
const IMPORT_LIMIT: usize = 1 << 30;

pub fn router() -> Router<Shared> {
    Router::new()
        .route("/users", get(users).post(add_user))
        .route("/users/{id}", patch(update_user).delete(remove_user))
        .route(
            "/users/{id}/servers",
            get(user_servers).put(set_user_servers),
        )
        .route("/users/{id}/copy-from/{from}", post(copy_from))
        .route("/users/{id}/clear-sid", post(clear_sid))
        .route("/servers", get(servers).post(add_server))
        .route("/servers/import", post(import_servers))
        .route("/servers/{id}", patch(update_server).delete(remove_server))
        .route("/groups", get(groups).post(add_group))
        .route("/groups/order", post(order_groups))
        .route("/groups/{id}", patch(rename_group).delete(remove_group))
        .route("/audit", get(audit))
        .route("/migration", get(migration_status))
        .route("/migration/recovery", post(set_recovery))
        .route("/migration/unlock", post(unlock))
        .route("/migration/export", post(export))
        .route("/migration/unfreeze", post(unfreeze))
        .route(
            "/migration/import",
            post(upload_import).layer(DefaultBodyLimit::max(IMPORT_LIMIT)),
        )
        .route("/migration/import/{upload}", post(confirm_import))
        .route("/settings/directory-password", post(set_directory_password))
}

/// Edits made on a frozen proxy would be lost at cutover, so they are refused.
fn not_frozen(app: &Shared) -> ApiResult<()> {
    if app.frozen() {
        Err(ApiError::conflict(
            "this proxy is frozen for migration; unfreeze it on the Migration page to make changes",
        ))
    } else {
        Ok(())
    }
}

// ---- users ------------------------------------------------------------------------------------

async fn users(State(app): State<Shared>, _: AdminUser) -> ApiResult<Json<Value>> {
    let rows = app.store.users_list()?;
    let list: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let u = r.user;
            json!({
                "id": u.id,
                "username": u.username,
                "display_name": u.display_name,
                "is_admin": u.is_admin,
                "bootstrap_admin": app.cfg.is_bootstrap_admin(&u.username),
                "sid_bound": u.sid.is_some(),
                "sid_mismatch": u.sid_mismatch,
                "local": u.local,
                "created": u.created,
                "last_login": u.last_login,
                "servers": r.server_count,
                "saved": r.saved_count,
            })
        })
        .collect();
    Ok(Json(json!({ "users": list })))
}

#[derive(Deserialize)]
struct NewUser {
    username: String,
}

/// Refused when an import replaced the database while a route was away from the gate.
fn same_generation(app: &Shared, generation: u64) -> ApiResult<()> {
    if app.generation() == generation {
        Ok(())
    } else {
        Err(ApiError::conflict(
            "this proxy's data was replaced while that request ran; try it again",
        ))
    }
}

async fn add_user(
    State(app): State<Shared>,
    AdminToken(token): AdminToken,
    Json(req): Json<NewUser>,
) -> ApiResult<Json<Value>> {
    let username = normalize_username(&req.username)
        .ok_or_else(|| ApiError::bad_request("that is not a valid username"))?;
    // Self-gated: the directory is asked without the gate held.
    let (generation, password) = {
        let _shared = app.gate.read().await;
        revalidate_admin(&app, &token)?;
        not_frozen(&app)?;
        let password = match app.lookup_directory() {
            Some(_) => app.directory_password().ok().flatten(),
            None => None,
        };
        (app.generation(), password)
    };
    // With a service account, check the account exists before adding it. A directory outage does
    // not block the add; the result says whether it was checked.
    let mut verified = false;
    let mut display_name = None;
    if let (Some(directory), Some(pw)) = (app.lookup_directory(), password) {
        match directory
            .lookup_many(&pw, std::slice::from_ref(&username))
            .await
        {
            Ok(found) => match found.into_iter().next().and_then(|(_, a)| a) {
                Some(account) => {
                    verified = true;
                    display_name = account.display_name;
                }
                None => {
                    return Err(ApiError::new(
                        StatusCode::NOT_FOUND,
                        format!("the directory has no account named {username}"),
                    ))
                }
            },
            Err(e) => tracing::warn!(error = %e, "could not check the new user in the directory"),
        }
    }
    let _shared = app.gate.read().await;
    same_generation(&app, generation)?;
    let admin = revalidate_admin(&app, &token)?;
    not_frozen(&app)?;
    let id = app.store.user_create(&username, display_name.as_deref())?;
    app.store.audit(&admin.username, "user.add", &username);
    Ok(Json(json!({ "id": id, "verified": verified })))
}

fn user_or_404(app: &Shared, id: i64) -> ApiResult<User> {
    app.store.user_by_id(id)?.ok_or_else(ApiError::not_found)
}

#[derive(Deserialize)]
struct UserPatch {
    is_admin: bool,
}

async fn update_user(
    State(app): State<Shared>,
    AdminUser(admin): AdminUser,
    Path(id): Path<i64>,
    Json(req): Json<UserPatch>,
) -> ApiResult<StatusCode> {
    not_frozen(&app)?;
    let user = user_or_404(&app, id)?;
    app.store.user_set_admin(id, req.is_admin)?;
    app.store.audit(
        &admin.username,
        if req.is_admin {
            "user.admin.grant"
        } else {
            "user.admin.revoke"
        },
        &user.username,
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_user(
    State(app): State<Shared>,
    AdminUser(admin): AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    not_frozen(&app)?;
    let user = user_or_404(&app, id)?;
    app.store.user_delete(id)?;
    app.live.end_user(id);
    app.store
        .audit(&admin.username, "user.remove", &user.username);
    Ok(StatusCode::NO_CONTENT)
}

async fn user_servers(
    State(app): State<Shared>,
    _: AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    user_or_404(&app, id)?;
    Ok(Json(json!({ "assigned": app.store.assignment_ids(id)? })))
}

#[derive(Deserialize)]
struct Assignments {
    server_ids: Vec<i64>,
}

async fn set_user_servers(
    State(app): State<Shared>,
    AdminUser(admin): AdminUser,
    Path(id): Path<i64>,
    Json(req): Json<Assignments>,
) -> ApiResult<Json<Value>> {
    not_frozen(&app)?;
    let user = user_or_404(&app, id)?;
    let before: HashSet<i64> = app.store.assignment_ids(id)?.into_iter().collect();
    let (added, removed) = app.store.set_assignments(id, &req.server_ids)?;
    let wanted: HashSet<i64> = req.server_ids.iter().copied().collect();
    for gone in before.difference(&wanted) {
        app.live.end_user_server(id, *gone);
    }
    if added + removed > 0 {
        app.store.audit(
            &admin.username,
            "user.servers",
            &format!("{}: +{added} -{removed}", user.username),
        );
    }
    Ok(Json(json!({ "added": added, "removed": removed })))
}

async fn copy_from(
    State(app): State<Shared>,
    AdminUser(admin): AdminUser,
    Path((id, from)): Path<(i64, i64)>,
) -> ApiResult<Json<Value>> {
    not_frozen(&app)?;
    let to = user_or_404(&app, id)?;
    let src = user_or_404(&app, from)?;
    let added = app.store.copy_assignments(from, id)?;
    app.store.audit(
        &admin.username,
        "user.servers.copy",
        &format!("{} <- {}: +{added}", to.username, src.username),
    );
    Ok(Json(json!({ "added": added })))
}

async fn clear_sid(
    State(app): State<Shared>,
    AdminUser(admin): AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    not_frozen(&app)?;
    let user = user_or_404(&app, id)?;
    app.store.user_clear_sid(id)?;
    app.live.end_user(id);
    app.store
        .audit(&admin.username, "user.sid.reset", &user.username);
    Ok(StatusCode::NO_CONTENT)
}

// ---- servers ----------------------------------------------------------------------------------

async fn servers(State(app): State<Shared>, _: AdminUser) -> ApiResult<Json<Value>> {
    let list: Vec<Value> = app
        .store
        .servers_list()?
        .into_iter()
        .map(|r| {
            json!({
                "id": r.server.id,
                "name": r.server.name,
                "host": r.server.host,
                "port": r.server.port,
                "group_id": r.server.group_id,
                "assigned": r.assigned,
            })
        })
        .collect();
    Ok(Json(json!({ "servers": list })))
}

#[derive(Deserialize)]
struct ServerForm {
    name: String,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    group_id: Option<i64>,
}

pub fn valid_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
        return Err("a name is 1 to 100 characters".into());
    }
    Ok(name.to_owned())
}

/// A DNS name or an IP address. Resolved at connection time, never here.
pub fn valid_host(host: &str) -> Result<String, String> {
    let host = host.trim();
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'));
    if ok {
        Ok(host.to_owned())
    } else {
        Err(format!("{host:?} is not a host name or address"))
    }
}

fn valid_port(port: Option<u16>) -> Result<u16, String> {
    match port.unwrap_or(3389) {
        0 => Err("port must be 1 to 65535".into()),
        p => Ok(p),
    }
}

fn server_fields(req: &ServerForm) -> ApiResult<(String, String, u16)> {
    Ok((
        valid_name(&req.name).map_err(ApiError::bad_request)?,
        valid_host(&req.host).map_err(ApiError::bad_request)?,
        valid_port(req.port).map_err(ApiError::bad_request)?,
    ))
}

async fn add_server(
    State(app): State<Shared>,
    AdminUser(admin): AdminUser,
    Json(req): Json<ServerForm>,
) -> ApiResult<Json<Value>> {
    not_frozen(&app)?;
    let (name, host, port) = server_fields(&req)?;
    let id = app.store.server_create(&name, &host, port, req.group_id)?;
    app.store.audit(
        &admin.username,
        "server.add",
        &format!("{name} ({host}:{port})"),
    );
    Ok(Json(json!({ "id": id })))
}

async fn update_server(
    State(app): State<Shared>,
    AdminUser(admin): AdminUser,
    Path(id): Path<i64>,
    Json(req): Json<ServerForm>,
) -> ApiResult<StatusCode> {
    not_frozen(&app)?;
    let (name, host, port) = server_fields(&req)?;
    app.store
        .server_update(id, &name, &host, port, req.group_id)?;
    app.store.audit(
        &admin.username,
        "server.edit",
        &format!("{name} ({host}:{port})"),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_server(
    State(app): State<Shared>,
    AdminUser(admin): AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    not_frozen(&app)?;
    let server = app
        .store
        .server_by_id(id)?
        .ok_or_else(ApiError::not_found)?;
    app.store.server_delete(id)?;
    app.live.end_server(id);
    app.store
        .audit(&admin.username, "server.remove", &server.name);
    Ok(StatusCode::NO_CONTENT)
}

/// Split one CSV line, honouring double quotes.
fn csv_fields(line: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            ('"', true) => quoted = false,
            ('"', false) if cur.trim().is_empty() => {
                cur.clear();
                quoted = true;
            }
            (',', false) => fields.push(std::mem::take(&mut cur)),
            (c, _) => cur.push(c),
        }
    }
    if quoted {
        return Err("unterminated quote".into());
    }
    fields.push(cur);
    Ok(fields.into_iter().map(|f| f.trim().to_owned()).collect())
}

/// `name,host[,port[,group]]` per line. A header row, blank lines and `#` comments are skipped.
/// Every problem is reported; nothing is imported unless the whole file is good.
pub fn parse_import(text: &str) -> Result<Vec<ImportRow>, Vec<String>> {
    let mut rows = Vec::new();
    let mut errors = Vec::new();
    let mut seen = HashSet::new();
    let mut first = true;
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if first {
            first = false;
            if line.to_ascii_lowercase().starts_with("name,") {
                continue;
            }
        }
        let fields = match csv_fields(line) {
            Ok(f) => f,
            Err(e) => {
                errors.push(format!("line {n}: {e}"));
                continue;
            }
        };
        if fields.len() < 2 || fields.len() > 4 {
            errors.push(format!("line {n}: expected name,host[,port[,group]]"));
            continue;
        }
        let name = match valid_name(&fields[0]) {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("line {n}: {e}"));
                continue;
            }
        };
        let host = match valid_host(&fields[1]) {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("line {n}: {e}"));
                continue;
            }
        };
        let port = match fields.get(2).map(String::as_str).unwrap_or("") {
            "" => 3389,
            p => match p.parse::<u16>() {
                Ok(p) if p > 0 => p,
                _ => {
                    errors.push(format!("line {n}: port {p:?} is not 1 to 65535"));
                    continue;
                }
            },
        };
        let group = match fields.get(3).map(|g| g.trim()).filter(|g| !g.is_empty()) {
            None => None,
            Some(g) => match valid_name(g) {
                Ok(v) => Some(v),
                Err(e) => {
                    errors.push(format!("line {n}: group: {e}"));
                    continue;
                }
            },
        };
        if !seen.insert(name.to_lowercase()) {
            errors.push(format!("line {n}: {name} appears more than once"));
            continue;
        }
        rows.push(ImportRow {
            name,
            host,
            port,
            group,
        });
    }
    if errors.is_empty() {
        Ok(rows)
    } else {
        Err(errors)
    }
}

#[derive(Deserialize)]
struct ImportText {
    csv: String,
}

async fn import_servers(
    State(app): State<Shared>,
    AdminUser(admin): AdminUser,
    Json(req): Json<ImportText>,
) -> ApiResult<Response> {
    not_frozen(&app)?;
    let rows = match parse_import(&req.csv) {
        Ok(rows) if rows.is_empty() => return Err(ApiError::bad_request("the file has no rows")),
        Ok(rows) => rows,
        Err(errors) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "nothing was imported; fix these lines", "lines": errors })),
            )
                .into_response())
        }
    };
    let (created, updated) = app.store.servers_import(&rows)?;
    app.store.audit(
        &admin.username,
        "server.import",
        &format!("{created} created, {updated} updated"),
    );
    Ok(Json(json!({ "created": created, "updated": updated })).into_response())
}

// ---- groups -----------------------------------------------------------------------------------

async fn groups(State(app): State<Shared>, _: AdminUser) -> ApiResult<Json<Value>> {
    let list: Vec<Value> = app
        .store
        .groups_list()?
        .into_iter()
        .map(|g| json!({ "id": g.id, "name": g.name, "sort": g.sort, "servers": g.server_count }))
        .collect();
    Ok(Json(json!({ "groups": list })))
}

#[derive(Deserialize)]
struct GroupForm {
    name: String,
}

async fn add_group(
    State(app): State<Shared>,
    AdminUser(admin): AdminUser,
    Json(req): Json<GroupForm>,
) -> ApiResult<Json<Value>> {
    not_frozen(&app)?;
    let name = valid_name(&req.name).map_err(ApiError::bad_request)?;
    let id = app.store.group_create(&name)?;
    app.store.audit(&admin.username, "group.add", &name);
    Ok(Json(json!({ "id": id })))
}

async fn rename_group(
    State(app): State<Shared>,
    AdminUser(admin): AdminUser,
    Path(id): Path<i64>,
    Json(req): Json<GroupForm>,
) -> ApiResult<StatusCode> {
    not_frozen(&app)?;
    let name = valid_name(&req.name).map_err(ApiError::bad_request)?;
    app.store.group_rename(id, &name)?;
    app.store.audit(&admin.username, "group.rename", &name);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct GroupOrder {
    ids: Vec<i64>,
}

async fn order_groups(
    State(app): State<Shared>,
    AdminUser(admin): AdminUser,
    Json(req): Json<GroupOrder>,
) -> ApiResult<StatusCode> {
    not_frozen(&app)?;
    app.store.group_order(&req.ids)?;
    app.store.audit(&admin.username, "group.order", "");
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_group(
    State(app): State<Shared>,
    AdminUser(admin): AdminUser,
    Path(id): Path<i64>,
) -> ApiResult<StatusCode> {
    not_frozen(&app)?;
    app.store.group_delete(id)?;
    app.store
        .audit(&admin.username, "group.remove", &id.to_string());
    Ok(StatusCode::NO_CONTENT)
}

// ---- activity ---------------------------------------------------------------------------------

#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    before: Option<i64>,
}

async fn audit(
    State(app): State<Shared>,
    _: AdminUser,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Value>> {
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let rows: Vec<Value> = app
        .store
        .audit_list(limit, q.before)?
        .into_iter()
        .map(|r| json!({ "id": r.id, "at": r.at, "actor": r.actor, "action": r.action, "detail": r.detail }))
        .collect();
    Ok(Json(json!({ "entries": rows })))
}

// ---- migration --------------------------------------------------------------------------------

async fn migration_status(State(app): State<Shared>, _: AdminUser) -> ApiResult<Json<Value>> {
    let counts = app.store.counts()?;
    Ok(Json(json!({
        "host": app.host_name,
        "recovery_set": Vault::recovery_set(&app.store)?,
        "unlocked": app.vault.is_unlocked(),
        "frozen": app.frozen(),
        "counts": counts,
        "live_sessions": app.live.count(),
        "directory": {
            "service_account": app.cfg.service_account(),
            "password_set": app.directory_password_set(),
        },
        "local_accounts": app.cfg.allow_local_accounts,
    })))
}

#[derive(Deserialize)]
struct RecoveryForm {
    #[serde(default)]
    current: Option<String>,
    new: String,
}

async fn set_recovery(
    State(app): State<Shared>,
    AdminUser(admin): AdminUser,
    Json(req): Json<RecoveryForm>,
) -> ApiResult<StatusCode> {
    not_frozen(&app)?;
    let changing = Vault::recovery_set(&app.store)?;
    app.vault
        .set_recovery(&app.store, req.current.as_deref(), &req.new)?;
    app.store.audit(
        &admin.username,
        if changing {
            "recovery.change"
        } else {
            "recovery.set"
        },
        "",
    );
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct PassphraseForm {
    passphrase: String,
}

async fn unlock(
    State(app): State<Shared>,
    AdminUser(admin): AdminUser,
    Json(req): Json<PassphraseForm>,
) -> ApiResult<StatusCode> {
    let key = app.vault.adopt(&app.store, &req.passphrase)?;
    app.vault.install(key);
    app.store.audit(&admin.username, "vault.unlock", "");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ExportForm {
    passphrase: String,
    #[serde(default)]
    freeze: bool,
}

/// Set when the request that started a supervised operation goes away.
struct Requester(Arc<AtomicBool>);

impl Drop for Requester {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Run a migration operation in a task of its own, which the request awaits. A request that ends
/// early (deadline, disconnect) does not cut the operation short or release its hold on the gate;
/// the operation is told through `gone` and decides what that means.
async fn supervised<T, F>(op: impl FnOnce(Arc<AtomicBool>) -> F) -> ApiResult<T>
where
    T: Send + 'static,
    F: std::future::Future<Output = ApiResult<T>> + Send + 'static,
{
    let gone = Arc::new(AtomicBool::new(false));
    let _requester = Requester(Arc::clone(&gone));
    tokio::spawn(op(gone)).await.map_err(ApiError::internal)?
}

/// A requester that left before an operation got the gate has abandoned it.
fn still_wanted(gone: &AtomicBool) -> ApiResult<()> {
    if gone.load(Ordering::SeqCst) {
        Err(ApiError::new(
            StatusCode::REQUEST_TIMEOUT,
            "the request ended before it could start",
        ))
    } else {
        Ok(())
    }
}

async fn export(
    State(app): State<Shared>,
    AdminToken(token): AdminToken,
    Json(req): Json<ExportForm>,
) -> ApiResult<Response> {
    let export = export_supervised(&app, token, req.passphrase, req.freeze)
        .await?
        .hand_over()
        .await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/zip".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", export.file_name),
            ),
        ],
        export.bytes,
    )
        .into_response())
}

/// Lifts the freeze an export set, unless disarmed. It travels with the archive, so an archive
/// dropped anywhere short of the response (a failure, an abandoned request, a result nobody
/// collected) leaves no freeze behind. It holds the export lock until the freeze is settled, so
/// the next export cannot mistake this one's freeze for an earlier one and then lose it.
pub struct FreezeUndo(Option<(Shared, u64, tokio::sync::OwnedMutexGuard<()>)>);

impl FreezeUndo {
    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for FreezeUndo {
    fn drop(&mut self) {
        if let Some((app, generation, lock)) = self.0.take() {
            match tokio::runtime::Handle::try_current() {
                Ok(rt) => {
                    rt.spawn(async move {
                        unfreeze_if_current(&app, generation).await;
                        drop(lock);
                    });
                }
                Err(_) => {
                    tracing::warn!("an export that was not delivered could not lift its freeze")
                }
            }
        }
    }
}

/// An export on its way to the requester.
pub struct Delivery {
    export: migrate::Export,
    undo: Option<FreezeUndo>,
}

impl Delivery {
    /// Hand the archive to the response. A freeze it set stops being pending, under a hold and
    /// only in the database it was set in, and stays. Called immediately before the response is
    /// built; cancelled while waiting for the hold, the delivery is dropped and lifts its freeze.
    pub async fn hand_over(self) -> ApiResult<migrate::Export> {
        if let Some(FreezeUndo(Some((app, generation, _)))) = &self.undo {
            let _shared = app.gate.read().await;
            if app.generation() == *generation {
                app.store.set_flag(META_FREEZE_PENDING, false)?;
            }
        }
        Ok(self.into_export())
    }

    fn into_export(self) -> migrate::Export {
        let Delivery { export, undo } = self;
        if let Some(undo) = undo {
            undo.disarm();
        }
        export
    }
}

pub async fn export_supervised(
    app: &Shared,
    token: Vec<u8>,
    passphrase: String,
    freeze: bool,
) -> ApiResult<Delivery> {
    let app = app.clone();
    supervised(move |gone| export_task(app, token, passphrase, freeze, gone)).await
}

async fn export_task(
    app: Shared,
    token: Vec<u8>,
    passphrase: String,
    freeze: bool,
    gone: Arc<AtomicBool>,
) -> ApiResult<Delivery> {
    // A wrong passphrase is turned away before anything waits on the gate. The check that counts
    // is made on the snapshot itself.
    {
        let app = app.clone();
        let pass = passphrase.clone();
        tokio::task::spawn_blocking(move || Vault::verify_recovery(&app.store, &pass))
            .await
            .map_err(ApiError::internal)?
            .map_err(migrate::MigrateError::from)?;
    }
    // One export at a time, so a failed export can only undo a freeze it set itself.
    let one = Arc::clone(&app.export_lock).lock_owned().await;
    let (admin, (db, counts), generation, froze) = if freeze {
        // Exclusive: requests in flight finish first, and no edit lands between the freeze and the
        // snapshot, so nothing acknowledged is missing from the export. The imported copy arrives
        // frozen and the import clears it.
        let _exclusive = app.gate.write().await;
        still_wanted(&gone)?;
        let admin = revalidate_admin(&app, &token)?;
        let froze = !app.frozen();
        if froze {
            // Marked pending until the archive is handed over, so a freeze stranded by a stop or
            // a crash is lifted at the next start.
            app.store.set_flag(META_FREEZE_PENDING, true)?;
            app.store.set_flag(META_FROZEN, true)?;
        }
        match snapshot_of(&app, &passphrase).await {
            Ok(s) => (admin, s, app.generation(), froze),
            Err(e) => {
                if froze {
                    let _ = app.store.set_flag(META_FROZEN, false);
                    let _ = app.store.set_flag(META_FREEZE_PENDING, false);
                }
                return Err(e);
            }
        }
    } else {
        let _shared = app.gate.read().await;
        still_wanted(&gone)?;
        let admin = revalidate_admin(&app, &token)?;
        (
            admin,
            snapshot_of(&app, &passphrase).await?,
            app.generation(),
            false,
        )
    };
    // From here a freeze this export set travels with its archive, with the export lock: every
    // early return below drops it, and dropping it lifts the freeze.
    let (undo, _one) = if froze {
        (Some(FreezeUndo(Some((app.clone(), generation, one)))), None)
    } else {
        (None, Some(one))
    };
    let export = {
        let app = app.clone();
        let pass = passphrase.clone();
        tokio::task::spawn_blocking(move || migrate::package(&app, &pass, &db, counts))
            .await
            .map_err(ApiError::internal)?
            .map_err(ApiError::from)?
    };
    let delivery = Delivery { export, undo };
    // Recorded under a hold, only in the database the snapshot came from, and only while someone
    // is waiting for the archive.
    let _shared = app.gate.read().await;
    still_wanted(&gone)?;
    if app.generation() == generation {
        app.store.audit(
            &admin.username,
            if freeze { "export.freeze" } else { "export" },
            &delivery.export.file_name,
        );
    }
    Ok(delivery)
}

async fn snapshot_of(app: &Shared, passphrase: &str) -> ApiResult<(Vec<u8>, crate::store::Counts)> {
    let app = app.clone();
    let pass = passphrase.to_owned();
    Ok(
        tokio::task::spawn_blocking(move || migrate::snapshot_verified(&app, &pass))
            .await
            .map_err(ApiError::internal)??,
    )
}

/// Undo an export's freeze, unless an import has replaced the database it was set in.
async fn unfreeze_if_current(app: &Shared, generation: u64) {
    let _exclusive = app.gate.write().await;
    if app.generation() == generation {
        let lifted = app
            .store
            .set_flag(META_FROZEN, false)
            .and_then(|()| app.store.set_flag(META_FREEZE_PENDING, false));
        if let Err(e) = lifted {
            tracing::warn!(error = %e, "an export that was not delivered could not lift its freeze");
        }
    }
}

async fn unfreeze(State(app): State<Shared>, AdminUser(admin): AdminUser) -> ApiResult<StatusCode> {
    app.store.set_flag(META_FROZEN, false)?;
    app.store.set_flag(META_FREEZE_PENDING, false)?;
    app.store.audit(&admin.username, "unfreeze", "");
    Ok(StatusCode::NO_CONTENT)
}

async fn upload_import(
    State(app): State<Shared>,
    AdminToken(token): AdminToken,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    // The body has arrived by now; only the staging runs under the gate.
    let _shared = app.gate.read().await;
    let admin = revalidate_admin(&app, &token)?;
    let (upload_id, manifest) = {
        let app = app.clone();
        tokio::task::spawn_blocking(move || migrate::stage(&app, &body))
            .await
            .map_err(ApiError::internal)??
    };
    let current = app.store.counts()?;
    app.store.audit(
        &admin.username,
        "import.upload",
        &format!(
            "from {} exported {}",
            manifest.source_host, manifest.exported_at
        ),
    );
    Ok(Json(json!({
        "upload_id": upload_id,
        "manifest": manifest,
        "this_host": app.host_name,
        "holds_data": migrate::holds_data(&current),
        "current": current,
    })))
}

#[derive(Deserialize)]
struct ConfirmForm {
    passphrase: String,
    #[serde(default)]
    confirm_host: Option<String>,
}

async fn confirm_import(
    State(app): State<Shared>,
    AdminToken(token): AdminToken,
    Path(upload): Path<String>,
    Json(req): Json<ConfirmForm>,
) -> ApiResult<Json<Value>> {
    let counts = import_exclusive(&app, token, upload, req.passphrase, req.confirm_host).await?;
    Ok(Json(json!({ "counts": counts })))
}

/// The swap runs with the gate held exclusively: every request in flight finishes first, and none
/// starts until the new database and its key are both in place. The task holding the gate runs to
/// the end of the swap whatever becomes of the request.
pub async fn import_exclusive(
    app: &Shared,
    token: Vec<u8>,
    upload: String,
    passphrase: String,
    confirm_host: Option<String>,
) -> ApiResult<crate::store::Counts> {
    let app = app.clone();
    supervised(move |gone| async move {
        let _exclusive = app.gate.write().await;
        still_wanted(&gone)?;
        let admin = revalidate_admin(&app, &token)?;
        let counts = {
            let app = app.clone();
            tokio::task::spawn_blocking(move || {
                migrate::confirm(&app, &upload, &passphrase, confirm_host.as_deref())
            })
            .await
            .map_err(ApiError::internal)??
        };
        // Written into the imported database, so the record travels with the data it describes.
        app.store.audit(
            &admin.username,
            "import",
            &format!(
                "{} users, {} servers, {} assignments, {} saved credentials",
                counts.users, counts.servers, counts.assignments, counts.credentials
            ),
        );
        Ok(counts)
    })
    .await
}

#[derive(Deserialize)]
struct PasswordForm {
    password: String,
}

async fn set_directory_password(
    State(app): State<Shared>,
    AdminToken(token): AdminToken,
    Json(req): Json<PasswordForm>,
) -> ApiResult<Json<Value>> {
    let (Some(account), Some(directory)) = (app.cfg.service_account(), app.lookup_directory())
    else {
        return Err(ApiError::bad_request(
            "no service_account is configured in config.toml",
        ));
    };
    if req.password.is_empty() {
        return Err(ApiError::bad_request(
            "enter the service account's password",
        ));
    }
    // Self-gated: the directory is asked without the gate held.
    let generation = {
        let _shared = app.gate.read().await;
        revalidate_admin(&app, &token)?;
        not_frozen(&app)?;
        app.generation()
    };
    // Checked before it is kept: a wrong password would silently disable every lookup.
    let probe = normalize_username(account).unwrap_or_default();
    let verified = match directory.lookup_many(&req.password, &[probe]).await {
        Ok(_) => true,
        Err(crate::directory::DirError::Config(m)) => return Err(ApiError::bad_request(m)),
        Err(e) => {
            tracing::warn!(error = %e, "could not verify the service account password; keeping it");
            false
        }
    };
    let _shared = app.gate.read().await;
    same_generation(&app, generation)?;
    let admin = revalidate_admin(&app, &token)?;
    not_frozen(&app)?;
    app.set_directory_password(&req.password)?;
    app.store.audit(&admin.username, "directory.password", "");
    Ok(Json(json!({ "verified": verified })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::tests::{call, signed_in, test_app};
    use axum::http::StatusCode;

    #[tokio::test]
    async fn a_non_admin_is_refused_on_every_admin_route() {
        let app = test_app();
        let (_, cookie) = signed_in(&app, "jdoe");
        let routes = [
            ("GET", "/api/admin/users"),
            ("POST", "/api/admin/users"),
            ("PATCH", "/api/admin/users/1"),
            ("DELETE", "/api/admin/users/1"),
            ("GET", "/api/admin/users/1/servers"),
            ("PUT", "/api/admin/users/1/servers"),
            ("POST", "/api/admin/users/1/copy-from/2"),
            ("POST", "/api/admin/users/1/clear-sid"),
            ("GET", "/api/admin/servers"),
            ("POST", "/api/admin/servers"),
            ("POST", "/api/admin/servers/import"),
            ("PATCH", "/api/admin/servers/1"),
            ("DELETE", "/api/admin/servers/1"),
            ("GET", "/api/admin/groups"),
            ("POST", "/api/admin/groups"),
            ("POST", "/api/admin/groups/order"),
            ("PATCH", "/api/admin/groups/1"),
            ("DELETE", "/api/admin/groups/1"),
            ("GET", "/api/admin/audit"),
            ("GET", "/api/admin/migration"),
            ("POST", "/api/admin/migration/recovery"),
            ("POST", "/api/admin/migration/unlock"),
            ("POST", "/api/admin/migration/export"),
            ("POST", "/api/admin/migration/unfreeze"),
            ("POST", "/api/admin/migration/import"),
            ("POST", "/api/admin/migration/import/x"),
            ("POST", "/api/admin/settings/directory-password"),
        ];
        for (m, p) in routes {
            let body = (m != "GET" && m != "DELETE").then(|| json!({}));
            let (s, _) = call(&app, m, p, Some(&cookie), body).await;
            assert!(
                s == StatusCode::FORBIDDEN,
                "{m} {p} returned {s}, expected 403"
            );
        }
    }

    #[tokio::test]
    async fn a_bootstrap_admin_can_manage_users_and_servers() {
        let app = test_app();
        let (_, cookie) = signed_in(&app, "boss");
        let (s, v) = call(
            &app,
            "POST",
            "/api/admin/users",
            Some(&cookie),
            Some(json!({"username": "CORP\\JDoe"})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let uid = v["id"].as_i64().unwrap();
        let (s, v) = call(
            &app,
            "POST",
            "/api/admin/servers",
            Some(&cookie),
            Some(json!({"name": "hist-01", "host": "hist-01.example"})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let sid = v["id"].as_i64().unwrap();
        let (s, _) = call(
            &app,
            "PUT",
            &format!("/api/admin/users/{uid}/servers"),
            Some(&cookie),
            Some(json!({"server_ids": [sid]})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let (_, v) = call(&app, "GET", "/api/admin/users", Some(&cookie), None).await;
        let jdoe = v["users"]
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["username"] == "jdoe")
            .unwrap();
        assert_eq!(jdoe["servers"], 1);
    }

    #[tokio::test]
    async fn a_frozen_proxy_refuses_admin_edits() {
        let app = test_app();
        let (_, cookie) = signed_in(&app, "boss");
        app.store.set_flag(crate::app::META_FROZEN, true).unwrap();
        let (s, _) = call(
            &app,
            "POST",
            "/api/admin/groups",
            Some(&cookie),
            Some(json!({"name": "G"})),
        )
        .await;
        assert_eq!(s, StatusCode::CONFLICT);
        let (s, _) = call(
            &app,
            "POST",
            "/api/admin/migration/unfreeze",
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        let (s, _) = call(
            &app,
            "POST",
            "/api/admin/groups",
            Some(&cookie),
            Some(json!({"name": "G"})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
    }

    const PASS: &str = "a long recovery phrase";

    /// True once something is waiting for the gate exclusively while the caller holds it shared.
    /// tokio's RwLock is fair: a queued writer makes every new shared hold wait, so `try_read`
    /// fails. With no writer queued it keeps succeeding. Waits up to 30 s for the writer to queue
    /// (a debug build's Argon2 runs before it).
    async fn writer_queued(app: &crate::web::Shared) -> bool {
        for _ in 0..300 {
            if app.gate.try_read().is_err() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        false
    }

    fn token_of(cookie: &str) -> Vec<u8> {
        crate::auth::token_hash(cookie.split_once('=').unwrap().1)
    }

    /// Polls every 5 ms for up to 30 s.
    async fn until(what: &str, cond: impl Fn() -> bool) {
        for _ in 0..6000 {
            if cond() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("timed out waiting until {what}");
    }

    /// A host holding an export of a host with `jdoe`, staged, and an administrator's session.
    fn staged_import() -> (crate::web::Shared, String, Vec<u8>) {
        use crate::web::tests::test_app_keyed;
        let old = test_app_keyed([1; 32], "oldhost");
        let new = test_app_keyed([2; 32], "newhost");
        old.vault.set_recovery(&old.store, None, PASS).unwrap();
        old.store.user_create("jdoe", None).unwrap();
        let exported = migrate::export(&old, PASS).unwrap();
        let (upload, _) = migrate::stage(&new, &exported.bytes).unwrap();
        let (_, cookie) = signed_in(&new, "boss");
        (new, upload, token_of(&cookie))
    }

    /// An import must wait for requests in flight, so none straddles the database swap.
    #[tokio::test]
    async fn an_import_waits_for_requests_in_flight_and_ends_every_connection() {
        let (new, upload, token) = staged_import();
        let (_, mut connection) = new.live.register(1, b"s".to_vec(), 0);
        let before = new.generation();

        let in_flight = new.gate.read().await;
        let new2 = new.clone();
        let task =
            tokio::spawn(
                async move { import_exclusive(&new2, token, upload, PASS.into(), None).await },
            );
        assert!(
            writer_queued(&new).await,
            "the import never waited on the gate"
        );
        assert!(
            !task.is_finished(),
            "the import finished while a request was in flight"
        );
        assert!(
            new.store.user_by_name("jdoe").unwrap().is_none(),
            "swapped under a request in flight"
        );
        drop(in_flight);
        task.await.unwrap().unwrap();
        assert!(new.store.user_by_name("jdoe").unwrap().is_some());
        assert!(
            connection.try_recv().is_ok(),
            "a connection outlived the import"
        );
        assert_ne!(
            new.generation(),
            before,
            "the import did not mark the database as replaced"
        );
    }

    /// Once an import has the gate, its request ending (a deadline, a closed tab) neither stops
    /// the swap nor lets the gate go before it is finished.
    #[tokio::test]
    async fn an_import_that_has_the_gate_finishes_after_its_request_ends() {
        let (new, upload, token) = staged_import();
        let new2 = new.clone();
        let task =
            tokio::spawn(
                async move { import_exclusive(&new2, token, upload, PASS.into(), None).await },
            );
        until("the import holds the gate", || new.gate.try_read().is_err()).await;
        task.abort();
        let _ = task.await;
        until("the import lets go of the gate", || {
            new.gate.try_write().is_ok()
        })
        .await;
        assert!(
            new.store.user_by_name("jdoe").unwrap().is_some(),
            "the gate came free before the swap was finished"
        );
    }

    /// A request that ends while its import is still waiting for the gate has abandoned it.
    #[tokio::test]
    async fn an_import_abandoned_before_it_has_the_gate_does_not_run() {
        let (new, upload, token) = staged_import();
        let in_flight = new.gate.read().await;
        let new2 = new.clone();
        let task =
            tokio::spawn(
                async move { import_exclusive(&new2, token, upload, PASS.into(), None).await },
            );
        assert!(
            writer_queued(&new).await,
            "the import never waited on the gate"
        );
        task.abort();
        let _ = task.await;
        drop(in_flight);
        until("the abandoned import lets go of the gate", || {
            new.gate.try_write().is_ok()
        })
        .await;
        assert!(
            new.store.user_by_name("jdoe").unwrap().is_none(),
            "an abandoned import ran"
        );
    }

    /// The migration routes take the gate themselves, so they check the caller again once they
    /// have it: a session that ended while the request waited, or that an import replaced, no
    /// longer authorizes anything.
    #[tokio::test]
    async fn a_migration_request_is_authorized_again_once_it_has_the_gate() {
        let app = test_app();
        app.vault.set_recovery(&app.store, None, PASS).unwrap();
        for (path, body) in [
            (
                "/api/admin/migration/export",
                json!({"passphrase": PASS, "freeze": true}),
            ),
            ("/api/admin/migration/import", json!({})),
            ("/api/admin/migration/import/x", json!({"passphrase": PASS})),
        ] {
            let (_, cookie) = signed_in(&app, "boss");
            let held = app.gate.write().await;
            let app2 = app.clone();
            let task =
                tokio::spawn(
                    async move { call(&app2, "POST", path, Some(&cookie), Some(body)).await },
                );
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            app.store
                .sessions_delete_user(app.store.user_by_name("boss").unwrap().unwrap().id)
                .unwrap();
            drop(held);
            let (s, v) = task.await.unwrap();
            assert_eq!(s, StatusCode::UNAUTHORIZED, "{path}: {v}");
        }
        assert!(!app.frozen(), "an export ran on a session that had ended");
    }

    /// A freezing export whose archive is never delivered lifts the freeze it set.
    #[tokio::test]
    async fn an_export_nobody_receives_leaves_no_freeze() {
        let app = test_app();
        let (_, cookie) = signed_in(&app, "boss");
        app.vault.set_recovery(&app.store, None, PASS).unwrap();
        let app2 = app.clone();
        let token = token_of(&cookie);
        let task =
            tokio::spawn(async move { export_supervised(&app2, token, PASS.into(), true).await });
        until("the export froze the proxy", || app.frozen()).await;
        task.abort();
        let _ = task.await;
        until("the undelivered export lifts its freeze", || !app.frozen()).await;
    }

    /// Cancelled at its last step, while waiting on the gate to record itself, an export lifts its
    /// freeze and records nothing.
    #[tokio::test]
    async fn an_export_cancelled_while_waiting_to_record_itself_lifts_its_freeze() {
        let app = test_app();
        let (_, cookie) = signed_in(&app, "boss");
        app.vault.set_recovery(&app.store, None, PASS).unwrap();
        // An unobstructed export's duration bounds how long packaging takes.
        let start = std::time::Instant::now();
        export_supervised(&app, token_of(&cookie), PASS.into(), false)
            .await
            .unwrap()
            .into_export();
        let unobstructed = start.elapsed();

        let app2 = app.clone();
        let token = token_of(&cookie);
        let task =
            tokio::spawn(async move { export_supervised(&app2, token, PASS.into(), true).await });
        until("the snapshot is taken", || {
            app.frozen() && app.gate.try_write().is_ok()
        })
        .await;
        let held = app.gate.write().await;
        // Packaging finishes and the export waits on the gate to record itself.
        tokio::time::sleep(unobstructed * 2).await;
        task.abort();
        let _ = task.await;
        drop(held);
        until("the export lifts its freeze", || !app.frozen()).await;
        let actions: Vec<String> = app
            .store
            .audit_list(50, None)
            .unwrap()
            .into_iter()
            .map(|r| r.action)
            .collect();
        assert!(
            !actions.iter().any(|a| a == "export.freeze"),
            "an export nobody received was recorded: {actions:?}"
        );
    }

    /// A freezing export marks its freeze pending until it hands over its archive, so a restart
    /// mid-export lifts the freeze and a restart after the handover keeps it.
    #[tokio::test]
    async fn a_freeze_is_pending_until_its_archive_is_handed_over() {
        let app = test_app();
        let (_, cookie) = signed_in(&app, "boss");
        app.vault.set_recovery(&app.store, None, PASS).unwrap();
        let app2 = app.clone();
        let token = token_of(&cookie);
        let task =
            tokio::spawn(async move { export_supervised(&app2, token, PASS.into(), true).await });
        until("the snapshot is taken", || {
            app.frozen() && app.gate.try_write().is_ok()
        })
        .await;
        let held = app.gate.write().await;
        assert!(
            app.store.flag(META_FREEZE_PENDING).unwrap(),
            "a freeze mid-export was not marked pending"
        );
        drop(held);
        let delivery = task.await.unwrap().unwrap();
        assert!(
            app.store.flag(META_FREEZE_PENDING).unwrap(),
            "the freeze stopped being pending before the archive was handed over"
        );
        delivery.hand_over().await.unwrap();
        assert!(
            !app.store.flag(META_FREEZE_PENDING).unwrap(),
            "a handed-over freeze stayed pending"
        );
        assert!(!app.lift_stranded_freeze().unwrap());
        assert!(app.frozen());
    }

    /// A process that ends with an archive finished but not yet handed over leaves a freeze the
    /// next start lifts.
    #[tokio::test]
    async fn a_freeze_whose_archive_was_never_collected_is_lifted_at_the_next_start() {
        let app = test_app();
        let (_, cookie) = signed_in(&app, "boss");
        app.vault.set_recovery(&app.store, None, PASS).unwrap();
        let delivery = export_supervised(&app, token_of(&cookie), PASS.into(), true)
            .await
            .unwrap();
        // The process ends here: nothing runs the delivery's drop.
        std::mem::forget(delivery);
        assert!(
            app.lift_stranded_freeze().unwrap(),
            "no pending freeze was found at start"
        );
        assert!(!app.frozen());
    }

    /// An archive dropped before the response takes it lifts its freeze; one handed over keeps it.
    #[tokio::test]
    async fn a_delivery_lifts_its_freeze_unless_handed_over() {
        let app = test_app();
        let (_, cookie) = signed_in(&app, "boss");
        app.vault.set_recovery(&app.store, None, PASS).unwrap();
        let delivery = export_supervised(&app, token_of(&cookie), PASS.into(), true)
            .await
            .unwrap();
        assert!(app.frozen());
        drop(delivery);
        assert!(
            app.export_lock.try_lock().is_err(),
            "the next export could start before the freeze was settled"
        );
        until("the dropped archive lifts its freeze", || !app.frozen()).await;
        until("the export lock comes free", || {
            app.export_lock.try_lock().is_ok()
        })
        .await;
        export_supervised(&app, token_of(&cookie), PASS.into(), true)
            .await
            .unwrap()
            .into_export();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(app.frozen(), "a delivered export lost its freeze");
    }

    /// An export whose database an import replaced after its snapshot records nothing in the new one.
    #[tokio::test]
    async fn an_export_records_nothing_in_a_database_replaced_since_its_snapshot() {
        let app = test_app();
        let (_, cookie) = signed_in(&app, "boss");
        app.vault.set_recovery(&app.store, None, PASS).unwrap();
        let app2 = app.clone();
        let token = token_of(&cookie);
        let task =
            tokio::spawn(async move { export_supervised(&app2, token, PASS.into(), true).await });
        until("the snapshot is taken", || {
            app.frozen() && app.gate.try_write().is_ok()
        })
        .await;
        app.bump_generation();
        task.await.unwrap().unwrap().into_export();
        let actions: Vec<String> = app
            .store
            .audit_list(50, None)
            .unwrap()
            .into_iter()
            .map(|r| r.action)
            .collect();
        assert!(
            !actions.iter().any(|a| a.starts_with("export")),
            "{actions:?}"
        );
    }

    /// An export that fails lifts only a freeze it set itself.
    #[tokio::test]
    async fn an_export_undoes_only_a_freeze_it_set() {
        let app = test_app();
        let (_, cookie) = signed_in(&app, "boss");
        app.vault.set_recovery(&app.store, None, PASS).unwrap();
        app.store.set_flag(META_FROZEN, true).unwrap();
        let app2 = app.clone();
        let token = token_of(&cookie);
        let task =
            tokio::spawn(async move { export_supervised(&app2, token, PASS.into(), true).await });
        until("the export holds the gate", || app.gate.try_read().is_err()).await;
        task.abort();
        let _ = task.await;
        until("the export finished", || app.export_lock.try_lock().is_ok()).await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            app.frozen(),
            "a failed export lifted a freeze it did not set"
        );
    }

    /// Exports run one at a time. Timed against an unobstructed export on the same host.
    #[tokio::test]
    async fn exports_run_one_at_a_time() {
        let app = test_app();
        let (_, cookie) = signed_in(&app, "boss");
        app.vault.set_recovery(&app.store, None, PASS).unwrap();
        let start = std::time::Instant::now();
        export_supervised(&app, token_of(&cookie), PASS.into(), false)
            .await
            .unwrap()
            .into_export();
        let unobstructed = start.elapsed();

        let one = app.export_lock.lock().await;
        let app2 = app.clone();
        let token = token_of(&cookie);
        let task =
            tokio::spawn(async move { export_supervised(&app2, token, PASS.into(), true).await });
        tokio::time::sleep(unobstructed * 3).await;
        assert!(
            !task.is_finished(),
            "an export ran while another held the export lock"
        );
        assert!(
            !app.frozen(),
            "an export froze the proxy while another held the export lock"
        );
        drop(one);
        task.await.unwrap().unwrap().into_export();
        assert!(app.frozen());
    }

    /// A freezing export takes the gate exclusively, so no edit lands between freeze and snapshot.
    #[tokio::test]
    async fn a_freezing_export_waits_for_edits_in_flight_and_a_wrong_passphrase_freezes_nothing() {
        let app = test_app();
        let (_, cookie) = signed_in(&app, "boss");
        app.vault.set_recovery(&app.store, None, PASS).unwrap();

        let (s, _) = call(
            &app,
            "POST",
            "/api/admin/migration/export",
            Some(&cookie),
            Some(json!({"passphrase": "not the phrase at all", "freeze": true})),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(!app.frozen(), "a refused export froze the host");

        let in_flight = app.gate.read().await;
        let app2 = app.clone();
        let cookie2 = cookie.clone();
        let task = tokio::spawn(async move {
            call(
                &app2,
                "POST",
                "/api/admin/migration/export",
                Some(&cookie2),
                Some(json!({"passphrase": PASS, "freeze": true})),
            )
            .await
        });
        assert!(
            writer_queued(&app).await,
            "the freezing export never waited on the gate"
        );
        assert!(!app.frozen(), "frozen while an edit was in flight");
        drop(in_flight);
        let (s, _) = task.await.unwrap();
        assert_eq!(s, StatusCode::OK);
        assert!(app.frozen());
    }

    #[test]
    fn a_good_csv_parses() {
        let rows = parse_import(
            "name,host,port,group\nhist-01,hist-01.example,,Historians\n\"eng, 2\",10.1.2.3,3390\n",
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].port, 3389);
        assert_eq!(rows[0].group.as_deref(), Some("Historians"));
        assert_eq!(rows[1].name, "eng, 2");
        assert_eq!(rows[1].port, 3390);
        assert_eq!(rows[1].group, None);
    }

    #[test]
    fn a_malformed_csv_reports_every_bad_line_and_imports_nothing() {
        let errors =
            parse_import("a,host.example\nb\nc,bad host\nd,ok.example,99999\na,dup.example\n")
                .unwrap_err();
        assert_eq!(errors.len(), 4, "{errors:?}");
        assert!(errors[0].starts_with("line 2"));
        assert!(errors[1].starts_with("line 3"));
        assert!(errors[2].starts_with("line 4"));
        assert!(errors[3].contains("more than once"));
    }
}
