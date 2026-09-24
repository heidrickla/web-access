//! The database: users, server groups, servers, assignments, saved credentials, sessions, audit.
//!
//! One SQLite file under `data_dir`. Access is serialised through a mutex; every query here is small,
//! and the scale is thousands of rows, not millions.

use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: i64 = 5;

/// v2: local accounts. A user row with a password hash signs in against it, never the directory.
const SCHEMA_V2: &str = "ALTER TABLE users ADD COLUMN local_hash TEXT;";

/// v3: a random incarnation per user and server row, set on insert. Work that outlives a row checks
/// the incarnation before writing against its id; v4 then stops ids being reused at all.
const SCHEMA_V3: &str = "
ALTER TABLE users ADD COLUMN incarnation INTEGER;
ALTER TABLE servers ADD COLUMN incarnation INTEGER;
UPDATE users SET incarnation = random();
UPDATE servers SET incarnation = random();
CREATE TRIGGER users_incarnation AFTER INSERT ON users WHEN NEW.incarnation IS NULL
BEGIN UPDATE users SET incarnation = random() WHERE id = NEW.id; END;
CREATE TRIGGER servers_incarnation AFTER INSERT ON servers WHEN NEW.incarnation IS NULL
BEGIN UPDATE servers SET incarnation = random() WHERE id = NEW.id; END;
";

/// v4: user and server ids are never reused, so an id kept anywhere names that row or nothing.
/// SQLite adds AUTOINCREMENT only by rebuilding the table: create, copy, drop, rename, then the
/// triggers again. Run with foreign keys off, and checked before it commits.
const SCHEMA_V4: &str = "
CREATE TABLE users_v4 (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT NOT NULL UNIQUE,
    display_name TEXT,
    sid          TEXT,
    is_admin     INTEGER NOT NULL DEFAULT 0,
    sid_mismatch INTEGER NOT NULL DEFAULT 0,
    created      INTEGER NOT NULL,
    last_login   INTEGER,
    local_hash   TEXT,
    incarnation  INTEGER
);
INSERT INTO users_v4 (id, username, display_name, sid, is_admin, sid_mismatch, created, last_login, local_hash, incarnation)
    SELECT id, username, display_name, sid, is_admin, sid_mismatch, created, last_login, local_hash, incarnation FROM users;
DROP TABLE users;
ALTER TABLE users_v4 RENAME TO users;
CREATE TRIGGER users_incarnation AFTER INSERT ON users WHEN NEW.incarnation IS NULL
BEGIN UPDATE users SET incarnation = random() WHERE id = NEW.id; END;
CREATE TABLE servers_v4 (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL DEFAULT 3389,
    group_id    INTEGER REFERENCES server_groups(id) ON DELETE SET NULL,
    incarnation INTEGER
);
INSERT INTO servers_v4 (id, name, host, port, group_id, incarnation)
    SELECT id, name, host, port, group_id, incarnation FROM servers;
DROP TABLE servers;
ALTER TABLE servers_v4 RENAME TO servers;
CREATE TRIGGER servers_incarnation AFTER INSERT ON servers WHEN NEW.incarnation IS NULL
BEGIN UPDATE servers SET incarnation = random() WHERE id = NEW.id; END;
";

/// v5: group ids are never reused either, rebuilt the same way; servers keep their group.
const SCHEMA_V5: &str = "
CREATE TABLE server_groups_v5 (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    sort INTEGER NOT NULL DEFAULT 0
);
INSERT INTO server_groups_v5 (id, name, sort) SELECT id, name, sort FROM server_groups;
DROP TABLE server_groups;
ALTER TABLE server_groups_v5 RENAME TO server_groups;
";

const SCHEMA_V1: &str = "
CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE users (
    id           INTEGER PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE,
    display_name TEXT,
    sid          TEXT,
    is_admin     INTEGER NOT NULL DEFAULT 0,
    sid_mismatch INTEGER NOT NULL DEFAULT 0,
    created      INTEGER NOT NULL,
    last_login   INTEGER
);
CREATE TABLE server_groups (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    sort INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE servers (
    id       INTEGER PRIMARY KEY,
    name     TEXT NOT NULL UNIQUE COLLATE NOCASE,
    host     TEXT NOT NULL,
    port     INTEGER NOT NULL DEFAULT 3389,
    group_id INTEGER REFERENCES server_groups(id) ON DELETE SET NULL
);
CREATE TABLE assignments (
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, server_id)
) WITHOUT ROWID;
CREATE TABLE credentials (
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    username  TEXT NOT NULL,
    domain    TEXT,
    nonce     BLOB NOT NULL,
    secret    BLOB NOT NULL,
    updated   INTEGER NOT NULL,
    PRIMARY KEY (user_id, server_id)
) WITHOUT ROWID;
CREATE TABLE sessions (
    token_hash BLOB PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created    INTEGER NOT NULL,
    expires    INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE TABLE session_log (
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ended     INTEGER NOT NULL,
    PRIMARY KEY (user_id, server_id)
) WITHOUT ROWID;
CREATE TABLE audit (
    id     INTEGER PRIMARY KEY,
    at     INTEGER NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_at ON audit(at);
";

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("the database schema version {found} is newer than this build supports ({supported})")]
    Newer { found: i64, supported: i64 },
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub display_name: Option<String>,
    pub sid: Option<String>,
    pub is_admin: bool,
    pub sid_mismatch: bool,
    pub created: i64,
    pub last_login: Option<i64>,
    /// A local account: signs in against a hash in this database, not the directory.
    pub local: bool,
    /// Set on insert; a row that reuses a deleted row's id has another.
    pub incarnation: i64,
}

#[derive(Debug, Clone)]
pub struct UserRow {
    pub user: User,
    pub server_count: i64,
    pub saved_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: i64,
    pub name: String,
    pub sort: i64,
    pub server_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub id: i64,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub group_id: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ServerRow {
    pub server: Server,
    pub assigned: i64,
}

/// A server as it appears in a user's own list.
#[derive(Debug, Clone)]
pub struct ListedServer {
    pub server: Server,
    pub group_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoredCredential {
    pub username: String,
    pub domain: Option<String>,
    pub nonce: Vec<u8>,
    pub secret: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AuditRow {
    pub id: i64,
    pub at: i64,
    pub actor: String,
    pub action: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Counts {
    pub users: i64,
    pub servers: i64,
    pub assignments: i64,
    pub credentials: i64,
}

/// One row of a server import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRow {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub group: Option<String>,
}

pub struct Store {
    path: PathBuf,
    conn: Mutex<Connection>,
}

/// Open a database file, apply pragmas, and bring its schema up to date.
pub fn open_connection(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    configure(&conn)?;
    migrate(&conn)?;
    Ok(conn)
}

fn configure(conn: &Connection) -> Result<()> {
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    Ok(())
}

pub fn schema_version(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row("PRAGMA user_version", [], |r| r.get(0))?)
}

/// A migration that rebuilds tables other tables refer to. Foreign keys go off outside the
/// transaction, as SQLite requires, and every reference is checked before it commits; any failure
/// rolls back and leaves the database as it was.
fn rebuild_with_foreign_keys_off(conn: &Connection, sql: &str, version: i64) -> Result<()> {
    conn.execute_batch("PRAGMA foreign_keys = OFF;")?;
    let migrated = (|| -> Result<()> {
        conn.execute_batch("BEGIN;")?;
        conn.execute_batch(sql)?;
        let broken: i64 = conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r.get(0))?;
        if broken > 0 {
            return Err(StoreError::Invalid(format!(
                "migrating to schema {version} would break {broken} reference(s); nothing was changed"
            )));
        }
        conn.execute_batch(&format!("PRAGMA user_version = {version}; COMMIT;"))?;
        Ok(())
    })();
    if migrated.is_err() {
        let _ = conn.execute_batch("ROLLBACK;");
    }
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    migrated
}

/// Forward-only. A database from a newer build is refused rather than guessed at.
pub fn migrate(conn: &Connection) -> Result<()> {
    let found = schema_version(conn)?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::Newer {
            found,
            supported: SCHEMA_VERSION,
        });
    }
    if found < 1 {
        conn.execute_batch(&format!("BEGIN; {SCHEMA_V1} PRAGMA user_version = 1; COMMIT;"))?;
    }
    if found < 2 {
        conn.execute_batch(&format!("BEGIN; {SCHEMA_V2} PRAGMA user_version = 2; COMMIT;"))?;
    }
    if found < 3 {
        conn.execute_batch(&format!("BEGIN; {SCHEMA_V3} PRAGMA user_version = 3; COMMIT;"))?;
    }
    if found < 4 {
        rebuild_with_foreign_keys_off(conn, SCHEMA_V4, 4)?;
    }
    if found < 5 {
        rebuild_with_foreign_keys_off(conn, SCHEMA_V5, 5)?;
    }
    Ok(())
}

fn user_from(r: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get(0)?,
        username: r.get(1)?,
        display_name: r.get(2)?,
        sid: r.get(3)?,
        is_admin: r.get::<_, i64>(4)? != 0,
        sid_mismatch: r.get::<_, i64>(5)? != 0,
        created: r.get(6)?,
        last_login: r.get(7)?,
        local: r.get::<_, i64>(8)? != 0,
        incarnation: r.get(9)?,
    })
}

const USER_COLS: &str = "u.id, u.username, u.display_name, u.sid, u.is_admin, u.sid_mismatch, u.created, u.last_login, u.local_hash IS NOT NULL, u.incarnation";

fn server_from(r: &rusqlite::Row<'_>) -> rusqlite::Result<Server> {
    Ok(Server {
        id: r.get(0)?,
        name: r.get(1)?,
        host: r.get(2)?,
        port: r.get::<_, i64>(3)? as u16,
        group_id: r.get(4)?,
    })
}

const SERVER_COLS: &str = "s.id, s.name, s.host, s.port, s.group_id";

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            path: path.to_owned(),
            conn: Mutex::new(open_connection(path)?),
        })
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        configure(&conn)?;
        migrate(&conn)?;
        Ok(Self {
            path: PathBuf::from(":memory:"),
            conn: Mutex::new(conn),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn c(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    // ---- meta ------------------------------------------------------------------------------

    pub fn meta_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .c()
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn meta_set(&self, key: &str, value: &[u8]) -> Result<()> {
        self.c().execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn meta_delete(&self, key: &str) -> Result<()> {
        self.c().execute("DELETE FROM meta WHERE key = ?1", [key])?;
        Ok(())
    }

    pub fn flag(&self, key: &str) -> Result<bool> {
        Ok(self.meta_get(key)?.is_some_and(|v| v == b"1"))
    }

    pub fn set_flag(&self, key: &str, on: bool) -> Result<()> {
        if on {
            self.meta_set(key, b"1")
        } else {
            self.meta_delete(key)
        }
    }

    // ---- users -----------------------------------------------------------------------------

    pub fn user_by_id(&self, id: i64) -> Result<Option<User>> {
        Ok(self
            .c()
            .query_row(
                &format!("SELECT {USER_COLS} FROM users u WHERE u.id = ?1"),
                [id],
                user_from,
            )
            .optional()?)
    }

    pub fn user_by_name(&self, username: &str) -> Result<Option<User>> {
        Ok(self
            .c()
            .query_row(
                &format!("SELECT {USER_COLS} FROM users u WHERE u.username = ?1"),
                [username],
                user_from,
            )
            .optional()?)
    }

    pub fn users_list(&self) -> Result<Vec<UserRow>> {
        let c = self.c();
        let mut stmt = c.prepare(&format!(
            "SELECT {USER_COLS},
                    (SELECT COUNT(*) FROM assignments a WHERE a.user_id = u.id),
                    (SELECT COUNT(*) FROM credentials k WHERE k.user_id = u.id)
             FROM users u ORDER BY u.username"
        ))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(UserRow {
                    user: user_from(r)?,
                    server_count: r.get(10)?,
                    saved_count: r.get(11)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn user_create(&self, username: &str, display_name: Option<&str>) -> Result<i64> {
        Ok(self.user_create_returning(username, display_name)?.id)
    }

    /// Create a user and return its row as stored, incarnation included, under one hold of the
    /// connection, so nothing comes between the insert and the read.
    pub fn user_create_returning(&self, username: &str, display_name: Option<&str>) -> Result<User> {
        let c = self.c();
        let exists: bool = c
            .query_row("SELECT 1 FROM users WHERE username = ?1", [username], |_| Ok(()))
            .optional()?
            .is_some();
        if exists {
            return Err(StoreError::Conflict(format!("{username} is already a user")));
        }
        c.execute(
            "INSERT INTO users (username, display_name, created) VALUES (?1, ?2, ?3)",
            params![username, display_name, now()],
        )?;
        let id = c.last_insert_rowid();
        Ok(c.query_row(&format!("SELECT {USER_COLS} FROM users u WHERE u.id = ?1"), [id], user_from)?)
    }

    /// A row on an id used before, which ids that are never reused cannot produce: for testing the
    /// incarnation checks that stand behind them.
    #[cfg(test)]
    pub fn user_create_at(&self, id: i64, username: &str) -> Result<i64> {
        self.c().execute(
            "INSERT INTO users (id, username, created) VALUES (?1, ?2, ?3)",
            params![id, username, now()],
        )?;
        Ok(id)
    }

    #[cfg(test)]
    pub fn server_create_at(&self, id: i64, name: &str, host: &str) -> Result<i64> {
        self.c().execute(
            "INSERT INTO servers (id, name, host) VALUES (?1, ?2, ?3)",
            params![id, name, host],
        )?;
        Ok(id)
    }

    /// Record a successful sign-in, binding the SID if this is the first.
    /// Record a sign-in on the row the caller read, and only while that row is unbound or bound to
    /// this SID: false, and nothing written, when the id now belongs to another incarnation or the
    /// row was bound to another account meanwhile.
    pub fn user_record_login(
        &self,
        id: i64,
        incarnation: i64,
        sid: &str,
        display_name: Option<&str>,
    ) -> Result<bool> {
        let n = self.c().execute(
            "UPDATE users SET sid = COALESCE(sid, ?2),
                              display_name = COALESCE(?3, display_name),
                              last_login = ?4
             WHERE id = ?1 AND incarnation = ?5 AND (sid IS NULL OR sid = ?2)",
            params![id, sid, display_name, now(), incarnation],
        )?;
        Ok(n > 0)
    }

    /// Create a local account, or reset the password of an existing one. An existing directory
    /// user of the same name is refused: the two would be indistinguishable at sign-in.
    pub fn local_account_set(&self, username: &str, hash: &str, sid: &str) -> Result<i64> {
        let c = self.c();
        let existing: Option<(i64, bool)> = c
            .query_row(
                "SELECT id, local_hash IS NOT NULL FROM users WHERE username = ?1",
                [username],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0)),
            )
            .optional()?;
        match existing {
            Some((_, false)) => Err(StoreError::Conflict(format!(
                "{username} is a directory user; choose another name for the local account"
            ))),
            Some((id, true)) => {
                c.execute("UPDATE users SET local_hash = ?2 WHERE id = ?1", params![id, hash])?;
                Ok(id)
            }
            None => {
                c.execute(
                    "INSERT INTO users (username, display_name, sid, created, local_hash)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![username, format!("{username} (local)"), sid, now(), hash],
                )?;
                Ok(c.last_insert_rowid())
            }
        }
    }

    pub fn local_hash(&self, id: i64) -> Result<Option<String>> {
        Ok(self
            .c()
            .query_row("SELECT local_hash FROM users WHERE id = ?1", [id], |r| r.get(0))
            .optional()?
            .flatten())
    }

    pub fn user_flag_mismatch(&self, id: i64) -> Result<()> {
        self.c()
            .execute("UPDATE users SET sid_mismatch = 1 WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn user_set_admin(&self, id: i64, admin: bool) -> Result<()> {
        let n = self.c().execute(
            "UPDATE users SET is_admin = ?2 WHERE id = ?1",
            params![id, admin as i64],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Unbind the SID so the next sign-in binds afresh. Saved credentials are bound to the old SID
    /// and could not be opened by the new one, so they go too.
    pub fn user_clear_sid(&self, id: i64) -> Result<()> {
        let mut c = self.c();
        let tx = c.transaction()?;
        let n = tx.execute(
            "UPDATE users SET sid = NULL, sid_mismatch = 0 WHERE id = ?1",
            [id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        tx.execute("DELETE FROM credentials WHERE user_id = ?1", [id])?;
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
        tx.commit()?;
        Ok(())
    }

    pub fn user_delete(&self, id: i64) -> Result<()> {
        let n = self.c().execute("DELETE FROM users WHERE id = ?1", [id])?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Directory users holding at least one unexpired session: the set the revocation sweep checks.
    /// Local accounts are not in the directory, so they are never swept.
    pub fn directory_users_with_sessions(&self, at: i64) -> Result<Vec<User>> {
        let c = self.c();
        let mut stmt = c.prepare(&format!(
            "SELECT {USER_COLS} FROM users u
             WHERE u.local_hash IS NULL
               AND EXISTS (SELECT 1 FROM sessions s WHERE s.user_id = u.id AND s.expires > ?1)"
        ))?;
        let rows = stmt
            .query_map([at], user_from)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ---- groups ----------------------------------------------------------------------------

    pub fn groups_list(&self) -> Result<Vec<Group>> {
        let c = self.c();
        let mut stmt = c.prepare(
            "SELECT g.id, g.name, g.sort,
                    (SELECT COUNT(*) FROM servers s WHERE s.group_id = g.id)
             FROM server_groups g ORDER BY g.sort, g.name",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Group {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    sort: r.get(2)?,
                    server_count: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn group_create(&self, name: &str) -> Result<i64> {
        let c = self.c();
        group_insert(&c, name)
    }

    pub fn group_rename(&self, id: i64, name: &str) -> Result<()> {
        let c = self.c();
        let taken: Option<i64> = c
            .query_row(
                "SELECT id FROM server_groups WHERE name = ?1 AND id <> ?2",
                params![name, id],
                |r| r.get(0),
            )
            .optional()?;
        if taken.is_some() {
            return Err(StoreError::Conflict(format!("a group named {name} exists")));
        }
        let n = c.execute(
            "UPDATE server_groups SET name = ?2 WHERE id = ?1",
            params![id, name],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Set the display order to the order of `ids`.
    pub fn group_order(&self, ids: &[i64]) -> Result<()> {
        let mut c = self.c();
        let tx = c.transaction()?;
        for (i, id) in ids.iter().enumerate() {
            tx.execute(
                "UPDATE server_groups SET sort = ?2 WHERE id = ?1",
                params![id, i as i64],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn group_delete(&self, id: i64) -> Result<()> {
        let c = self.c();
        let used: i64 = c.query_row(
            "SELECT COUNT(*) FROM servers WHERE group_id = ?1",
            [id],
            |r| r.get(0),
        )?;
        if used > 0 {
            return Err(StoreError::Conflict(format!(
                "the group still holds {used} server(s)"
            )));
        }
        let n = c.execute("DELETE FROM server_groups WHERE id = ?1", [id])?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    // ---- servers ---------------------------------------------------------------------------

    pub fn servers_list(&self) -> Result<Vec<ServerRow>> {
        let c = self.c();
        let mut stmt = c.prepare(&format!(
            "SELECT {SERVER_COLS}, (SELECT COUNT(*) FROM assignments a WHERE a.server_id = s.id)
             FROM servers s ORDER BY s.name"
        ))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(ServerRow {
                    server: server_from(r)?,
                    assigned: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn server_by_id(&self, id: i64) -> Result<Option<Server>> {
        Ok(self
            .c()
            .query_row(
                &format!("SELECT {SERVER_COLS} FROM servers s WHERE s.id = ?1"),
                [id],
                server_from,
            )
            .optional()?)
    }

    pub fn server_create(
        &self,
        name: &str,
        host: &str,
        port: u16,
        group_id: Option<i64>,
    ) -> Result<i64> {
        let c = self.c();
        name_free(&c, name, None)?;
        group_exists(&c, group_id)?;
        c.execute(
            "INSERT INTO servers (name, host, port, group_id) VALUES (?1, ?2, ?3, ?4)",
            params![name, host, port as i64, group_id],
        )?;
        Ok(c.last_insert_rowid())
    }

    pub fn server_update(
        &self,
        id: i64,
        name: &str,
        host: &str,
        port: u16,
        group_id: Option<i64>,
    ) -> Result<()> {
        let c = self.c();
        name_free(&c, name, Some(id))?;
        group_exists(&c, group_id)?;
        let n = c.execute(
            "UPDATE servers SET name = ?2, host = ?3, port = ?4, group_id = ?5 WHERE id = ?1",
            params![id, name, host, port as i64, group_id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    pub fn server_delete(&self, id: i64) -> Result<()> {
        let n = self.c().execute("DELETE FROM servers WHERE id = ?1", [id])?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Create or update servers by name, creating named groups as needed. All or nothing.
    pub fn servers_import(&self, rows: &[ImportRow]) -> Result<(usize, usize)> {
        let mut c = self.c();
        let tx = c.transaction()?;
        let (mut created, mut updated) = (0, 0);
        for row in rows {
            let group_id = match &row.group {
                None => None,
                Some(name) => {
                    let found: Option<i64> = tx
                        .query_row(
                            "SELECT id FROM server_groups WHERE name = ?1",
                            [name],
                            |r| r.get(0),
                        )
                        .optional()?;
                    Some(match found {
                        Some(id) => id,
                        None => group_insert(&tx, name)?,
                    })
                }
            };
            let existing: Option<i64> = tx
                .query_row("SELECT id FROM servers WHERE name = ?1", [&row.name], |r| {
                    r.get(0)
                })
                .optional()?;
            match existing {
                Some(id) => {
                    tx.execute(
                        "UPDATE servers SET host = ?2, port = ?3, group_id = ?4 WHERE id = ?1",
                        params![id, row.host, row.port as i64, group_id],
                    )?;
                    updated += 1;
                }
                None => {
                    tx.execute(
                        "INSERT INTO servers (name, host, port, group_id) VALUES (?1, ?2, ?3, ?4)",
                        params![row.name, row.host, row.port as i64, group_id],
                    )?;
                    created += 1;
                }
            }
        }
        tx.commit()?;
        Ok((created, updated))
    }

    pub fn servers_empty(&self) -> Result<bool> {
        let n: i64 = self
            .c()
            .query_row("SELECT COUNT(*) FROM servers", [], |r| r.get(0))?;
        Ok(n == 0)
    }

    // ---- assignments -----------------------------------------------------------------------

    /// THE AUTHORIZATION PREDICATE. `assigned_servers` applies the same condition as a join.
    pub fn is_assigned(&self, user_id: i64, server_id: i64) -> Result<bool> {
        Ok(self
            .c()
            .query_row(
                "SELECT 1 FROM assignments WHERE user_id = ?1 AND server_id = ?2",
                params![user_id, server_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn assigned_servers(&self, user_id: i64) -> Result<Vec<ListedServer>> {
        let c = self.c();
        // Ungrouped servers sort after every group.
        let mut stmt = c.prepare(&format!(
            "SELECT {SERVER_COLS}, g.name
             FROM assignments a
             JOIN servers s ON s.id = a.server_id
             LEFT JOIN server_groups g ON g.id = s.group_id
             WHERE a.user_id = ?1
             ORDER BY COALESCE(g.sort, 1000000000), g.name, s.name COLLATE NOCASE"
        ))?;
        let rows = stmt
            .query_map([user_id], |r| {
                Ok(ListedServer {
                    server: server_from(r)?,
                    group_name: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn assignment_ids(&self, user_id: i64) -> Result<Vec<i64>> {
        let c = self.c();
        let mut stmt =
            c.prepare("SELECT server_id FROM assignments WHERE user_id = ?1 ORDER BY server_id")?;
        let rows = stmt
            .query_map([user_id], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<i64>>>()?;
        Ok(rows)
    }

    /// Replace a user's assignments with exactly `ids`. Returns (added, removed).
    pub fn set_assignments(&self, user_id: i64, ids: &[i64]) -> Result<(usize, usize)> {
        let mut c = self.c();
        let tx = c.transaction()?;
        let user_exists = tx
            .query_row("SELECT 1 FROM users WHERE id = ?1", [user_id], |_| Ok(()))
            .optional()?
            .is_some();
        if !user_exists {
            return Err(StoreError::NotFound);
        }
        let wanted: HashSet<i64> = ids.iter().copied().collect();
        for id in &wanted {
            let ok = tx
                .query_row("SELECT 1 FROM servers WHERE id = ?1", [id], |_| Ok(()))
                .optional()?
                .is_some();
            if !ok {
                return Err(StoreError::Invalid(format!("no server with id {id}")));
            }
        }
        let current: HashSet<i64> = {
            let mut stmt = tx.prepare("SELECT server_id FROM assignments WHERE user_id = ?1")?;
            let v = stmt
                .query_map([user_id], |r| r.get(0))?
                .collect::<rusqlite::Result<HashSet<i64>>>()?;
            v
        };
        let mut added = 0;
        for id in wanted.difference(&current) {
            tx.execute(
                "INSERT INTO assignments (user_id, server_id) VALUES (?1, ?2)",
                params![user_id, id],
            )?;
            added += 1;
        }
        let mut removed = 0;
        for id in current.difference(&wanted) {
            tx.execute(
                "DELETE FROM assignments WHERE user_id = ?1 AND server_id = ?2",
                params![user_id, id],
            )?;
            // A credential for a server the user can no longer reach has no purpose.
            tx.execute(
                "DELETE FROM credentials WHERE user_id = ?1 AND server_id = ?2",
                params![user_id, id],
            )?;
            removed += 1;
        }
        tx.commit()?;
        Ok((added, removed))
    }

    /// Add every assignment `from` holds to `to`. Returns how many were new.
    pub fn copy_assignments(&self, from: i64, to: i64) -> Result<usize> {
        let c = self.c();
        let n = c.execute(
            "INSERT OR IGNORE INTO assignments (user_id, server_id)
             SELECT ?2, server_id FROM assignments WHERE user_id = ?1",
            params![from, to],
        )?;
        Ok(n)
    }

    // ---- credentials -----------------------------------------------------------------------

    pub fn credential_get(&self, user_id: i64, server_id: i64) -> Result<Option<StoredCredential>> {
        Ok(self
            .c()
            .query_row(
                "SELECT username, domain, nonce, secret FROM credentials
                 WHERE user_id = ?1 AND server_id = ?2",
                params![user_id, server_id],
                |r| {
                    Ok(StoredCredential {
                        username: r.get(0)?,
                        domain: r.get(1)?,
                        nonce: r.get(2)?,
                        secret: r.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn credential_put(&self, user_id: i64, server_id: i64, cred: &StoredCredential) -> Result<()> {
        self.c().execute(
            "INSERT INTO credentials (user_id, server_id, username, domain, nonce, secret, updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(user_id, server_id) DO UPDATE SET
                username = excluded.username, domain = excluded.domain,
                nonce = excluded.nonce, secret = excluded.secret, updated = excluded.updated",
            params![
                user_id,
                server_id,
                cred.username,
                cred.domain,
                cred.nonce,
                cred.secret,
                now()
            ],
        )?;
        Ok(())
    }

    pub fn credential_delete(&self, user_id: i64, server_id: i64) -> Result<bool> {
        Ok(self.c().execute(
            "DELETE FROM credentials WHERE user_id = ?1 AND server_id = ?2",
            params![user_id, server_id],
        )? > 0)
    }

    pub fn saved_server_ids(&self, user_id: i64) -> Result<HashSet<i64>> {
        let c = self.c();
        let mut stmt = c.prepare("SELECT server_id FROM credentials WHERE user_id = ?1")?;
        let rows = stmt
            .query_map([user_id], |r| r.get(0))?
            .collect::<rusqlite::Result<HashSet<i64>>>()?;
        Ok(rows)
    }

    // ---- sessions --------------------------------------------------------------------------

    /// Create a sign-in session for the row the caller authenticated, and only that row: false,
    /// and nothing written, when the id now belongs to another incarnation.
    pub fn session_create(
        &self,
        token_hash: &[u8],
        user_id: i64,
        incarnation: i64,
        expires: i64,
    ) -> Result<bool> {
        let n = self.c().execute(
            "INSERT INTO sessions (token_hash, user_id, created, expires)
             SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM users WHERE id = ?2 AND incarnation = ?5)",
            params![token_hash, user_id, now(), expires, incarnation],
        )?;
        Ok(n > 0)
    }

    /// The user behind an unexpired session.
    pub fn session_user(&self, token_hash: &[u8], at: i64) -> Result<Option<User>> {
        Ok(self
            .c()
            .query_row(
                &format!(
                    "SELECT {USER_COLS} FROM sessions s JOIN users u ON u.id = s.user_id
                     WHERE s.token_hash = ?1 AND s.expires > ?2"
                ),
                params![token_hash, at],
                user_from,
            )
            .optional()?)
    }

    pub fn session_delete(&self, token_hash: &[u8]) -> Result<()> {
        self.c()
            .execute("DELETE FROM sessions WHERE token_hash = ?1", [token_hash])?;
        Ok(())
    }

    pub fn sessions_delete_user(&self, user_id: i64) -> Result<usize> {
        Ok(self
            .c()
            .execute("DELETE FROM sessions WHERE user_id = ?1", [user_id])?)
    }

    pub fn sessions_purge(&self, at: i64) -> Result<usize> {
        Ok(self
            .c()
            .execute("DELETE FROM sessions WHERE expires <= ?1", [at])?)
    }

    // ---- session log -----------------------------------------------------------------------

    /// The incarnations of a user row and a server row, as `(user, server)`.
    pub fn incarnations(&self, user_id: i64, server_id: i64) -> Result<Option<(i64, i64)>> {
        Ok(self
            .c()
            .query_row(
                "SELECT u.incarnation, s.incarnation FROM users u, servers s WHERE u.id = ?1 AND s.id = ?2",
                params![user_id, server_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// Record a session's end, only against the user and server rows it was opened with: a row
    /// that has reused a deleted row's id has another incarnation. Returns whether it was recorded.
    pub fn session_ended(
        &self,
        user_id: i64,
        user_incarnation: i64,
        server_id: i64,
        server_incarnation: i64,
        at: i64,
    ) -> Result<bool> {
        let n = self.c().execute(
            "INSERT INTO session_log (user_id, server_id, ended)
             SELECT ?1, ?3, ?5
              WHERE EXISTS (SELECT 1 FROM users WHERE id = ?1 AND incarnation = ?2)
                AND EXISTS (SELECT 1 FROM servers WHERE id = ?3 AND incarnation = ?4)
             ON CONFLICT(user_id, server_id) DO UPDATE SET ended = excluded.ended",
            params![user_id, user_incarnation, server_id, server_incarnation, at],
        )?;
        Ok(n > 0)
    }

    /// Server id -> when this user's last session to it ended, for ends after `since`.
    pub fn recent_ends(&self, user_id: i64, since: i64) -> Result<HashMap<i64, i64>> {
        let c = self.c();
        let mut stmt = c.prepare(
            "SELECT server_id, ended FROM session_log WHERE user_id = ?1 AND ended > ?2",
        )?;
        let rows = stmt
            .query_map(params![user_id, since], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<HashMap<i64, i64>>>()?;
        Ok(rows)
    }

    // ---- audit -----------------------------------------------------------------------------

    /// Best effort: an audit write that fails is logged, never allowed to fail the action.
    pub fn audit(&self, actor: &str, action: &str, detail: &str) {
        if let Err(e) = self.c().execute(
            "INSERT INTO audit (at, actor, action, detail) VALUES (?1, ?2, ?3, ?4)",
            params![now(), actor, action, detail],
        ) {
            tracing::warn!(error = %e, %actor, %action, "audit write failed");
        }
    }

    pub fn audit_list(&self, limit: i64, before: Option<i64>) -> Result<Vec<AuditRow>> {
        let c = self.c();
        let mut stmt = c.prepare(
            "SELECT id, at, actor, action, detail FROM audit
             WHERE (?2 IS NULL OR id < ?2) ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit, before], |r| {
                Ok(AuditRow {
                    id: r.get(0)?,
                    at: r.get(1)?,
                    actor: r.get(2)?,
                    action: r.get(3)?,
                    detail: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ---- whole-database operations ---------------------------------------------------------

    pub fn counts(&self) -> Result<Counts> {
        let c = self.c();
        counts_of(&c)
    }

    /// SQLite's own consistency check. Err carries its first complaint.
    pub fn integrity(&self) -> std::result::Result<(), String> {
        let c = self.c();
        let verdict: rusqlite::Result<String> =
            c.query_row("PRAGMA integrity_check", [], |r| r.get(0));
        match verdict {
            Ok(v) if v == "ok" => Ok(()),
            Ok(v) => Err(v),
            Err(e) => Err(e.to_string()),
        }
    }

    /// A consistent copy of the whole database, written to `dest`, which must not exist.
    pub fn snapshot_to(&self, dest: &Path) -> Result<Counts> {
        let c = self.c();
        let counts = counts_of(&c)?;
        c.execute("VACUUM INTO ?1", [dest.to_string_lossy().as_ref()])?;
        Ok(counts)
    }

    /// Replace the database file with `new_file`, which has already been validated. The current
    /// file is renamed over; the caller keeps its own backup first.
    pub fn replace_with(&self, new_file: &Path) -> Result<()> {
        let mut c = self.c();
        // Release the file before renaming over it: Windows refuses to replace an open file.
        let placeholder = Connection::open_in_memory()?;
        let old = std::mem::replace(&mut *c, placeholder);
        drop(old);
        let installed = std::fs::rename(new_file, &self.path);
        // Reopen whichever file is now in place, so a failed rename leaves the old data serving.
        *c = open_connection(&self.path)?;
        installed?;
        Ok(())
    }
}

fn counts_of(c: &Connection) -> Result<Counts> {
    let one = |sql: &str| -> Result<i64> { Ok(c.query_row(sql, [], |r| r.get(0))?) };
    Ok(Counts {
        users: one("SELECT COUNT(*) FROM users")?,
        servers: one("SELECT COUNT(*) FROM servers")?,
        assignments: one("SELECT COUNT(*) FROM assignments")?,
        credentials: one("SELECT COUNT(*) FROM credentials")?,
    })
}

fn group_insert(c: &Connection, name: &str) -> Result<i64> {
    let exists = c
        .query_row("SELECT 1 FROM server_groups WHERE name = ?1", [name], |_| Ok(()))
        .optional()?
        .is_some();
    if exists {
        return Err(StoreError::Conflict(format!("a group named {name} exists")));
    }
    let next: i64 = c.query_row(
        "SELECT COALESCE(MAX(sort), -1) + 1 FROM server_groups",
        [],
        |r| r.get(0),
    )?;
    c.execute(
        "INSERT INTO server_groups (name, sort) VALUES (?1, ?2)",
        params![name, next],
    )?;
    Ok(c.last_insert_rowid())
}

fn name_free(c: &Connection, name: &str, except: Option<i64>) -> Result<()> {
    let taken: Option<i64> = c
        .query_row(
            "SELECT id FROM servers WHERE name = ?1 AND (?2 IS NULL OR id <> ?2)",
            params![name, except],
            |r| r.get(0),
        )
        .optional()?;
    if taken.is_some() {
        return Err(StoreError::Conflict(format!("a server named {name} exists")));
    }
    Ok(())
}

fn group_exists(c: &Connection, group_id: Option<i64>) -> Result<()> {
    if let Some(id) = group_id {
        let ok = c
            .query_row("SELECT 1 FROM server_groups WHERE id = ?1", [id], |_| Ok(()))
            .optional()?
            .is_some();
        if !ok {
            return Err(StoreError::Invalid(format!("no group with id {id}")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::open_in_memory().unwrap()
    }

    #[test]
    fn assignment_replacement_reports_what_changed() {
        let s = store();
        let u = s.user_create("jdoe", None).unwrap();
        let a = s.server_create("hist-01", "hist-01.example", 3389, None).unwrap();
        let b = s.server_create("eng-02", "eng-02.example", 3389, None).unwrap();
        assert_eq!(s.set_assignments(u, &[a, b]).unwrap(), (2, 0));
        assert_eq!(s.set_assignments(u, &[b]).unwrap(), (0, 1));
        assert_eq!(s.assignment_ids(u).unwrap(), vec![b]);
        assert!(matches!(
            s.set_assignments(u, &[b, 999]),
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(s.assignment_ids(u).unwrap(), vec![b], "a refused set changes nothing");
    }

    #[test]
    fn removing_an_assignment_removes_its_saved_credential() {
        let s = store();
        let u = s.user_create("jdoe", None).unwrap();
        let a = s.server_create("hist-01", "h", 3389, None).unwrap();
        s.set_assignments(u, &[a]).unwrap();
        let cred = StoredCredential {
            username: "x".into(),
            domain: None,
            nonce: vec![0; 12],
            secret: vec![1; 20],
        };
        s.credential_put(u, a, &cred).unwrap();
        s.set_assignments(u, &[]).unwrap();
        assert!(s.credential_get(u, a).unwrap().is_none());
    }

    #[test]
    fn a_group_with_servers_cannot_be_deleted() {
        let s = store();
        let g = s.group_create("Historians").unwrap();
        let sv = s.server_create("hist-01", "h", 3389, Some(g)).unwrap();
        assert!(matches!(s.group_delete(g), Err(StoreError::Conflict(_))));
        s.server_delete(sv).unwrap();
        s.group_delete(g).unwrap();
    }

    #[test]
    fn server_names_are_unique_regardless_of_case() {
        let s = store();
        s.server_create("Hist-01", "h", 3389, None).unwrap();
        assert!(matches!(
            s.server_create("hist-01", "h2", 3389, None),
            Err(StoreError::Conflict(_))
        ));
    }

    #[test]
    fn import_creates_groups_and_updates_by_name() {
        let s = store();
        let rows = vec![
            ImportRow { name: "a".into(), host: "a.example".into(), port: 3389, group: Some("G1".into()) },
            ImportRow { name: "b".into(), host: "b.example".into(), port: 3390, group: None },
        ];
        assert_eq!(s.servers_import(&rows).unwrap(), (2, 0));
        let again = vec![ImportRow { name: "A".into(), host: "a2.example".into(), port: 3389, group: Some("g1".into()) }];
        assert_eq!(s.servers_import(&again).unwrap(), (0, 1));
        assert_eq!(s.groups_list().unwrap().len(), 1);
        let a = s.servers_list().unwrap().into_iter().find(|r| r.server.name == "a").unwrap();
        assert_eq!(a.server.host, "a2.example");
    }

    fn inc(s: &Store, id: i64) -> i64 {
        s.user_by_id(id).unwrap().unwrap().incarnation
    }

    #[test]
    fn a_session_is_refused_at_expiry() {
        let s = store();
        let u = s.user_create("jdoe", None).unwrap();
        assert!(s.session_create(b"hash", u, inc(&s, u), 1000).unwrap());
        assert!(s.session_user(b"hash", 999).unwrap().is_some());
        assert!(s.session_user(b"hash", 1000).unwrap().is_none());
    }

    /// A deleted user's, server's or group's id is never given to a new row, so an id kept anywhere names
    /// that row or nothing.
    #[test]
    fn a_deleted_rows_id_is_never_given_to_a_new_row() {
        let s = store();
        let alice = s.user_create("alice", None).unwrap();
        s.user_delete(alice).unwrap();
        let bob = s.user_create("bob", None).unwrap();
        assert!(bob > alice, "user id {alice} was given to a new row");
        let a = s.server_create("hist-01", "h", 3389, None).unwrap();
        s.server_delete(a).unwrap();
        let b = s.server_create("eng-01", "e", 3389, None).unwrap();
        assert!(b > a, "server id {a} was given to a new row");
        let g = s.group_create("G").unwrap();
        s.group_delete(g).unwrap();
        let h = s.group_create("H").unwrap();
        assert!(h > g, "group id {g} was given to a new row");
        let created = s.user_create_returning("carol", None).unwrap();
        assert_eq!(Some(created.clone()), s.user_by_id(created.id).unwrap());
    }

    /// A version 3 database keeps every row and every reference through the rebuild, its cascades
    /// still work, and from then on ids are not reused.
    #[test]
    fn a_version_3_database_migrates_to_ids_that_are_never_reused() {
        let conn = Connection::open_in_memory().unwrap();
        configure(&conn).unwrap();
        conn.execute_batch(&format!("{SCHEMA_V1} {SCHEMA_V2} {SCHEMA_V3} PRAGMA user_version = 3;")).unwrap();
        conn.execute_batch(
            "INSERT INTO users (id, username, created) VALUES (1, 'alice', 1), (2, 'bob', 1);
             INSERT INTO server_groups (id, name) VALUES (1, 'G');
             INSERT INTO servers (id, name, host, group_id) VALUES (1, 'hist-01', 'h', 1), (2, 'eng-01', 'e', NULL);
             INSERT INTO assignments VALUES (1, 1), (2, 2);
             INSERT INTO credentials VALUES (2, 2, 'ops', NULL, x'00', x'01', 1);
             INSERT INTO sessions VALUES (x'aa', 2, 1, 99);
             INSERT INTO session_log VALUES (2, 2, 5);",
        )
        .unwrap();
        let before: i64 = conn.query_row("SELECT incarnation FROM users WHERE id = 2", [], |r| r.get(0)).unwrap();

        migrate(&conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);
        let one = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(one("SELECT COUNT(*) FROM users"), 2);
        assert_eq!(one("SELECT COUNT(*) FROM servers"), 2);
        assert_eq!(one("SELECT group_id FROM servers WHERE id = 1"), 1);
        assert_eq!(one("SELECT incarnation FROM users WHERE id = 2"), before, "an incarnation changed");
        assert_eq!(one("SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
        assert_eq!(one("PRAGMA foreign_keys"), 1, "foreign keys were left off");

        // References survived: deleting bob cascades to everything of his.
        conn.execute("DELETE FROM users WHERE id = 2", []).unwrap();
        for table in ["assignments", "credentials", "sessions", "session_log"] {
            assert_eq!(one(&format!("SELECT COUNT(*) FROM {table} WHERE user_id = 2")), 0, "{table} kept bob's rows");
        }
        // A deleted group leaves its servers ungrouped, and its id is not given to a new group.
        conn.execute("DELETE FROM server_groups WHERE id = 1", []).unwrap();
        assert_eq!(one("SELECT group_id IS NULL FROM servers WHERE id = 1"), 1);
        conn.execute("INSERT INTO server_groups (name) VALUES ('H')", []).unwrap();
        assert_eq!(one("SELECT id FROM server_groups WHERE name = 'H'"), 2, "a group id was given to a new group");
        conn.execute("DELETE FROM servers WHERE id = 1", []).unwrap();
        assert_eq!(one("SELECT COUNT(*) FROM assignments WHERE server_id = 1"), 0);

        conn.execute("INSERT INTO users (username, created) VALUES ('carol', 1)", []).unwrap();
        assert_eq!(one("SELECT id FROM users WHERE username = 'carol'"), 3, "bob's id was given to a new row");
        assert_ne!(one("SELECT incarnation IS NOT NULL FROM users WHERE username = 'carol'"), 0);
        conn.execute("INSERT INTO servers (name, host) VALUES ('new-01', 'n')", []).unwrap();
        assert_eq!(one("SELECT id FROM servers WHERE name = 'new-01'"), 3);
    }

    /// A rebuild that would leave a broken reference is refused and changes nothing: the version,
    /// the tables and foreign-key enforcement are as they were.
    #[test]
    fn a_migration_that_would_break_references_changes_nothing() {
        let conn = Connection::open_in_memory().unwrap();
        configure(&conn).unwrap();
        conn.execute_batch(&format!("{SCHEMA_V1} {SCHEMA_V2} {SCHEMA_V3} PRAGMA user_version = 3;")).unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF;
             INSERT INTO sessions VALUES (x'bb', 99, 1, 99);
             PRAGMA foreign_keys = ON;",
        )
        .unwrap();
        assert!(migrate(&conn).is_err(), "a migration with a broken reference went through");
        assert_eq!(schema_version(&conn).unwrap(), 3);
        let rebuilt: i64 = conn
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE sql LIKE '%AUTOINCREMENT%'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rebuilt, 0, "the refused migration left rebuilt tables behind");
        let on: i64 = conn.query_row("PRAGMA foreign_keys", [], |r| r.get(0)).unwrap();
        assert_eq!(on, 1, "foreign keys were left off");
    }

    /// Behind ids that are never reused: were a row ever to arrive on a deleted row's id, a sign-in
    /// that authenticated the old row would neither record its login on it nor get a session.
    #[test]
    fn a_sign_in_never_lands_on_a_row_that_reused_its_id() {
        let s = store();
        let alice = s.user_create("alice", None).unwrap();
        let authenticated = inc(&s, alice);
        s.user_delete(alice).unwrap();
        let bob = s.user_create_at(alice, "bob").unwrap();
        assert!(!s.user_record_login(bob, authenticated, "S-1-5-21-9", None).unwrap());
        assert!(s.user_by_id(bob).unwrap().unwrap().sid.is_none(), "the login landed on another row");
        assert!(!s.session_create(b"alice's", bob, authenticated, now() + 100).unwrap());
        assert!(s.session_user(b"alice's", now()).unwrap().is_none(), "the session went to another row");
        assert!(s.user_record_login(bob, inc(&s, bob), "S-1-5-21-9", None).unwrap());
        assert!(s.session_create(b"bob's", bob, inc(&s, bob), now() + 100).unwrap());
    }

    #[test]
    fn clearing_the_sid_drops_credentials_and_sessions() {
        let s = store();
        let u = s.user_create("jdoe", None).unwrap();
        let a = s.server_create("hist-01", "h", 3389, None).unwrap();
        s.user_record_login(u, inc(&s, u), "S-1-5-21-1", None).unwrap();
        s.credential_put(u, a, &StoredCredential { username: "x".into(), domain: None, nonce: vec![0; 12], secret: vec![1] }).unwrap();
        s.session_create(b"h", u, inc(&s, u), now() + 100).unwrap();
        s.user_clear_sid(u).unwrap();
        let user = s.user_by_id(u).unwrap().unwrap();
        assert!(user.sid.is_none());
        assert!(s.credential_get(u, a).unwrap().is_none());
        assert!(s.session_user(b"h", now()).unwrap().is_none());
    }

    /// Two first sign-ins that both read a row unbound cannot both use it: once one account has
    /// bound it, a sign-in from another is refused.
    #[test]
    fn a_row_bound_by_one_account_refuses_a_sign_in_from_another() {
        let s = store();
        let u = s.user_create("jdoe", None).unwrap();
        let row = inc(&s, u);
        assert!(s.user_record_login(u, row, "SID-FIRST", None).unwrap());
        assert!(!s.user_record_login(u, row, "SID-SECOND", None).unwrap(), "a second account shared the row");
        assert_eq!(s.user_by_id(u).unwrap().unwrap().sid.as_deref(), Some("SID-FIRST"));
        assert!(s.user_record_login(u, row, "SID-FIRST", None).unwrap(), "the bound account was refused");
    }

    #[test]
    fn a_first_login_binds_the_sid_and_later_ones_do_not_change_it() {
        let s = store();
        let u = s.user_create("jdoe", None).unwrap();
        s.user_record_login(u, inc(&s, u), "S-1-5-21-1", Some("J Doe")).unwrap();
        s.user_record_login(u, inc(&s, u), "S-1-5-21-2", None).unwrap();
        let user = s.user_by_id(u).unwrap().unwrap();
        assert_eq!(user.sid.as_deref(), Some("S-1-5-21-1"));
        assert_eq!(user.display_name.as_deref(), Some("J Doe"));
    }

    #[test]
    fn a_version_1_database_gains_local_accounts() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&format!("{SCHEMA_V1} PRAGMA user_version = 1;")).unwrap();
        conn.execute(
            "INSERT INTO users (username, created) VALUES ('jdoe', 1)",
            [],
        )
        .unwrap();
        migrate(&conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), SCHEMA_VERSION);
        let local: i64 = conn
            .query_row("SELECT local_hash IS NOT NULL FROM users WHERE username = 'jdoe'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(local, 0);
    }

    #[test]
    fn a_local_account_is_created_reset_and_kept_apart_from_directory_users() {
        let s = store();
        let id = s.local_account_set("devtest", "h1", "local:1").unwrap();
        assert!(s.user_by_id(id).unwrap().unwrap().local);
        assert_eq!(s.local_account_set("devtest", "h2", "local:ignored").unwrap(), id);
        assert_eq!(s.local_hash(id).unwrap().as_deref(), Some("h2"));
        s.user_create("jdoe", None).unwrap();
        assert!(matches!(s.local_account_set("jdoe", "h", "local:2"), Err(StoreError::Conflict(_))));
    }

    #[test]
    fn the_revocation_sweep_never_sees_local_accounts() {
        let s = store();
        let local = s.local_account_set("devtest", "h", "local:1").unwrap();
        let dir = s.user_create("jdoe", None).unwrap();
        s.session_create(b"a", local, inc(&s, local), now() + 100).unwrap();
        s.session_create(b"b", dir, inc(&s, dir), now() + 100).unwrap();
        let swept: Vec<i64> = s.directory_users_with_sessions(now()).unwrap().iter().map(|u| u.id).collect();
        assert_eq!(swept, vec![dir]);
    }

    #[test]
    fn a_newer_schema_is_refused() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1).unwrap();
        assert!(matches!(migrate(&conn), Err(StoreError::Newer { .. })));
    }
}
