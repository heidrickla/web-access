//! Export and import of the whole database, for moving to new hardware and for backups.
//!
//! An export is a zip holding `manifest.json` and `data.db.enc`: a consistent snapshot of the
//! database encrypted under the recovery passphrase. Import on another host decrypts it, re-wraps
//! the master key for that host, and swaps the database in while running. Users, servers,
//! assignments, saved credentials and sign-in sessions all carry over.

use crate::app::{App, META_FROZEN};
use crate::store::{now, Counts, Store, StoreError, SCHEMA_VERSION};
use crate::vault::{self, Vault, VaultError};
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

pub const FORMAT: u32 = 1;
const AAD_EXPORT: &[u8] = b"web-access export v1";
const MANIFEST: &str = "manifest.json";
const DATA: &str = "data.db.enc";
/// How long an uploaded archive waits for its confirmation.
const PENDING_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub format: u32,
    pub schema: i64,
    pub source_host: String,
    pub exported_at: i64,
    pub data_sha256: String,
    pub counts: Counts,
}

pub struct PendingImport {
    pub blob: Vec<u8>,
    pub uploaded: Instant,
}

#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    #[error("set a recovery passphrase before exporting")]
    NoRecovery,
    #[error("the passphrase is not correct")]
    WrongPassphrase,
    #[error("not a web-access export: {0}")]
    BadArchive(String),
    #[error("this export is from a newer version (schema {0}); upgrade this proxy first")]
    Newer(i64),
    #[error("{0}")]
    Confirm(String),
    #[error("that upload has expired; upload the file again")]
    Expired,
    #[error("the imported database failed its integrity check: {0}")]
    Integrity(String),
    #[error(transparent)]
    Vault(VaultError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<VaultError> for MigrateError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::WrongPassphrase => MigrateError::WrongPassphrase,
            VaultError::NoRecovery => MigrateError::NoRecovery,
            other => MigrateError::Vault(other),
        }
    }
}

pub type Result<T> = std::result::Result<T, MigrateError>;

pub struct Export {
    pub file_name: String,
    pub bytes: Vec<u8>,
    pub manifest: Manifest,
}

/// Removes a temporary file however the function holding it returns.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_path(dir: &Path, prefix: &str) -> PathBuf {
    dir.join(format!("{prefix}-{}.tmp", &crate::auth::random_token()[..16]))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// (year, month, day, hour, minute, second) in UTC from unix seconds.
fn utc_parts(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

/// `20260923T231500Z` from unix seconds.
pub fn utc_stamp(secs: i64) -> String {
    let (y, m, d, h, mi, s) = utc_parts(secs);
    format!("{y:04}{m:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// Snapshot, encrypt and package. The passphrase must open this database's recovery wrap, so an
/// export cannot be made under a passphrase nobody can later import with.
pub fn export(app: &App, passphrase: &str) -> Result<Export> {
    Vault::verify_recovery(&app.store, passphrase)?;
    let (db, counts) = snapshot(app)?;
    package(app, passphrase, &db, counts)
}

/// A consistent copy of the whole database, and what it holds.
pub fn snapshot(app: &App) -> Result<(Vec<u8>, Counts)> {
    let tmp = TempFile(temp_path(&app.cfg.data_dir(), "export"));
    let counts = app.store.snapshot_to(&tmp.0)?;
    let db = std::fs::read(&tmp.0)?;
    Ok((db, counts))
}

/// Encrypt a snapshot under the passphrase and wrap it with its manifest.
pub fn package(app: &App, passphrase: &str, db: &[u8], counts: Counts) -> Result<Export> {
    let blob = vault::encrypt_with_passphrase(passphrase, AAD_EXPORT, db)?;
    let exported_at = now();
    let manifest = Manifest {
        format: FORMAT,
        schema: SCHEMA_VERSION,
        source_host: app.host_name.clone(),
        exported_at,
        data_sha256: hex(digest(&SHA256, &blob).as_ref()),
        counts,
    };
    let bytes = build_zip(&manifest, &blob)?;
    Ok(Export {
        file_name: format!(
            "web-access-export-{}-{}.zip",
            app.host_name,
            utc_stamp(exported_at)
        ),
        bytes,
        manifest,
    })
}

pub fn build_zip(manifest: &Manifest, blob: &[u8]) -> Result<Vec<u8>> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let (y, mo, d, h, mi, s) = utc_parts(manifest.exported_at);
    let mut options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    if let Ok(t) = zip::DateTime::from_date_and_time(y as u16, mo as u8, d as u8, h as u8, mi as u8, s as u8) {
        options = options.last_modified_time(t);
    }
    let json = serde_json::to_vec_pretty(manifest)
        .map_err(|e| MigrateError::BadArchive(e.to_string()))?;
    let bad = |e: zip::result::ZipError| MigrateError::BadArchive(e.to_string());
    zip.start_file(MANIFEST, options).map_err(bad)?;
    zip.write_all(&json)?;
    zip.start_file(DATA, options).map_err(bad)?;
    zip.write_all(blob)?;
    Ok(zip.finish().map_err(bad)?.into_inner())
}

/// Open an archive and check everything that can be checked without the passphrase.
pub fn read_zip(bytes: &[u8]) -> Result<(Manifest, Vec<u8>)> {
    let bad = |e: zip::result::ZipError| MigrateError::BadArchive(e.to_string());
    let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(bad)?;
    let mut read = |name: &str| -> Result<Vec<u8>> {
        let mut entry = archive
            .by_name(name)
            .map_err(|_| MigrateError::BadArchive(format!("{name} is missing")))?;
        let mut out = Vec::new();
        entry.read_to_end(&mut out)?;
        Ok(out)
    };
    let manifest: Manifest = serde_json::from_slice(&read(MANIFEST)?)
        .map_err(|e| MigrateError::BadArchive(format!("{MANIFEST}: {e}")))?;
    let blob = read(DATA)?;
    if manifest.format != FORMAT {
        return Err(MigrateError::BadArchive(format!(
            "format {} is not {FORMAT}",
            manifest.format
        )));
    }
    if manifest.schema > SCHEMA_VERSION {
        return Err(MigrateError::Newer(manifest.schema));
    }
    if hex(digest(&SHA256, &blob).as_ref()) != manifest.data_sha256 {
        return Err(MigrateError::BadArchive(
            "the data does not match its checksum; the file is damaged or was altered".into(),
        ));
    }
    Ok((manifest, blob))
}

/// Whether an import here would replace something. A fresh host holds exactly one user, the
/// administrator who signed in to run the import, and no servers.
pub fn holds_data(c: &Counts) -> bool {
    c.servers > 0 || c.users > 1
}

/// Hold an uploaded archive until an administrator confirms it.
pub fn stage(app: &App, bytes: &[u8]) -> Result<(String, Manifest)> {
    let (manifest, blob) = read_zip(bytes)?;
    let id = crate::auth::random_token();
    let mut pending = app.imports.lock().unwrap_or_else(|p| p.into_inner());
    pending.retain(|_, p| p.uploaded.elapsed() < PENDING_TTL);
    pending.insert(
        id.clone(),
        PendingImport {
            blob,
            uploaded: Instant::now(),
        },
    );
    Ok((id, manifest))
}

/// Apply a staged archive. A host that already holds data needs its own name typed as confirmation.
pub fn confirm(
    app: &App,
    upload_id: &str,
    passphrase: &str,
    confirm_host: Option<&str>,
) -> Result<Counts> {
    // The upload stays staged until an import succeeds, so a mistyped passphrase or host name
    // costs a retype, not a re-upload.
    let blob = app
        .imports
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(upload_id)
        .filter(|p| p.uploaded.elapsed() < PENDING_TTL)
        .map(|p| p.blob.clone())
        .ok_or(MigrateError::Expired)?;
    let current = app.store.counts()?;
    let confirmed = confirm_host
        .map(|h| h.trim().eq_ignore_ascii_case(&app.host_name))
        .unwrap_or(false);
    if holds_data(&current) && !confirmed {
        return Err(MigrateError::Confirm(format!(
            "this proxy already holds {} user(s) and {} server(s); type its name, {}, to replace them",
            current.users, current.servers, app.host_name
        )));
    }
    let counts = apply(app, &blob, passphrase)?;
    app.imports
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(upload_id);
    Ok(counts)
}

/// Decrypt, validate, back up the current database, and swap the import in.
pub fn apply(app: &App, blob: &[u8], passphrase: &str) -> Result<Counts> {
    let db = vault::decrypt_with_passphrase(passphrase, AAD_EXPORT, blob)?;
    let dir = app.cfg.data_dir();
    let staged_path = temp_path(&dir, "import");
    let guard = TempFile(staged_path.clone());
    std::fs::write(&staged_path, &db)?;

    let (key, counts) = {
        // Opening migrates an older schema forward.
        let staged = Store::open(&staged_path)?;
        if let Err(problem) = staged.integrity() {
            return Err(MigrateError::Integrity(problem));
        }
        let key = app.vault.adopt(&staged, passphrase)?;
        staged.set_flag(META_FROZEN, false)?;
        (key, staged.counts()?)
    };

    let backup = dir.join(format!("backup-{}.db", utc_stamp(now())));
    app.store.snapshot_to(&backup)?;
    app.store.replace_with(&staged_path)?;
    std::mem::forget(guard); // renamed into place; nothing left to remove
    app.vault.install(key);
    app.tickets.clear();
    // Connections were admitted against identities the imported database may give to someone else.
    app.live.end_all();
    tracing::info!(backup = %backup.display(), ?counts, "database imported");
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_stamps_are_correct() {
        assert_eq!(utc_stamp(0), "19700101T000000Z");
        assert_eq!(utc_stamp(1_790_291_700), "20260924T231500Z");
        assert_eq!(utc_stamp(951_782_400), "20000229T000000Z");
    }

    fn manifest_for(blob: &[u8]) -> Manifest {
        Manifest {
            format: FORMAT,
            schema: SCHEMA_VERSION,
            source_host: "old".into(),
            exported_at: 1,
            data_sha256: hex(digest(&SHA256, blob).as_ref()),
            counts: Counts::default(),
        }
    }

    #[test]
    fn an_archive_round_trips() {
        let blob = b"ciphertext".to_vec();
        let zip = build_zip(&manifest_for(&blob), &blob).unwrap();
        let (m, b) = read_zip(&zip).unwrap();
        assert_eq!(b, blob);
        assert_eq!(m.source_host, "old");
    }

    #[test]
    fn altered_data_is_refused() {
        let blob = b"ciphertext".to_vec();
        let zip = build_zip(&manifest_for(&blob), b"ciphertexT").unwrap();
        assert!(matches!(read_zip(&zip), Err(MigrateError::BadArchive(_))));
    }

    #[test]
    fn a_newer_schema_is_refused() {
        let blob = b"x".to_vec();
        let mut m = manifest_for(&blob);
        m.schema = SCHEMA_VERSION + 1;
        let zip = build_zip(&m, &blob).unwrap();
        assert!(matches!(read_zip(&zip), Err(MigrateError::Newer(_))));
    }

    #[test]
    fn a_non_zip_is_refused() {
        assert!(matches!(read_zip(b"not a zip"), Err(MigrateError::BadArchive(_))));
    }

    use crate::web::tests::{call, signed_in, test_app_keyed};
    use axum::http::StatusCode;
    use serde_json::json;

    const PASS: &str = "cutover passphrase";

    /// The cutover drill: everything a user has on the old host works on the new one, including the
    /// sign-in session they already hold and a password saved under the old host's key.
    #[tokio::test]
    async fn an_export_imports_on_another_host_with_everything_intact() {
        let old = test_app_keyed([1; 32], "oldhost");
        let new = test_app_keyed([2; 32], "newhost");

        let (uid, cookie) = signed_in(&old, "jdoe");
        let g = old.store.group_create("Historians").unwrap();
        let s = old.store.server_create("hist-01", "hist-01.example", 3389, Some(g)).unwrap();
        old.store.set_assignments(uid, &[s]).unwrap();
        old.vault.set_recovery(&old.store, None, PASS).unwrap();
        let (st, _) = call(&old, "PUT", &format!("/api/credentials/{s}"), Some(&cookie),
            Some(json!({"username": "ops", "password": "p@ss"}))).await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        // Frozen before the snapshot, as a console export may be: the import must not arrive frozen.
        old.store.set_flag(META_FROZEN, true).unwrap();

        assert!(matches!(export(&old, "not the passphrase"), Err(MigrateError::WrongPassphrase)));
        let exported = export(&old, PASS).unwrap();
        assert_eq!(exported.manifest.counts.credentials, 1);
        assert!(exported.file_name.starts_with("web-access-export-oldhost-"));

        let (upload, manifest) = stage(&new, &exported.bytes).unwrap();
        assert_eq!(manifest.counts.users, 1);
        assert!(matches!(confirm(&new, &upload, "not the passphrase", None), Err(MigrateError::WrongPassphrase)));
        // Still staged after a wrong passphrase.
        let counts = confirm(&new, &upload, PASS, None).unwrap();
        assert_eq!(counts.servers, 1);
        assert!(!new.frozen());

        // The old session cookie is honoured on the new host.
        let (st, me) = call(&new, "GET", "/api/me", Some(&cookie), None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(me["username"], "jdoe");
        // And the password saved under the old host's key opens under the new one.
        let (st, v) = call(&new, "POST", "/api/connect", Some(&cookie), Some(json!({"server": s}))).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["credential"]["password"], "p@ss");
        // The staged upload is gone once used.
        assert!(matches!(confirm(&new, &upload, PASS, None), Err(MigrateError::Expired)));
    }

    #[tokio::test]
    async fn importing_over_existing_data_needs_the_host_name() {
        let old = test_app_keyed([1; 32], "oldhost");
        let new = test_app_keyed([2; 32], "newhost");
        old.vault.set_recovery(&old.store, None, PASS).unwrap();
        old.store.user_create("jdoe", None).unwrap();
        new.store.server_create("existing", "e.example", 3389, None).unwrap();

        let exported = export(&old, PASS).unwrap();
        let (upload, _) = stage(&new, &exported.bytes).unwrap();
        assert!(matches!(confirm(&new, &upload, PASS, None), Err(MigrateError::Confirm(_))));
        assert!(matches!(confirm(&new, &upload, PASS, Some("oldhost")), Err(MigrateError::Confirm(_))));
        confirm(&new, &upload, PASS, Some("NewHost")).unwrap();
        assert!(new.store.user_by_name("jdoe").unwrap().is_some());
        let backups = std::fs::read_dir(new.cfg.data_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("backup-"))
            .count();
        assert_eq!(backups, 1, "the replaced database is kept");
    }

    #[tokio::test]
    async fn a_tampered_export_changes_nothing() {
        let old = test_app_keyed([1; 32], "oldhost");
        let new = test_app_keyed([2; 32], "newhost");
        old.vault.set_recovery(&old.store, None, PASS).unwrap();
        old.store.user_create("jdoe", None).unwrap();
        let exported = export(&old, PASS).unwrap();
        let (manifest, mut blob) = read_zip(&exported.bytes).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        // Re-packed with a matching checksum, so only the encryption can notice.
        let forged = Manifest { data_sha256: hex(digest(&SHA256, &blob).as_ref()), ..manifest };
        let zip = build_zip(&forged, &blob).unwrap();
        let (upload, _) = stage(&new, &zip).unwrap();
        // Refused by the authenticated decryption itself, not by some later check.
        assert!(matches!(confirm(&new, &upload, PASS, None), Err(MigrateError::WrongPassphrase)));
        assert_eq!(new.store.counts().unwrap(), Counts::default());
    }
}
