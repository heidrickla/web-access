//! Export and import of the whole database, for moving to new hardware and for backups.
//!
//! An export is a zip holding `manifest.json` and `data.db.enc`: a consistent snapshot of the
//! database encrypted under the recovery passphrase. Import on another host decrypts it, re-wraps
//! the master key for that host, and swaps the database in while running. Users, servers,
//! assignments, saved credentials and sign-in sessions all carry over.

use crate::app::{App, META_FREEZE_PENDING, META_FROZEN};
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
/// Uploads held at once. Each is a whole database in memory; the oldest gives way.
const MAX_PENDING: usize = 2;

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
    dir.join(format!(
        "{prefix}-{}.tmp",
        &crate::auth::random_token()[..16]
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// (year, month, day, hour, minute, second) in UTC from unix seconds.
pub fn utc_parts(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
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

/// Snapshot, encrypt and package.
pub fn export(app: &App, passphrase: &str) -> Result<Export> {
    let (db, counts) = snapshot_verified(app, passphrase)?;
    package(app, passphrase, &db, counts)
}

/// A consistent copy of the whole database, and what it holds. The passphrase must open the
/// recovery wrap IN THE COPY, the one the import will use, so a passphrase changed since it was
/// last checked cannot produce an export nobody can import.
pub fn snapshot_verified(app: &App, passphrase: &str) -> Result<(Vec<u8>, Counts)> {
    let tmp = TempFile(temp_path(&app.cfg.data_dir(), "export"));
    let counts = app.store.snapshot_to(&tmp.0)?;
    Vault::verify_recovery(&Store::open(&tmp.0)?, passphrase)?;
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
    if let Ok(t) =
        zip::DateTime::from_date_and_time(y as u16, mo as u8, d as u8, h as u8, mi as u8, s as u8)
    {
        options = options.last_modified_time(t);
    }
    let json =
        serde_json::to_vec_pretty(manifest).map_err(|e| MigrateError::BadArchive(e.to_string()))?;
    let bad = |e: zip::result::ZipError| MigrateError::BadArchive(e.to_string());
    zip.start_file(MANIFEST, options).map_err(bad)?;
    zip.write_all(&json)?;
    zip.start_file(DATA, options).map_err(bad)?;
    zip.write_all(blob)?;
    Ok(zip.finish().map_err(bad)?.into_inner())
}

/// Open an archive and check everything that can be checked without the passphrase.
pub fn read_zip(bytes: &[u8]) -> Result<(Manifest, Vec<u8>)> {
    // A truncated file has no central directory, which is where this fails.
    let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(|e| {
        MigrateError::BadArchive(format!(
            "this is not a complete export; the file is damaged or incomplete: {e}"
        ))
    })?;
    let mut read = |name: &str| -> Result<Vec<u8>> {
        let mut entry = archive
            .by_name(name)
            .map_err(|_| MigrateError::BadArchive(format!("{name} is missing")))?;
        let mut out = Vec::new();
        // A damaged copy fails zip's own checksum here, before the SHA-256 below.
        entry.read_to_end(&mut out).map_err(|e| {
            MigrateError::BadArchive(format!(
                "{name} could not be read; the file is damaged or incomplete: {e}"
            ))
        })?;
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
    while pending.len() >= MAX_PENDING {
        let Some(oldest) = pending
            .iter()
            .min_by_key(|(_, p)| p.uploaded)
            .map(|(id, _)| id.clone())
        else {
            break;
        };
        pending.remove(&oldest);
    }
    pending.insert(
        id.clone(),
        PendingImport {
            blob,
            uploaded: Instant::now(),
        },
    );
    Ok((id, manifest))
}

/// Drop uploads whose confirmation window has passed at `at`; the number dropped.
pub fn sweep_pending(app: &App, at: Instant) -> usize {
    let mut pending = app.imports.lock().unwrap_or_else(|p| p.into_inner());
    let before = pending.len();
    pending.retain(|_, p| at.saturating_duration_since(p.uploaded) < PENDING_TTL);
    before - pending.len()
}

/// Drop an upload an administrator cancelled. Whether it was held.
pub fn cancel(app: &App, upload_id: &str) -> bool {
    app.imports
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(upload_id)
        .is_some()
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

/// Import backups kept in the data directory; older ones are deleted by the next import.
pub const KEEP_BACKUPS: usize = 5;

/// Keep the newest `keep` import backups (`backup-<stamp>.db`) in `dir` and delete the rest. The
/// stamp sorts in time order. Copies kept before a schema migration are named differently and are
/// left alone.
pub fn prune_backups(dir: &Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut backups: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("backup-2") && n.ends_with(".db"))
        })
        .collect();
    backups.sort();
    let excess = backups.len().saturating_sub(keep);
    for old in &backups[..excess] {
        match std::fs::remove_file(old) {
            Ok(()) => tracing::info!(removed = %old.display(), "deleted an old import backup"),
            Err(e) => {
                tracing::warn!(file = %old.display(), error = %e, "could not delete an old import backup")
            }
        }
    }
}

/// Delete temporary files an export or import left behind when a process stopped partway: at
/// service start, and only files older than `min_age`, so a command-line export running meanwhile
/// keeps its own.
pub fn sweep_temp_files(dir: &Path, min_age: std::time::Duration) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for path in entries.filter_map(|e| e.ok().map(|e| e.path())) {
        // With the SQLite files a crash can leave beside an open temporary database.
        let named = path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
            (n.starts_with("export-") || n.starts_with("import-"))
                && [".tmp", ".tmp-wal", ".tmp-shm", ".tmp-journal"]
                    .iter()
                    .any(|end| n.ends_with(end))
        });
        let old = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= min_age);
        if named && old && std::fs::remove_file(&path).is_ok() {
            tracing::info!(removed = %path.display(), "deleted a temporary file left by an interrupted export or import");
        }
    }
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
        staged.set_flag(META_FREEZE_PENDING, false)?;
        // Pages loaded before the import name rows by the ids they had then.
        crate::app::new_instance(&staged)?;
        (key, staged.counts()?)
    };

    let backup = dir.join(format!("backup-{}.db", utc_stamp(now())));
    app.store.snapshot_to(&backup)?;
    if let Err(e) = app.store.replace_with(&staged_path) {
        // Refused: this attempt's copy goes, and the older backups stay, however often it is tried.
        let _ = std::fs::remove_file(&backup);
        return Err(e.into());
    }
    prune_backups(&dir, KEEP_BACKUPS);
    std::mem::forget(guard); // renamed into place; nothing left to remove
    app.bump_generation();
    app.vault.install(key);
    app.tickets.clear();
    // Connections were admitted against identities the imported database may give to someone else.
    app.live.end_all();
    tracing::info!(backup = %backup.display(), ?counts, "database imported");
    Ok(counts)
}

/// A manifest that matches `blob`, for tests elsewhere that need a readable archive.
#[cfg(test)]
pub fn test_manifest(blob: &[u8]) -> Manifest {
    Manifest {
        format: FORMAT,
        schema: SCHEMA_VERSION,
        source_host: "old".into(),
        exported_at: 1,
        data_sha256: hex(digest(&SHA256, blob).as_ref()),
        counts: Counts::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uploads_held_are_capped_cancellable_and_swept() {
        let app = crate::web::tests::test_app();
        let zip = build_zip(&test_manifest(b"blob"), b"blob").unwrap();
        let held = |app: &App| app.imports.lock().unwrap().len();
        let (first, _) = stage(&app, &zip).unwrap();
        let (second, _) = stage(&app, &zip).unwrap();
        let (third, _) = stage(&app, &zip).unwrap();
        assert_eq!(held(&app), MAX_PENDING);
        assert!(
            !app.imports.lock().unwrap().contains_key(&first),
            "the oldest was kept"
        );
        assert!(cancel(&app, &second));
        assert!(!cancel(&app, &second));
        assert_eq!(sweep_pending(&app, Instant::now()), 0);
        let later = Instant::now() + PENDING_TTL + Duration::from_secs(1);
        assert_eq!(sweep_pending(&app, later), 1);
        assert!(!app.imports.lock().unwrap().contains_key(&third));
    }

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
        assert!(matches!(
            read_zip(b"not a zip"),
            Err(MigrateError::BadArchive(_))
        ));
    }

    /// A truncated copy and a copy with a flipped byte are both reported as damaged, never as a
    /// server fault.
    #[test]
    fn a_damaged_copy_is_reported_as_damaged() {
        let blob = vec![7u8; 4096];
        let zip = build_zip(&manifest_for(&blob), &blob).unwrap();
        let truncated = &zip[..zip.len() - 40];
        assert!(matches!(
            read_zip(truncated),
            Err(MigrateError::BadArchive(_))
        ));
        let mut flipped = zip.clone();
        // Inside the stored data, which zip's own checksum covers.
        let at = zip.windows(64).position(|w| w == &blob[..64]).unwrap() + 100;
        flipped[at] ^= 0xff;
        assert!(matches!(
            read_zip(&flipped),
            Err(MigrateError::BadArchive(_))
        ));
    }

    /// Only the newest import backups stay; copies kept before a schema migration and other files
    /// are left alone.
    #[test]
    fn old_import_backups_are_pruned() {
        let dir = std::env::temp_dir().join(format!(
            "web-access-prune-{}",
            &crate::auth::random_token()[..12]
        ));
        std::fs::create_dir_all(&dir).unwrap();
        for day in 1..=7 {
            std::fs::write(dir.join(format!("backup-202609{day:02}T000000Z.db")), b"x").unwrap();
        }
        std::fs::write(dir.join("backup-schema3-20260901T000000Z.db"), b"x").unwrap();
        std::fs::write(dir.join("web-access.db"), b"x").unwrap();
        prune_backups(&dir, 5);
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "backup-20260903T000000Z.db",
                "backup-20260904T000000Z.db",
                "backup-20260905T000000Z.db",
                "backup-20260906T000000Z.db",
                "backup-20260907T000000Z.db",
                "backup-schema3-20260901T000000Z.db",
                "web-access.db",
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Leftover temporary files go at service start, but not one younger than the cut-off, which a
    /// command-line export may still be writing.
    #[test]
    fn stale_temporary_files_are_swept_and_fresh_ones_kept() {
        let dir = std::env::temp_dir().join(format!(
            "web-access-sweep-{}",
            &crate::auth::random_token()[..12]
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("export-abc.tmp"), b"x").unwrap();
        std::fs::write(dir.join("import-def.tmp"), b"x").unwrap();
        std::fs::write(dir.join("import-def.tmp-wal"), b"x").unwrap();
        std::fs::write(dir.join("import-def.tmp-shm"), b"x").unwrap();
        std::fs::write(dir.join("other.tmp"), b"x").unwrap();
        sweep_temp_files(&dir, std::time::Duration::from_secs(3600));
        assert!(
            dir.join("export-abc.tmp").exists(),
            "a fresh temp file was swept"
        );
        sweep_temp_files(&dir, std::time::Duration::ZERO);
        assert!(!dir.join("export-abc.tmp").exists());
        assert!(!dir.join("import-def.tmp").exists());
        assert!(!dir.join("import-def.tmp-wal").exists());
        assert!(!dir.join("import-def.tmp-shm").exists());
        assert!(
            dir.join("other.tmp").exists(),
            "an unrelated file was swept"
        );
        let _ = std::fs::remove_dir_all(&dir);
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
        let s = old
            .store
            .server_create("hist-01", "hist-01.example", 3389, Some(g), None)
            .unwrap();
        old.store.set_assignments(uid, &[s]).unwrap();
        old.vault.set_recovery(&old.store, None, PASS).unwrap();
        let (st, _) = call(
            &old,
            "PUT",
            &format!("/api/credentials/{s}"),
            Some(&cookie),
            Some(json!({"username": "ops", "password": "p@ss"})),
        )
        .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        // Frozen before the snapshot, as a console export may be: the import must not arrive frozen.
        old.store.set_flag(META_FROZEN, true).unwrap();

        assert!(matches!(
            export(&old, "not the passphrase"),
            Err(MigrateError::WrongPassphrase)
        ));
        let exported = export(&old, PASS).unwrap();
        assert_eq!(exported.manifest.counts.credentials, 1);
        assert!(exported.file_name.starts_with("web-access-export-oldhost-"));

        let (upload, manifest) = stage(&new, &exported.bytes).unwrap();
        assert_eq!(manifest.counts.users, 1);
        assert!(matches!(
            confirm(&new, &upload, "not the passphrase", None),
            Err(MigrateError::WrongPassphrase)
        ));
        // Still staged after a wrong passphrase.
        let counts = confirm(&new, &upload, PASS, None).unwrap();
        assert_eq!(counts.servers, 1);
        assert!(!new.frozen());

        // The old session cookie is honoured on the new host.
        let (st, me) = call(&new, "GET", "/api/me", Some(&cookie), None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(me["username"], "jdoe");
        // And the password saved under the old host's key opens under the new one.
        let (st, v) = call(
            &new,
            "POST",
            "/api/connect",
            Some(&cookie),
            Some(json!({"server": s})),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["credential"]["password"], "p@ss");
        // The staged upload is gone once used.
        assert!(matches!(
            confirm(&new, &upload, PASS, None),
            Err(MigrateError::Expired)
        ));
    }

    /// The passphrase is checked against the recovery wrap inside the snapshot, the one an import
    /// will need, not against whatever the live database held when the export was asked for.
    #[tokio::test]
    async fn an_export_is_checked_against_the_wrap_in_its_own_snapshot() {
        let app = test_app_keyed([1; 32], "oldhost");
        app.vault.set_recovery(&app.store, None, PASS).unwrap();
        app.vault
            .set_recovery(&app.store, Some(PASS), "a changed recovery phrase")
            .unwrap();
        assert!(matches!(
            snapshot_verified(&app, PASS),
            Err(MigrateError::WrongPassphrase)
        ));
        let (db, _) = snapshot_verified(&app, "a changed recovery phrase").unwrap();
        assert!(!db.is_empty());
    }

    /// Restoring a host's own export gives it a new instance: pages loaded in between named rows
    /// that the restore may give to others.
    #[tokio::test]
    async fn an_import_gives_the_database_a_new_instance_even_when_restoring_its_own_export() {
        let app = test_app_keyed([1; 32], "samehost");
        app.vault.set_recovery(&app.store, None, PASS).unwrap();
        app.store.user_create("jdoe", None).unwrap();
        let exported = export(&app, PASS).unwrap();
        let before = app.instance();
        assert!(!before.is_empty());
        let (upload, _) = stage(&app, &exported.bytes).unwrap();
        confirm(&app, &upload, PASS, Some("samehost")).unwrap();
        assert_ne!(
            app.instance(),
            before,
            "the restore kept the instance pages loaded before it carry"
        );
        assert!(!app.instance().is_empty());
    }

    /// A swap refused because another process holds the database leaves no copy of its own and
    /// prunes nothing: repeated refusals must not push out the backup of an earlier import.
    #[tokio::test]
    async fn a_refused_swap_keeps_the_earlier_backups() {
        let old = test_app_keyed([1; 32], "oldhost");
        let new = test_app_keyed([2; 32], "newhost");
        old.vault.set_recovery(&old.store, None, PASS).unwrap();
        old.store.user_create("jdoe", None).unwrap();
        let dir = new.cfg.data_dir();
        for day in 1..=KEEP_BACKUPS {
            std::fs::write(dir.join(format!("backup-202609{day:02}T000000Z.db")), b"x").unwrap();
        }
        let backups = || {
            let mut names: Vec<String> = std::fs::read_dir(&dir)
                .unwrap()
                .filter_map(|e| e.ok()?.file_name().into_string().ok())
                .filter(|n| n.starts_with("backup-2"))
                .collect();
            names.sort();
            names
        };
        let before = backups();
        let exported = export(&old, PASS).unwrap();
        let (upload, _) = stage(&new, &exported.bytes).unwrap();
        let elsewhere = rusqlite::Connection::open(new.cfg.database_path()).unwrap();
        let _: i64 = elsewhere
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
            .unwrap();
        for _ in 0..2 {
            assert!(confirm(&new, &upload, PASS, Some("newhost")).is_err());
        }
        assert_eq!(backups(), before, "a refused swap changed the backups");
        drop(elsewhere);
    }

    #[tokio::test]
    async fn importing_over_existing_data_needs_the_host_name() {
        let old = test_app_keyed([1; 32], "oldhost");
        let new = test_app_keyed([2; 32], "newhost");
        old.vault.set_recovery(&old.store, None, PASS).unwrap();
        old.store.user_create("jdoe", None).unwrap();
        new.store
            .server_create("existing", "e.example", 3389, None, None)
            .unwrap();

        let exported = export(&old, PASS).unwrap();
        let (upload, _) = stage(&new, &exported.bytes).unwrap();
        assert!(matches!(
            confirm(&new, &upload, PASS, None),
            Err(MigrateError::Confirm(_))
        ));
        assert!(matches!(
            confirm(&new, &upload, PASS, Some("oldhost")),
            Err(MigrateError::Confirm(_))
        ));
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
        let forged = Manifest {
            data_sha256: hex(digest(&SHA256, &blob).as_ref()),
            ..manifest
        };
        let zip = build_zip(&forged, &blob).unwrap();
        let (upload, _) = stage(&new, &zip).unwrap();
        // Refused by the authenticated decryption itself, not by some later check.
        assert!(matches!(
            confirm(&new, &upload, PASS, None),
            Err(MigrateError::WrongPassphrase)
        ));
        assert_eq!(new.store.counts().unwrap(), Counts::default());
    }
}
