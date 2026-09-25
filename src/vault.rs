//! Encryption of saved credentials.
//!
//! One 256-bit master key encrypts every saved password with AES-256-GCM. The master key is stored
//! twice in the database:
//!
//! | Wrap     | Under                                   | Used for                              |
//! |----------|-----------------------------------------|---------------------------------------|
//! | local    | DPAPI, machine scope (key file off Windows) | unattended start on this host     |
//! | recovery | Argon2id of an administrator's passphrase   | moving the database to another host |
//!
//! A database opened on a host whose local wrap does not match (it was copied from elsewhere) starts
//! LOCKED: nothing saved can be read or written until an administrator unlocks it with the recovery
//! passphrase, which re-wraps the key for this host.

use crate::store::{Store, StoreError};
use argon2::{Algorithm, Argon2, Params, Version};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use std::path::Path;
use std::sync::RwLock;

pub const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const FORMAT: u8 = 1;
const MIN_PASSPHRASE: usize = 12;

const META_LOCAL: &str = "master_local";
const META_RECOVERY: &str = "master_recovery";
#[cfg(any(not(windows), test))]
const AAD_LOCAL: &[u8] = b"web-access local wrap v1";
const AAD_RECOVERY: &[u8] = b"web-access recovery wrap v1";

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("the credential store is locked; an administrator must unlock it with the recovery passphrase")]
    Locked,
    #[error("the passphrase is not correct")]
    WrongPassphrase,
    #[error("no recovery passphrase has been set")]
    NoRecovery,
    #[error("the passphrase must be at least {MIN_PASSPHRASE} characters")]
    Weak,
    #[error("decryption failed")]
    Crypto,
    #[error("key protection: {0}")]
    Protect(String),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;

/// Wraps key material for this host only.
pub trait KeyProtector: Send + Sync {
    fn protect(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>>;
}

/// DPAPI on Windows; a key file in `data_dir` elsewhere.
pub fn local_protector(data_dir: &Path) -> Result<Box<dyn KeyProtector>> {
    #[cfg(windows)]
    {
        let _ = data_dir;
        Ok(Box::new(dpapi::Dpapi))
    }
    #[cfg(not(windows))]
    {
        Ok(Box::new(KeyFile::load_or_create(
            &data_dir.join("local.key"),
        )?))
    }
}

/// A random key kept in a file. The protector off Windows, and in tests.
#[cfg(any(not(windows), test))]
pub struct KeyFile {
    key: [u8; KEY_LEN],
}

#[cfg(any(not(windows), test))]
impl KeyFile {
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) if bytes.len() == KEY_LEN => {
                let mut key = [0u8; KEY_LEN];
                key.copy_from_slice(&bytes);
                Ok(Self { key })
            }
            Ok(_) => Err(VaultError::Protect(format!(
                "{} is not a {KEY_LEN}-byte key",
                path.display()
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = random_key()?;
                write_private(path, &key)?;
                Ok(Self { key })
            }
            Err(e) => Err(e.into()),
        }
    }

    #[cfg(test)]
    pub fn from_key(key: [u8; KEY_LEN]) -> Self {
        Self { key }
    }
}

#[cfg(any(not(windows), test))]
impl KeyProtector for KeyFile {
    fn protect(&self, data: &[u8]) -> Result<Vec<u8>> {
        seal_blob(&self.key, AAD_LOCAL, data)
    }
    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>> {
        open_blob(&self.key, AAD_LOCAL, blob)
    }
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    Ok(())
}

#[cfg(all(not(unix), test))]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data)?;
    Ok(())
}

pub struct Vault {
    master: RwLock<Option<[u8; KEY_LEN]>>,
    protector: Box<dyn KeyProtector>,
}

impl Vault {
    /// Load the master key, creating one for a new database.
    pub fn load(store: &Store, protector: Box<dyn KeyProtector>) -> Result<Self> {
        let vault = Self {
            master: RwLock::new(None),
            protector,
        };
        match store.meta_get(META_LOCAL)? {
            Some(blob) => match vault.protector.unprotect(&blob) {
                Ok(key) if key.len() == KEY_LEN => vault.install(to_key(&key)),
                Ok(_) | Err(_) => tracing::warn!(
                    "the credential store's local key does not open on this host; it stays locked until an administrator unlocks it with the recovery passphrase"
                ),
            },
            None if store.meta_get(META_RECOVERY)?.is_some() => tracing::warn!(
                "the credential store has no local key on this host; it stays locked until an administrator unlocks it with the recovery passphrase"
            ),
            None => {
                let key = random_key()?;
                store.meta_set(META_LOCAL, &vault.protector.protect(&key)?)?;
                vault.install(key);
            }
        }
        Ok(vault)
    }

    pub fn install(&self, key: [u8; KEY_LEN]) {
        *self.master.write().unwrap_or_else(|p| p.into_inner()) = Some(key);
    }

    fn key(&self) -> Result<[u8; KEY_LEN]> {
        self.master
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .ok_or(VaultError::Locked)
    }

    pub fn is_unlocked(&self) -> bool {
        self.key().is_ok()
    }

    pub fn recovery_set(store: &Store) -> Result<bool> {
        Ok(store.meta_get(META_RECOVERY)?.is_some())
    }

    /// Encrypt under the master key. Returns (nonce, ciphertext).
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let blob = seal_blob(&self.key()?, aad, plaintext)?;
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        Ok((nonce.to_vec(), ct.to_vec()))
    }

    pub fn open(&self, aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut blob = Vec::with_capacity(nonce.len() + ciphertext.len());
        blob.extend_from_slice(nonce);
        blob.extend_from_slice(ciphertext);
        open_blob(&self.key()?, aad, &blob)
    }

    /// Nonce and ciphertext in one value, for single secrets kept in `meta`.
    pub fn seal_value(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        seal_blob(&self.key()?, aad, plaintext)
    }

    pub fn open_value(&self, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
        open_blob(&self.key()?, aad, blob)
    }

    /// Set the recovery passphrase, or change it. Changing requires the current one. The master key
    /// is re-wrapped; saved credentials are untouched.
    pub fn set_recovery(&self, store: &Store, current: Option<&str>, new: &str) -> Result<()> {
        let key = self.key()?;
        check_strength(new)?;
        if let Some(blob) = store.meta_get(META_RECOVERY)? {
            let current = current.ok_or(VaultError::WrongPassphrase)?;
            if unwrap_recovery(&blob, current)? != key {
                return Err(VaultError::WrongPassphrase);
            }
        }
        store.meta_set(META_RECOVERY, &wrap_recovery(&key, new)?)?;
        Ok(())
    }

    /// Confirm a passphrase opens this database's recovery wrap.
    pub fn verify_recovery(store: &Store, passphrase: &str) -> Result<[u8; KEY_LEN]> {
        let blob = store
            .meta_get(META_RECOVERY)?
            .ok_or(VaultError::NoRecovery)?;
        unwrap_recovery(&blob, passphrase)
    }

    /// Take a database's master key through its recovery wrap and wrap it for this host, in that
    /// database. Returns the key so the caller can `install` it once the database is in place.
    pub fn adopt(&self, store: &Store, passphrase: &str) -> Result<[u8; KEY_LEN]> {
        let key = Self::verify_recovery(store, passphrase)?;
        store.meta_set(META_LOCAL, &self.protector.protect(&key)?)?;
        Ok(key)
    }
}

pub fn check_strength(passphrase: &str) -> Result<()> {
    if passphrase.chars().count() < MIN_PASSPHRASE {
        return Err(VaultError::Weak);
    }
    Ok(())
}

/// A local account's password as `argon2id$<salt hex>$<hash hex>`, the same Argon2id parameters as
/// the recovery passphrase.
pub fn hash_password(password: &str) -> Result<String> {
    let mut salt = [0u8; SALT_LEN];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| VaultError::Protect("the OS random source failed".into()))?;
    let hash = derive(password, &salt)?;
    Ok(format!("argon2id${}${}", hex(&salt), hex(&hash)))
}

/// Compare in constant time. A malformed stored value never verifies.
pub fn verify_password(password: &str, stored: &str) -> bool {
    let mut parts = stored.split('$');
    let (Some("argon2id"), Some(salt), Some(want), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let (Some(salt), Some(want)) = (unhex(salt), unhex(want)) else {
        return false;
    };
    match derive(password, &salt) {
        Ok(got) => {
            got.len() == want.len()
                && got.iter().zip(&want).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
        }
        Err(_) => false,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Associated data binding a saved credential to one user and one server.
pub fn credential_aad(sid: &str, server_id: i64) -> Vec<u8> {
    format!("credential\0{sid}\0{server_id}").into_bytes()
}

pub fn wrap_recovery(key: &[u8; KEY_LEN], passphrase: &str) -> Result<Vec<u8>> {
    encrypt_with_passphrase(passphrase, AAD_RECOVERY, key)
}

pub fn unwrap_recovery(blob: &[u8], passphrase: &str) -> Result<[u8; KEY_LEN]> {
    let key = decrypt_with_passphrase(passphrase, AAD_RECOVERY, blob)?;
    if key.len() != KEY_LEN {
        return Err(VaultError::Crypto);
    }
    Ok(to_key(&key))
}

/// `FORMAT || salt || nonce || ciphertext`, keyed by Argon2id of the passphrase.
pub fn encrypt_with_passphrase(passphrase: &str, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| VaultError::Protect("the OS random source failed".into()))?;
    let kek = derive(passphrase, &salt)?;
    let sealed = seal_blob(&kek, aad, data)?;
    let mut out = Vec::with_capacity(1 + SALT_LEN + sealed.len());
    out.push(FORMAT);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// A wrong passphrase and a tampered blob are indistinguishable by design: both fail the tag.
pub fn decrypt_with_passphrase(passphrase: &str, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 1 + SALT_LEN + NONCE_LEN || blob[0] != FORMAT {
        return Err(VaultError::Crypto);
    }
    let salt = &blob[1..1 + SALT_LEN];
    let kek = derive(passphrase, salt)?;
    open_blob(&kek, aad, &blob[1 + SALT_LEN..]).map_err(|_| VaultError::WrongPassphrase)
}

/// Argon2id, 64 MiB, 3 passes: a fraction of a second here, expensive to guess at scale.
fn derive(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(64 * 1024, 3, 1, Some(KEY_LEN))
        .map_err(|e| VaultError::Protect(e.to_string()))?;
    let mut out = [0u8; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| VaultError::Protect(e.to_string()))?;
    Ok(out)
}

fn random_key() -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| VaultError::Protect("the OS random source failed".into()))?;
    Ok(key)
}

fn to_key(bytes: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&bytes[..KEY_LEN]);
    key
}

/// `nonce || ciphertext+tag` under AES-256-GCM with a fresh random nonce.
fn seal_blob(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let sealing =
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| VaultError::Crypto)?);
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| VaultError::Protect("the OS random source failed".into()))?;
    let mut in_out = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut in_out,
        )
        .map_err(|_| VaultError::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_LEN + in_out.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&in_out);
    Ok(out)
}

fn open_blob(key: &[u8; KEY_LEN], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return Err(VaultError::Crypto);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let opening =
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).map_err(|_| VaultError::Crypto)?);
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| VaultError::Crypto)?;
    let mut in_out = ct.to_vec();
    let plain = opening
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| VaultError::Crypto)?;
    Ok(plain.to_vec())
}

#[cfg(windows)]
mod dpapi {
    //! DPAPI, machine scope: any process on this machine may unwrap, no other machine can. The
    //! service (LocalService) and an administrator's console run the same code, so user scope would
    //! lock one out of what the other wrote. The files themselves are protected by the data
    //! directory's ACL.
    use super::{KeyProtector, Result, VaultError};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE,
        CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    const ENTROPY: &[u8] = b"web-access master key v1";

    pub struct Dpapi;

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        }
    }

    fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        // SAFETY: DPAPI returned a buffer of cbData bytes it allocated with LocalAlloc.
        unsafe {
            let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            LocalFree(out.pbData as _);
            v
        }
    }

    impl KeyProtector for Dpapi {
        fn protect(&self, data: &[u8]) -> Result<Vec<u8>> {
            let input = blob(data);
            let entropy = blob(ENTROPY);
            let mut out = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            // SAFETY: every pointer is to a live local or null where the API permits null.
            let ok = unsafe {
                CryptProtectData(
                    &input,
                    std::ptr::null(),
                    &entropy,
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            };
            if ok == 0 {
                return Err(VaultError::Protect(
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            Ok(take(out))
        }

        fn unprotect(&self, data: &[u8]) -> Result<Vec<u8>> {
            let input = blob(data);
            let entropy = blob(ENTROPY);
            let mut out = CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: std::ptr::null_mut(),
            };
            // SAFETY: as above.
            let ok = unsafe {
                CryptUnprotectData(
                    &input,
                    std::ptr::null_mut(),
                    &entropy,
                    std::ptr::null(),
                    std::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut out,
                )
            };
            if ok == 0 {
                return Err(VaultError::Protect(
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            Ok(take(out))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_with(store: &Store, key: [u8; KEY_LEN]) -> Vault {
        Vault::load(store, Box::new(KeyFile::from_key(key))).unwrap()
    }

    #[test]
    fn a_key_file_is_created_once_reloaded_after_and_refused_when_malformed() {
        let dir = std::env::temp_dir().join(format!("web-access-keyfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("local.key");
        let _ = std::fs::remove_file(&path);

        let first = KeyFile::load_or_create(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap().len(), KEY_LEN);
        let blob = first.protect(b"master").unwrap();
        let again = KeyFile::load_or_create(&path).unwrap();
        assert_eq!(again.unprotect(&blob).unwrap(), b"master");

        std::fs::write(&path, [1u8; 5]).unwrap();
        assert!(KeyFile::load_or_create(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_credential_round_trips_and_is_bound_to_its_user_and_server() {
        let store = Store::open_in_memory().unwrap();
        let v = vault_with(&store, [7; KEY_LEN]);
        let aad = credential_aad("S-1-5-21-1", 4);
        let (nonce, ct) = v.seal(&aad, b"hunter22").unwrap();
        assert_eq!(v.open(&aad, &nonce, &ct).unwrap(), b"hunter22");
        assert!(
            v.open(&credential_aad("S-1-5-21-2", 4), &nonce, &ct)
                .is_err(),
            "other user"
        );
        assert!(
            v.open(&credential_aad("S-1-5-21-1", 5), &nonce, &ct)
                .is_err(),
            "other server"
        );
    }

    #[test]
    fn the_recovery_wrap_round_trips_and_refuses_a_wrong_passphrase() {
        let store = Store::open_in_memory().unwrap();
        let v = vault_with(&store, [7; KEY_LEN]);
        v.set_recovery(&store, None, "correct horse battery")
            .unwrap();
        assert!(Vault::verify_recovery(&store, "correct horse battery").is_ok());
        assert!(matches!(
            Vault::verify_recovery(&store, "wrong passphrase!!"),
            Err(VaultError::WrongPassphrase)
        ));
    }

    #[test]
    fn changing_the_passphrase_needs_the_current_one_and_keeps_credentials_readable() {
        let store = Store::open_in_memory().unwrap();
        let v = vault_with(&store, [7; KEY_LEN]);
        let (nonce, ct) = v.seal(b"a", b"secret").unwrap();
        v.set_recovery(&store, None, "first passphrase").unwrap();
        assert!(v.set_recovery(&store, None, "second passphrase").is_err());
        assert!(v
            .set_recovery(&store, Some("not the first!"), "second passphrase")
            .is_err());
        v.set_recovery(&store, Some("first passphrase"), "second passphrase")
            .unwrap();
        assert!(Vault::verify_recovery(&store, "second passphrase").is_ok());
        assert_eq!(v.open(b"a", &nonce, &ct).unwrap(), b"secret");
    }

    #[test]
    fn a_short_passphrase_is_refused() {
        let store = Store::open_in_memory().unwrap();
        let v = vault_with(&store, [7; KEY_LEN]);
        assert!(matches!(
            v.set_recovery(&store, None, "short"),
            Err(VaultError::Weak)
        ));
    }

    #[test]
    fn a_database_under_another_hosts_key_opens_locked_and_adopt_unlocks_it() {
        let store = Store::open_in_memory().unwrap();
        let first = vault_with(&store, [1; KEY_LEN]);
        let (nonce, ct) = first.seal(b"a", b"secret").unwrap();
        first
            .set_recovery(&store, None, "migration passphrase")
            .unwrap();

        // Same database, different host key: the local wrap does not open.
        let second = vault_with(&store, [2; KEY_LEN]);
        assert!(!second.is_unlocked());
        assert!(matches!(
            second.open(b"a", &nonce, &ct),
            Err(VaultError::Locked)
        ));

        assert!(second.adopt(&store, "wrong passphrase!").is_err());
        let key = second.adopt(&store, "migration passphrase").unwrap();
        second.install(key);
        assert_eq!(second.open(b"a", &nonce, &ct).unwrap(), b"secret");

        // And the re-wrap persisted: a fresh open under the second host's key is unlocked.
        let third = vault_with(&store, [2; KEY_LEN]);
        assert!(third.is_unlocked());
    }

    #[test]
    fn a_local_password_verifies_and_a_wrong_one_does_not() {
        let stored = hash_password("dev account password").unwrap();
        assert!(stored.starts_with("argon2id$"));
        assert!(verify_password("dev account password", &stored));
        assert!(!verify_password("dev account passworD", &stored));
        assert!(!verify_password("", &stored));
        assert_ne!(
            stored,
            hash_password("dev account password").unwrap(),
            "salted"
        );
        assert!(!verify_password("x", "argon2id$zz$00"));
        assert!(!verify_password("x", "plain"));
    }

    #[test]
    fn passphrase_encryption_detects_tampering() {
        let mut blob = encrypt_with_passphrase("export passphrase", b"x", b"data").unwrap();
        assert_eq!(
            decrypt_with_passphrase("export passphrase", b"x", &blob).unwrap(),
            b"data"
        );
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(decrypt_with_passphrase("export passphrase", b"x", &blob).is_err());
    }
}
