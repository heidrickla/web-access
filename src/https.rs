//! The listener's certificate. Read at start, read again when its files change so a renewal
//! needs no restart, and its expiry logged, with a warning each day from `WARN_DAYS` out.

use crate::config::Https;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};
use tracing::{error, info, warn};

/// Days before expiry that the log starts warning.
pub const WARN_DAYS: i64 = 30;
/// How often the files are looked at.
pub const CHECK_EVERY: Duration = Duration::from_secs(60);

/// What identifies one version of the files: modification time and length of each.
type Stamp = [Option<(SystemTime, u64)>; 2];

#[derive(Debug)]
pub struct Certificate {
    files: Https,
    current: RwLock<Arc<CertifiedKey>>,
    not_after: RwLock<i64>,
    stamp: Mutex<Stamp>,
    warned_day: Mutex<i64>,
}

/// A certificate chain and key read from the configured files, and the leaf's notAfter.
fn load(files: &Https) -> Result<(CertifiedKey, i64), String> {
    let cert_pem =
        std::fs::read(&files.cert).map_err(|e| format!("reading {}: {e}", files.cert))?;
    let key_pem = std::fs::read(&files.key).map_err(|e| format!("reading {}: {e}", files.key))?;
    let certs = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", files.cert))?;
    let Some(leaf) = certs.first() else {
        return Err(format!("{} holds no certificate", files.cert));
    };
    let not_after = x509_parser::parse_x509_certificate(leaf)
        .map_err(|e| format!("{}: {e}", files.cert))?
        .1
        .validity()
        .not_after
        .timestamp();
    let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| match e {
        pem::Error::NoItemsFound => format!("{} holds no private key", files.key),
        e => format!("{}: {e}", files.key),
    })?;
    let key = CertifiedKey::from_der(certs, key, &rustls::crypto::ring::default_provider())
        .map_err(|e| format!("{} and {}: {e}", files.cert, files.key))?;
    Ok((key, not_after))
}

fn stamp_of(files: &Https) -> Stamp {
    let one = |path: &str| {
        std::fs::metadata(path)
            .ok()
            .and_then(|m| Some((m.modified().ok()?, m.len())))
    };
    [one(&files.cert), one(&files.key)]
}

/// The day's warning for a certificate ending at `not_after`, or none while it has longer.
pub fn expiry_warning(not_after: i64, now: i64) -> Option<String> {
    let left = (not_after - now).div_euclid(86_400);
    if not_after <= now {
        Some("the HTTPS certificate has expired; browsers refuse the proxy".into())
    } else if left < WARN_DAYS {
        Some(format!(
            "the HTTPS certificate expires in {left} day(s); renew it"
        ))
    } else {
        None
    }
}

impl Certificate {
    pub fn open(files: &Https) -> Result<Arc<Self>, String> {
        let stamp = stamp_of(files);
        let (key, not_after) = load(files)?;
        Ok(Arc::new(Self {
            files: files.clone(),
            current: RwLock::new(Arc::new(key)),
            not_after: RwLock::new(not_after),
            stamp: Mutex::new(stamp),
            warned_day: Mutex::new(i64::MIN),
        }))
    }

    pub fn not_after(&self) -> i64 {
        *self.not_after.read().unwrap_or_else(|p| p.into_inner())
    }

    /// Read the files again if they changed. `Some(Ok(not_after))` when a new certificate is in
    /// use, `Some(Err)` when the new files were refused and the previous certificate kept.
    pub fn reload_if_changed(&self) -> Option<Result<i64, String>> {
        let now = stamp_of(&self.files);
        {
            let mut seen = self.stamp.lock().unwrap_or_else(|p| p.into_inner());
            if *seen == now {
                return None;
            }
            // A half-written file is refused below and read again once it changes once more.
            *seen = now;
        }
        Some(load(&self.files).map(|(key, not_after)| {
            *self.current.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(key);
            *self.not_after.write().unwrap_or_else(|p| p.into_inner()) = not_after;
            not_after
        }))
    }

    /// Log the expiry warning once per day.
    fn warn_if_ending(&self, now: i64) {
        let Some(text) = expiry_warning(self.not_after(), now) else {
            return;
        };
        let day = now.div_euclid(86_400);
        let mut warned = self.warned_day.lock().unwrap_or_else(|p| p.into_inner());
        if *warned != day {
            *warned = day;
            warn!(cert = %self.files.cert, not_after = %crate::migrate::utc_stamp(self.not_after()), "{text}");
        }
    }
}

impl ResolvesServerCert for Certificate {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(
            &self.current.read().unwrap_or_else(|p| p.into_inner()),
        ))
    }
}

pub fn server_config(cert: Arc<Certificate>) -> rustls::ServerConfig {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// Watches the files for the life of the process.
pub async fn watch(cert: Arc<Certificate>) {
    info!(cert = %cert.files.cert, not_after = %crate::migrate::utc_stamp(cert.not_after()), "HTTPS certificate");
    let mut tick = tokio::time::interval(CHECK_EVERY);
    loop {
        tick.tick().await;
        match cert.reload_if_changed() {
            Some(Ok(not_after)) => info!(
                cert = %cert.files.cert,
                not_after = %crate::migrate::utc_stamp(not_after),
                "HTTPS certificate reloaded"
            ),
            Some(Err(e)) => {
                error!(error = %e, "the changed HTTPS certificate was refused; the previous one stays in use")
            }
            None => {}
        }
        cert.warn_if_ending(crate::store::now());
    }
}

/// At most one line a minute for a stream of failed handshakes, carrying how many it stands for.
#[derive(Default)]
pub struct HandshakeLog {
    state: Mutex<(Option<Instant>, u64)>,
}

impl HandshakeLog {
    /// Whether to log this failure now, and how many were left unlogged since the last line.
    pub fn admit(&self, at: Instant) -> Option<u64> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match state.0 {
            Some(last) if at.saturating_duration_since(last) < Duration::from_secs(60) => {
                state.1 += 1;
                None
            }
            _ => {
                let skipped = state.1;
                *state = (Some(at), 0);
                Some(skipped)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");

    fn files_in(dir: &std::path::Path, which: &str) -> Https {
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::copy(format!("{FIX}{which}-cert.pem"), &cert).unwrap();
        std::fs::copy(format!("{FIX}{which}-key.pem"), &key).unwrap();
        Https {
            cert: cert.to_string_lossy().into_owned(),
            key: key.to_string_lossy().into_owned(),
        }
    }

    fn leaf(cert: &Certificate) -> Vec<u8> {
        cert.current.read().unwrap().cert[0].to_vec()
    }

    #[test]
    fn a_renewed_certificate_is_used_without_a_restart_and_a_broken_one_is_refused() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!(
            "web-access-https-{}",
            &crate::auth::random_token()[..12]
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let files = files_in(&dir, "localhost");
        let cert = Certificate::open(&files).unwrap();
        let first = leaf(&cert);
        assert!(cert.reload_if_changed().is_none());

        files_in(&dir, "server");
        assert!(matches!(cert.reload_if_changed(), Some(Ok(_))));
        assert_ne!(leaf(&cert), first, "the renewed certificate is not in use");
        let renewed = leaf(&cert);

        std::fs::write(&files.cert, "not a certificate").unwrap();
        assert!(matches!(cert.reload_if_changed(), Some(Err(_))));
        assert_eq!(
            leaf(&cert),
            renewed,
            "a broken file replaced a working certificate"
        );
    }

    #[test]
    fn expiry_is_warned_from_thirty_days_out() {
        let day = 86_400;
        assert_eq!(expiry_warning(100 * day, 60 * day), None);
        assert!(expiry_warning(100 * day, 71 * day)
            .unwrap()
            .contains("29 day"));
        assert!(expiry_warning(100 * day, 100 * day)
            .unwrap()
            .contains("expired"));
    }

    #[test]
    fn failed_handshakes_are_logged_once_a_minute_with_a_count() {
        let log = HandshakeLog::default();
        let t = Instant::now();
        assert_eq!(log.admit(t), Some(0));
        assert_eq!(log.admit(t + Duration::from_secs(1)), None);
        assert_eq!(log.admit(t + Duration::from_secs(2)), None);
        assert_eq!(log.admit(t + Duration::from_secs(61)), Some(2));
    }
}
