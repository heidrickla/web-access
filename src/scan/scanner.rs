//! A verdict on a file's bytes before the proxy passes them on. Only an explicit `Clean` lets a
//! file through; a scanner that cannot say, takes too long or is not running refuses it.

use crate::config::{Scan, Scanner as Kind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Detected,
    /// No verdict: the scanner failed, is not running, or took too long.
    Unavailable(String),
}

pub trait Scanner: Send + Sync {
    /// For the Settings tab and the log.
    fn describe(&self) -> String;
    /// Blocking; called on a blocking thread.
    fn scan(&self, name: &str, bytes: &[u8]) -> Verdict;
}

/// The scanner the config names, or none when scanning is off.
pub fn from_config(scan: &Scan, data_dir: &Path) -> Option<Arc<dyn Scanner>> {
    match scan.scanner {
        Kind::Off => None,
        Kind::Command => Some(Arc::new(Command {
            argv: scan.command.clone(),
            clean: scan.clean_exit_codes.clone(),
            detected: scan.detected_exit_codes.clone(),
            timeout: Duration::from_secs(scan.timeout_secs),
            staging: staging_dir(data_dir),
        })),
        #[cfg(windows)]
        Kind::Amsi => Some(Arc::new(amsi::Amsi::new())),
        // The config refuses amsi off Windows; a scanner that never answers keeps it closed anyway.
        #[cfg(not(windows))]
        Kind::Amsi => Some(Arc::new(Missing)),
    }
}

/// Where the command scanner's copies go, inside the data directory and its access list.
pub fn staging_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("scan-staging")
}

/// A copy left by a scan that never finished (a crash, a stop) is removed at start.
pub fn clear_staging(data_dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(staging_dir(data_dir)) {
        for e in entries.flatten() {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

#[cfg(not(windows))]
struct Missing;

#[cfg(not(windows))]
impl Scanner for Missing {
    fn describe(&self) -> String {
        "AMSI (not available here)".into()
    }
    fn scan(&self, _: &str, _: &[u8]) -> Verdict {
        Verdict::Unavailable("AMSI needs Windows".into())
    }
}

// AMSI_RESULT values (amsi.h). Anything else, and any failed HRESULT, is no verdict. Outside
// Windows only the tests use them.
#[cfg_attr(not(windows), allow(dead_code))]
const AMSI_RESULT_CLEAN: i32 = 0;
#[cfg_attr(not(windows), allow(dead_code))]
const AMSI_RESULT_NOT_DETECTED: i32 = 1;
#[cfg_attr(not(windows), allow(dead_code))]
const AMSI_RESULT_BLOCKED_BY_ADMIN_START: i32 = 0x4000;
#[cfg_attr(not(windows), allow(dead_code))]
const AMSI_RESULT_BLOCKED_BY_ADMIN_END: i32 = 0x4fff;
#[cfg_attr(not(windows), allow(dead_code))]
const AMSI_RESULT_DETECTED: i32 = 0x8000;

/// What an `AmsiScanBuffer` call said.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn amsi_verdict(hr: i32, result: i32) -> Verdict {
    if hr != 0 {
        return Verdict::Unavailable(format!("AmsiScanBuffer failed with {hr:#010x}"));
    }
    match result {
        AMSI_RESULT_CLEAN | AMSI_RESULT_NOT_DETECTED => Verdict::Clean,
        r if r >= AMSI_RESULT_DETECTED => Verdict::Detected,
        r if (AMSI_RESULT_BLOCKED_BY_ADMIN_START..=AMSI_RESULT_BLOCKED_BY_ADMIN_END)
            .contains(&r) =>
        {
            Verdict::Detected
        }
        r => Verdict::Unavailable(format!("AMSI answered {r}, which is no verdict")),
    }
}

#[cfg(windows)]
mod amsi {
    use super::{amsi_verdict, Scanner, Verdict};
    use windows_sys::Win32::System::Antimalware::{
        AmsiCloseSession, AmsiInitialize, AmsiOpenSession, AmsiScanBuffer, AmsiUninitialize,
        HAMSICONTEXT, HAMSISESSION,
    };

    pub struct Amsi {
        context: Result<HAMSICONTEXT, i32>,
        providers: Vec<String>,
    }

    // SAFETY: an AMSI context may be used from any thread; every scan opens a session of its own.
    unsafe impl Send for Amsi {}
    unsafe impl Sync for Amsi {}

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    impl Amsi {
        pub fn new() -> Self {
            let app = wide("web-access proxy");
            let mut context: HAMSICONTEXT = std::ptr::null_mut();
            // SAFETY: `app` is NUL-terminated and outlives the call; `context` is a valid out pointer.
            let hr = unsafe { AmsiInitialize(app.as_ptr(), &mut context) };
            Self {
                context: if hr == 0 { Ok(context) } else { Err(hr) },
                providers: providers(),
            }
        }
    }

    /// The anti-malware products registered with AMSI, by the names their COM classes carry.
    fn providers() -> Vec<String> {
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
        };
        let mut out = Vec::new();
        let path = wide(r"SOFTWARE\Microsoft\AMSI\Providers");
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: `path` is NUL-terminated and outlives the call; `key` is a valid out pointer.
        if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) } != 0 {
            return out;
        }
        for index in 0.. {
            let mut name = [0u16; 128];
            let mut len = name.len() as u32;
            // SAFETY: `name` holds `len` characters; the optional out pointers are null.
            let rc = unsafe {
                RegEnumKeyExW(
                    key,
                    index,
                    name.as_mut_ptr(),
                    &mut len,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if rc != 0 {
                break;
            }
            let clsid = String::from_utf16_lossy(&name[..len as usize]);
            out.push(class_name(&clsid).unwrap_or(clsid));
        }
        // SAFETY: opened above and closed once.
        unsafe { RegCloseKey(key) };
        out
    }

    /// A COM class's default value, such as "MfeAntimalwareProvider Class".
    fn class_name(clsid: &str) -> Option<String> {
        use windows_sys::Win32::System::Registry::{
            RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ,
        };
        let sub = wide(&format!(r"SOFTWARE\Classes\CLSID\{clsid}"));
        let mut buf = [0u16; 256];
        let mut size = (buf.len() * 2) as u32;
        // SAFETY: `sub` is NUL-terminated; `buf` holds `size` bytes; a null value name reads the
        // key's default value.
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                sub.as_ptr(),
                std::ptr::null(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if rc != 0 {
            return None;
        }
        // `size` counts bytes, the terminating NUL included.
        let chars = (size as usize / 2).saturating_sub(1);
        let s = String::from_utf16_lossy(&buf[..chars]);
        (!s.is_empty()).then_some(s)
    }

    impl Drop for Amsi {
        fn drop(&mut self) {
            if let Ok(context) = self.context {
                // SAFETY: the context came from AmsiInitialize and is released once.
                unsafe { AmsiUninitialize(context) };
            }
        }
    }

    impl Scanner for Amsi {
        fn describe(&self) -> String {
            if self.providers.is_empty() {
                "AMSI, with no anti-malware product registered".into()
            } else {
                format!("AMSI: {}", self.providers.join(", "))
            }
        }

        fn scan(&self, name: &str, bytes: &[u8]) -> Verdict {
            let context = match self.context {
                Ok(c) => c,
                Err(hr) => {
                    return Verdict::Unavailable(format!("AmsiInitialize failed with {hr:#010x}"))
                }
            };
            let Ok(length) = u32::try_from(bytes.len()) else {
                return Verdict::Unavailable("larger than AMSI scans at once (4 GB)".into());
            };
            let mut session: HAMSISESSION = std::ptr::null_mut();
            // SAFETY: a live context and a valid out pointer.
            let hr = unsafe { AmsiOpenSession(context, &mut session) };
            if hr != 0 {
                return Verdict::Unavailable(format!("AmsiOpenSession failed with {hr:#010x}"));
            }
            let content = wide(name);
            let mut result = 0;
            // SAFETY: `bytes` is valid for `length` bytes, `content` is NUL-terminated, and both
            // outlive the call; `result` is a valid out pointer.
            let hr = unsafe {
                AmsiScanBuffer(
                    context,
                    bytes.as_ptr().cast(),
                    length,
                    content.as_ptr(),
                    session,
                    &mut result,
                )
            };
            // SAFETY: the session was opened on this context above and is closed once.
            unsafe { AmsiCloseSession(context, session) };
            amsi_verdict(hr, result)
        }
    }
}

/// A scanner program run on a copy of the file, its exit code the verdict.
struct Command {
    argv: Vec<String>,
    clean: Vec<i32>,
    detected: Vec<i32>,
    timeout: Duration,
    staging: PathBuf,
}

impl Scanner for Command {
    fn describe(&self) -> String {
        format!("command {}", self.argv[0])
    }

    fn scan(&self, _name: &str, bytes: &[u8]) -> Verdict {
        if let Err(e) = std::fs::create_dir_all(&self.staging) {
            return Verdict::Unavailable(format!("staging folder: {e}"));
        }
        // A random name: the scanner never sees the sender's file name.
        let path = self
            .staging
            .join(format!("{}.bin", &crate::auth::random_token()[..24]));
        let verdict = self.run(&path, bytes);
        let _ = std::fs::remove_file(&path);
        verdict
    }
}

impl Command {
    fn run(&self, path: &Path, bytes: &[u8]) -> Verdict {
        if let Err(e) = std::fs::write(path, bytes) {
            return Verdict::Unavailable(format!("writing the copy: {e}"));
        }
        let file = path.to_string_lossy();
        let args: Vec<String> = self.argv[1..]
            .iter()
            .map(|a| a.replace("{file}", &file))
            .collect();
        let mut child = match std::process::Command::new(&self.argv[0])
            .args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return Verdict::Unavailable(format!("starting {}: {e}", self.argv[0])),
        };
        let until = Instant::now() + self.timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return match status.code() {
                        Some(c) if self.clean.contains(&c) => Verdict::Clean,
                        Some(c) if self.detected.contains(&c) => Verdict::Detected,
                        other => Verdict::Unavailable(format!("scanner exited with {other:?}")),
                    };
                }
                Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(50)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Verdict::Unavailable("the scanner took too long".into());
                }
                Err(e) => return Verdict::Unavailable(format!("waiting for the scanner: {e}")),
            }
        }
    }
}

/// The EICAR anti-virus test file, reversed so this source and the binary never carry it.
const EICAR_REVERSED: &str =
    "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";

pub fn eicar() -> Vec<u8> {
    EICAR_REVERSED.bytes().rev().collect()
}

/// Proves the scanner answers both ways: the EICAR test file must come back Detected and a
/// harmless file Clean. Anything else means files cannot be scanned.
pub fn check(scanner: &dyn Scanner) -> Result<(), String> {
    match scanner.scan("web-access-check.com", &eicar()) {
        Verdict::Detected => {}
        v => return Err(format!("the EICAR test file came back {v:?}, not detected")),
    }
    match scanner.scan(
        "web-access-check.txt",
        b"web-access scanner check, a harmless file\n",
    ) {
        Verdict::Clean => Ok(()),
        v => Err(format!("a harmless file came back {v:?}, not clean")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_clean_and_not_detected_let_a_file_through() {
        assert_eq!(amsi_verdict(0, 0), Verdict::Clean);
        assert_eq!(amsi_verdict(0, 1), Verdict::Clean);
        assert_eq!(amsi_verdict(0, 0x8000), Verdict::Detected);
        assert_eq!(amsi_verdict(0, 0x9000), Verdict::Detected);
        assert_eq!(amsi_verdict(0, 0x4000), Verdict::Detected);
        assert_eq!(amsi_verdict(0, 0x4fff), Verdict::Detected);
        assert!(matches!(amsi_verdict(0, 2), Verdict::Unavailable(_)));
        assert!(matches!(amsi_verdict(0, 0x5000), Verdict::Unavailable(_)));
        assert!(matches!(
            amsi_verdict(-2147024891, 0),
            Verdict::Unavailable(_)
        ));
    }

    #[test]
    fn the_test_file_is_rebuilt_at_run_time() {
        let e = eicar();
        assert_eq!(e.len(), 68);
        assert!(e.starts_with(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"));
        assert!(e.ends_with(b"-TEST-FILE!$H+H*"));
    }

    /// A stand-in scanner with a script of verdicts.
    struct Scripted(Verdict, Verdict);
    impl Scanner for Scripted {
        fn describe(&self) -> String {
            "scripted".into()
        }
        fn scan(&self, name: &str, _: &[u8]) -> Verdict {
            if name.ends_with(".com") {
                self.0.clone()
            } else {
                self.1.clone()
            }
        }
    }

    #[test]
    fn the_check_needs_a_detection_and_a_clean_answer() {
        assert!(check(&Scripted(Verdict::Detected, Verdict::Clean)).is_ok());
        assert!(check(&Scripted(Verdict::Clean, Verdict::Clean)).is_err());
        assert!(check(&Scripted(Verdict::Detected, Verdict::Detected)).is_err());
        let down = Verdict::Unavailable("down".into());
        assert!(check(&Scripted(down.clone(), down)).is_err());
    }

    fn command(argv: &[&str], timeout: Duration, staging: &Path) -> Command {
        Command {
            argv: argv.iter().map(|a| (*a).to_owned()).collect(),
            clean: vec![0],
            detected: vec![1],
            timeout,
            staging: staging.to_owned(),
        }
    }

    #[cfg(windows)]
    const EXIT: [&str; 3] = ["cmd", "/c", "exit"];
    #[cfg(not(windows))]
    const EXIT: [&str; 3] = ["sh", "-c", "exit \"$0\""];

    #[test]
    fn the_command_scanner_goes_by_its_exit_codes_and_leaves_no_copy() {
        let staging = std::env::temp_dir().join(format!(
            "web-access-scan-{}",
            &crate::auth::random_token()[..12]
        ));
        let slow = Duration::from_secs(30);
        for (code, want) in [
            ("0", Verdict::Clean),
            ("1", Verdict::Detected),
            (
                "3",
                Verdict::Unavailable("scanner exited with Some(3)".into()),
            ),
        ] {
            // sh takes the code as $0 and the path as $1; cmd's exit ignores the path after it.
            let argv = [EXIT[0], EXIT[1], EXIT[2], code, "{file}"];
            let v = command(&argv, slow, &staging).scan("a.txt", b"body");
            assert_eq!(v, want, "exit {code}");
        }
        #[cfg(windows)]
        let sleeper = ["ping", "-n", "6", "127.0.0.1"];
        #[cfg(not(windows))]
        let sleeper = ["sleep", "5"];
        let started = Instant::now();
        let v = command(&sleeper, Duration::from_secs(1), &staging).scan("a.txt", b"body");
        assert_eq!(v, Verdict::Unavailable("the scanner took too long".into()));
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "not killed at the timeout"
        );
        let left = std::fs::read_dir(&staging).unwrap().count();
        let _ = std::fs::remove_dir_all(&staging);
        assert_eq!(left, 0, "a copy was left behind");
    }

    /// The real AMSI provider on this host. Run with --ignored on a Windows machine with an
    /// anti-malware product registered, as the real-install check does.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn amsi_on_this_host_detects_the_test_file_and_passes_a_harmless_one() {
        let amsi = amsi::Amsi::new();
        let named = amsi.describe();
        assert!(
            named.starts_with("AMSI: ") && !named.contains('{'),
            "{named}"
        );
        check(&amsi).unwrap();
    }
}
