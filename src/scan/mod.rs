//! Files crossing the clipboard channel are held until scanned. The proxy frames the relayed
//! stream (`framing`), finds the clipboard channel (`route`), and stands between the two clipboard
//! endpoints (`clip`): it fetches a whole offer from the sender, has the scanner (`scanner`) judge
//! every file, and only then offers the clean copy to the receiver. Every other byte passes
//! through unchanged.

pub mod clip;
pub mod framing;
pub mod route;
pub mod scanner;

use crate::config::Scan;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The scanner the config names, with the proof that it answers.
pub struct ScanService {
    pub scanner: Arc<dyn scanner::Scanner>,
    pub timeout: Duration,
    pub staging: Arc<clip::Staging>,
    pub check_every: Duration,
    health: Mutex<Health>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Health {
    pub scanner: String,
    pub ok: bool,
    pub detail: String,
    pub checked_at: Option<i64>,
}

impl ScanService {
    pub fn new(scan: &Scan, data_dir: &Path) -> Option<Arc<Self>> {
        let scanner = scanner::from_config(scan, data_dir)?;
        Some(Arc::new(Self {
            health: Mutex::new(Health {
                scanner: scanner.describe(),
                detail: "not checked yet".into(),
                ..Health::default()
            }),
            scanner,
            timeout: Duration::from_secs(scan.timeout_secs),
            check_every: Duration::from_secs(scan.check_every_mins * 60),
            staging: clip::Staging::new(scan.max_staged_mb.saturating_mul(1024 * 1024)),
        }))
    }

    pub fn health(&self) -> Health {
        self.health
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Whether an offer may be scanned now: the last check passed, and no more than two checks
    /// and ten minutes ago.
    pub fn healthy(&self) -> Result<(), String> {
        let h = self.health();
        let fresh = i64::try_from(self.check_every.as_secs() * 2 + 600).unwrap_or(i64::MAX);
        match h.checked_at {
            None => Err(h.detail),
            Some(_) if !h.ok => Err(h.detail),
            Some(at) if crate::store::now() - at > fresh => {
                Err("the scanner has not been checked recently".into())
            }
            Some(_) => Ok(()),
        }
    }

    /// Scans the EICAR test file and a harmless one, and records whether the answers were right.
    pub async fn check(&self) -> Health {
        let scanner = Arc::clone(&self.scanner);
        let job = tokio::task::spawn_blocking(move || scanner::check(scanner.as_ref()));
        let result = match tokio::time::timeout(self.timeout, job).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => Err(format!("the check failed: {e}")),
            Err(_) => Err("the scanner did not answer in time".into()),
        };
        let mut h = self.health.lock().unwrap_or_else(|p| p.into_inner());
        h.ok = result.is_ok();
        h.detail = match result {
            Ok(()) => "detects the EICAR test file and passes a harmless one".into(),
            Err(e) => e,
        };
        h.checked_at = Some(crate::store::now());
        h.clone()
    }

    /// A service with a stand-in scanner, checked and passing.
    #[cfg(test)]
    pub fn for_test(scanner: Arc<dyn scanner::Scanner>) -> Arc<Self> {
        Arc::new(Self {
            health: Mutex::new(Health {
                scanner: scanner.describe(),
                ok: true,
                detail: String::new(),
                checked_at: Some(crate::store::now()),
            }),
            scanner,
            timeout: Duration::from_secs(5),
            staging: clip::Staging::new(1 << 30),
            check_every: Duration::from_secs(3600),
        })
    }

    #[cfg(test)]
    pub fn set_health(&self, ok: bool, at: i64) {
        let mut h = self.health.lock().unwrap();
        h.ok = ok;
        h.checked_at = Some(at);
    }
}

/// The activity log's line when a check changes the scanner's standing: failing on the first
/// failure after a pass or at start, restored on the first pass after a failure.
pub fn transition(was: &Health, now: &Health) -> Option<(&'static str, String)> {
    let was_failing = was.checked_at.is_some() && !was.ok;
    match (was_failing, now.ok) {
        (false, false) => Some(("scan.failing", now.detail.clone())),
        (true, true) => Some(("scan.restored", now.scanner.clone())),
        _ => None,
    }
}

/// Short messages for a signed-in user's page, oldest dropped past a handful.
#[derive(Default)]
pub struct Notices {
    inner: Mutex<(u64, HashMap<i64, VecDeque<Notice>>)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Notice {
    pub seq: u64,
    pub text: String,
    pub bad: bool,
}

const NOTICES_KEPT: usize = 32;

impl Notices {
    pub fn push(&self, user_id: i64, text: String, bad: bool) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.0 += 1;
        let seq = g.0;
        let q = g.1.entry(user_id).or_default();
        q.push_back(Notice { seq, text, bad });
        while q.len() > NOTICES_KEPT {
            q.pop_front();
        }
    }

    /// The user's notices after `after`, and the newest sequence number overall.
    pub fn since(&self, user_id: i64, after: u64) -> (Vec<Notice>, u64) {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let list =
            g.1.get(&user_id)
                .map(|q| q.iter().filter(|n| n.seq > after).cloned().collect())
                .unwrap_or_default();
        (list, g.0)
    }
}

/// What a report tells the user, and whether it is bad news.
pub fn notice_text(report: &clip::Report, server: &str) -> (String, bool) {
    use clip::{Dir, Report};
    let names = |files: &[(String, u64)]| {
        if files.is_empty() {
            "files".to_owned()
        } else {
            files
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    match report {
        Report::Started {
            dir: Dir::Upload,
            files,
        } => (
            format!("scanning {} before they reach {server}", names(files)),
            false,
        ),
        Report::Started {
            dir: Dir::Download,
            files,
        } => (format!("scanning {} from {server}", names(files)), false),
        Report::Passed {
            dir: Dir::Upload,
            files,
        } => (
            format!("{} passed the scan; paste on {server}", names(files)),
            false,
        ),
        Report::Passed {
            dir: Dir::Download,
            files,
        } => (
            format!("{} from {server} passed the scan", names(files)),
            false,
        ),
        Report::Refused {
            dir: Dir::Upload,
            files,
            reason,
        } => (
            format!("{} not sent to {server}: {reason}", names(files)),
            true,
        ),
        Report::Refused {
            dir: Dir::Download,
            files,
            reason,
        } => (
            format!("{} from {server} refused: {reason}", names(files)),
            true,
        ),
    }
}

/// The activity log's lines for a report: one per file passed or refused.
pub fn audit_lines(report: &clip::Report, server: &str) -> Vec<(&'static str, String)> {
    use clip::Report;
    match report {
        Report::Started { .. } => Vec::new(),
        Report::Passed { dir, files } => files
            .iter()
            .map(|(n, s)| (action(*dir), format!("{n} ({s} bytes), {server}: passed")))
            .collect(),
        Report::Refused { dir, files, reason } if files.is_empty() => {
            vec![(action(*dir), format!("{server}: refused: {reason}"))]
        }
        Report::Refused { dir, files, reason } => files
            .iter()
            .map(|(n, s)| {
                (
                    action(*dir),
                    format!("{n} ({s} bytes), {server}: refused: {reason}"),
                )
            })
            .collect(),
    }
}

fn action(dir: clip::Dir) -> &'static str {
    match dir {
        clip::Dir::Upload => "file.upload",
        clip::Dir::Download => "file.download",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clip::{Dir, Report};

    #[test]
    fn notices_are_per_user_in_order_and_bounded() {
        let n = Notices::default();
        n.push(1, "a".into(), false);
        n.push(2, "b".into(), true);
        n.push(1, "c".into(), false);
        let (mine, last) = n.since(1, 0);
        assert_eq!(
            mine.iter().map(|x| x.text.as_str()).collect::<Vec<_>>(),
            ["a", "c"]
        );
        assert_eq!(last, 3);
        assert_eq!(n.since(1, 1).0.len(), 1);
        assert!(n.since(3, 0).0.is_empty());
        for i in 0..100 {
            n.push(1, format!("{i}"), false);
        }
        assert_eq!(n.since(1, 0).0.len(), NOTICES_KEPT);
    }

    #[test]
    fn every_file_passed_or_refused_is_logged_and_a_start_is_not() {
        let files = vec![("a.txt".to_owned(), 3), ("b.exe".to_owned(), 4)];
        let refused = Report::Refused {
            dir: Dir::Upload,
            files: files.clone(),
            reason: "b.exe: malware detected".into(),
        };
        let lines = audit_lines(&refused, "hist-01");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1].0, "file.upload");
        assert!(lines[1].1.starts_with("b.exe (4 bytes), hist-01: refused"));
        let started = Report::Started {
            dir: Dir::Download,
            files,
        };
        assert!(audit_lines(&started, "hist-01").is_empty());
        let (text, bad) = notice_text(&refused, "hist-01");
        assert!(bad);
        assert!(text.starts_with("a.txt, b.exe not sent to hist-01"));
    }

    #[test]
    fn an_unchecked_or_failing_scanner_refuses_and_a_fresh_pass_admits() {
        let scan = Scan {
            scanner: crate::config::Scanner::Command,
            command: vec!["scanner".into(), "{file}".into()],
            detected_exit_codes: vec![1],
            ..Scan::default()
        };
        let s = ScanService::new(&scan, Path::new(".")).unwrap();
        let now = crate::store::now();
        assert!(s.healthy().is_err(), "unchecked");
        s.set_health(false, now);
        assert!(s.healthy().is_err());
        s.set_health(true, now);
        assert!(s.healthy().is_ok());
        // Two missed hourly checks and ten minutes: no longer vouched for.
        s.set_health(true, now - 2 * 3600 - 590);
        assert!(s.healthy().is_ok());
        s.set_health(true, now - 2 * 3600 - 610);
        assert!(s.healthy().is_err(), "stale");
    }

    #[test]
    fn only_a_change_of_standing_is_logged() {
        let h = |checked: bool, ok: bool| Health {
            scanner: "amsi".into(),
            ok,
            detail: "d".into(),
            checked_at: checked.then_some(1),
        };
        assert_eq!(
            transition(&h(false, false), &h(true, false)).unwrap().0,
            "scan.failing"
        );
        assert!(
            transition(&h(false, false), &h(true, true)).is_none(),
            "first pass"
        );
        assert!(transition(&h(true, true), &h(true, true)).is_none());
        assert_eq!(
            transition(&h(true, true), &h(true, false)).unwrap().0,
            "scan.failing"
        );
        assert!(
            transition(&h(true, false), &h(true, false)).is_none(),
            "still failing"
        );
        assert_eq!(
            transition(&h(true, false), &h(true, true)).unwrap().0,
            "scan.restored"
        );
    }
}
