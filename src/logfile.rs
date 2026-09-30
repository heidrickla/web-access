//! The service's log: one file per UTC day beside the config, the newest `keep` kept.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub struct DailyLog {
    dir: PathBuf,
    stem: String,
    keep: usize,
    open: Mutex<Option<(i64, File)>>,
}

impl DailyLog {
    /// Files are `<dir>/<stem>-<yyyy>-<mm>-<dd>.log`.
    pub fn new(dir: &Path, stem: &str, keep: usize) -> Arc<Self> {
        Arc::new(Self {
            dir: dir.to_owned(),
            stem: stem.to_owned(),
            keep,
            open: Mutex::new(None),
        })
    }

    fn name_for(&self, day: i64) -> String {
        let (y, m, d, ..) = crate::migrate::utc_parts(day * 86_400);
        format!("{}-{y:04}-{m:02}-{d:02}.log", self.stem)
    }

    /// Today's file, for the first log line.
    pub fn current_path(&self) -> PathBuf {
        self.dir
            .join(self.name_for(crate::store::now().div_euclid(86_400)))
    }

    fn write_at(&self, now: i64, buf: &[u8]) -> io::Result<()> {
        let day = now.div_euclid(86_400);
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        if open.as_ref().is_none_or(|(d, _)| *d != day) {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.dir.join(self.name_for(day)))?;
            *open = Some((day, file));
            self.prune();
        }
        match open.as_mut() {
            Some((_, file)) => file.write_all(buf),
            None => Ok(()),
        }
    }

    /// Dated files beyond the newest `keep` go. Other files in the directory are never touched.
    fn prune(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let prefix = format!("{}-", self.stem);
        let mut dated: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.strip_prefix(&prefix))
                    .and_then(|rest| rest.strip_suffix(".log"))
                    .is_some_and(is_date)
            })
            .collect();
        dated.sort();
        let excess = dated.len().saturating_sub(self.keep);
        for old in &dated[..excess] {
            let _ = std::fs::remove_file(old);
        }
    }
}

/// `yyyy-mm-dd`, digits in place.
fn is_date(s: &str) -> bool {
    s.len() == 10
        && s.char_indices().all(|(i, c)| match i {
            4 | 7 => c == '-',
            _ => c.is_ascii_digit(),
        })
}

/// What `tracing_subscriber` writes one event through.
pub struct Writer(pub Arc<DailyLog>);

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_at(crate::store::now(), buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_day_opens_a_new_file_and_only_the_newest_are_kept() {
        let dir = std::env::temp_dir().join(format!(
            "web-access-logs-{}",
            &crate::auth::random_token()[..12]
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Not ours: an undated log from an earlier version, and a lookalike name.
        std::fs::write(dir.join("web-access-proxy.log"), "old").unwrap();
        std::fs::write(dir.join("web-access-proxy-notes.log"), "mine").unwrap();
        let log = DailyLog::new(&dir, "web-access-proxy", 3);
        let day = 86_400;
        let start = 20_000 * day;
        for n in 0..5 {
            log.write_at(start + n * day + 5, format!("line {n}\n").as_bytes())
                .unwrap();
            log.write_at(start + n * day + 6, b"more\n").unwrap();
        }
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        let newest = log.name_for(start / day + 4);
        assert_eq!(names.len(), 5, "{names:?}");
        assert!(names.contains(&"web-access-proxy.log".to_owned()));
        assert!(names.contains(&"web-access-proxy-notes.log".to_owned()));
        assert_eq!(
            std::fs::read_to_string(dir.join(&newest)).unwrap(),
            "line 4\nmore\n"
        );
        assert!(!names.contains(&log.name_for(start / day + 1)));
    }
}
