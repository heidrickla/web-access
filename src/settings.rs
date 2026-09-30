//! What an administrator sets on the Settings tab. One JSON value in the database, so a change is a
//! single write, travels with an export, and takes effect without a restart.

use crate::store::{Result, Store};
use serde::{Deserialize, Serialize};

const KEY: &str = "settings";

pub const MAX_SIGNIN_HOURS: u32 = 720;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// How long a sign-in lasts, from the sign-in or its renewal.
    pub signin_hours: u32,
    /// Opening a server with less than this left asks for the password first, so a desktop is not
    /// cut off by the sign-in expiring. 0 never asks.
    pub renew_below_hours: u32,
    /// The largest file sent either way over the clipboard channel, in MB. 0 is no limit.
    pub max_file_mb: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            signin_hours: 24,
            renew_below_hours: 18,
            max_file_mb: 0,
        }
    }
}

impl Settings {
    pub fn check(&self) -> std::result::Result<(), String> {
        if !(1..=MAX_SIGNIN_HOURS).contains(&self.signin_hours) {
            return Err(format!("a sign-in lasts 1 to {MAX_SIGNIN_HOURS} hours"));
        }
        // At or above the sign-in's own length, every server opened would ask for the password.
        if self.renew_below_hours >= self.signin_hours {
            return Err(format!(
                "ask for the password again under fewer hours than a sign-in lasts ({})",
                self.signin_hours
            ));
        }
        Ok(())
    }

    pub fn signin_secs(&self) -> i64 {
        i64::from(self.signin_hours) * 3600
    }

    pub fn renew_below_secs(&self) -> i64 {
        i64::from(self.renew_below_hours) * 3600
    }

    pub fn max_file_bytes(&self) -> Option<u64> {
        (self.max_file_mb > 0).then(|| u64::from(self.max_file_mb) * 1024 * 1024)
    }

    /// For the activity log: "sign-in 24 h, ask again under 18 h, files any size".
    pub fn describe(&self) -> String {
        let files = match self.max_file_mb {
            0 => "any size".to_owned(),
            mb => format!("up to {mb} MB"),
        };
        format!(
            "sign-in {} h, ask again under {} h, files {files}",
            self.signin_hours, self.renew_below_hours
        )
    }
}

/// The stored settings, or the defaults where none are stored. A stored value that no longer
/// passes the check is replaced by the defaults rather than obeyed.
pub fn read(store: &Store) -> Result<Settings> {
    let stored = store
        .meta_get(KEY)?
        .and_then(|v| serde_json::from_slice::<Settings>(&v).ok())
        .filter(|s| s.check().is_ok());
    Ok(stored.unwrap_or_default())
}

pub fn write(store: &Store, settings: &Settings) -> Result<()> {
    let json = serde_json::to_vec(settings).expect("settings serialise");
    store.meta_set(KEY, &json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::open_in_memory().unwrap()
    }

    #[test]
    fn defaults_until_something_is_stored() {
        let s = store();
        assert_eq!(read(&s).unwrap(), Settings::default());
        let set = Settings {
            signin_hours: 12,
            renew_below_hours: 8,
            max_file_mb: 25,
        };
        write(&s, &set).unwrap();
        assert_eq!(read(&s).unwrap(), set);
        assert_eq!(read(&s).unwrap().signin_secs(), 12 * 3600);
        assert_eq!(read(&s).unwrap().max_file_bytes(), Some(25 * 1024 * 1024));
        assert_eq!(Settings::default().max_file_bytes(), None);
    }

    #[test]
    fn a_renewal_point_at_or_past_the_sign_in_length_is_refused() {
        let at = Settings {
            signin_hours: 18,
            renew_below_hours: 18,
            max_file_mb: 0,
        };
        assert!(at.check().is_err());
        let under = Settings {
            renew_below_hours: 17,
            ..at
        };
        assert!(under.check().is_ok());
        assert!(Settings {
            signin_hours: 0,
            renew_below_hours: 0,
            max_file_mb: 0
        }
        .check()
        .is_err());
        assert!(Settings {
            signin_hours: MAX_SIGNIN_HOURS + 1,
            ..Settings::default()
        }
        .check()
        .is_err());
    }

    #[test]
    fn a_stored_value_that_fails_the_check_reads_as_the_defaults() {
        let s = store();
        s.meta_set(KEY, br#"{"signin_hours":4,"renew_below_hours":9}"#)
            .unwrap();
        assert_eq!(read(&s).unwrap(), Settings::default());
    }
}
