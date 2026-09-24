use super::{MakeCritical, RawControl};

/// ManageDsaITcontrol ([RFC 3296](https://tools.ietf.org/html/rfc3296)).
///
/// This control can only be used for requests; there is no corresponding
/// response control.
pub struct ManageDsaIt;

pub const MANAGE_DSA_IT_OID: &str = "2.16.840.1.113730.3.4.2";

impl MakeCritical for ManageDsaIt {}

impl From<ManageDsaIt> for RawControl {
    fn from(_mdi: ManageDsaIt) -> RawControl {
        RawControl {
            ctype: MANAGE_DSA_IT_OID.to_owned(),
            crit: false,
            val: None,
        }
    }
}
