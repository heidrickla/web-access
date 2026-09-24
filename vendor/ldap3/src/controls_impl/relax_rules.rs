use super::{MakeCritical, RawControl};

/// Relax Rules control ([draft specification](https://tools.ietf.org/html/draft-zeilenga-ldap-relax-03)).
///
/// This control can only be used for requests; there is no corresponding
/// result control.
pub struct RelaxRules;

pub const RELAX_RULES_OID: &str = "1.3.6.1.4.1.4203.666.5.12";

impl MakeCritical for RelaxRules {}

impl From<RelaxRules> for RawControl {
    fn from(_rr: RelaxRules) -> RawControl {
        RawControl {
            ctype: RELAX_RULES_OID.to_owned(),
            crit: false,
            val: None,
        }
    }
}
