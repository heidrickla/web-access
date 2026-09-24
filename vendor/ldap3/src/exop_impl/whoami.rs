use std::str;

use super::{Exop, ExopParser};

pub const WHOAMI_OID: &str = "1.3.6.1.4.1.4203.1.11.3";

/// Who Am I extended operation ([RFC 4532](https://tools.ietf.org/html/rfc4532)).
///
/// This operation doesn't have any data associated with a request. It can be combined
/// with request controls, and if those controls change the authorization status
/// of the request, it will be reflected in the response.
#[derive(Debug)]
pub struct WhoAmI;

/// Who Am I response.
#[derive(Debug)]
pub struct WhoAmIResp {
    /// Authorization Id, the identity which LDAP uses for access control
    /// on this connection.
    pub authzid: String,
}

impl From<WhoAmI> for Exop {
    fn from(_w: WhoAmI) -> Exop {
        Exop {
            name: Some(WHOAMI_OID.to_owned()),
            val: None,
        }
    }
}

impl ExopParser for WhoAmIResp {
    fn parse(val: &[u8]) -> WhoAmIResp {
        WhoAmIResp {
            authzid: str::from_utf8(val).expect("authzid").to_owned(),
        }
    }
}
