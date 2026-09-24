use super::RawControl;

/// Proxy Authorization control ([RFC 4370](https://tools.ietf.org/html/rfc4370)).
///
/// This control only has the request part, and must be marked as critical.
/// For that reason, it doesn't implement `MakeCritical`.
#[derive(Clone, Debug)]
pub struct ProxyAuth {
    /// Authorization identity, empty if anonymous.
    pub authzid: String,
}

pub const PROXY_AUTH_OID: &str = "2.16.840.1.113730.3.4.18";

impl From<ProxyAuth> for RawControl {
    fn from(pa: ProxyAuth) -> RawControl {
        RawControl {
            ctype: PROXY_AUTH_OID.to_owned(),
            crit: true,
            val: Some(pa.authzid.into_bytes()),
        }
    }
}
