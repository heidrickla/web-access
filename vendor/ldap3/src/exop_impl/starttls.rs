use super::Exop;

pub const STARTTLS_OID: &str = "1.3.6.1.4.1.1466.20037";

/// StartTLS extended operation ([RFC 4511](https://tools.ietf.org/html/rfc4511#section-4.14)).
///
/// This operation isn't meant to be directly used by user code; it is used by
/// connection-establishment routines when the StartTLS mechanism of securing the
/// connection is requested by the user.
pub struct StartTLS;

impl From<StartTLS> for Exop {
    fn from(_s: StartTLS) -> Exop {
        Exop {
            name: Some(STARTTLS_OID.to_owned()),
            val: None,
        }
    }
}
