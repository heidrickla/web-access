use bytes::BytesMut;

use super::{MakeCritical, RawControl};
use crate::filter::parse;
use lber::structures::ASNTag;
use lber::write;

pub const ASSERTION_OID: &str = "1.3.6.1.1.12";

/// Assertion control ([RFC 4528](https://tools.ietf.org/html/rfc4528)).
#[derive(Debug)]
pub struct Assertion<S> {
    /// String representation of the assertion filter.
    pub filter: S,
}

impl<S: AsRef<str>> Assertion<S> {
    /// Create a new control instance with the specified filter.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(filter: S) -> RawControl {
        Assertion { filter }.into()
    }
}

impl<S> MakeCritical for Assertion<S> {}

impl<S: AsRef<str>> From<Assertion<S>> for RawControl {
    fn from(assn: Assertion<S>) -> RawControl {
        let filter_ref = assn.filter.as_ref();
        let filter = parse(filter_ref).expect("filter").into_structure();
        let mut buf = BytesMut::with_capacity(filter_ref.len()); // ballpark
        write::encode_into(&mut buf, filter).expect("encoded");
        RawControl {
            ctype: ASSERTION_OID.to_owned(),
            crit: false,
            val: Some(Vec::from(&buf[..])),
        }
    }
}
