use bytes::BytesMut;
use lber::{structures::ASNTag, write};

use super::RawControl;

use crate::filter::parse_matched_values;

pub const MATCHED_VALUES_OID: &str = "1.2.826.0.1.3344810.2.3";

/// Matched Values control ([RFC 3876](https://tools.ietf.org/html/rfc3876.html))
///
/// This control is used to return a subset of attribute values from an entry.
/// To avoid complicating the filter parser, the `dnAttributes` flag can be set
/// in an Extensible Match expression despite not being specified in the RFC and
/// having no meaning in this kind of filter.
#[derive(Clone, Debug)]
pub struct MatchedValues<S> {
    filter: S,
}

impl<S: AsRef<str>> MatchedValues<S> {
    /// Create a new control instance with the specified filter.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(filter: S) -> RawControl {
        MatchedValues { filter }.into()
    }
}

impl<S: AsRef<str>> From<MatchedValues<S>> for RawControl {
    fn from(assn: MatchedValues<S>) -> RawControl {
        let filter_ref = assn.filter.as_ref();
        let filter = parse_matched_values(filter_ref)
            .expect("filter")
            .into_structure();
        let mut buf = BytesMut::with_capacity(filter_ref.len()); // ballpark
        write::encode_into(&mut buf, filter).expect("encoded");
        RawControl {
            ctype: MATCHED_VALUES_OID.to_owned(),
            crit: false,
            val: Some(Vec::from(&buf[..])),
        }
    }
}
