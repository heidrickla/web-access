use super::{ControlParser, MakeCritical, RawControl};

use bytes::BytesMut;

use lber::common::TagClass;
use lber::parse::{parse_tag, parse_uint};
use lber::structures::{ASNTag, Integer, OctetString, Sequence, Tag};
use lber::universal::Types;
use lber::write;

/// Paged Results control ([RFC 2696](https://tools.ietf.org/html/rfc2696)).
///
/// This struct can be used both for requests and responses, although `size`
/// means different things in each case.
#[derive(Clone, Debug)]
pub struct PagedResults {
    /// For requests, desired page size. For responses, a server's estimate
    /// of the result set size, if non-zero.
    pub size: i32,
    /// Paging cookie.
    pub cookie: Vec<u8>,
}

pub const PAGED_RESULTS_OID: &str = "1.2.840.113556.1.4.319";

impl MakeCritical for PagedResults {}

impl From<PagedResults> for RawControl {
    fn from(pr: PagedResults) -> RawControl {
        let cookie_len = pr.cookie.len();
        let cval = Tag::Sequence(Sequence {
            inner: vec![
                Tag::Integer(Integer {
                    inner: pr.size as i64,
                    ..Default::default()
                }),
                Tag::OctetString(OctetString {
                    inner: pr.cookie,
                    ..Default::default()
                }),
            ],
            ..Default::default()
        })
        .into_structure();
        let mut buf = BytesMut::with_capacity(cookie_len + 16);
        write::encode_into(&mut buf, cval).expect("encoded");
        RawControl {
            ctype: PAGED_RESULTS_OID.to_owned(),
            crit: false,
            val: Some(Vec::from(&buf[..])),
        }
    }
}

impl ControlParser for PagedResults {
    fn parse(val: &[u8]) -> PagedResults {
        let mut pr_comps = match parse_tag(val) {
            Ok((_, tag)) => tag,
            _ => panic!("failed to parse paged results value components"),
        }
        .expect_constructed()
        .expect("paged results components")
        .into_iter();
        let size = match parse_uint(
            pr_comps
                .next()
                .expect("element")
                .match_class(TagClass::Universal)
                .and_then(|t| t.match_id(Types::Integer as u64))
                .and_then(|t| t.expect_primitive())
                .expect("paged results size")
                .as_slice(),
        ) {
            Ok((_, size)) => size as i32,
            _ => panic!("failed to parse size"),
        };
        let cookie = pr_comps
            .next()
            .expect("element")
            .expect_primitive()
            .expect("octet string");
        PagedResults { size, cookie }
    }
}
