use super::{Exop, ExopParser};

use bytes::BytesMut;

use lber::common::TagClass;
use lber::parse::parse_tag;
use lber::structures::{ASNTag, OctetString, Sequence, Tag};
use lber::write;

pub const PASSMOD_OID: &str = "1.3.6.1.4.1.4203.1.11.1";

/// Password Modify extended operation ([RFC 3062](https://tools.ietf.org/html/rfc3062)).
///
/// The structure contains elements of a Password Modify request. The precise semantics
/// of having a particular field present or absent will depend on the server receiving
/// the request; consult the server documentation. Some rules are prescribed by the RFC
/// and should generally apply:
///
/// * The `user_id` field contains the identity of the user whose password is being changed.
///   This may or may not be a DN. If the field is absent, the identity associated with the
///   current connection will be used.
///
/// * If `old_pass` is present, it must match the existing password.
///
/// * If `new_pass` is not present, the server may autogenerate the new password.
///
/// Although the specification doesn't constrain the values of old and new passwords, this
/// implementation limits them to UTF-8 strings.
#[derive(Clone, Debug)]
pub struct PasswordModify<'a> {
    pub user_id: Option<&'a str>,
    pub old_pass: Option<&'a str>,
    pub new_pass: Option<&'a str>,
}

/// Password Modify response.
///
/// If the server has generated a new password, it must send its value in the response.
#[derive(Clone, Debug)]
pub struct PasswordModifyResp {
    pub gen_pass: String,
}

impl<'a> From<PasswordModify<'a>> for Exop {
    fn from(pm: PasswordModify<'a>) -> Exop {
        let mut pm_vec = vec![];
        if let Some(user_id) = pm.user_id {
            pm_vec.push(Tag::OctetString(OctetString {
                id: 0,
                class: TagClass::Context,
                inner: Vec::from(user_id.as_bytes()),
            }));
        }
        if let Some(old_pass) = pm.old_pass {
            pm_vec.push(Tag::OctetString(OctetString {
                id: 1,
                class: TagClass::Context,
                inner: Vec::from(old_pass.as_bytes()),
            }));
        }
        if let Some(new_pass) = pm.new_pass {
            pm_vec.push(Tag::OctetString(OctetString {
                id: 2,
                class: TagClass::Context,
                inner: Vec::from(new_pass.as_bytes()),
            }));
        }
        let val = if pm_vec.is_empty() {
            None
        } else {
            let pm_val = Tag::Sequence(Sequence {
                inner: pm_vec,
                ..Default::default()
            })
            .into_structure();
            let mut buf = BytesMut::new();
            write::encode_into(&mut buf, pm_val).expect("encoded");
            Some(Vec::from(&buf[..]))
        };
        Exop {
            name: Some(PASSMOD_OID.to_owned()),
            val,
        }
    }
}

impl ExopParser for PasswordModifyResp {
    fn parse(val: &[u8]) -> PasswordModifyResp {
        let tags = match parse_tag(val) {
            Ok((_, tag)) => tag,
            _ => panic!("failed to parse password modify return value"),
        };
        let mut tags = tags
            .expect_constructed()
            .expect("password modify sequence")
            .into_iter();
        let gen_pass = tags
            .next()
            .expect("element")
            .match_class(TagClass::Context)
            .and_then(|t| t.match_id(0))
            .and_then(|t| t.expect_primitive())
            .expect("generated password")
            .as_slice()
            .to_owned();
        let gen_pass = String::from_utf8(gen_pass).expect("generated password not UTF-8");
        PasswordModifyResp { gen_pass }
    }
}
