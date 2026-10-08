//! SAML 2.0 sign-in: the proxy as a service provider for the site's identity provider (ADFS, Entra
//! ID). Service-provider-initiated Web SSO only: the AuthnRequest leaves by the HTTP-Redirect
//! binding and the Response returns by the HTTP-POST binding.
//!
//! | Accepted | Refused |
//! |---|---|
//! | a Response to a request this proxy issued to the same browser, used once | IdP-initiated responses, replays |
//! | one Assertion, signed by a certificate in the IdP metadata | EncryptedAssertion, an unsigned Assertion |
//! | exclusive c14n, RSA-SHA256/384/512, SHA-256/384/512 digests | other algorithms and transforms, comments, DTDs |
//!
//! The account is the directory account whose objectSid the assertion's SID attribute names, read
//! with the service account. A name is never matched: the site's domains share short names.

use crate::config::SamlConfig;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bergshamra_dsig::verify::verify_all_document;
use bergshamra_dsig::{DsigContext, VerifyResult};
use bergshamra_keys::KeysManager;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::io::Write;
use std::sync::Mutex;
use uppsala::{Document, NodeId, NodeKind};

const NS_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const NS_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const NS_METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
const BINDING_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const SIGNATURE_METHODS: &[&str] = &[
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
];
const DIGEST_METHODS: &[&str] = &[
    "http://www.w3.org/2001/04/xmlenc#sha256",
    "http://www.w3.org/2001/04/xmldsig-more#sha384",
    "http://www.w3.org/2001/04/xmlenc#sha512",
];

/// The cookie that ties a response to the browser that started the sign-in.
pub const FLOW_COOKIE: &str = "wa_saml";
/// How long a started sign-in may take at the identity provider.
pub const FLOW_SECS: i64 = 300;
/// Spent request and assertion IDs held at once; past it sign-ins are refused until some expire.
const MAX_SPENT: usize = 100_000;
/// The largest decoded response read.
const MAX_RESPONSE_BYTES: usize = 1 << 20;
/// Element nesting a response or metadata document may have.
const MAX_DEPTH: u32 = 64;

#[derive(Debug, thiserror::Error)]
pub enum SamlError {
    #[error("identity provider metadata: {0}")]
    Metadata(String),
    /// What the user and the activity log are told.
    #[error("{0}")]
    Refused(String),
}

fn refuse<T>(why: impl Into<String>) -> Result<T, SamlError> {
    Err(SamlError::Refused(why.into()))
}

/// What the identity provider's metadata says, as far as sign-in needs it.
#[derive(Debug, Clone)]
pub struct Idp {
    pub entity_id: String,
    /// The single sign-on endpoint for the Redirect binding.
    pub sso_url: String,
    /// DER certificates it signs with: two during a certificate rollover.
    pub certs: Vec<Vec<u8>>,
}

/// A response that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// In the form `directory::canonical_sid` gives.
    pub sid: String,
    pub name_id: Option<String>,
}

pub struct ServiceProvider {
    pub idp: Idp,
    pub entity_id: String,
    pub acs_url: String,
    sid_attribute: String,
    skew: i64,
    /// Signs the flow cookie. New at every start, so a restart ends sign-ins in progress.
    flow_key: hmac::Key,
    /// Request IDs answered and assertion IDs consumed, until they could no longer be accepted.
    spent: Mutex<HashMap<String, i64>>,
    /// A fixed clock, so a route test can present the fixtures within their validity.
    #[cfg(test)]
    pub test_now: Option<i64>,
}

/// The XML parser for anything from outside: no DTD, bounded depth.
fn parse(xml: &str) -> Result<Document<'_>, String> {
    uppsala::Parser::new()
        .with_forbid_dtd(true)
        .with_max_depth(MAX_DEPTH)
        .parse(xml)
        .map_err(|e| e.to_string())
}

fn is(doc: &Document<'_>, id: NodeId, ns: &str, local: &str) -> bool {
    doc.element(id)
        .is_some_and(|e| e.matches_name_ns(ns, local))
}

fn child_elements(doc: &Document<'_>, id: NodeId) -> Vec<NodeId> {
    doc.children(id)
        .into_iter()
        .filter(|c| doc.element(*c).is_some())
        .collect()
}

fn children_named(doc: &Document<'_>, id: NodeId, ns: &str, local: &str) -> Vec<NodeId> {
    child_elements(doc, id)
        .into_iter()
        .filter(|c| is(doc, *c, ns, local))
        .collect()
}

/// The child with this name; refused when there are several.
fn one_child(
    doc: &Document<'_>,
    id: NodeId,
    ns: &str,
    local: &str,
) -> Result<Option<NodeId>, SamlError> {
    let found = children_named(doc, id, ns, local);
    if found.len() > 1 {
        return refuse(format!("more than one {local} where one is allowed"));
    }
    Ok(found.first().copied())
}

fn required_child(
    doc: &Document<'_>,
    id: NodeId,
    ns: &str,
    local: &str,
) -> Result<NodeId, SamlError> {
    match one_child(doc, id, ns, local)? {
        Some(c) => Ok(c),
        None => refuse(format!("no {local} element")),
    }
}

/// An attribute without a namespace prefix. A prefixed one of the same local name is not it.
fn attr<'d>(doc: &'d Document<'_>, id: NodeId, name: &str) -> Option<&'d str> {
    doc.element(id)?
        .attributes
        .iter()
        .find(|a| a.name.namespace_uri.is_none() && *a.name.local_name == *name)
        .map(|a| &*a.value)
}

/// An element's text, which must be text alone: an element or comment inside it would let the
/// text the signature covers differ from the text read.
fn text(doc: &Document<'_>, id: NodeId) -> Result<String, SamlError> {
    let mut out = String::new();
    for c in doc.children(id) {
        match doc.node_kind(c) {
            Some(NodeKind::Text(t)) | Some(NodeKind::CData(t)) => out.push_str(t),
            _ => return refuse("an element holds more than text where text is expected"),
        }
    }
    Ok(out.trim().to_owned())
}

/// No comments and no processing instructions anywhere: no identity provider sends them, and a
/// comment is dropped by exclusive canonicalization, so it can change what is read without
/// changing what is signed.
fn plain(doc: &Document<'_>) -> Result<(), SamlError> {
    for n in doc.descendants(doc.root()) {
        if matches!(
            doc.node_kind(n),
            Some(NodeKind::Comment(_)) | Some(NodeKind::ProcessingInstruction(_))
        ) {
            return refuse("the response carries comments or processing instructions");
        }
    }
    Ok(())
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

// ---- time -----------------------------------------------------------------------------------

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = yoe + era * 400;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `YYYY-MM-DDThh:mm:ss[.fraction]Z` to Unix seconds. SAML times are UTC and carry no offset.
pub fn parse_instant(s: &str) -> Option<i64> {
    let (date, time) = s.strip_suffix('Z')?.split_once('T')?;
    let time = match time.split_once('.') {
        Some((t, frac)) if !frac.is_empty() && frac.bytes().all(|b| b.is_ascii_digit()) => t,
        Some(_) => return None,
        None => time,
    };
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    let d: Vec<&str> = date.split('-').collect();
    let t: Vec<&str> = time.split(':').collect();
    if d.len() != 3 || !digits(d[0], 4) || !digits(d[1], 2) || !digits(d[2], 2) {
        return None;
    }
    if t.len() != 3 || !t.iter().all(|p| digits(p, 2)) {
        return None;
    }
    let (y, m, day): (i64, u32, u32) = (d[0].parse().ok()?, d[1].parse().ok()?, d[2].parse().ok()?);
    let (h, mi, sec): (i64, i64, i64) =
        (t[0].parse().ok()?, t[1].parse().ok()?, t[2].parse().ok()?);
    if !(1..=12).contains(&m) || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    let days = days_from_civil(y, m, day);
    if civil_from_days(days) != (y, m, day) {
        return None;
    }
    Some(days * 86_400 + h * 3600 + mi * 60 + sec)
}

/// Unix seconds as a SAML time.
pub fn instant(unix: i64) -> String {
    let (y, m, d) = civil_from_days(unix.div_euclid(86_400));
    let s = unix.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        s / 3600,
        s % 3600 / 60,
        s % 60
    )
}

fn time_attr(doc: &Document<'_>, id: NodeId, name: &str) -> Result<Option<i64>, SamlError> {
    match attr(doc, id, name) {
        None => Ok(None),
        Some(v) => match parse_instant(v) {
            Some(t) => Ok(Some(t)),
            None => refuse(format!("{name} {v:?} is not a SAML time")),
        },
    }
}

// ---- metadata -------------------------------------------------------------------------------

/// The identity provider in an EntityDescriptor, or in the one EntityDescriptor of an
/// EntitiesDescriptor that describes an identity provider.
pub fn parse_metadata(xml: &str) -> Result<Idp, SamlError> {
    let bad = |m: String| SamlError::Metadata(m);
    let doc = parse(xml.trim_start_matches('\u{feff}')).map_err(bad)?;
    let root = doc
        .document_element()
        .ok_or_else(|| bad("empty document".into()))?;
    let entities = if is(&doc, root, NS_METADATA, "EntityDescriptor") {
        vec![root]
    } else if is(&doc, root, NS_METADATA, "EntitiesDescriptor") {
        children_named(&doc, root, NS_METADATA, "EntityDescriptor")
    } else {
        return Err(bad("not SAML metadata".into()));
    };
    let mut idps: Vec<(NodeId, NodeId)> = Vec::new();
    for e in entities {
        for d in children_named(&doc, e, NS_METADATA, "IDPSSODescriptor") {
            idps.push((e, d));
        }
    }
    let [(entity, descriptor)] = idps[..] else {
        return Err(bad(format!(
            "{} identity provider descriptors; exactly one is needed",
            idps.len()
        )));
    };
    let entity_id = attr(&doc, entity, "entityID")
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| bad("the identity provider has no entityID".into()))?
        .to_owned();
    if !attr(&doc, descriptor, "protocolSupportEnumeration")
        .unwrap_or("")
        .split_whitespace()
        .any(|p| p == NS_PROTOCOL)
    {
        return Err(bad("the identity provider does not declare SAML 2.0".into()));
    }
    let sso_url = children_named(&doc, descriptor, NS_METADATA, "SingleSignOnService")
        .into_iter()
        .filter(|s| attr(&doc, *s, "Binding") == Some(BINDING_REDIRECT))
        .find_map(|s| attr(&doc, s, "Location"))
        .filter(|l| l.starts_with("https://") || l.starts_with("http://"))
        .ok_or_else(|| bad("no SingleSignOnService for the HTTP-Redirect binding".into()))?
        .to_owned();
    let mut certs: Vec<Vec<u8>> = Vec::new();
    for kd in children_named(&doc, descriptor, NS_METADATA, "KeyDescriptor") {
        if !matches!(attr(&doc, kd, "use"), None | Some("signing")) {
            continue;
        }
        for ki in children_named(&doc, kd, NS_DSIG, "KeyInfo") {
            for xd in children_named(&doc, ki, NS_DSIG, "X509Data") {
                for c in children_named(&doc, xd, NS_DSIG, "X509Certificate") {
                    let b64: String = text(&doc, c)
                        .map_err(|e| bad(e.to_string()))?
                        .chars()
                        .filter(|c| !c.is_ascii_whitespace())
                        .collect();
                    let der = STANDARD
                        .decode(b64)
                        .map_err(|e| bad(format!("a signing certificate is not base64: {e}")))?;
                    bergshamra_keys::loader::load_x509_cert_der(&der)
                        .map_err(|e| bad(format!("a signing certificate cannot be read: {e}")))?;
                    if !certs.contains(&der) {
                        certs.push(der);
                    }
                }
            }
        }
    }
    if certs.is_empty() {
        return Err(bad("no signing certificate".into()));
    }
    Ok(Idp {
        entity_id,
        sso_url,
        certs,
    })
}

// ---- the service provider -------------------------------------------------------------------

impl ServiceProvider {
    pub fn load(cfg: &SamlConfig) -> Result<Self, SamlError> {
        let xml = std::fs::read_to_string(&cfg.idp_metadata)
            .map_err(|e| SamlError::Metadata(format!("{}: {e}", cfg.idp_metadata)))?;
        Ok(Self::new(cfg, parse_metadata(&xml)?))
    }

    pub fn new(cfg: &SamlConfig, idp: Idp) -> Self {
        let mut key = [0u8; 32];
        SystemRandom::new()
            .fill(&mut key)
            .expect("the OS random source failed");
        Self {
            idp,
            entity_id: cfg.entity_id(),
            acs_url: cfg.acs_url(),
            sid_attribute: cfg.sid_attribute.clone(),
            skew: cfg.clock_skew_secs as i64,
            flow_key: hmac::Key::new(hmac::HMAC_SHA256, &key),
            spent: Mutex::new(HashMap::new()),
            #[cfg(test)]
            test_now: None,
        }
    }

    /// The time requests are made and responses checked at.
    pub fn now(&self) -> i64 {
        #[cfg(test)]
        if let Some(t) = self.test_now {
            return t;
        }
        crate::store::now()
    }

    /// This proxy's metadata, for IT to import as a relying party.
    pub fn metadata(&self) -> String {
        format!(
            concat!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
                "<md:EntityDescriptor xmlns:md=\"{md}\" entityID=\"{id}\">\n",
                "  <md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\" ",
                "protocolSupportEnumeration=\"{proto}\">\n",
                "    <md:AssertionConsumerService Binding=\"{post}\" Location=\"{acs}\" index=\"0\" ",
                "isDefault=\"true\"/>\n",
                "  </md:SPSSODescriptor>\n",
                "</md:EntityDescriptor>\n"
            ),
            md = NS_METADATA,
            id = xml_escape(&self.entity_id),
            proto = NS_PROTOCOL,
            post = BINDING_POST,
            acs = xml_escape(&self.acs_url),
        )
    }

    fn flow_mac(&self, id: &str, expires: i64) -> String {
        hmac::sign(&self.flow_key, format!("{id}.{expires}").as_bytes())
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// A new sign-in: the identity provider URL to send the browser to, and the flow cookie value
    /// that the response must come back with. Nothing is stored until a response is accepted.
    pub fn start(&self, now: i64) -> (String, String) {
        let id = format!("_{}", &crate::auth::random_token()[..40]);
        let expires = now + FLOW_SECS;
        let flow = format!("{id}.{expires}.{}", self.flow_mac(&id, expires));
        let request = format!(
            concat!(
                "<samlp:AuthnRequest xmlns:samlp=\"{proto}\" xmlns:saml=\"{assertion}\" ",
                "ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{at}\" Destination=\"{dest}\" ",
                "AssertionConsumerServiceURL=\"{acs}\" ProtocolBinding=\"{post}\">",
                "<saml:Issuer>{issuer}</saml:Issuer></samlp:AuthnRequest>"
            ),
            proto = NS_PROTOCOL,
            assertion = NS_ASSERTION,
            id = id,
            at = instant(now),
            dest = xml_escape(&self.idp.sso_url),
            acs = xml_escape(&self.acs_url),
            post = BINDING_POST,
            issuer = xml_escape(&self.entity_id),
        );
        let mut deflate =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        deflate
            .write_all(request.as_bytes())
            .expect("deflating to memory");
        let encoded = STANDARD.encode(deflate.finish().expect("deflating to memory"));
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("SAMLRequest", &encoded)
            .finish();
        let sep = if self.idp.sso_url.contains('?') {
            '&'
        } else {
            '?'
        };
        (format!("{}{sep}{query}", self.idp.sso_url), flow)
    }

    /// The request ID a flow cookie was issued for, while it is current.
    fn flow_request(&self, flow: Option<&str>, now: i64) -> Result<String, SamlError> {
        const LOST: &str = "this browser did not start the sign-in, or took longer than five \
                            minutes; start it again from this proxy's page";
        let Some(flow) = flow else {
            return refuse(LOST);
        };
        let mut parts = flow.rsplitn(3, '.');
        let (Some(mac), Some(expires), Some(id)) = (parts.next(), parts.next(), parts.next())
        else {
            return refuse(LOST);
        };
        let (Ok(expires), Some(tag)) = (expires.parse::<i64>(), hex_bytes(mac)) else {
            return refuse(LOST);
        };
        let signed = format!("{id}.{expires}");
        if hmac::verify(&self.flow_key, signed.as_bytes(), &tag).is_err() || expires <= now {
            return refuse(LOST);
        }
        Ok(id.to_owned())
    }

    /// Checks a SAMLResponse from the POST binding against the flow cookie it arrived with.
    pub fn accept(
        &self,
        saml_response: &str,
        flow: Option<&str>,
        now: i64,
    ) -> Result<Verified, SamlError> {
        let request_id = self.flow_request(flow, now)?;
        let compact: String = saml_response
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        if compact.len() > MAX_RESPONSE_BYTES / 3 * 4 + 4 {
            return refuse("the identity provider's response is too large");
        }
        let Ok(bytes) = STANDARD.decode(compact) else {
            return refuse("the identity provider's response is not base64");
        };
        let Ok(xml) = String::from_utf8(bytes) else {
            return refuse("the identity provider's response is not UTF-8");
        };
        let doc = match parse(&xml) {
            Ok(d) => d,
            Err(e) => return refuse(format!("the identity provider's response is refused: {e}")),
        };
        plain(&doc)?;
        let Some(root) = doc.document_element() else {
            return refuse("the identity provider's response is empty");
        };
        if !is(&doc, root, NS_PROTOCOL, "Response") || attr(&doc, root, "Version") != Some("2.0") {
            return refuse("the identity provider did not send a SAML 2.0 Response");
        }
        match attr(&doc, root, "InResponseTo") {
            None => {
                return refuse(
                    "the identity provider sent a sign-in this proxy did not ask for; start the \
                     sign-in from this proxy's page",
                )
            }
            Some(irt) if irt != request_id => {
                return refuse(
                    "the response answers a different sign-in than this browser started; start \
                     again",
                )
            }
            Some(_) => {}
        }
        if let Some(dest) = attr(&doc, root, "Destination") {
            if dest != self.acs_url {
                return refuse(format!(
                    "the response is addressed to {dest}, not {}",
                    self.acs_url
                ));
            }
        }
        if let Some(issuer) = one_child(&doc, root, NS_ASSERTION, "Issuer")? {
            if text(&doc, issuer)? != self.idp.entity_id {
                return refuse("the response is from a different identity provider");
            }
        }
        self.check_status(&doc, root)?;
        if !children_named(&doc, root, NS_ASSERTION, "EncryptedAssertion").is_empty() {
            return refuse(
                "the identity provider encrypted the assertion; ask IT to send it signed and \
                 unencrypted to this relying party",
            );
        }
        let all: Vec<NodeId> = doc
            .descendants(root)
            .into_iter()
            .filter(|n| is(&doc, *n, NS_ASSERTION, "Assertion"))
            .collect();
        let direct = children_named(&doc, root, NS_ASSERTION, "Assertion");
        if direct.len() != 1 || all.len() != 1 {
            return refuse("the response must carry exactly one assertion");
        }
        let assertion = direct[0];
        self.check_signatures(&doc, root, assertion)?;
        let (verified, assertion_id, expires) =
            self.check_assertion(&doc, assertion, &request_id, now)?;
        // Both IDs are spent only by a response that passed every check, so a forged response
        // cannot fill the table.
        let mut spent = lock(&self.spent);
        spent.retain(|_, until| *until > now);
        let (request_key, assertion_key) = (format!("r:{request_id}"), format!("a:{assertion_id}"));
        if spent.contains_key(&request_key) || spent.contains_key(&assertion_key) {
            return refuse("this sign-in was already used; start again");
        }
        if spent.len() + 2 > MAX_SPENT {
            return refuse("too many sign-ins in the last few minutes; try again shortly");
        }
        spent.insert(request_key, now + FLOW_SECS + self.skew);
        spent.insert(assertion_key, expires.max(now + FLOW_SECS) + self.skew);
        Ok(verified)
    }

    fn check_status(&self, doc: &Document<'_>, root: NodeId) -> Result<(), SamlError> {
        let status = required_child(doc, root, NS_PROTOCOL, "Status")?;
        let code = required_child(doc, status, NS_PROTOCOL, "StatusCode")?;
        let value = attr(doc, code, "Value").unwrap_or("");
        if value == STATUS_SUCCESS {
            return Ok(());
        }
        let short = |v: &str| v.rsplit(':').next().unwrap_or(v).to_owned();
        let mut why = short(value);
        if let Some(sub) = one_child(doc, code, NS_PROTOCOL, "StatusCode")? {
            why = format!("{why}/{}", short(attr(doc, sub, "Value").unwrap_or("")));
        }
        if let Some(m) = one_child(doc, status, NS_PROTOCOL, "StatusMessage")? {
            why = format!("{why}: {}", text(doc, m)?);
        }
        refuse(format!("the identity provider refused the sign-in ({why})"))
    }

    /// Every signature in the document verifies against a pinned certificate, each has the one
    /// shape this proxy accepts, and one of them is enveloped in the Assertion and covers it.
    fn check_signatures(
        &self,
        doc: &Document<'_>,
        root: NodeId,
        assertion: NodeId,
    ) -> Result<(), SamlError> {
        let sigs: Vec<NodeId> = doc
            .descendants(root)
            .into_iter()
            .filter(|n| is(doc, *n, NS_DSIG, "Signature"))
            .collect();
        if sigs.is_empty() {
            return refuse("the assertion is not signed");
        }
        for s in &sigs {
            check_signature_shape(doc, *s)?;
            let parent = doc.parent(*s);
            if parent != Some(root) && parent != Some(assertion) {
                return refuse("a signature is somewhere other than the Response or the Assertion");
            }
        }
        let mut valid = vec![false; sigs.len()];
        let mut covers_assertion = false;
        for cert in &self.idp.certs {
            let key = bergshamra_keys::loader::load_x509_cert_der(cert)
                .map_err(|e| SamlError::Refused(format!("a pinned certificate: {e}")))?;
            let mut keys = KeysManager::new();
            keys.add_key(key);
            let ctx = DsigContext::new(keys);
            let results = verify_all_document(&ctx, doc)
                .map_err(|e| SamlError::Refused(format!("the signature cannot be checked: {e}")))?;
            if results.len() != sigs.len() {
                return refuse("the signatures found differ from the signatures checked");
            }
            for (i, r) in results.iter().enumerate() {
                let VerifyResult::Valid {
                    signature_node,
                    references,
                    ..
                } = r
                else {
                    continue;
                };
                if *signature_node != sigs[i] || !r.all_reference_digests_verified() {
                    continue;
                }
                let [reference] = &references[..] else {
                    continue;
                };
                let signed = doc.parent(sigs[i]);
                if reference.resolved_node != signed {
                    continue;
                }
                valid[i] = true;
                covers_assertion |= signed == Some(assertion);
            }
        }
        if !valid.iter().all(|v| *v) {
            return refuse(
                "a signature did not verify against the identity provider's certificates",
            );
        }
        if !covers_assertion {
            return refuse("the assertion is not signed");
        }
        Ok(())
    }

    /// The checks of the Web SSO profile on the signed assertion. Returns what was verified, the
    /// assertion ID and the last moment the assertion could be accepted.
    fn check_assertion(
        &self,
        doc: &Document<'_>,
        a: NodeId,
        request_id: &str,
        now: i64,
    ) -> Result<(Verified, String, i64), SamlError> {
        let skew = self.skew;
        if attr(doc, a, "Version") != Some("2.0") {
            return refuse("the assertion is not SAML 2.0");
        }
        let Some(id) = attr(doc, a, "ID").filter(|v| !v.is_empty()) else {
            return refuse("the assertion has no ID");
        };
        let issuer = required_child(doc, a, NS_ASSERTION, "Issuer")?;
        if text(doc, issuer)? != self.idp.entity_id {
            return refuse("the assertion is from a different identity provider");
        }
        match time_attr(doc, a, "IssueInstant")? {
            Some(t) if t <= now + skew => {}
            Some(_) => {
                return refuse(
                    "the assertion was issued in the future; check the clocks of this proxy and \
                     the identity provider",
                )
            }
            None => return refuse("the assertion has no IssueInstant"),
        }

        let subject = required_child(doc, a, NS_ASSERTION, "Subject")?;
        let name_id = match one_child(doc, subject, NS_ASSERTION, "NameID")? {
            Some(n) => Some(text(doc, n)?),
            None => None,
        };
        let mut confirmed_until: Option<i64> = None;
        for sc in children_named(doc, subject, NS_ASSERTION, "SubjectConfirmation") {
            if attr(doc, sc, "Method") != Some(BEARER) {
                continue;
            }
            let Some(data) = one_child(doc, sc, NS_ASSERTION, "SubjectConfirmationData")? else {
                continue;
            };
            let until = time_attr(doc, data, "NotOnOrAfter")?;
            if attr(doc, data, "Recipient") == Some(self.acs_url.as_str())
                && attr(doc, data, "InResponseTo") == Some(request_id)
                && attr(doc, data, "NotBefore").is_none()
                && until.is_some_and(|u| now < u + skew)
            {
                confirmed_until = confirmed_until.max(until);
            }
        }
        let Some(confirmed_until) = confirmed_until else {
            return refuse(
                "the assertion is not addressed to this proxy's sign-in, or it has expired",
            );
        };

        let conditions = required_child(doc, a, NS_ASSERTION, "Conditions")?;
        if time_attr(doc, conditions, "NotBefore")?.is_some_and(|t| now + skew < t) {
            return refuse("the assertion is not valid yet; check the clocks");
        }
        let conditions_until = time_attr(doc, conditions, "NotOnOrAfter")?;
        if conditions_until.is_some_and(|t| now >= t + skew) {
            return refuse("the assertion has expired");
        }
        let mut audiences = 0;
        for c in child_elements(doc, conditions) {
            if is(doc, c, NS_ASSERTION, "AudienceRestriction") {
                let mut ours = false;
                for au in children_named(doc, c, NS_ASSERTION, "Audience") {
                    ours |= text(doc, au)? == self.entity_id;
                }
                if !ours {
                    return refuse(format!(
                        "the assertion is for another relying party, not {}",
                        self.entity_id
                    ));
                }
                audiences += 1;
            } else if !is(doc, c, NS_ASSERTION, "OneTimeUse")
                && !is(doc, c, NS_ASSERTION, "ProxyRestriction")
            {
                return refuse("the assertion carries a condition this proxy does not understand");
            }
        }
        if audiences == 0 {
            return refuse("the assertion names no audience");
        }

        let statements = children_named(doc, a, NS_ASSERTION, "AuthnStatement");
        if statements.is_empty() {
            return refuse("the assertion has no AuthnStatement");
        }
        for s in statements {
            if time_attr(doc, s, "SessionNotOnOrAfter")?.is_some_and(|t| t <= now) {
                return refuse("the identity provider's session has ended; sign in again");
            }
        }

        let mut found: Vec<NodeId> = Vec::new();
        for st in children_named(doc, a, NS_ASSERTION, "AttributeStatement") {
            for at in children_named(doc, st, NS_ASSERTION, "Attribute") {
                if attr(doc, at, "Name") == Some(self.sid_attribute.as_str()) {
                    found.push(at);
                }
            }
        }
        let [sid_attr] = found[..] else {
            return refuse(format!(
                "the assertion must carry the {} attribute once",
                self.sid_attribute
            ));
        };
        let values = children_named(doc, sid_attr, NS_ASSERTION, "AttributeValue");
        let [value] = values[..] else {
            return refuse(format!(
                "the {} attribute must hold one value",
                self.sid_attribute
            ));
        };
        let raw = text(doc, value)?;
        let Some(sid) = crate::directory::canonical_sid(&raw) else {
            return refuse(format!(
                "the {} attribute holds {raw:?}, which is not a SID",
                self.sid_attribute
            ));
        };
        let expires = conditions_until.map_or(confirmed_until, |c| c.max(confirmed_until));
        Ok((Verified { sid, name_id }, id.to_owned(), expires))
    }
}

/// The one signature shape this proxy accepts: exclusive c14n without comments, an RSA SHA-2
/// signature, and one same-document Reference whose transforms are exactly enveloped-signature
/// then exclusive c14n. No Object, no external or XPath reference, nothing that reads a file.
fn check_signature_shape(doc: &Document<'_>, sig: NodeId) -> Result<(), SamlError> {
    const SHAPE: &str = "a signature has a form this proxy does not accept";
    let algorithm = |id: NodeId| attr(doc, id, "Algorithm").unwrap_or("");
    for c in child_elements(doc, sig) {
        let ok = is(doc, c, NS_DSIG, "SignedInfo")
            || is(doc, c, NS_DSIG, "SignatureValue")
            || is(doc, c, NS_DSIG, "KeyInfo");
        if !ok {
            return refuse(SHAPE);
        }
    }
    let info = required_child(doc, sig, NS_DSIG, "SignedInfo")?;
    let mut c14n = 0;
    let mut method = 0;
    let mut references = Vec::new();
    for c in child_elements(doc, info) {
        if is(doc, c, NS_DSIG, "CanonicalizationMethod") && algorithm(c) == EXC_C14N {
            c14n += 1;
        } else if is(doc, c, NS_DSIG, "SignatureMethod")
            && SIGNATURE_METHODS.contains(&algorithm(c))
            && child_elements(doc, c).is_empty()
        {
            method += 1;
        } else if is(doc, c, NS_DSIG, "Reference") {
            references.push(c);
        } else {
            return refuse(SHAPE);
        }
    }
    let [reference] = references[..] else {
        return refuse(SHAPE);
    };
    if c14n != 1 || method != 1 {
        return refuse(SHAPE);
    }
    let uri = attr(doc, reference, "URI").unwrap_or("");
    let target = uri.strip_prefix('#').unwrap_or("");
    if target.is_empty()
        || !target
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return refuse(SHAPE);
    }
    let mut transforms = None;
    let mut digest = 0;
    let mut value = 0;
    for c in child_elements(doc, reference) {
        if is(doc, c, NS_DSIG, "Transforms") && transforms.is_none() {
            transforms = Some(c);
        } else if is(doc, c, NS_DSIG, "DigestMethod")
            && DIGEST_METHODS.contains(&algorithm(c))
            && child_elements(doc, c).is_empty()
        {
            digest += 1;
        } else if is(doc, c, NS_DSIG, "DigestValue") {
            value += 1;
        } else {
            return refuse(SHAPE);
        }
    }
    let Some(transforms) = transforms else {
        return refuse(SHAPE);
    };
    let steps = child_elements(doc, transforms);
    let [enveloped, exclusive] = steps[..] else {
        return refuse(SHAPE);
    };
    let transform_ok =
        |t: NodeId, alg: &str| is(doc, t, NS_DSIG, "Transform") && algorithm(t) == alg;
    if !transform_ok(enveloped, ENVELOPED)
        || !child_elements(doc, enveloped).is_empty()
        || !transform_ok(exclusive, EXC_C14N)
        || digest != 1
        || value != 1
    {
        return refuse(SHAPE);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    // Signed by xmlsec1 (scripts/saml-fixtures.sh). Key a signs; key b is the metadata's
    // encryption key, then a second signing key in the rollover metadata.
    const META: &str = include_str!("../tests/fixtures/saml/idp-metadata.xml");
    const ROLLOVER: &str = include_str!("../tests/fixtures/saml/idp-metadata-rollover.xml");
    const SIGNED: &str = include_str!("../tests/fixtures/saml/response-assertion-signed.xml");
    const BOTH: &str = include_str!("../tests/fixtures/saml/response-both-signed.xml");
    const RESPONSE_ONLY: &str = include_str!("../tests/fixtures/saml/response-response-signed.xml");
    const KEY_B: &str = include_str!("../tests/fixtures/saml/response-key-b.xml");
    const SID: &str = "S-1-5-21-1004336348-1177238915-682003330-1105";
    const ACS: &str = "https://access.example.test/api/saml/acs";

    fn cfg() -> SamlConfig {
        SamlConfig {
            url: "https://access.example.test".into(),
            idp_metadata: String::new(),
            entity_id: None,
            sid_attribute: "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid"
                .into(),
            clock_skew_secs: 180,
        }
    }

    fn sp_with(c: &SamlConfig, meta: &str) -> ServiceProvider {
        ServiceProvider::new(c, parse_metadata(meta).unwrap())
    }

    fn sp() -> ServiceProvider {
        sp_with(&cfg(), META)
    }

    /// One minute after the fixtures were issued.
    fn at() -> i64 {
        parse_instant("2026-10-08T12:01:00Z").unwrap()
    }

    impl ServiceProvider {
        /// The flow cookie `start` would have set for request `id`.
        pub(crate) fn flow_for(&self, id: &str, expires: i64) -> String {
            format!("{id}.{expires}.{}", self.flow_mac(id, expires))
        }

        /// The response, from the browser that started request `_req1`.
        fn take(&self, xml: &str) -> Result<Verified, SamlError> {
            let flow = self.flow_for("_req1", at() + FLOW_SECS);
            self.accept(&STANDARD.encode(xml), Some(&flow), at())
        }
    }

    #[track_caller]
    fn refused(r: Result<Verified, SamlError>, says: &str) {
        match r {
            Err(SamlError::Refused(m)) => assert!(m.contains(says), "refused, but: {m}"),
            other => panic!("not refused: {other:?}"),
        }
    }

    /// The signed Assertion element of `SIGNED`.
    fn signed_assertion() -> &'static str {
        &SIGNED[SIGNED.find("<saml:Assertion").unwrap()..SIGNED.find("</samlp:Response>").unwrap()]
    }

    /// The same assertion with its signature cut out, its ID and name changed.
    fn forged_assertion() -> String {
        let a = signed_assertion();
        let start = a.find("<ds:Signature").unwrap();
        let end = a.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
        format!("{}{}", &a[..start], &a[end..])
            .replace("ID=\"_a1\"", "ID=\"_forged\"")
            .replace("jdoe@", "boss@")
    }

    #[test]
    fn a_signed_assertion_signs_in() {
        let v = sp().take(SIGNED).unwrap();
        assert_eq!(v.sid, SID);
        assert_eq!(v.name_id.as_deref(), Some("jdoe@corp.example.test"));
    }

    #[test]
    fn a_response_signed_as_well_signs_in() {
        assert_eq!(sp().take(BOTH).unwrap().sid, SID);
    }

    #[test]
    fn a_signature_on_the_response_alone_is_not_enough() {
        refused(sp().take(RESPONSE_ONLY), "the assertion is not signed");
    }

    #[test]
    fn a_key_outside_the_metadata_and_an_encryption_key_do_not_verify() {
        refused(sp().take(KEY_B), "did not verify");
    }

    #[test]
    fn during_a_rollover_either_signing_key_verifies() {
        assert_eq!(sp_with(&cfg(), ROLLOVER).take(KEY_B).unwrap().sid, SID);
        assert_eq!(sp_with(&cfg(), ROLLOVER).take(SIGNED).unwrap().sid, SID);
    }

    #[test]
    fn a_changed_name_breaks_the_signature() {
        refused(
            sp().take(&SIGNED.replace("jdoe@corp", "boss@corp")),
            "did not verify",
        );
    }

    #[test]
    fn comments_and_dtds_are_refused_before_anything_is_read() {
        let commented = SIGNED.replace(
            "jdoe@corp.example.test</saml:NameID>",
            "jdoe@corp.example.test<!---->.evil</saml:NameID>",
        );
        refused(sp().take(&commented), "comments");
        let dtd = format!("<!DOCTYPE r [<!ENTITY x \"y\">]>{SIGNED}");
        refused(sp().take(&dtd), "response is refused");
    }

    #[test]
    fn a_second_assertion_is_refused_wherever_it_is() {
        let signed = signed_assertion();
        let forged = forged_assertion();
        let hidden = forged.replace(
            "<saml:Subject>",
            &format!("<saml:Advice>{signed}</saml:Advice><saml:Subject>"),
        );
        for xml in [
            SIGNED.replace("<saml:Assertion", &format!("{forged}<saml:Assertion")),
            SIGNED.replace("</samlp:Response>", &format!("{forged}</samlp:Response>")),
            SIGNED.replace(signed, &hidden),
        ] {
            refused(sp().take(&xml), "exactly one assertion");
        }
    }

    #[test]
    fn a_valid_signature_moved_off_the_assertion_does_not_cover_it() {
        // The enveloped transform drops the signature, so the assertion without it has the same
        // digest: only the signature's place ties it to what it signs.
        let a = signed_assertion();
        let start = a.find("<ds:Signature").unwrap();
        let end = a.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
        let bare = format!("{}{}", &a[..start], &a[end..]);
        let moved = SIGNED.replace(a, &bare).replace(
            "</saml:Issuer><samlp:Status>",
            &format!("</saml:Issuer>{}<samlp:Status>", &a[start..end]),
        );
        assert!(moved.contains("<ds:Signature"));
        refused(sp().take(&moved), "signature");
    }

    #[test]
    fn the_response_belongs_to_the_browser_that_asked_and_is_used_once() {
        let sp = sp();
        let xml = STANDARD.encode(SIGNED);
        refused(sp.accept(&xml, None, at()), "did not start");
        refused(
            sp.accept(&xml, Some("_req1.99999999999.00"), at()),
            "did not start",
        );
        let other_process = sp_with(&cfg(), META).flow_for("_req1", at() + FLOW_SECS);
        refused(sp.accept(&xml, Some(&other_process), at()), "did not start");
        let expired = sp.flow_for("_req1", at());
        refused(sp.accept(&xml, Some(&expired), at()), "did not start");
        let other_request = sp.flow_for("_req2", at() + FLOW_SECS);
        refused(
            sp.accept(&xml, Some(&other_request), at()),
            "different sign-in",
        );
        let flow = sp.flow_for("_req1", at() + FLOW_SECS);
        sp.accept(&xml, Some(&flow), at()).unwrap();
        refused(sp.accept(&xml, Some(&flow), at()), "already used");
    }

    #[test]
    fn an_unsolicited_response_is_refused() {
        let unsolicited = SIGNED.replacen(" InResponseTo=\"_req1\"", "", 1);
        refused(sp().take(&unsolicited), "did not ask for");
    }

    #[test]
    fn times_hold_within_the_skew_and_not_past_it() {
        // Issued 12:00, confirmation until 12:05, skew 180 s: 11:57:00 to 12:07:59.
        for (now, ok) in [
            ("2026-10-08T11:56:59Z", false),
            ("2026-10-08T11:57:00Z", true),
            ("2026-10-08T12:07:59Z", true),
            ("2026-10-08T12:08:00Z", false),
        ] {
            let now = parse_instant(now).unwrap();
            let sp = sp();
            let flow = sp.flow_for("_req1", now + FLOW_SECS);
            let r = sp.accept(&STANDARD.encode(SIGNED), Some(&flow), now);
            assert_eq!(r.is_ok(), ok, "{}: {r:?}", instant(now));
        }
    }

    #[test]
    fn the_status_destination_recipient_and_audience_are_checked() {
        refused(
            sp().take(&SIGNED.replace("status:Success", "status:Responder")),
            "refused the sign-in (Responder)",
        );
        refused(
            sp().take(&SIGNED.replace(
                &format!("Destination=\"{ACS}\""),
                "Destination=\"https://elsewhere.test/acs\"",
            )),
            "addressed to",
        );
        let mut other_name = cfg();
        other_name.entity_id = Some("https://other.example.test".into());
        refused(
            sp_with(&other_name, META).take(SIGNED),
            "another relying party",
        );
        // Another address, and no Destination to give it away: the signed Recipient differs.
        let mut other_address = cfg();
        other_address.url = "https://other.example.test".into();
        other_address.entity_id = Some("https://access.example.test/api/saml/metadata".into());
        let undirected = SIGNED.replacen(&format!(" Destination=\"{ACS}\""), "", 1);
        refused(
            sp_with(&other_address, META).take(&undirected),
            "not addressed to this proxy",
        );
    }

    #[test]
    fn an_encrypted_assertion_is_refused_saying_what_to_ask_for() {
        let encrypted = SIGNED.replace(
            signed_assertion(),
            "<saml:EncryptedAssertion><xenc:EncryptedData \
             xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/></saml:EncryptedAssertion>",
        );
        refused(sp().take(&encrypted), "unencrypted");
    }

    #[test]
    fn the_sid_attribute_must_be_present_once() {
        let mut c = cfg();
        c.sid_attribute = "objectSid".into();
        refused(
            sp_with(&c, META).take(SIGNED),
            "must carry the objectSid attribute once",
        );
    }

    #[test]
    fn a_signature_of_another_shape_is_refused_before_it_is_checked() {
        for (from, to) in [
            ("xmldsig-more#rsa-sha256", "xmldsig#rsa-sha1"),
            ("xmlenc#sha256", "xmldsig#sha1"),
            ("URI=\"#_a1\"", "URI=\"\""),
            ("URI=\"#_a1\"", "URI=\"secret.txt\""),
            (
                "CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"",
                "CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\"",
            ),
            (
                "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
                "",
            ),
        ] {
            assert!(SIGNED.contains(from), "{from}");
            refused(
                sp().take(&SIGNED.replacen(from, to, 1)),
                "form this proxy does not accept",
            );
        }
    }

    #[test]
    fn the_request_and_the_metadata_name_this_proxy() {
        let sp = sp();
        let (url, flow) = sp.start(at());
        let query = url
            .strip_prefix("https://idp.example.test/adfs/ls/?")
            .unwrap();
        let (_, encoded) = form_urlencoded::parse(query.as_bytes())
            .find(|(k, _)| k == "SAMLRequest")
            .unwrap();
        let mut request = String::new();
        flate2::read::DeflateDecoder::new(&STANDARD.decode(encoded.as_bytes()).unwrap()[..])
            .read_to_string(&mut request)
            .unwrap();
        let doc = parse(&request).unwrap();
        let root = doc.document_element().unwrap();
        assert!(is(&doc, root, NS_PROTOCOL, "AuthnRequest"));
        assert_eq!(attr(&doc, root, "AssertionConsumerServiceURL"), Some(ACS));
        assert_eq!(
            attr(&doc, root, "IssueInstant"),
            Some("2026-10-08T12:01:00Z")
        );
        assert_eq!(
            attr(&doc, root, "Destination"),
            Some("https://idp.example.test/adfs/ls/")
        );
        let issuer = required_child(&doc, root, NS_ASSERTION, "Issuer").unwrap();
        assert_eq!(
            text(&doc, issuer).unwrap(),
            "https://access.example.test/api/saml/metadata"
        );
        let id = attr(&doc, root, "ID").unwrap();
        assert_eq!(sp.flow_request(Some(&flow), at()).unwrap(), id);

        let md = sp.metadata();
        let doc = parse(&md).unwrap();
        let root = doc.document_element().unwrap();
        assert_eq!(
            attr(&doc, root, "entityID"),
            Some("https://access.example.test/api/saml/metadata")
        );
        assert!(md.contains(&format!("Location=\"{ACS}\"")));
    }

    #[test]
    fn metadata_gives_the_redirect_endpoint_and_only_signing_keys() {
        let idp = parse_metadata(META).unwrap();
        assert_eq!(
            idp.entity_id,
            "https://idp.example.test/adfs/services/trust"
        );
        assert_eq!(idp.sso_url, "https://idp.example.test/adfs/ls/");
        assert_eq!(idp.certs.len(), 1);
        assert_eq!(parse_metadata(ROLLOVER).unwrap().certs.len(), 2);
        let no_redirect = META.replace("bindings:HTTP-Redirect", "bindings:SOAP");
        let no_signing = META.replace("use=\"signing\"", "use=\"encryption\"");
        let two = format!(
            "<md:EntitiesDescriptor xmlns:md=\"{NS_METADATA}\">{}{}</md:EntitiesDescriptor>",
            META.trim(),
            META.trim()
        );
        for bad in [no_redirect, no_signing, two, "<x/>".to_owned()] {
            assert!(
                matches!(parse_metadata(&bad), Err(SamlError::Metadata(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn saml_times_parse_in_utc_and_bad_ones_do_not() {
        assert_eq!(parse_instant("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_instant("2026-10-08T12:01:00Z"), Some(1_791_460_860));
        assert_eq!(
            parse_instant("2026-10-08T12:01:00.123Z"),
            parse_instant("2026-10-08T12:01:00Z")
        );
        assert_eq!(
            instant(parse_instant("2024-02-29T23:59:59Z").unwrap()),
            "2024-02-29T23:59:59Z"
        );
        for bad in [
            "2026-10-08T12:01:00",
            "2026-10-08T12:01:00+00:00",
            "2025-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-10-08 12:01:00Z",
            "26-10-08T12:01:00Z",
            "2026-10-08T12:01:00.Z",
            "2026-10-08T24:00:00Z",
        ] {
            assert_eq!(parse_instant(bad), None, "{bad}");
        }
    }
}
