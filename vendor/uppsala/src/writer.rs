//! Imperative XML writer for constructing XML documents and fragments.
//!
//! [`XmlWriter`] provides a push-based API for building XML output without
//! needing to construct a full DOM tree first. This is useful for generating
//! XML fragments, building templates, or any scenario where streaming
//! construction is more natural than tree manipulation.
//!
//! # Example
//!
//! ```
//! use uppsala::XmlWriter;
//!
//! let mut w = XmlWriter::new();
//! w.write_declaration();
//! w.start_element("root", &[("xmlns", "http://example.com")]);
//! w.start_element("child", &[("id", "1")]);
//! w.text("Hello, world!");
//! w.end_element("child");
//! w.empty_element("empty", &[]);
//! w.end_element("root");
//!
//! let xml = w.into_string();
//! assert!(xml.starts_with("<?xml"));
//! ```

use std::borrow::Cow;

/// An imperative XML writer that builds output incrementally.
///
/// Content is written to an internal buffer. Text and attribute values are
/// automatically escaped. Use [`raw`](XmlWriter::raw) to inject pre-escaped
/// content.
pub struct XmlWriter {
    buf: String,
}

impl XmlWriter {
    /// Create a new empty XML writer.
    pub fn new() -> Self {
        XmlWriter { buf: String::new() }
    }

    /// Create a new XML writer with a pre-allocated buffer capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        XmlWriter {
            buf: String::with_capacity(capacity),
        }
    }

    /// Write the XML declaration: `<?xml version="1.0" encoding="UTF-8"?>`.
    pub fn write_declaration(&mut self) {
        self.buf
            .push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    }

    /// Write a custom XML declaration with the specified version, optional encoding,
    /// and optional standalone flag.
    pub fn write_declaration_full(
        &mut self,
        version: &str,
        encoding: Option<&str>,
        standalone: Option<bool>,
    ) {
        self.buf.push_str("<?xml version=\"");
        self.buf.push_str(&safe_xml_version(version));
        self.buf.push('"');
        if let Some(enc) = encoding {
            self.buf.push_str(" encoding=\"");
            self.buf.push_str(&safe_xml_encoding(enc));
            self.buf.push('"');
        }
        if let Some(sa) = standalone {
            self.buf.push_str(" standalone=\"");
            self.buf.push_str(if sa { "yes" } else { "no" });
            self.buf.push('"');
        }
        self.buf.push_str("?>");
    }

    /// Open an element with the given name and attributes.
    ///
    /// Attributes are written as `key="escaped_value"`. You must call
    /// [`end_element`](XmlWriter::end_element) with the same name to close it.
    ///
    /// # Example
    ///
    /// ```
    /// use uppsala::XmlWriter;
    ///
    /// let mut w = XmlWriter::new();
    /// w.start_element("div", &[("class", "main"), ("id", "content")]);
    /// w.text("Hello");
    /// w.end_element("div");
    /// assert_eq!(w.into_string(), r#"<div class="main" id="content">Hello</div>"#);
    /// ```
    pub fn start_element(&mut self, name: &str, attrs: &[(&str, &str)]) {
        let name = safe_xml_qname(name);
        self.buf.push('<');
        self.buf.push_str(&name);
        let mut seen_attrs = Vec::new();
        for &(key, val) in attrs {
            write_sanitized_attr_to_string(&mut self.buf, key, val, &mut seen_attrs);
        }
        self.buf.push('>');
    }

    /// Write a self-closing empty element: `<name attr="val"/>`.
    ///
    /// # Example
    ///
    /// ```
    /// use uppsala::XmlWriter;
    ///
    /// let mut w = XmlWriter::new();
    /// w.empty_element("br", &[]);
    /// assert_eq!(w.into_string(), "<br/>");
    /// ```
    pub fn empty_element(&mut self, name: &str, attrs: &[(&str, &str)]) {
        let name = safe_xml_qname(name);
        self.buf.push('<');
        self.buf.push_str(&name);
        let mut seen_attrs = Vec::new();
        for &(key, val) in attrs {
            write_sanitized_attr_to_string(&mut self.buf, key, val, &mut seen_attrs);
        }
        self.buf.push_str("/>");
    }

    /// Open an element with attributes whose values implement `AsRef<str>`.
    ///
    /// This is a more flexible version of [`start_element`](Self::start_element)
    /// that accepts owned `String` values directly, avoiding the need to build
    /// a temporary `Vec<(&str, &str)>` when some values are computed.
    ///
    /// # Example
    ///
    /// ```
    /// use uppsala::XmlWriter;
    ///
    /// let mut w = XmlWriter::new();
    /// let count = 42.to_string();
    /// w.start_element_with("item", [("id", count.as_str()), ("type", "fixed")]);
    /// w.end_element("item");
    /// assert_eq!(w.into_string(), r#"<item id="42" type="fixed"></item>"#);
    /// ```
    pub fn start_element_with<I, K, V>(&mut self, name: &str, attrs: I)
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let name = safe_xml_qname(name);
        self.buf.push('<');
        self.buf.push_str(&name);
        // Collect first so the seen-name borrows outlive the loop (the
        // iterator's items are owned per-iteration otherwise).
        let attrs: Vec<(K, V)> = attrs.into_iter().collect();
        let mut seen_attrs = Vec::new();
        for (key, val) in &attrs {
            write_sanitized_attr_to_string(
                &mut self.buf,
                key.as_ref(),
                val.as_ref(),
                &mut seen_attrs,
            );
        }
        self.buf.push('>');
    }

    /// Write a self-closing empty element with generic attribute values.
    ///
    /// This is a more flexible version of [`empty_element`](Self::empty_element)
    /// that accepts owned `String` values directly.
    ///
    /// # Example
    ///
    /// ```
    /// use uppsala::XmlWriter;
    ///
    /// let mut w = XmlWriter::new();
    /// let id = 7.to_string();
    /// w.empty_element_with("br", [("id", id.as_str())]);
    /// assert_eq!(w.into_string(), r#"<br id="7"/>"#);
    /// ```
    pub fn empty_element_with<I, K, V>(&mut self, name: &str, attrs: I)
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let name = safe_xml_qname(name);
        self.buf.push('<');
        self.buf.push_str(&name);
        // Collect first so the seen-name borrows outlive the loop.
        let attrs: Vec<(K, V)> = attrs.into_iter().collect();
        let mut seen_attrs = Vec::new();
        for (key, val) in &attrs {
            write_sanitized_attr_to_string(
                &mut self.buf,
                key.as_ref(),
                val.as_ref(),
                &mut seen_attrs,
            );
        }
        self.buf.push_str("/>");
    }

    /// Write an expanded empty element: `<name attr="val"></name>`.
    ///
    /// This is the form required by W3C Canonical XML (C14N).
    pub fn empty_element_expanded(&mut self, name: &str, attrs: &[(&str, &str)]) {
        let name = safe_xml_qname(name);
        self.buf.push('<');
        self.buf.push_str(&name);
        let mut seen_attrs = Vec::new();
        for &(key, val) in attrs {
            write_sanitized_attr_to_string(&mut self.buf, key, val, &mut seen_attrs);
        }
        self.buf.push_str("></");
        self.buf.push_str(&name);
        self.buf.push('>');
    }

    /// Close an element: `</name>`.
    pub fn end_element(&mut self, name: &str) {
        let name = safe_xml_qname(name);
        self.buf.push_str("</");
        self.buf.push_str(&name);
        self.buf.push('>');
    }

    /// Write escaped text content.
    ///
    /// Special characters (`&`, `<`, `>`, `\r`) are automatically escaped.
    pub fn text(&mut self, content: &str) {
        write_escaped_text_to_string(&mut self.buf, content);
    }

    /// Write a CDATA section: `<![CDATA[content]]>`.
    ///
    /// If `content` contains the CDATA terminator `]]>` it is split across
    /// multiple CDATA sections per the standard workaround, so the emitted
    /// text reparses to exactly the input. Callers do not need to
    /// pre-validate content.
    pub fn cdata(&mut self, content: &str) {
        self.buf.push_str("<![CDATA[");
        self.buf.push_str(&split_cdata_content(content));
        self.buf.push_str("]]>");
    }

    /// Write a comment: `<!--content-->`.
    ///
    /// Sequences of `-` characters are automatically separated by spaces and
    /// a trailing `-` is padded, so a comment with any content remains
    /// well-formed (comments must not contain `--` or end with `-` per
    /// XML 1.0 section 2.5). The sanitized output round-trips to a single
    /// well-formed comment rather than terminating early and smuggling
    /// markup.
    pub fn comment(&mut self, content: &str) {
        self.buf.push_str("<!--");
        self.buf.push_str(&sanitize_comment_content(content));
        self.buf.push_str("-->");
    }

    /// Write a processing instruction: `<?target data?>` or `<?target?>`.
    ///
    /// Two sanitizations are applied. A `target` that case-insensitively
    /// matches the reserved name `xml` is renamed to `_xml` so the emitted
    /// PI cannot be confused with an XML declaration on reparse. If `data`
    /// contains the PI terminator `?>`, a space is inserted between the
    /// two characters so the PI does not terminate early.
    pub fn processing_instruction(&mut self, target: &str, data: Option<&str>) {
        self.buf.push_str("<?");
        self.buf.push_str(&sanitize_pi_target(target));
        if let Some(d) = data {
            self.buf.push(' ');
            self.buf.push_str(&sanitize_pi_data(d));
        }
        self.buf.push_str("?>");
    }

    /// Inject raw, pre-escaped XML content.
    ///
    /// No escaping is performed. Use this when you have XML content that is
    /// already properly escaped or when embedding pre-built fragments.
    pub fn raw(&mut self, xml: &str) {
        self.buf.push_str(xml);
    }

    /// Get a reference to the current output.
    pub fn as_str(&self) -> &str {
        &self.buf
    }

    /// Consume the writer and return the output string.
    pub fn into_string(self) -> String {
        self.buf
    }

    /// Consume the writer and return the output as bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf.into_bytes()
    }

    /// Returns the current length of the output in bytes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns true if no output has been written.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Default for XmlWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for XmlWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.buf)
    }
}

// ─── Structural-markup sanitizers (F-13 / F-14 / F-15) ─────────────────────
//
// These three functions prevent "round-trip injection" attacks where an
// attacker-controlled comment, PI, or CDATA body contains the section's
// own terminator (`-->`, `?>`, `]]>`) and thereby smuggles arbitrary XML
// into the emitted output. Each returns `Cow::Borrowed` when the input is
// already safe (the common case) and `Cow::Owned` only when sanitization
// is needed. Shared between `XmlWriter` and the DOM serializer so both
// entry points close the same hole.

/// Sanitize comment content so it cannot contain `--` or end with `-`,
/// both of which would break XML 1.0 comment well-formedness (and in the
/// adversarial case let the comment terminate early and smuggle markup).
///
/// Consecutive `-` characters are separated by a space; a trailing `-`
/// gets a trailing space. The transform is reversible *semantically* (the
/// intent of the text is preserved; a human reading the comment sees the
/// same words) but byte-inequivalent.
pub(crate) fn sanitize_comment_content(s: &str) -> Cow<'_, str> {
    if !s.contains("--") && !s.ends_with('-') && s.chars().all(is_xml_char) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 4);
    let mut prev_was_dash = false;
    for c in s.chars() {
        let c = sanitized_xml_char(c);
        if c == '-' && prev_was_dash {
            out.push(' ');
        }
        out.push(c);
        prev_was_dash = c == '-';
    }
    if out.ends_with('-') {
        out.push(' ');
    }
    Cow::Owned(out)
}

/// Sanitize PI data so it cannot contain the PI terminator `?>`. A space
/// is inserted between the `?` and `>` so the byte sequence no longer
/// matches the parser's terminator scan.
pub(crate) fn sanitize_pi_data(s: &str) -> Cow<'_, str> {
    if !s.contains("?>") && s.chars().all(is_xml_char) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 4);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        let c = sanitized_xml_char(c);
        if c == '?' && chars.peek() == Some(&'>') {
            out.push('?');
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Sanitize a PI target so it cannot collide with the reserved name
/// `xml` (case-insensitive per XML 1.0 section 2.6). Without this, a
/// programmatic `processing_instruction("xml", ...)` would emit bytes
/// syntactically indistinguishable from an XML declaration - and an
/// attacker who controls the target name could force a malformed or
/// reparse-rejected document. Renaming to `_xml` preserves the "this
/// is a PI" intent while making the output unambiguously a PI node.
pub(crate) fn sanitize_pi_target(s: &str) -> Cow<'_, str> {
    // The reserved target `xml` (any case) is renamed so the PI cannot be
    // mistaken for an XML declaration.
    if s.eq_ignore_ascii_case("xml") {
        return Cow::Owned(format!("_{}", s));
    }
    // A PI target must be a valid XML NCName (no ':'). Without this check a target
    // containing `?>` plus markup (e.g. `foo?><evil>`) is written verbatim
    // between `<?` and the data, breaking out of PI position and smuggling
    // sibling elements into the output. Any invalid target collapses to `_`.
    if is_valid_xml_ncname(s) {
        Cow::Borrowed(s)
    } else {
        Cow::Borrowed("_")
    }
}

/// Split CDATA content at every occurrence of `]]>` using the standard
/// `]]]]><![CDATA[>` workaround. XML 1.0 forbids `]]>` inside a single
/// CDATA section, but two adjacent CDATA sections that each contain half
/// the sequence reparse to the original text.
///
/// Example: `"hello]]>world"` becomes `"hello]]]]><![CDATA[>world"`. When
/// the caller wraps that in `<![CDATA[ ... ]]>` the emitted document is
/// `<![CDATA[hello]]]]><![CDATA[>world]]>`, which reparses as two adjacent
/// CDATA sections concatenating to `"hello]]>world"`.
pub(crate) fn split_cdata_content(s: &str) -> Cow<'_, str> {
    if !s.contains("]]>") && s.chars().all(is_xml_char) {
        return Cow::Borrowed(s);
    }
    let sanitized: String = s.chars().map(sanitized_xml_char).collect();
    Cow::Owned(sanitized.replace("]]>", "]]]]><![CDATA[>"))
}

pub(crate) fn sanitized_xml_char(c: char) -> char {
    if is_xml_char(c) {
        c
    } else {
        '\u{FFFD}'
    }
}

pub(crate) fn is_xml_char(c: char) -> bool {
    matches!(c,
        '\u{9}' | '\u{A}' | '\u{D}' |
        '\u{20}'..='\u{D7FF}' |
        '\u{E000}'..='\u{FFFD}' |
        '\u{10000}'..='\u{10FFFF}'
    )
}

/// Return `s` if it is a version this library can both serialize and
/// parse — `"1.0"` or `"1.1"` — and a safe fallback `"1.0"` otherwise.
///
/// Tighter than the XML 1.0 `VersionNum` production (`'1.' [0-9]+`)
/// because `parse_xml_declaration` only accepts `1.0` / `1.1`; emitting
/// any other version (e.g. `1.42`) would produce a document this
/// library refuses to reparse.
///
/// Without this, an attacker who can mutate `Document::xml_declaration`
/// or pass an attacker-controlled string to
/// [`XmlWriter::write_declaration_full`] can close the enclosing
/// `<?xml ... ?>` early with a `"?>` byte pair and smuggle arbitrary
/// markup ahead of the root element. The same smuggle class the
/// comment / PI / CDATA sanitizers above close for those node kinds.
pub(crate) fn safe_xml_version(s: &str) -> Cow<'_, str> {
    if s == "1.0" || s == "1.1" {
        Cow::Borrowed(s)
    } else {
        Cow::Borrowed("1.0")
    }
}

/// Return `s` if it matches the XML 1.0 `EncName` production
/// (`[A-Za-z] ([A-Za-z0-9._] | '-')*`); otherwise return a safe
/// fallback `"UTF-8"`. Same threat model and rationale as
/// [`safe_xml_version`].
pub(crate) fn safe_xml_encoding(s: &str) -> Cow<'_, str> {
    if is_valid_xml_encoding(s) {
        Cow::Borrowed(s)
    } else {
        Cow::Borrowed("UTF-8")
    }
}

/// XML 1.0 §4.3.3 `EncName ::= [A-Za-z] ([A-Za-z0-9._] | '-')*`.
fn is_valid_xml_encoding(s: &str) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_alphabetic() => {}
        _ => return false,
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Return a safe XML QName for structural markup names. Invalid names are
/// replaced by `_` so programmatic name input cannot break out of tag or
/// attribute-name position and smuggle markup into serialized output.
pub(crate) fn safe_xml_qname(s: &str) -> Cow<'_, str> {
    if is_valid_xml_qname(s) {
        Cow::Borrowed(s)
    } else {
        Cow::Borrowed("_")
    }
}

/// Return a safe XML NCName for namespace declaration prefixes.
pub(crate) fn safe_xml_ncname(s: &str) -> Cow<'_, str> {
    if is_valid_xml_ncname(s) {
        Cow::Borrowed(s)
    } else {
        Cow::Borrowed("_")
    }
}

/// Return a safe XML QName that is unique among names already emitted for
/// the same element.
///
/// Sanitization can collapse distinct invalid inputs such as `"bad attr"` and
/// `"bad\tattr"` to the same fallback name (`"_"`). XML forbids duplicate
/// attribute names, so callers pass a per-element `seen` set and this helper
/// appends deterministic suffixes (`_1`, `_2`, ...) when needed.
///
/// `seen` holds `Cow`s and the returned name borrows the input whenever the
/// name is valid and unused -- the overwhelmingly common case for parsed
/// documents -- so that path performs no allocation at all (the serializer
/// calls this once per attribute per element per serialize).
pub(crate) fn unique_safe_xml_qname<'a>(s: &'a str, seen: &mut Vec<Cow<'a, str>>) -> Cow<'a, str> {
    let base = safe_xml_qname(s);
    if !seen.contains(&base) {
        seen.push(base.clone());
        return base;
    }

    let mut suffix = 1usize;
    loop {
        let candidate = format!("{}_{}", base, suffix);
        if !seen.iter().any(|n| n.as_ref() == candidate) {
            seen.push(Cow::Owned(candidate.clone()));
            return Cow::Owned(candidate);
        }
        suffix += 1;
    }
}

/// Owned-input variant of [`unique_safe_xml_qname`], for callers whose name
/// string is built per call (a prefixed attribute's `prefix:local` join) and
/// so cannot be borrowed by the `seen` list. Identical sanitization and
/// dedup semantics.
pub(crate) fn unique_safe_xml_qname_owned(s: String, seen: &mut Vec<Cow<'_, str>>) -> String {
    let base = if is_valid_xml_qname(&s) {
        s
    } else {
        "_".to_string()
    };
    if !seen.iter().any(|n| n.as_ref() == base) {
        seen.push(Cow::Owned(base.clone()));
        return base;
    }

    let mut suffix = 1usize;
    loop {
        let candidate = format!("{}_{}", base, suffix);
        if !seen.iter().any(|n| n.as_ref() == candidate) {
            seen.push(Cow::Owned(candidate.clone()));
            return candidate;
        }
        suffix += 1;
    }
}

/// Write the serialized form of a possibly-prefixed name directly to the
/// sink, sanitizing exactly like `safe_xml_qname(prefixed_name())` but
/// without materialising the `prefix:local` string first. The valid-name
/// path (every parsed document) performs zero allocation; an invalid name
/// collapses to `_` just as before. Used for element open AND close tags,
/// which previously each paid a `format!` per prefixed element.
pub(crate) fn write_qname_sanitized(
    out: &mut dyn core::fmt::Write,
    prefix: Option<&str>,
    local: &str,
) -> core::fmt::Result {
    match prefix {
        Some(p) => {
            // `prefixed_name()` would yield "p:local"; that string is a valid
            // QName exactly when both pieces are valid NCNames.
            if is_valid_xml_ncname(p) && is_valid_xml_ncname(local) {
                out.write_str(p)?;
                out.write_char(':')?;
                out.write_str(local)
            } else {
                out.write_str("_")
            }
        }
        // Unprefixed: the raw name may itself be "a:b" (a QName with the colon
        // stored in the local name), so validate with the QName production,
        // matching `safe_xml_qname` on the joined string.
        None => {
            if is_valid_xml_qname(local) {
                out.write_str(local)
            } else {
                out.write_str("_")
            }
        }
    }
}

pub(crate) fn is_valid_xml_qname(s: &str) -> bool {
    // Byte-level colon split (a colon is a single ASCII byte, so byte offsets
    // are char boundaries); avoids the generic pattern-searcher machinery on
    // this per-name-per-serialize path.
    let bytes = s.as_bytes();
    match bytes.iter().position(|&b| b == b':') {
        None => is_valid_xml_ncname(s),
        Some(i) => {
            let rest = &bytes[i + 1..];
            !rest.contains(&b':')
                && is_valid_xml_ncname(&s[..i])
                && is_valid_xml_ncname(&s[i + 1..])
        }
    }
}

pub(crate) fn is_valid_xml_ncname(s: &str) -> bool {
    // ASCII fast path, single pass: names in real-world XML are overwhelmingly
    // ASCII, and this predicate runs for every element/attribute name on every
    // serialize. Byte checks avoid the char-decode loop. We validate ASCII
    // bytes as we go and only fall through to the exact Unicode-production check
    // the moment a non-ASCII byte appears (an ASCII byte is a whole char, so an
    // invalid one is invalid under either production and can fail fast).
    let bytes = s.as_bytes();
    let Some(&first) = bytes.first() else {
        return false;
    };
    if first.is_ascii() {
        if !(first.is_ascii_alphabetic() || first == b'_') {
            return false;
        }
        // SIMD scan of the continuation bytes: the length of the leading run of
        // ASCII NCName characters (`[0-9A-Za-z_.-]`). A run that ends before the
        // string does means the next byte is either an invalid ASCII byte (the
        // name is invalid) or the start of a non-ASCII character (fall through
        // to the full Unicode production). An all-ASCII valid name is settled in
        // this single pass, with no char-decode.
        let pos = 1 + crate::simd::scan_ncname_continuation(&bytes[1..]);
        if pos == bytes.len() {
            return true;
        }
        if bytes[pos] < 0x80 {
            return false;
        }
        // else: non-ASCII byte present -> fall through to the Unicode check.
    }
    // A non-ASCII byte is present somewhere: validate against the full Unicode
    // NameStartChar / NameChar productions.
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if is_ncname_start_char(c) => {}
        _ => return false,
    }
    chars.all(is_ncname_char)
}

/// XML 1.0 `NCNameStartChar` — the full `NameStartChar` production minus `:`.
///
/// Must mirror the parser's accepted ranges so that names produced by the
/// parser round-trip through serialization without being sanitized to `_`
/// (e.g. `<é/>`). Sanitization only exists to neutralize *invalid*
/// programmatic names, not to reject valid non-ASCII ones.
fn is_ncname_start_char(c: char) -> bool {
    matches!(c,
        'A'..='Z' | '_' | 'a'..='z' |
        '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' |
        '\u{F8}'..='\u{2FF}' | '\u{370}'..='\u{37D}' |
        '\u{37F}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}' |
        '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}' |
        '\u{3001}'..='\u{D7FF}' | '\u{F900}'..='\u{FDCF}' |
        '\u{FDF0}'..='\u{FFFD}' | '\u{10000}'..='\u{EFFFF}'
    )
}

/// XML 1.0 `NCNameChar` — the full `NameChar` production minus `:`.
fn is_ncname_char(c: char) -> bool {
    is_ncname_start_char(c)
        || matches!(c,
            '-' | '.' | '0'..='9' | '\u{B7}' |
            '\u{0300}'..='\u{036F}' | '\u{203F}'..='\u{2040}'
        )
}

// ─── Internal escaping helpers (write directly to String, no allocation) ───

/// Run-based XML escaping core, shared by the text and attribute writers.
///
/// Instead of matching and pushing one character at a time (the bulk of a large
/// document is unescaped text, so that pays a per-character `push` capacity
/// check and UTF-8 re-encode over and over), this scans for the next byte that
/// actually needs escaping or sanitizing and copies the whole preceding "safe"
/// run in one `push_str` (which lowers to a SIMD `memcpy`). On ASCII-heavy
/// payloads like SAML metadata this is the common case, so most bytes are
/// copied in bulk and only the rare special byte is handled individually.
///
/// Semantics are identical to the previous per-character version: `&<>` and
/// `\r` are always escaped; in attribute context `"`, `\t` and `\n` are escaped
/// too; control characters that are not valid XML 1.0 characters are replaced
/// with U+FFFD (via the same rule as [`sanitized_xml_char`]); everything else,
/// including valid multi-byte characters, is copied verbatim.
#[inline]
fn write_escaped_run_based(buf: &mut String, s: &str, is_attr: bool) {
    let bytes = s.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        // Decide whether byte `b` needs individual handling. ASCII bytes take a
        // cheap branch; any byte >= 0x80 starts a multi-byte char and is decoded
        // on the slow path (rare in this workload).
        let special = if b >= 0x80 {
            true
        } else {
            match b {
                b'&' | b'<' | b'>' | b'\r' => true,
                b'"' if is_attr => true,
                b'\t' | b'\n' if is_attr => true,
                // Control characters other than XML-valid \t, \n (and \r, which
                // is handled above) must be sanitized.
                0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F => true,
                _ => false,
            }
        };
        if !special {
            i += 1;
            continue;
        }
        // Flush the accumulated safe run in one bulk copy.
        if start < i {
            buf.push_str(&s[start..i]);
        }
        if b >= 0x80 {
            // Multi-byte UTF-8 character: copy it verbatim when it is a valid
            // XML character, otherwise emit the replacement character.
            let ch = s[i..].chars().next().unwrap();
            let n = ch.len_utf8();
            if is_xml_char(ch) {
                buf.push_str(&s[i..i + n]);
            } else {
                buf.push('\u{FFFD}');
            }
            i += n;
        } else {
            match b {
                b'&' => buf.push_str("&amp;"),
                b'<' => buf.push_str("&lt;"),
                b'>' => buf.push_str("&gt;"),
                b'\r' => buf.push_str("&#xD;"),
                b'"' if is_attr => buf.push_str("&quot;"),
                b'\t' if is_attr => buf.push_str("&#x9;"),
                b'\n' if is_attr => buf.push_str("&#xA;"),
                // Remaining ASCII control characters are all invalid XML chars.
                _ => buf.push(sanitized_xml_char(b as char)),
            }
            i += 1;
        }
        start = i;
    }
    if start < bytes.len() {
        buf.push_str(&s[start..]);
    }
}

/// Run-based XML escaping to a generic `fmt::Write` sink -- the same
/// algorithm and byte-identical output as [`write_escaped_run_based`], for
/// the DOM serializer's `&mut dyn fmt::Write` pipeline. The previous
/// per-character loop there paid a virtual `write_char` call (plus a UTF-8
/// re-encode) for every byte of every text node and attribute value, which
/// profiled as ~38% of whole-document serialization; bulk `write_str` of the
/// safe runs removes that entirely.
pub(crate) fn write_escaped_run_dyn(
    out: &mut dyn core::fmt::Write,
    s: &str,
    is_attr: bool,
) -> core::fmt::Result {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // SIMD-scan the longest verbatim-copyable run (16 bytes/cycle on
        // x86_64) and bulk-write it, then handle the one special byte.
        let run = crate::simd::scan_escape_run(&bytes[i..], is_attr);
        if run > 0 {
            out.write_str(&s[i..i + run])?;
            i += run;
            if i >= bytes.len() {
                break;
            }
        }
        let b = bytes[i];
        if b >= 0x80 {
            // Multi-byte UTF-8 character: copy verbatim when it is a valid
            // XML character, otherwise emit the replacement character.
            let ch = s[i..].chars().next().unwrap();
            let n = ch.len_utf8();
            if is_xml_char(ch) {
                out.write_str(&s[i..i + n])?;
            } else {
                out.write_char('\u{FFFD}')?;
            }
            i += n;
        } else {
            match b {
                b'&' => out.write_str("&amp;")?,
                b'<' => out.write_str("&lt;")?,
                b'>' => out.write_str("&gt;")?,
                b'\r' => out.write_str("&#xD;")?,
                b'"' if is_attr => out.write_str("&quot;")?,
                b'\t' if is_attr => out.write_str("&#x9;")?,
                b'\n' if is_attr => out.write_str("&#xA;")?,
                // Remaining ASCII control characters are all invalid XML chars.
                _ => out.write_char(sanitized_xml_char(b as char))?,
            }
            i += 1;
        }
    }
    Ok(())
}

/// Write text content with XML escaping directly to a String.
fn write_escaped_text_to_string(buf: &mut String, s: &str) {
    write_escaped_run_based(buf, s, false);
}

/// Write attribute value with XML escaping directly to a String.
fn write_escaped_attr_to_string(buf: &mut String, s: &str) {
    write_escaped_run_based(buf, s, true);
}

/// Write one attribute after structural-name sanitization and per-element
/// collision disambiguation.
fn write_sanitized_attr_to_string<'a>(
    buf: &mut String,
    key: &'a str,
    value: &str,
    seen_attrs: &mut Vec<Cow<'a, str>>,
) {
    let key = unique_safe_xml_qname(key, seen_attrs);
    buf.push(' ');
    buf.push_str(&key);
    buf.push_str("=\"");
    write_escaped_attr_to_string(buf, value);
    buf.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Run-based escaping core (text + attribute) ────────────────────

    fn esc_text(s: &str) -> String {
        let mut buf = String::new();
        write_escaped_text_to_string(&mut buf, s);
        buf
    }

    fn esc_attr(s: &str) -> String {
        let mut buf = String::new();
        write_escaped_attr_to_string(&mut buf, s);
        buf
    }

    #[test]
    fn text_escaping_handles_markup_and_cr() {
        // In text context `& < >` and CR are escaped; `" \t \n` are NOT.
        assert_eq!(
            esc_text("a & b < c > d\r\n\t\"x\""),
            "a &amp; b &lt; c &gt; d&#xD;\n\t\"x\""
        );
        // A run with no special bytes is copied verbatim (bulk path).
        assert_eq!(esc_text("plain ascii text 123"), "plain ascii text 123");
        // Leading and trailing specials (run boundaries at both ends).
        assert_eq!(esc_text("<x>"), "&lt;x&gt;");
    }

    #[test]
    fn attr_escaping_adds_quote_tab_newline() {
        // Attribute context additionally escapes `"`, TAB and LF; CR too.
        assert_eq!(
            esc_attr("a & b < c > d \"q\" \t \n \r"),
            "a &amp; b &lt; c &gt; d &quot;q&quot; &#x9; &#xA; &#xD;"
        );
        // `>` is escaped in both contexts, `'` is left as-is.
        assert_eq!(esc_attr("'apos' > gt"), "'apos' &gt; gt");
    }

    #[test]
    fn invalid_xml_control_chars_become_replacement() {
        // NUL and other C0 controls (except \t \n \r) are not valid XML 1.0
        // characters and are replaced with U+FFFD in both contexts.
        assert_eq!(esc_text("a\u{0}b"), "a\u{FFFD}b");
        assert_eq!(
            esc_text("\u{1}\u{8}\u{B}\u{C}\u{1F}"),
            "\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}"
        );
        assert_eq!(esc_attr("x\u{0}y"), "x\u{FFFD}y");
        // \t \n \r remain valid XML chars in text context (not replaced).
        assert_eq!(esc_text("\t\n\r"), "\t\n&#xD;");
    }

    #[test]
    fn multibyte_chars_pass_through_or_sanitize() {
        // Valid multi-byte UTF-8 is copied verbatim, even adjacent to specials.
        assert_eq!(esc_text("café & déjà-vu — ☃"), "café &amp; déjà-vu — ☃");
        assert_eq!(esc_attr("naïve=\"x\""), "naïve=&quot;x&quot;");
        // U+FFFE is a non-character (invalid XML char) and is replaced, while
        // the surrounding valid multi-byte characters survive.
        assert_eq!(esc_text("é\u{FFFE}é"), "é\u{FFFD}é");
        assert_eq!(esc_attr("é\u{FFFE}é"), "é\u{FFFD}é");
    }

    #[test]
    fn escaping_matches_public_writer_api() {
        // The public `text` / attribute paths route through the same core.
        let mut w = XmlWriter::new();
        w.text("a & b < c\r");
        assert_eq!(w.as_str(), "a &amp; b &lt; c&#xD;");

        let mut w = XmlWriter::new();
        w.empty_element("e", &[("k", "v & \"w\"\t")]);
        assert_eq!(w.into_string(), "<e k=\"v &amp; &quot;w&quot;&#x9;\"/>");
    }

    // ─── Pure-function tests for the sanitizers ────────────────────────

    #[test]
    fn sanitize_comment_passes_safe_content() {
        assert!(matches!(
            sanitize_comment_content("hello world"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(sanitize_comment_content(""), Cow::Borrowed(_)));
        assert!(matches!(
            sanitize_comment_content("single - dash"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn sanitize_comment_separates_consecutive_dashes() {
        assert_eq!(&*sanitize_comment_content("a--b"), "a- -b");
        assert_eq!(&*sanitize_comment_content("a---b"), "a- - -b");
        // `"--"` ends with `-` after separator insertion, so the
        // trailing-dash fixup also kicks in.
        assert_eq!(&*sanitize_comment_content("--"), "- - ");
        assert_eq!(&*sanitize_comment_content("-->"), "- ->");
    }

    #[test]
    fn sanitize_comment_pads_trailing_dash() {
        assert_eq!(&*sanitize_comment_content("foo-"), "foo- ");
        assert_eq!(&*sanitize_comment_content("-"), "- ");
        assert_eq!(&*sanitize_comment_content("a--"), "a- - ");
    }

    #[test]
    fn sanitize_pi_data_inserts_space_in_terminator() {
        assert!(matches!(sanitize_pi_data("safe data"), Cow::Borrowed(_)));
        assert_eq!(&*sanitize_pi_data("a?>b"), "a? >b");
        assert_eq!(&*sanitize_pi_data("?>?>"), "? >? >");
        assert_eq!(&*sanitize_pi_data(""), "");
    }

    #[test]
    fn sanitize_pi_target_renames_reserved_xml() {
        // Reserved name (case-insensitive) is renamed.
        assert_eq!(&*sanitize_pi_target("xml"), "_xml");
        assert_eq!(&*sanitize_pi_target("XML"), "_XML");
        assert_eq!(&*sanitize_pi_target("Xml"), "_Xml");
        assert_eq!(&*sanitize_pi_target("xMl"), "_xMl");
    }

    #[test]
    fn sanitize_pi_target_passes_legitimate_names() {
        // Any other name is Borrowed-through.
        assert!(matches!(sanitize_pi_target("xsl"), Cow::Borrowed(_)));
        assert!(matches!(
            sanitize_pi_target("xml-stylesheet"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(sanitize_pi_target("xmlrpc"), Cow::Borrowed(_)));
        assert!(matches!(sanitize_pi_target(""), Cow::Borrowed(_)));
    }

    #[test]
    fn split_cdata_preserves_safe_content() {
        assert!(matches!(
            split_cdata_content("hello world"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(split_cdata_content(""), Cow::Borrowed(_)));
    }

    #[test]
    fn split_cdata_splits_terminator() {
        assert_eq!(
            &*split_cdata_content("hello]]>world"),
            "hello]]]]><![CDATA[>world"
        );
        assert_eq!(&*split_cdata_content("]]>"), "]]]]><![CDATA[>");
    }

    // ─── Round-trip smuggle-prevention tests (F-13 / F-14 / F-15) ──────

    #[test]
    fn roundtrip_comment_smuggle_is_blocked() {
        // Attacker-controlled comment text tries to close the comment
        // early and inject a sibling element.
        let mut w = XmlWriter::new();
        w.start_element("r", &[]);
        w.comment("safe --> <injected/> <!--trailing");
        w.end_element("r");
        let out = w.into_string();

        // The emitted XML must reparse without any injected element
        // becoming a sibling of <r>.
        let doc = crate::parse(&out).expect("sanitized output must reparse");
        let root = doc.document_element().unwrap();
        let element_children: Vec<_> = doc
            .children(root)
            .into_iter()
            .filter(|c| matches!(doc.node_kind(*c), Some(crate::NodeKind::Element(_))))
            .collect();
        assert!(
            element_children.is_empty(),
            "comment sanitization failed; output smuggled an element: {:?}",
            out
        );
    }

    #[test]
    fn roundtrip_pi_smuggle_is_blocked() {
        let mut w = XmlWriter::new();
        w.start_element("r", &[]);
        w.processing_instruction("x", Some("?><injected/>"));
        w.end_element("r");
        let out = w.into_string();

        let doc = crate::parse(&out).expect("sanitized output must reparse");
        let root = doc.document_element().unwrap();
        let element_children: Vec<_> = doc
            .children(root)
            .into_iter()
            .filter(|c| matches!(doc.node_kind(*c), Some(crate::NodeKind::Element(_))))
            .collect();
        assert!(
            element_children.is_empty(),
            "PI sanitization failed; output smuggled an element: {:?}",
            out
        );
    }

    #[test]
    fn roundtrip_pi_reserved_xml_target_is_renamed() {
        // Attacker constructs a PI with the reserved `xml` target, hoping
        // to either forge an XML declaration (start-of-document) or reach
        // a parser-rejection DoS (elsewhere). Sanitization renames the
        // target to `_xml`, and the document reparses as a well-formed
        // <r> with one ordinary PI child.
        let mut w = XmlWriter::new();
        w.start_element("r", &[]);
        w.processing_instruction("xml", Some("version=\"1.0\" standalone=\"yes\""));
        w.end_element("r");
        let out = w.into_string();

        assert!(
            !out.contains("<?xml "),
            "reserved `xml` target must not reach the output: {:?}",
            out
        );
        let doc = crate::parse(&out).expect("sanitized output must reparse");
        let root = doc.document_element().unwrap();
        let pi_children: Vec<_> = doc
            .children(root)
            .into_iter()
            .filter_map(|c| match doc.node_kind(c) {
                Some(crate::NodeKind::ProcessingInstruction(pi)) => Some(pi),
                _ => None,
            })
            .collect();
        assert_eq!(pi_children.len(), 1, "expected exactly one PI child");
        assert_eq!(&*pi_children[0].target, "_xml");
    }

    // ─── XML-declaration version/encoding validation (M-1) ────────────

    #[test]
    fn safe_xml_version_passes_valid() {
        // Only the two version numbers the parser actually accepts.
        assert!(matches!(safe_xml_version("1.0"), Cow::Borrowed(_)));
        assert!(matches!(safe_xml_version("1.1"), Cow::Borrowed(_)));
        assert_eq!(&*safe_xml_version("1.0"), "1.0");
        assert_eq!(&*safe_xml_version("1.1"), "1.1");
    }

    #[test]
    fn safe_xml_version_rejects_invalid() {
        // Empty, wrong major, missing minor, syntactically-valid but
        // unsupported (1.42 / 1.10), trailing garbage, injection.
        assert_eq!(&*safe_xml_version(""), "1.0");
        assert_eq!(&*safe_xml_version("1"), "1.0");
        assert_eq!(&*safe_xml_version("1."), "1.0");
        assert_eq!(&*safe_xml_version("2.0"), "1.0");
        assert_eq!(&*safe_xml_version("1.10"), "1.0");
        assert_eq!(&*safe_xml_version("1.42"), "1.0");
        assert_eq!(&*safe_xml_version("1.0a"), "1.0");
        assert_eq!(&*safe_xml_version("1.0\"?><x/><?y "), "1.0");
        assert_eq!(&*safe_xml_version("1.0 "), "1.0");
    }

    #[test]
    fn safe_xml_encoding_passes_valid() {
        assert!(matches!(safe_xml_encoding("UTF-8"), Cow::Borrowed(_)));
        assert!(matches!(safe_xml_encoding("utf-8"), Cow::Borrowed(_)));
        assert!(matches!(safe_xml_encoding("ISO-8859-1"), Cow::Borrowed(_)));
        assert!(matches!(safe_xml_encoding("US_ASCII.1"), Cow::Borrowed(_)));
        assert_eq!(&*safe_xml_encoding("UTF-8"), "UTF-8");
    }

    #[test]
    fn safe_xml_encoding_rejects_invalid() {
        // Empty, digit-first, leading dash, injection, control chars.
        assert_eq!(&*safe_xml_encoding(""), "UTF-8");
        assert_eq!(&*safe_xml_encoding("1UTF"), "UTF-8");
        assert_eq!(&*safe_xml_encoding("-foo"), "UTF-8");
        assert_eq!(&*safe_xml_encoding("UTF-8\"?><x/>"), "UTF-8");
        assert_eq!(&*safe_xml_encoding("utf 8"), "UTF-8");
        assert_eq!(&*safe_xml_encoding("utf\x00"), "UTF-8");
    }

    #[test]
    fn roundtrip_xml_writer_declaration_version_injection_blocked() {
        // Attacker-controlled version string tries to close the
        // declaration early and inject a root-sibling PI.
        let mut w = XmlWriter::new();
        w.write_declaration_full("1.0\"?><!-- smuggled -->", Some("UTF-8"), None);
        w.start_element("r", &[]);
        w.end_element("r");
        let out = w.into_string();
        assert!(
            !out.contains("smuggled"),
            "attacker-controlled version must not reach output: {:?}",
            out
        );
        let doc = crate::parse(&out).expect("sanitized output must reparse");
        assert_eq!(doc.xml_declaration.as_ref().unwrap().version, "1.0");
    }

    #[test]
    fn roundtrip_xml_writer_declaration_encoding_injection_blocked() {
        let mut w = XmlWriter::new();
        w.write_declaration_full("1.0", Some("UTF-8\"?><inject/><?x "), None);
        w.start_element("r", &[]);
        w.end_element("r");
        let out = w.into_string();
        assert!(
            !out.contains("<inject"),
            "attacker-controlled encoding must not reach output: {:?}",
            out
        );
        let doc = crate::parse(&out).expect("sanitized output must reparse");
        // Root must still be <r/>, not the smuggled sibling.
        let root = doc.document_element().unwrap();
        match doc.node_kind(root) {
            Some(crate::NodeKind::Element(e)) => {
                assert_eq!(&*e.name.local_name, "r");
            }
            _ => panic!("expected element root"),
        }
        assert_eq!(
            doc.xml_declaration.as_ref().unwrap().encoding.as_deref(),
            Some("UTF-8")
        );
    }

    #[test]
    fn roundtrip_dom_declaration_version_injection_blocked() {
        // Same threat model, exercised through the DOM serializer path.
        let mut doc = crate::parse("<r/>").expect("parse");
        doc.xml_declaration = Some(crate::dom::XmlDeclaration {
            version: "1.0\"?><forged/><?y ".into(),
            encoding: Some("UTF-8".into()),
            standalone: None,
        });
        let out = doc.to_xml();
        assert!(
            !out.contains("<forged"),
            "DOM-mutation version injection not blocked: {:?}",
            out
        );
        let reparsed = crate::parse(&out).expect("sanitized output must reparse");
        assert_eq!(reparsed.xml_declaration.as_ref().unwrap().version, "1.0");
    }

    #[test]
    fn roundtrip_dom_declaration_encoding_injection_blocked() {
        let mut doc = crate::parse("<r/>").expect("parse");
        doc.xml_declaration = Some(crate::dom::XmlDeclaration {
            version: "1.0".into(),
            encoding: Some("UTF-8\"?><forged/><?y ".into()),
            standalone: None,
        });
        let out = doc.to_xml();
        assert!(
            !out.contains("<forged"),
            "DOM-mutation encoding injection not blocked: {:?}",
            out
        );
        let reparsed = crate::parse(&out).expect("sanitized output must reparse");
        assert_eq!(
            reparsed
                .xml_declaration
                .as_ref()
                .unwrap()
                .encoding
                .as_deref(),
            Some("UTF-8")
        );
    }

    #[test]
    fn roundtrip_cdata_smuggle_is_blocked() {
        let mut w = XmlWriter::new();
        w.start_element("r", &[]);
        w.cdata("safe]]><injected/>more");
        w.end_element("r");
        let out = w.into_string();

        let doc = crate::parse(&out).expect("split CDATA must reparse");
        let root = doc.document_element().unwrap();
        // Exactly one (concatenated) CDATA text child, no smuggled elements.
        let element_children: Vec<_> = doc
            .children(root)
            .into_iter()
            .filter(|c| matches!(doc.node_kind(*c), Some(crate::NodeKind::Element(_))))
            .collect();
        assert!(
            element_children.is_empty(),
            "CDATA split failed; output smuggled an element: {:?}",
            out
        );
        // And the semantic text content must round-trip unchanged.
        assert_eq!(
            doc.text_content_deep(root),
            "safe]]><injected/>more",
            "CDATA split must preserve the original text semantically"
        );
    }
}
