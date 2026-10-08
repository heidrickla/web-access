//! Accelerated byte scanning for parser hot loops.
//!
//! On x86_64 (where SSE2 is guaranteed), text content and attribute values are
//! scanned 16 bytes at a time instead of 1. Other architectures use a one-pass
//! scalar scanner because XML-character validation must happen while searching
//! for delimiters.

/// Scan `data` for content delimiter bytes (`<`, `&`, `\r`, `]`).
///
/// Returns `(bytes_advanced, needs_validation)` where `needs_validation` is true
/// if any non-ASCII byte (>= 0x80) or illegal control character (< 0x20 except
/// TAB, LF) was encountered in the scanned range.
///
/// **Delimiter-set contract.** The stop set is exactly `{ '<', '&', '\r', ']' }`
/// — all ASCII, so the returned offset is always on a UTF-8 char boundary. The
/// sole production consumer is the pull parser (`pull::parse_text_event`), which
/// dispatches on the byte this scanner stops at. If the stop set ever changes,
/// update that consumer's match arms to match; it degrades gracefully (appends
/// one UTF-8 character as content) rather than panicking on an unexpected stop
/// byte, so a missed update is a correctness bug, not a crash -- keep it that
/// way.
#[inline(always)]
pub(crate) fn scan_content_delimiters(data: &[u8]) -> (usize, bool) {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: SSE2 is guaranteed on all x86_64 processors.
        unsafe { scan_content_sse2(data) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        scan_content_scalar(data)
    }
}

/// Scan `data` for attribute delimiter bytes (`&`, `<`) or the closing `quote` byte.
///
/// Returns `(bytes_advanced, needs_validation)` where `needs_validation` is true
/// if any non-ASCII byte or illegal control character was encountered.
#[inline(always)]
pub(crate) fn scan_attr_delimiters(data: &[u8], quote: u8) -> (usize, bool) {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: SSE2 is guaranteed on all x86_64 processors.
        unsafe { scan_attr_sse2(data, quote) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        scan_attr_scalar(data, quote)
    }
}

/// Find a single byte without adding a dependency.
#[inline(always)]
pub(crate) fn find_byte(data: &[u8], byte: u8) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: SSE2 is guaranteed on all x86_64 processors.
        unsafe { find_byte_sse2(data, byte) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        find_byte_scalar(data, byte)
    }
}

/// Length of the prefix of `data` that the serializer's escaper can copy
/// verbatim: bytes that are not `&`, `<`, `>`, `\r` (plus `"`, `\t`, `\n` in
/// attribute context), not an invalid ASCII control character, and not the
/// start of a multi-byte sequence (>= 0x80, which needs char-level XML
/// validity checking). The serializer bulk-copies this run and handles the
/// single following special byte individually.
#[inline(always)]
pub(crate) fn scan_escape_run(data: &[u8], is_attr: bool) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: SSE2 is guaranteed on all x86_64 processors.
        unsafe { scan_escape_sse2(data, is_attr) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        scan_escape_scalar(data, is_attr)
    }
}

/// Length of the leading run of ASCII NCName *continuation* characters
/// (`[0-9A-Za-z_.-]`). Any other byte — including any non-ASCII byte
/// (`>= 0x80`) — ends the run.
///
/// This is the SIMD core of `writer::is_valid_xml_ncname`'s ASCII fast path:
/// the caller inspects the byte at the returned offset to decide between
/// "all valid ASCII" (offset == len), an "invalid ASCII name" (offset byte
/// `< 0x80`), and "fall through to the Unicode `NameChar` production" (offset
/// byte `>= 0x80`, the start of a multi-byte character).
#[inline(always)]
pub(crate) fn scan_ncname_continuation(data: &[u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: SSE2 is guaranteed on all x86_64 processors.
        unsafe { scan_name_like_continuation_sse2::<false>(data) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        scan_name_like_continuation_scalar::<false>(data)
    }
}

/// Length of the leading run of ASCII XML Name continuation characters
/// (`[0-9A-Za-z_.:-]`). Non-ASCII bytes stop the run so the parser can fall
/// through to the full Unicode `NameChar` production.
#[inline(always)]
pub(crate) fn scan_name_continuation(data: &[u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: SSE2 is guaranteed on all x86_64 processors.
        unsafe { scan_name_like_continuation_sse2::<true>(data) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        scan_name_like_continuation_scalar::<true>(data)
    }
}

/// Scalar fallback / tail scan for XML name-like continuation scanners. The
/// byte classification is the reference the SSE2 path must match exactly.
fn scan_name_like_continuation_scalar<const ALLOW_COLON: bool>(data: &[u8]) -> usize {
    let mut pos = 0;
    while pos < data.len() {
        let b = data[pos];
        if !(b.is_ascii_alphanumeric()
            || matches!(b, b'_' | b'-' | b'.')
            || (ALLOW_COLON && b == b':'))
        {
            break;
        }
        pos += 1;
    }
    pos
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn scan_name_like_continuation_sse2<const ALLOW_COLON: bool>(data: &[u8]) -> usize {
    use std::arch::x86_64::*;

    let mut pos = 0;
    // Range bounds and standalone XML-name punctuation.
    let v_0 = _mm_set1_epi8(b'0' as i8);
    let v_9 = _mm_set1_epi8(b'9' as i8);
    let v_ua = _mm_set1_epi8(b'A' as i8);
    let v_uz = _mm_set1_epi8(b'Z' as i8);
    let v_la = _mm_set1_epi8(b'a' as i8);
    let v_lz = _mm_set1_epi8(b'z' as i8);
    let v_us = _mm_set1_epi8(b'_' as i8);
    let v_hy = _mm_set1_epi8(b'-' as i8);
    let v_dot = _mm_set1_epi8(b'.' as i8);
    let v_colon = _mm_set1_epi8(b':' as i8);

    while pos + 16 <= data.len() {
        let chunk = _mm_loadu_si128(data.as_ptr().add(pos) as *const __m128i);

        // Unsigned range test [lo, hi]: `max(x, lo) == x` (x >= lo) and
        // `min(x, hi) == x` (x <= hi). Non-ASCII bytes (>= 0x80) fail every
        // range and every single-char equality, so they end the run.
        let in_range = |lo, hi| {
            _mm_and_si128(
                _mm_cmpeq_epi8(_mm_max_epu8(chunk, lo), chunk),
                _mm_cmpeq_epi8(_mm_min_epu8(chunk, hi), chunk),
            )
        };
        let singles = _mm_or_si128(
            _mm_cmpeq_epi8(chunk, v_us),
            _mm_or_si128(_mm_cmpeq_epi8(chunk, v_hy), _mm_cmpeq_epi8(chunk, v_dot)),
        );
        let singles = if ALLOW_COLON {
            _mm_or_si128(singles, _mm_cmpeq_epi8(chunk, v_colon))
        } else {
            singles
        };
        let valid = _mm_or_si128(
            _mm_or_si128(in_range(v_0, v_9), in_range(v_ua, v_uz)),
            _mm_or_si128(in_range(v_la, v_lz), singles),
        );

        // A lane is 0xFF when valid, so its movemask bit is 1; the first invalid
        // lane is the first 0 bit in the low 16.
        let invalid = (!(_mm_movemask_epi8(valid) as u32)) & 0xFFFF;
        if invalid != 0 {
            return pos + invalid.trailing_zeros() as usize;
        }
        pos += 16;
    }

    pos + scan_name_like_continuation_scalar::<ALLOW_COLON>(&data[pos..])
}

fn find_byte_scalar(data: &[u8], byte: u8) -> Option<usize> {
    data.iter().position(|&b| b == byte)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn find_byte_sse2(data: &[u8], byte: u8) -> Option<usize> {
    use std::arch::x86_64::*;

    let mut pos = 0;
    let needle = _mm_set1_epi8(byte as i8);
    while pos + 16 <= data.len() {
        let chunk = _mm_loadu_si128(data.as_ptr().add(pos) as *const __m128i);
        let mask = _mm_movemask_epi8(_mm_cmpeq_epi8(chunk, needle)) as u32;
        if mask != 0 {
            return Some(pos + mask.trailing_zeros() as usize);
        }
        pos += 16;
    }
    find_byte_scalar(&data[pos..], byte).map(|tail| pos + tail)
}

/// Scalar fallback / tail scan for [`scan_escape_run`]. The byte
/// classification must match `writer::write_escaped_run_dyn`'s special-byte
/// rules exactly.
fn scan_escape_scalar(data: &[u8], is_attr: bool) -> usize {
    let mut pos = 0;
    while pos < data.len() {
        let b = data[pos];
        let special = if b >= 0x80 {
            true
        } else {
            match b {
                b'&' | b'<' | b'>' | b'\r' => true,
                b'"' | b'\t' | b'\n' if is_attr => true,
                0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F => true,
                _ => false,
            }
        };
        if special {
            break;
        }
        pos += 1;
    }
    pos
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn scan_escape_sse2(data: &[u8], is_attr: bool) -> usize {
    use std::arch::x86_64::*;

    let mut pos = 0;

    let v_amp = _mm_set1_epi8(b'&' as i8);
    let v_lt = _mm_set1_epi8(b'<' as i8);
    let v_gt = _mm_set1_epi8(b'>' as i8);
    let v_cr = _mm_set1_epi8(b'\r' as i8);
    let v_quot = _mm_set1_epi8(b'"' as i8);
    let v_tab = _mm_set1_epi8(0x09);
    let v_lf = _mm_set1_epi8(0x0A);
    let v_1f = _mm_set1_epi8(0x1F_u8 as i8);

    while pos + 16 <= data.len() {
        let chunk = _mm_loadu_si128(data.as_ptr().add(pos) as *const __m128i);

        // Escaped delimiters common to both contexts.
        let mut special = _mm_or_si128(
            _mm_or_si128(_mm_cmpeq_epi8(chunk, v_amp), _mm_cmpeq_epi8(chunk, v_lt)),
            _mm_or_si128(_mm_cmpeq_epi8(chunk, v_gt), _mm_cmpeq_epi8(chunk, v_cr)),
        );
        if is_attr {
            special = _mm_or_si128(
                special,
                _mm_or_si128(
                    _mm_cmpeq_epi8(chunk, v_quot),
                    _mm_or_si128(_mm_cmpeq_epi8(chunk, v_tab), _mm_cmpeq_epi8(chunk, v_lf)),
                ),
            );
        }
        // Invalid ASCII control characters: <= 0x1F minus TAB/LF (CR is
        // already a delimiter above; TAB/LF are delimiters in attr context).
        let le_1f = _mm_cmpeq_epi8(_mm_min_epu8(chunk, v_1f), chunk);
        let allowed_ctrl = _mm_or_si128(_mm_cmpeq_epi8(chunk, v_tab), _mm_cmpeq_epi8(chunk, v_lf));
        let bad_ctrl = _mm_andnot_si128(allowed_ctrl, le_1f);

        // High bit set = start/continuation of a multi-byte character.
        let mask = (_mm_movemask_epi8(special) as u32)
            | (_mm_movemask_epi8(bad_ctrl) as u32)
            | (_mm_movemask_epi8(chunk) as u32);
        if mask != 0 {
            return pos + mask.trailing_zeros() as usize;
        }
        pos += 16;
    }

    pos + scan_escape_scalar(&data[pos..], is_attr)
}

// ---------------------------------------------------------------------------
// SSE2 implementations (x86_64 only)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn scan_content_sse2(data: &[u8]) -> (usize, bool) {
    use std::arch::x86_64::*;

    let mut pos = 0;
    let mut needs_validation = false;

    // Broadcast delimiter bytes to all 16 lanes
    let v_lt = _mm_set1_epi8(b'<' as i8);
    let v_amp = _mm_set1_epi8(b'&' as i8);
    let v_cr = _mm_set1_epi8(b'\r' as i8);
    let v_rsq = _mm_set1_epi8(b']' as i8);

    // For control-char detection: bytes <= 0x1F excluding TAB(0x09), LF(0x0A), CR(0x0D)
    let v_1f = _mm_set1_epi8(0x1F_u8 as i8);
    let v_tab = _mm_set1_epi8(0x09);
    let v_lf = _mm_set1_epi8(0x0A);

    while pos + 16 <= data.len() {
        let chunk = _mm_loadu_si128(data.as_ptr().add(pos) as *const __m128i);

        // OR together all delimiter equality checks
        let eq_cr = _mm_cmpeq_epi8(chunk, v_cr);
        let delimiters = _mm_or_si128(
            _mm_or_si128(_mm_cmpeq_epi8(chunk, v_lt), _mm_cmpeq_epi8(chunk, v_amp)),
            _mm_or_si128(eq_cr, _mm_cmpeq_epi8(chunk, v_rsq)),
        );
        let delim_mask = _mm_movemask_epi8(delimiters) as u32;

        // Check for bytes needing XML char validation (skip once flag is set)
        if !needs_validation {
            // Non-ASCII: high bit set (byte >= 0x80)
            let hi_bits = _mm_movemask_epi8(chunk) as u32;
            // Control chars: byte <= 0x1F, excluding TAB, LF, and CR
            // (CR is a delimiter so it won't matter, but excluding it avoids
            // false positives when \r is the stopping delimiter)
            let le_1f = _mm_cmpeq_epi8(_mm_min_epu8(chunk, v_1f), chunk);
            let allowed = _mm_or_si128(
                _mm_cmpeq_epi8(chunk, v_tab),
                _mm_or_si128(_mm_cmpeq_epi8(chunk, v_lf), eq_cr),
            );
            let bad_ctrl = _mm_andnot_si128(allowed, le_1f);
            let mut validate_bits = hi_bits | (_mm_movemask_epi8(bad_ctrl) as u32);
            // Only the bytes BEFORE the first delimiter belong to the run the
            // caller validates, so restrict the validation lanes to them. This
            // makes `needs_validation` match the scalar reference exactly, which
            // stops at the delimiter: without the mask, an invalid byte *after*
            // the delimiter in the same 16-byte chunk would set the flag even
            // though that byte is not part of the returned run (a benign but
            // real SSE2-vs-scalar divergence — e.g. `"<" + 0xC3 + "a"*14`).
            // When this chunk has no delimiter every lane is in the run, so keep
            // all 16 (`1 << 0` wraps to a full-ones mask only via the branch).
            if delim_mask != 0 {
                let d = delim_mask.trailing_zeros();
                validate_bits &= (1u32 << d).wrapping_sub(1);
            }
            if validate_bits != 0 {
                needs_validation = true;
            }
        }

        if delim_mask != 0 {
            return (pos + delim_mask.trailing_zeros() as usize, needs_validation);
        }
        pos += 16;
    }

    // Scalar tail for remaining < 16 bytes
    let (tail_advance, tail_flag) = scan_content_scalar(&data[pos..]);
    (pos + tail_advance, needs_validation || tail_flag)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn scan_attr_sse2(data: &[u8], quote: u8) -> (usize, bool) {
    use std::arch::x86_64::*;

    let mut pos = 0;
    let mut needs_validation = false;

    // Broadcast delimiter bytes
    let v_amp = _mm_set1_epi8(b'&' as i8);
    let v_lt = _mm_set1_epi8(b'<' as i8);
    let v_quote = _mm_set1_epi8(quote as i8);

    // For control-char detection: bytes <= 0x1F excluding TAB, LF, CR
    let v_1f = _mm_set1_epi8(0x1F_u8 as i8);
    let v_tab = _mm_set1_epi8(0x09);
    let v_lf = _mm_set1_epi8(0x0A);
    let v_cr = _mm_set1_epi8(0x0D);

    while pos + 16 <= data.len() {
        let chunk = _mm_loadu_si128(data.as_ptr().add(pos) as *const __m128i);

        // OR together delimiter equality checks (quote, &, <)
        let delimiters = _mm_or_si128(
            _mm_cmpeq_epi8(chunk, v_quote),
            _mm_or_si128(_mm_cmpeq_epi8(chunk, v_amp), _mm_cmpeq_epi8(chunk, v_lt)),
        );
        let delim_mask = _mm_movemask_epi8(delimiters) as u32;

        if !needs_validation {
            let hi_bits = _mm_movemask_epi8(chunk) as u32;
            let le_1f = _mm_cmpeq_epi8(_mm_min_epu8(chunk, v_1f), chunk);
            let allowed = _mm_or_si128(
                _mm_cmpeq_epi8(chunk, v_tab),
                _mm_or_si128(_mm_cmpeq_epi8(chunk, v_lf), _mm_cmpeq_epi8(chunk, v_cr)),
            );
            let bad_ctrl = _mm_andnot_si128(allowed, le_1f);
            let mut validate_bits = hi_bits | (_mm_movemask_epi8(bad_ctrl) as u32);
            // Restrict validation lanes to bytes before the first delimiter so
            // the flag matches `scan_attr_scalar` exactly (see the same fix in
            // scan_content_sse2). Keep all 16 lanes when the chunk has no
            // delimiter.
            if delim_mask != 0 {
                let d = delim_mask.trailing_zeros();
                validate_bits &= (1u32 << d).wrapping_sub(1);
            }
            if validate_bits != 0 {
                needs_validation = true;
            }
        }

        if delim_mask != 0 {
            return (pos + delim_mask.trailing_zeros() as usize, needs_validation);
        }
        pos += 16;
    }

    // Scalar tail
    let (tail_advance, tail_flag) = scan_attr_scalar(&data[pos..], quote);
    (pos + tail_advance, needs_validation || tail_flag)
}

// ---------------------------------------------------------------------------
// Scalar fallback (used for SIMD tail bytes and non-x86_64 delimiter scans)
// ---------------------------------------------------------------------------

fn scan_content_scalar(data: &[u8]) -> (usize, bool) {
    let mut pos = 0;
    let mut needs_validation = false;
    while pos < data.len() {
        let b = data[pos];
        if b == b'<' || b == b'&' || b == b'\r' || b == b']' {
            break;
        }
        if b >= 0x80 || (b < 0x20 && b != 0x09 && b != 0x0A) {
            needs_validation = true;
        }
        pos += 1;
    }
    (pos, needs_validation)
}

fn scan_attr_scalar(data: &[u8], quote: u8) -> (usize, bool) {
    let mut pos = 0;
    let mut needs_validation = false;
    while pos < data.len() {
        let b = data[pos];
        if b == quote || b == b'&' || b == b'<' {
            break;
        }
        if b >= 0x80 || (b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D) {
            needs_validation = true;
        }
        pos += 1;
    }
    (pos, needs_validation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_stops_at_lt() {
        let data = b"hello<world";
        let (pos, flag) = scan_content_delimiters(data);
        assert_eq!(pos, 5);
        assert!(!flag);
    }

    #[test]
    fn content_stops_at_amp() {
        let data = b"hello&world";
        let (pos, flag) = scan_content_delimiters(data);
        assert_eq!(pos, 5);
        assert!(!flag);
    }

    #[test]
    fn content_stops_at_cr() {
        let data = b"hello\rworld";
        let (pos, flag) = scan_content_delimiters(data);
        assert_eq!(pos, 5);
        assert!(!flag);
    }

    #[test]
    fn content_stops_at_bracket() {
        let data = b"hello]world";
        let (pos, flag) = scan_content_delimiters(data);
        assert_eq!(pos, 5);
        assert!(!flag);
    }

    #[test]
    fn content_scans_full_ascii() {
        let data = b"hello world 12345";
        let (pos, flag) = scan_content_delimiters(data);
        assert_eq!(pos, data.len());
        assert!(!flag);
    }

    #[test]
    fn content_detects_non_ascii() {
        let data = "hello wörld<".as_bytes();
        let (pos, flag) = scan_content_delimiters(data);
        // 'ö' is 2 bytes in UTF-8, so "hello wörld" = 12 bytes, then '<' at byte 12
        assert_eq!(pos, 12);
        assert!(flag);
    }

    #[test]
    fn content_detects_control_char() {
        // "hello" (5) + \x01 (1) + "world" (5) + "<" (1) = 12 bytes; '<' at index 11
        let data = b"hello\x01world<";
        let (pos, flag) = scan_content_delimiters(data);
        assert_eq!(pos, 11);
        assert!(flag);
    }

    #[test]
    fn content_allows_tab_and_lf() {
        let data = b"hello\tworld\n<";
        let (pos, flag) = scan_content_delimiters(data);
        assert_eq!(pos, 12);
        assert!(!flag);
    }

    #[test]
    fn content_empty_input() {
        let (pos, flag) = scan_content_delimiters(b"");
        assert_eq!(pos, 0);
        assert!(!flag);
    }

    #[test]
    fn content_long_text_with_delimiter() {
        // 32 clean bytes then a delimiter — exercises SIMD + tail
        let mut data = vec![b'a'; 32];
        data.push(b'<');
        let (pos, flag) = scan_content_delimiters(&data);
        assert_eq!(pos, 32);
        assert!(!flag);
    }

    #[test]
    fn content_long_text_no_delimiter() {
        let data = vec![b'x'; 100];
        let (pos, flag) = scan_content_delimiters(&data);
        assert_eq!(pos, 100);
        assert!(!flag);
    }

    #[test]
    fn attr_stops_at_double_quote() {
        let data = b"hello\"world";
        let (pos, flag) = scan_attr_delimiters(data, b'"');
        assert_eq!(pos, 5);
        assert!(!flag);
    }

    #[test]
    fn attr_stops_at_single_quote() {
        let data = b"hello'world";
        let (pos, flag) = scan_attr_delimiters(data, b'\'');
        assert_eq!(pos, 5);
        assert!(!flag);
    }

    #[test]
    fn attr_stops_at_amp() {
        let data = b"hello&world";
        let (pos, flag) = scan_attr_delimiters(data, b'"');
        assert_eq!(pos, 5);
        assert!(!flag);
    }

    #[test]
    fn attr_stops_at_lt() {
        let data = b"hello<world";
        let (pos, flag) = scan_attr_delimiters(data, b'"');
        assert_eq!(pos, 5);
        assert!(!flag);
    }

    #[test]
    fn attr_allows_cr_without_flagging() {
        // CR is not a stop byte for attr scan, and is allowed whitespace
        let data = b"hello\rworld\"";
        let (pos, flag) = scan_attr_delimiters(data, b'"');
        assert_eq!(pos, 11);
        assert!(!flag);
    }

    #[test]
    fn attr_detects_non_ascii() {
        let data = "héllo\"".as_bytes();
        let (pos, flag) = scan_attr_delimiters(data, b'"');
        // 'é' is 2 bytes, so "héllo" = 6 bytes
        assert_eq!(pos, 6);
        assert!(flag);
    }

    #[test]
    fn attr_detects_control_char() {
        let data = b"hel\x02lo\"";
        let (pos, flag) = scan_attr_delimiters(data, b'"');
        assert_eq!(pos, 6);
        assert!(flag);
    }

    #[test]
    fn attr_long_text() {
        let mut data = vec![b'z'; 50];
        data.push(b'"');
        let (pos, flag) = scan_attr_delimiters(&data, b'"');
        assert_eq!(pos, 50);
        assert!(!flag);
    }

    #[test]
    fn ncname_continuation_stops_and_lengths() {
        // Full leading run of valid continuation chars.
        assert_eq!(scan_ncname_continuation(b"abc-1.2_z"), 9);
        // Stops at the first invalid ASCII byte.
        assert_eq!(scan_ncname_continuation(b"abc def"), 3);
        assert_eq!(scan_ncname_continuation(b"ab:cd"), 2);
        // Stops at a non-ASCII byte (caller falls through to Unicode).
        assert_eq!(scan_ncname_continuation("ab\u{e9}".as_bytes()), 2);
        // Empty / immediate stop.
        assert_eq!(scan_ncname_continuation(b""), 0);
        assert_eq!(scan_ncname_continuation(b" x"), 0);
        // Length spanning the SIMD chunk boundary + tail.
        assert_eq!(scan_ncname_continuation(b"aaaaaaaaaaaaaaaaaa"), 18);
        assert_eq!(scan_ncname_continuation(b"aaaaaaaaaaaaaaaaa/"), 17);
    }

    #[test]
    fn name_continuation_allows_colon() {
        // Parser XML Names allow ':'; serializer NCNames intentionally do not.
        assert_eq!(scan_name_continuation(b"abc:def-1.2_z"), 13);
        assert_eq!(scan_ncname_continuation(b"abc:def-1.2_z"), 3);
        assert_eq!(scan_name_continuation(b"abc def"), 3);
        assert_eq!(scan_name_continuation("abc\u{e9}".as_bytes()), 3);
        assert_eq!(scan_name_continuation(b"aaaaaaaaaaaaaaaaaa"), 18);
        assert_eq!(scan_name_continuation(b"aaaaaaaaaaaaaaaaa/"), 17);
    }

    #[test]
    fn ncname_continuation_sse2_matches_scalar() {
        // Differential spot-check (the exhaustive check lives in the fuzz
        // harness fuzz_simd_differential): every stop byte at every position
        // across the 16-byte SIMD boundary must agree with the scalar scan.
        for len in 0..40usize {
            for p in 0..len {
                for &sp in &[b' ', b':', b'/', 0x00u8, 0x80u8, 0xFFu8] {
                    let mut d = vec![b'a'; len];
                    d[p] = sp;
                    assert_eq!(
                        scan_ncname_continuation(&d),
                        scan_name_like_continuation_scalar::<false>(&d),
                        "len={len} pos={p} byte={sp:#04x}"
                    );
                }
            }
        }
    }

    #[test]
    fn name_continuation_sse2_matches_scalar() {
        for len in 0..40usize {
            for p in 0..len {
                for &sp in &[b' ', b'/', 0x00u8, 0x80u8, 0xFFu8] {
                    let mut d = vec![b'a'; len];
                    d[p] = sp;
                    assert_eq!(
                        scan_name_continuation(&d),
                        scan_name_like_continuation_scalar::<true>(&d),
                        "len={len} pos={p} byte={sp:#04x}"
                    );
                }
            }
        }
    }

    #[test]
    fn find_byte_matches_scalar() {
        for len in 0..40usize {
            for p in 0..=len {
                let mut d = vec![b'a'; len];
                if p < len {
                    d[p] = b';';
                }
                assert_eq!(
                    find_byte(&d, b';'),
                    find_byte_scalar(&d, b';'),
                    "len={len} pos={p}"
                );
            }
        }
    }

    #[test]
    fn content_flag_matches_scalar_when_delim_precedes_invalid() {
        // Regression: a delimiter at lane 0 followed by an invalid byte within
        // the same 16-byte SIMD chunk must NOT set needs_validation — the
        // returned run is empty, and the scalar reference stops at the
        // delimiter with the flag clear. The SSE2 path previously over-reported
        // here (returned (0, true) vs scalar (0, false)).
        let mut data = vec![b'<', 0xC3];
        data.resize(16, b'a'); // delimiter, invalid byte, then clean fill
        assert_eq!(scan_content_delimiters(&data), (0, false));

        // Non-empty run followed by a delimiter then an invalid byte, all in one
        // chunk: the run "aa" is clean, so the flag stays false.
        let mut data2 = vec![b'a', b'a', b'<', 0xC3];
        data2.resize(16, b'a');
        assert_eq!(scan_content_delimiters(&data2), (2, false));

        // Same shape for attribute scanning (quote at lane 0).
        let mut adata = vec![b'"', 0xC3];
        adata.resize(16, b'a');
        assert_eq!(scan_attr_delimiters(&adata, b'"'), (0, false));
    }
}

/// Fuzz-only surface exposing both the scalar reference and the SSE2
/// implementations of every scanner (plus a direct handle on the serializer's
/// escaper), so the differential fuzz harnesses can assert the two paths agree.
/// Compiled only under `--features fuzzing`; never part of a normal or release
/// build. Child module → can reach the parent's private `scan_*_scalar`/`_sse2`.
#[cfg(feature = "fuzzing")]
pub mod fuzz_exports {
    /// Arch-dispatched entry points (what the parser actually calls). Wrapped
    /// rather than `pub use`d because the originals are `pub(crate)`.
    pub fn scan_content_delimiters(data: &[u8]) -> (usize, bool) {
        super::scan_content_delimiters(data)
    }
    pub fn scan_attr_delimiters(data: &[u8], quote: u8) -> (usize, bool) {
        super::scan_attr_delimiters(data, quote)
    }
    pub fn scan_escape_run(data: &[u8], is_attr: bool) -> usize {
        super::scan_escape_run(data, is_attr)
    }
    pub fn scan_ncname_continuation(data: &[u8]) -> usize {
        super::scan_ncname_continuation(data)
    }
    pub fn scan_name_continuation(data: &[u8]) -> usize {
        super::scan_name_continuation(data)
    }
    pub fn find_byte(data: &[u8], byte: u8) -> Option<usize> {
        super::find_byte(data, byte)
    }

    /// Scalar references — the ground truth, available on every architecture.
    pub fn scan_content_scalar(data: &[u8]) -> (usize, bool) {
        super::scan_content_scalar(data)
    }
    pub fn scan_attr_scalar(data: &[u8], quote: u8) -> (usize, bool) {
        super::scan_attr_scalar(data, quote)
    }
    pub fn scan_escape_scalar(data: &[u8], is_attr: bool) -> usize {
        super::scan_escape_scalar(data, is_attr)
    }
    pub fn scan_ncname_continuation_scalar(data: &[u8]) -> usize {
        super::scan_name_like_continuation_scalar::<false>(data)
    }
    pub fn scan_name_continuation_scalar(data: &[u8]) -> usize {
        super::scan_name_like_continuation_scalar::<true>(data)
    }
    pub fn find_byte_scalar(data: &[u8], byte: u8) -> Option<usize> {
        super::find_byte_scalar(data, byte)
    }

    /// SSE2 implementations (x86_64 only). Safe wrappers: SSE2 is guaranteed on
    /// x86_64, matching the SAFETY note at the real call sites.
    #[cfg(target_arch = "x86_64")]
    pub fn scan_content_sse2(data: &[u8]) -> (usize, bool) {
        unsafe { super::scan_content_sse2(data) }
    }
    #[cfg(target_arch = "x86_64")]
    pub fn scan_attr_sse2(data: &[u8], quote: u8) -> (usize, bool) {
        unsafe { super::scan_attr_sse2(data, quote) }
    }
    #[cfg(target_arch = "x86_64")]
    pub fn scan_escape_sse2(data: &[u8], is_attr: bool) -> usize {
        unsafe { super::scan_escape_sse2(data, is_attr) }
    }
    #[cfg(target_arch = "x86_64")]
    pub fn scan_ncname_continuation_sse2(data: &[u8]) -> usize {
        unsafe { super::scan_name_like_continuation_sse2::<false>(data) }
    }
    #[cfg(target_arch = "x86_64")]
    pub fn scan_name_continuation_sse2(data: &[u8]) -> usize {
        unsafe { super::scan_name_like_continuation_sse2::<true>(data) }
    }
    #[cfg(target_arch = "x86_64")]
    pub fn find_byte_sse2(data: &[u8], byte: u8) -> Option<usize> {
        unsafe { super::find_byte_sse2(data, byte) }
    }

    /// Escape `s` through the real serializer escaper (`write_escaped_run_dyn`),
    /// returning the fragment. Lets the escape harness assert the output never
    /// contains an injectable byte, independent of the SSE2/scalar comparison.
    pub fn escape_to_string(s: &str, is_attr: bool) -> String {
        let mut out = String::new();
        let _ = crate::writer::write_escaped_run_dyn(&mut out, s, is_attr);
        out
    }
}
