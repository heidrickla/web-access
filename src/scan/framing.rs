//! Cuts one direction of the relayed stream into whole units, so the clipboard channel can be
//! read and written without splitting anything else. Units keep their original bytes: what is not
//! the clipboard channel is forwarded exactly as it arrived.
//!
//! After RDCleanPath the stream carries, in order: the CredSSP messages of network level
//! authentication (DER, when NLA was negotiated); under HYBRID_EX, the server's four-byte Early
//! User Authorization Result; then TPKT (slow-path) and fast-path PDUs.

use ironrdp_pdu::{find_size, Action};

/// A PDU larger than this is not RDP; the stream is out of step.
const MAX_UNIT: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unit {
    /// CredSSP, or the Early User Authorization Result: passed on, never read.
    Opaque(Vec<u8>),
    /// Slow-path: X.224, where MCS and the virtual channels are.
    Tpkt(Vec<u8>),
    FastPath(Vec<u8>),
}

impl Unit {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Unit::Opaque(b) | Unit::Tpkt(b) | Unit::FastPath(b) => b,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("the RDP stream is out of step: {0}")]
    OutOfStep(String),
}

pub struct Framer {
    buf: Vec<u8>,
    from_server: bool,
    hybrid_ex: bool,
    /// A TPKT has been seen in this direction: authentication is over and fast-path may follow.
    mcs: bool,
    euar_seen: bool,
}

impl Framer {
    /// `hybrid_ex`: the server selected PROTOCOL_HYBRID_EX, so it sends the Early User
    /// Authorization Result after authentication.
    pub fn new(from_server: bool, hybrid_ex: bool) -> Self {
        Self {
            buf: Vec::new(),
            from_server,
            hybrid_ex,
            mcs: false,
            euar_seen: false,
        }
    }

    /// Adds bytes as they arrived and returns every unit now complete.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Unit>, FrameError> {
        self.buf.extend_from_slice(bytes);
        let mut units = Vec::new();
        while let Some(unit) = self.next_unit()? {
            units.push(unit);
        }
        Ok(units)
    }

    fn next_unit(&mut self) -> Result<Option<Unit>, FrameError> {
        let Some(&first) = self.buf.first() else {
            return Ok(None);
        };
        // State changes only once a unit is whole: a piece that stops mid-unit decides nothing.
        let euar = !self.mcs && self.from_server && self.hybrid_ex && !self.euar_seen;
        let (len, kind): (usize, fn(Vec<u8>) -> Unit) = if !self.mcs && first == 0x30 {
            match der_length(&self.buf)? {
                Some(n) => (n, Unit::Opaque),
                None => return Ok(None),
            }
        } else if euar && first != 0x03 {
            (4, Unit::Opaque)
        } else {
            let info = find_size(&self.buf).map_err(|e| FrameError::OutOfStep(e.to_string()))?;
            let Some(info) = info else {
                return Ok(None);
            };
            match info.action {
                Action::X224 => (info.length, Unit::Tpkt),
                Action::FastPath if self.mcs => (info.length, Unit::FastPath),
                Action::FastPath => {
                    return Err(FrameError::OutOfStep(format!(
                        "byte {first:#04x} before the connection sequence"
                    )))
                }
            }
        };
        if len == 0 || len > MAX_UNIT {
            return Err(FrameError::OutOfStep(format!("a unit of {len} bytes")));
        }
        if self.buf.len() < len {
            return Ok(None);
        }
        let rest = self.buf.split_off(len);
        let unit = kind(std::mem::replace(&mut self.buf, rest));
        match unit {
            Unit::Tpkt(_) => self.mcs = true,
            Unit::Opaque(_) if euar && first != 0x30 => self.euar_seen = true,
            _ => {}
        }
        Ok(Some(unit))
    }
}

/// The whole length of a DER TLV starting at `buf[0]`, once its length octets are in.
fn der_length(buf: &[u8]) -> Result<Option<usize>, FrameError> {
    let Some(&first) = buf.get(1) else {
        return Ok(None);
    };
    if first < 0x80 {
        return Ok(Some(2 + usize::from(first)));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 || n > 4 {
        return Err(FrameError::OutOfStep(format!("a DER length of {n} octets")));
    }
    let Some(octets) = buf.get(2..2 + n) else {
        return Ok(None);
    };
    let len = octets
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
    Ok(Some(2 + n + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tpkt(body: &[u8]) -> Vec<u8> {
        let len = (4 + body.len()) as u16;
        let mut v = vec![0x03, 0x00];
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    /// Fast-path with a one-byte length.
    fn fast_path(body: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, (2 + body.len()) as u8];
        v.extend_from_slice(body);
        v
    }

    fn der(body: &[u8]) -> Vec<u8> {
        let mut v = vec![0x30];
        if body.len() < 0x80 {
            v.push(body.len() as u8);
        } else {
            v.push(0x82);
            v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        }
        v.extend_from_slice(body);
        v
    }

    fn whole_stream() -> (Vec<u8>, Vec<Unit>) {
        let units = vec![
            Unit::Opaque(der(&[0xa0; 10])),
            Unit::Opaque(der(&[0xa1; 300])),
            Unit::Opaque(vec![0x00, 0x00, 0x00, 0x00]),
            Unit::Tpkt(tpkt(&[0x02, 0xf0, 0x80, 0x7f, 0x66])),
            Unit::FastPath(fast_path(&[1, 2, 3, 4, 5])),
            Unit::Tpkt(tpkt(&[0x02, 0xf0, 0x80, 0x68, 1, 2, 3])),
        ];
        let bytes = units.iter().flat_map(|u| u.bytes().to_vec()).collect();
        (bytes, units)
    }

    #[test]
    fn units_come_out_whole_however_the_bytes_arrive() {
        let (bytes, want) = whole_stream();
        // All at once, one byte at a time, and in uneven pieces.
        for piece in [bytes.len(), 1, 7, 13] {
            let mut f = Framer::new(true, true);
            let mut got = Vec::new();
            for chunk in bytes.chunks(piece) {
                got.extend(f.push(chunk).unwrap());
            }
            assert_eq!(got, want, "pieces of {piece}");
        }
    }

    #[test]
    fn the_early_authorization_result_is_expected_only_from_a_hybrid_ex_server() {
        // From the client, or from a plain HYBRID server, a zero byte before MCS is out of step.
        let mut client = Framer::new(false, true);
        assert!(client.push(&[0x00, 0x00, 0x00, 0x00]).is_err());
        let mut hybrid = Framer::new(true, false);
        assert!(hybrid.push(&[0x00, 0x00, 0x00, 0x00]).is_err());
        let mut ex = Framer::new(true, true);
        assert_eq!(ex.push(&[0x00, 0x00, 0x00, 0x00]).unwrap().len(), 1);
    }

    #[test]
    fn fast_path_is_refused_before_the_connection_sequence_and_sizes_are_bounded() {
        let mut f = Framer::new(false, false);
        assert!(f.push(&fast_path(&[1, 2])).is_err());
        let mut f = Framer::new(false, false);
        assert!(f.push(&[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff]).is_err());
        let mut f = Framer::new(false, false);
        assert!(f.push(&[0x30, 0x85]).is_err());
    }

    #[test]
    fn a_partial_unit_waits_for_the_rest() {
        let mut f = Framer::new(false, false);
        let t = tpkt(&[9; 50]);
        assert!(f.push(&t[..20]).unwrap().is_empty());
        assert_eq!(f.push(&t[20..]).unwrap(), vec![Unit::Tpkt(t)]);
    }
}
