//! Finds the clipboard channel in the MCS connection sequence and lifts its PDUs out of the stream.
//! Every other slow-path unit passes through as it arrived.
//!
//! The channel's id is the Connect Response's channel id at the position of `cliprdr` in the
//! Connect Initial's channel list. Its data arrives in MCS Send Data Request (client to server) and
//! Send Data Indication (server to client) PDUs, chunked by CHANNEL_PDU_HEADER.

use ironrdp_cliprdr::pdu::ClipboardPdu;
use ironrdp_core::{decode, Decode, ReadCursor};
use ironrdp_pdu::mcs::{ConnectInitial, ConnectResponse, McsMessage};
use ironrdp_pdu::rdp::vc::{ChannelControlFlags, ChannelPduHeader};
use ironrdp_pdu::x224::{X224Data, X224};
use ironrdp_svc::{
    client_encode_svc_messages, server_encode_svc_messages, ChannelFlags, SvcMessage,
};

pub const CLIPRDR: &str = "cliprdr";

/// The channel options that let a server bulk-compress the channel's data.
const COMPRESS_OPTIONS: u32 = 0x0080_0000 | 0x0040_0000;

/// A clipboard PDU larger than this is refused rather than buffered.
const MAX_PDU: usize = 64 << 20;

#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("the clipboard channel sent compressed data, which this proxy does not read")]
    Compressed,
    #[error("the clipboard channel is out of step: {0}")]
    OutOfStep(String),
    #[error("cannot write to the clipboard channel before it is known")]
    NoChannel,
}

pub enum Routed {
    /// Forward the unit as it arrived.
    Pass,
    /// Forward this in its place (the Connect Initial, with clipboard compression switched off).
    Replace(Vec<u8>),
    /// A clipboard chunk, held. Once a PDU is whole: its bytes and every unit that carried it.
    Clip(Option<Whole>),
}

#[derive(Clone)]
pub struct Whole {
    pub pdu: Vec<u8>,
    pub units: Vec<Vec<u8>>,
}

impl Whole {
    #[cfg(test)]
    pub fn decode(&self) -> Result<ClipboardPdu<'_>, RouteError> {
        decode::<ClipboardPdu<'_>>(&self.pdu).map_err(|e| RouteError::OutOfStep(e.to_string()))
    }
}

#[derive(Default)]
struct Dechunker {
    pdu: Vec<u8>,
    length: usize,
    units: Vec<Vec<u8>>,
}

impl Dechunker {
    fn push(&mut self, user_data: &[u8], unit: &[u8]) -> Result<Option<Whole>, RouteError> {
        let mut cursor = ReadCursor::new(user_data);
        let header = ChannelPduHeader::decode(&mut cursor)
            .map_err(|e| RouteError::OutOfStep(e.to_string()))?;
        if header
            .flags
            .contains(ChannelControlFlags::PACKET_COMPRESSED)
        {
            return Err(RouteError::Compressed);
        }
        let length = usize::try_from(header.length).unwrap_or(usize::MAX);
        if length > MAX_PDU {
            return Err(RouteError::OutOfStep(format!("a PDU of {length} bytes")));
        }
        if header.flags.contains(ChannelControlFlags::FLAG_FIRST) {
            if !self.units.is_empty() {
                return Err(RouteError::OutOfStep(
                    "a first chunk before the last one".into(),
                ));
            }
            self.length = length;
            self.pdu = Vec::with_capacity(length);
        } else if self.units.is_empty() {
            return Err(RouteError::OutOfStep("a chunk with no first chunk".into()));
        }
        self.pdu.extend_from_slice(cursor.remaining());
        self.units.push(unit.to_vec());
        if self.pdu.len() > self.length {
            return Err(RouteError::OutOfStep("chunks longer than their PDU".into()));
        }
        if !header.flags.contains(ChannelControlFlags::FLAG_LAST) {
            return Ok(None);
        }
        if self.pdu.len() != self.length {
            return Err(RouteError::OutOfStep(
                "chunks shorter than their PDU".into(),
            ));
        }
        Ok(Some(Whole {
            pdu: std::mem::take(&mut self.pdu),
            units: std::mem::take(&mut self.units),
        }))
    }
}

#[derive(Default)]
pub struct Route {
    names: Option<Vec<String>>,
    cliprdr: Option<u16>,
    /// The client's MCS user channel, the initiator of its Send Data Requests.
    user_channel: Option<u16>,
    /// The initiator of the server's Send Data Indications.
    server_initiator: Option<u16>,
    from_client: Dechunker,
    from_server: Dechunker,
}

fn x224_data(unit: &[u8]) -> Option<Vec<u8>> {
    decode::<X224<X224Data<'_>>>(unit)
        .ok()
        .map(|X224(d)| d.data.into_owned())
}

impl Route {
    #[cfg(test)]
    pub fn cliprdr(&self) -> Option<u16> {
        self.cliprdr
    }

    pub fn read_client(&mut self, unit: &[u8]) -> Result<Routed, RouteError> {
        if self.names.is_none() {
            if let Some(names) = x224_data(unit)
                .and_then(|d| decode::<ConnectInitial>(&d).ok())
                .and_then(|ci| ci.channel_names())
            {
                let names: Vec<String> = names
                    .iter()
                    .map(|c| c.name.as_str().unwrap_or_default().to_owned())
                    .collect();
                let replaced = names
                    .iter()
                    .any(|n| n == CLIPRDR)
                    .then(|| no_compression(unit))
                    .flatten();
                self.names = Some(names);
                return Ok(replaced.map_or(Routed::Pass, Routed::Replace));
            }
            return Ok(Routed::Pass);
        }
        match decode::<X224<McsMessage<'_>>>(unit) {
            Ok(X224(McsMessage::SendDataRequest(r))) => {
                self.user_channel = Some(r.initiator_id);
                if Some(r.channel_id) == self.cliprdr {
                    return self.from_client.push(&r.user_data, unit).map(Routed::Clip);
                }
                Ok(Routed::Pass)
            }
            _ => Ok(Routed::Pass),
        }
    }

    pub fn read_server(&mut self, unit: &[u8]) -> Result<Routed, RouteError> {
        if self.cliprdr.is_none() {
            if let Some(names) = &self.names {
                if let Some(ids) = x224_data(unit)
                    .and_then(|d| decode::<ConnectResponse>(&d).ok())
                    .map(|cr| cr.channel_ids())
                {
                    self.cliprdr = names
                        .iter()
                        .position(|n| n == CLIPRDR)
                        .and_then(|i| ids.get(i).copied());
                    return Ok(Routed::Pass);
                }
            }
        }
        match decode::<X224<McsMessage<'_>>>(unit) {
            Ok(X224(McsMessage::SendDataIndication(i))) => {
                self.server_initiator = Some(i.initiator_id);
                if Some(i.channel_id) == self.cliprdr {
                    return self.from_server.push(&i.user_data, unit).map(Routed::Clip);
                }
                Ok(Routed::Pass)
            }
            _ => Ok(Routed::Pass),
        }
    }

    /// A clipboard PDU of the proxy's own, framed for the server.
    pub fn to_server(&self, pdu: ClipboardPdu<'static>) -> Result<Vec<u8>, RouteError> {
        let (Some(channel), Some(user)) = (self.cliprdr, self.user_channel) else {
            return Err(RouteError::NoChannel);
        };
        client_encode_svc_messages(vec![message(pdu)], channel, user)
            .map_err(|e| RouteError::OutOfStep(e.to_string()))
    }

    /// A clipboard PDU of the proxy's own, framed for the client.
    pub fn to_client(&self, pdu: ClipboardPdu<'static>) -> Result<Vec<u8>, RouteError> {
        let (Some(channel), Some(initiator)) = (self.cliprdr, self.server_initiator) else {
            return Err(RouteError::NoChannel);
        };
        server_encode_svc_messages(vec![message(pdu)], channel, initiator)
            .map_err(|e| RouteError::OutOfStep(e.to_string()))
    }
}

/// CHANNEL_FLAG_SHOW_PROTOCOL is required on clipboard messages (MS-RDPBCGR), as IronRDP's own
/// clipboard client sets it.
fn message(pdu: ClipboardPdu<'static>) -> SvcMessage {
    SvcMessage::from(pdu).with_flags(ChannelFlags::SHOW_PROTOCOL)
}

/// The Connect Initial with the clipboard channel's compression options cleared, in place: the
/// server then never bulk-compresses clipboard data, and nothing else about the unit changes.
fn no_compression(unit: &[u8]) -> Option<Vec<u8>> {
    let name = b"cliprdr\0";
    let at = unit.windows(name.len()).position(|w| w == name)? + name.len();
    if unit[at..].windows(name.len()).any(|w| w == name) {
        return None;
    }
    let options = u32::from_le_bytes(unit.get(at..at + 4)?.try_into().ok()?);
    let mut out = unit.to_vec();
    out[at..at + 4].copy_from_slice(&(options & !COMPRESS_OPTIONS).to_le_bytes());
    Some(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ironrdp_cliprdr::pdu::{
        ClipboardFormat, ClipboardFormatId, ClipboardFormatName, FormatList,
    };
    use ironrdp_core::encode_vec;
    use ironrdp_pdu::gcc::{
        ChannelDef, ChannelName, ChannelOptions, ClientCoreData, ClientGccBlocks,
        ClientNetworkData, ClientSecurityData, ConferenceCreateResponse, RdpVersion,
        ServerCoreData, ServerGccBlocks, ServerNetworkData, ServerSecurityData,
    };
    use ironrdp_pdu::mcs::{DomainParameters, SendDataIndication, SendDataRequest};
    use std::borrow::Cow;

    pub const USER: u16 = 1007;
    pub const IO: u16 = 1003;
    pub const CLIP: u16 = 1005;
    pub const OTHER: u16 = 1006;
    pub const QUIET: [u8; 16] = [0x08, 0, 0, 0, 0x03, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];

    fn client_core() -> ClientCoreData {
        ClientCoreData {
            version: RdpVersion(0x0008_0004),
            desktop_width: 1280,
            desktop_height: 800,
            color_depth: ironrdp_pdu::gcc::ColorDepth::Bpp8,
            sec_access_sequence: ironrdp_pdu::gcc::SecureAccessSequence::Del,
            keyboard_layout: 0x409,
            client_build: 1,
            client_name: "test".into(),
            keyboard_type: ironrdp_pdu::gcc::KeyboardType(4),
            keyboard_subtype: 0,
            keyboard_functional_keys_count: 12,
            ime_file_name: String::new(),
            optional_data: Default::default(),
        }
    }

    /// A Connect Initial naming rdpsnd, cliprdr and drdynvc, cliprdr asking for compression.
    pub fn connect_initial() -> Vec<u8> {
        let channel = |name: &str, options| ChannelDef {
            name: ChannelName::from_utf8(name).unwrap(),
            options,
        };
        let blocks = ClientGccBlocks {
            core: client_core(),
            security: ClientSecurityData::no_security(),
            network: Some(ClientNetworkData {
                channels: vec![
                    channel("rdpsnd", ChannelOptions::INITIALIZED),
                    channel(
                        CLIPRDR,
                        ChannelOptions::INITIALIZED
                            | ChannelOptions::COMPRESS_RDP
                            | ChannelOptions::SHOW_PROTOCOL,
                    ),
                    channel(
                        "drdynvc",
                        ChannelOptions::INITIALIZED | ChannelOptions::COMPRESS_RDP,
                    ),
                ],
            }),
            cluster: None,
            monitor: None,
            message_channel: None,
            multi_transport_channel: None,
            monitor_extended: None,
        };
        let ci = ConnectInitial::with_gcc_blocks(blocks).unwrap();
        encode_vec(&X224(X224Data {
            data: Cow::Owned(encode_vec(&ci).unwrap()),
        }))
        .unwrap()
    }

    pub fn connect_response() -> Vec<u8> {
        let blocks = ServerGccBlocks {
            core: ServerCoreData {
                version: RdpVersion(0x0008_0004),
                optional_data: Default::default(),
            },
            network: ServerNetworkData {
                channel_ids: vec![1004, CLIP, OTHER],
                io_channel: IO,
            },
            security: ServerSecurityData::no_security(),
            message_channel: None,
            multi_transport_channel: None,
        };
        let cr = ConnectResponse {
            conference_create_response: ConferenceCreateResponse::new(USER, blocks).unwrap(),
            called_connect_id: 0,
            domain_parameters: DomainParameters::target(),
        };
        encode_vec(&X224(X224Data {
            data: Cow::Owned(encode_vec(&cr).unwrap()),
        }))
        .unwrap()
    }

    /// A route past the connection sequence, with both initiators seen.
    pub fn connected() -> Route {
        let mut r = Route::default();
        r.read_client(&connect_initial()).unwrap();
        r.read_server(&connect_response()).unwrap();
        r.read_client(&send_request(OTHER, &QUIET)).unwrap();
        r.read_server(&send_indication(OTHER, &QUIET)).unwrap();
        r
    }

    pub fn send_request(channel: u16, user_data: &[u8]) -> Vec<u8> {
        encode_vec(&X224(McsMessage::SendDataRequest(SendDataRequest {
            initiator_id: USER,
            channel_id: channel,
            user_data: Cow::Owned(user_data.to_vec()),
        })))
        .unwrap()
    }

    pub fn send_indication(channel: u16, user_data: &[u8]) -> Vec<u8> {
        encode_vec(&X224(McsMessage::SendDataIndication(SendDataIndication {
            initiator_id: IO,
            channel_id: channel,
            user_data: Cow::Owned(user_data.to_vec()),
        })))
        .unwrap()
    }

    fn big_format_list() -> ClipboardPdu<'static> {
        let formats: Vec<ClipboardFormat> = (0..200)
            .map(|i| {
                ClipboardFormat::new(ClipboardFormatId::new(0xc000 + i))
                    .with_name(ClipboardFormatName::new(format!("A registered format {i}")))
            })
            .collect();
        ClipboardPdu::FormatList(FormatList::new_unicode(&formats, true).unwrap())
    }

    /// Units for one PDU, chunked as a client would send them.
    pub fn from_client_units(pdu: ClipboardPdu<'static>, max: usize) -> Vec<Vec<u8>> {
        let bytes = ironrdp_svc::client_encode_svc_messages_with_max_chunk_len(
            vec![message(pdu)],
            CLIP,
            USER,
            max,
        )
        .unwrap();
        units(&bytes, false)
    }

    pub fn units(bytes: &[u8], from_server: bool) -> Vec<Vec<u8>> {
        crate::scan::framing::Framer::new(from_server, false)
            .push(bytes)
            .unwrap()
            .into_iter()
            .map(|u| u.bytes().to_vec())
            .collect()
    }

    #[test]
    fn the_clipboard_channel_is_found_and_its_compression_switched_off() {
        let mut r = Route::default();
        let ci = connect_initial();
        let Routed::Replace(sent) = r.read_client(&ci).unwrap() else {
            panic!("the Connect Initial was not rewritten");
        };
        assert_eq!(sent.len(), ci.len());
        let data = x224_data(&sent).unwrap();
        let names = decode::<ConnectInitial>(&data)
            .unwrap()
            .channel_names()
            .unwrap();
        let clip = names
            .iter()
            .find(|c| c.name.as_str() == Some(CLIPRDR))
            .unwrap();
        assert!(!clip.options.contains(ChannelOptions::COMPRESS_RDP));
        assert!(clip.options.contains(ChannelOptions::SHOW_PROTOCOL));
        let other = names
            .iter()
            .find(|c| c.name.as_str() == Some("drdynvc"))
            .unwrap();
        assert!(other.options.contains(ChannelOptions::COMPRESS_RDP));
        assert!(matches!(
            r.read_server(&connect_response()).unwrap(),
            Routed::Pass
        ));
        assert_eq!(r.cliprdr(), Some(CLIP));
    }

    #[test]
    fn a_clipboard_pdu_is_put_back_together_from_its_chunks() {
        let mut r = connected();
        let units = from_client_units(big_format_list(), 1600);
        assert!(units.len() > 1, "the test PDU must span chunks");
        let mut whole = None;
        for (n, unit) in units.iter().enumerate() {
            match r.read_client(unit).unwrap() {
                Routed::Clip(Some(w)) => {
                    assert_eq!(n, units.len() - 1);
                    whole = Some(w);
                }
                Routed::Clip(None) => assert!(n < units.len() - 1),
                _ => panic!("a clipboard chunk passed through"),
            }
        }
        let whole = whole.unwrap();
        assert_eq!(
            whole.units, units,
            "the units kept are the ones that arrived"
        );
        assert!(matches!(
            whole.decode().unwrap(),
            ClipboardPdu::FormatList(_)
        ));
        assert!(matches!(
            r.read_client(&send_request(OTHER, &QUIET)).unwrap(),
            Routed::Pass
        ));
    }

    #[test]
    fn a_compressed_clipboard_chunk_is_refused() {
        let mut r = connected();
        let flags = (ChannelControlFlags::FLAG_FIRST
            | ChannelControlFlags::FLAG_LAST
            | ChannelControlFlags::PACKET_COMPRESSED)
            .bits();
        let mut data = 4u32.to_le_bytes().to_vec();
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&[1, 2, 3, 4]);
        assert!(matches!(
            r.read_server(&send_indication(CLIP, &data)),
            Err(RouteError::Compressed)
        ));
    }

    #[test]
    fn a_pdu_written_by_the_proxy_reads_back_the_same_on_either_side() {
        let r = connected();
        for (bytes, to_server) in [
            (r.to_server(big_format_list()).unwrap(), true),
            (r.to_client(big_format_list()).unwrap(), false),
        ] {
            let mut reader = connected();
            let mut whole = None;
            for u in units(&bytes, !to_server) {
                let routed = if to_server {
                    reader.read_client(&u)
                } else {
                    reader.read_server(&u)
                };
                if let Routed::Clip(Some(w)) = routed.unwrap() {
                    whole = Some(w);
                }
            }
            let whole = whole.expect("the PDU came back whole");
            assert_eq!(whole.pdu, encode_vec(&big_format_list()).unwrap());
        }
    }
}
