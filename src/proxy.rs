//! The session: RDCleanPath handshake, then bytes.
//!
//! The proxy never decodes RDP. It performs the X.224 exchange and the TLS handshake on the
//! client's behalf, hands back the server's certificate chain so the CLIENT can judge who it
//! reached, and then moves bytes until one side stops.

use crate::auth::Authenticator;
use crate::config::{Tls, VerifyMode};
use crate::policy::{Catalogue, Denied};
use crate::resolve::resolve_one;

use futures_util::{SinkExt, StreamExt};
use ironrdp_rdcleanpath::{RDCleanPath, RDCleanPathPdu};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{info, warn};

/// A TPKT header is four bytes and carries the total length of the unit in bytes 2..4, big endian.
/// The X.224 connection confirm is one such unit and must be read whole before TLS begins.
const TPKT_HEADER: usize = 4;
const TPKT_MAX: usize = 65535;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("websocket: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("the first message was not an RDCleanPath request")]
    NotARequest,
    #[error("refused")]
    Refused,
    #[error("tls: {0}")]
    Tls(String),
}

pub struct Session {
    pub catalogue: Arc<Catalogue>,
    pub authenticator: Arc<dyn Authenticator>,
    pub tls: Arc<TlsSetup>,
}

pub struct TlsSetup {
    pub connector: TlsConnector,
    pub mode: VerifyMode,
}

impl Session {
    pub async fn run(
        &self,
        mut ws: WebSocketStream<TcpStream>,
        peer: std::net::SocketAddr,
    ) -> Result<(), SessionError> {
        // 1. The client's RDCleanPath request.
        let first = loop {
            match ws.next().await {
                Some(Ok(Message::Binary(b))) => break b,
                Some(Ok(Message::Ping(p))) => ws.send(Message::Pong(p)).await?,
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(e.into()),
                None => return Ok(()),
            }
        };

        let pdu = RDCleanPathPdu::from_der(&first).map_err(|_| SessionError::NotARequest)?;
        let (target_id, proxy_auth, x224, _pcb) = match pdu
            .into_enum()
            .map_err(|_| SessionError::NotARequest)?
        {
            RDCleanPath::Request {
                destination,
                proxy_auth,
                server_auth: _,
                preconnection_blob,
                x224_connection_request,
            } => (
                destination,
                proxy_auth,
                x224_connection_request,
                preconnection_blob,
            ),
            RDCleanPath::Response { .. }
            | RDCleanPath::GeneralErr(_)
            | RDCleanPath::NegotiationErr { .. } => return Err(SessionError::NotARequest),
        };

        // THE DESTINATION FIELD CARRIES A TARGET ID, NOT AN ADDRESS. RDCleanPath was designed for a
        // client that names a host; here the field is an opaque key into the allowlist, so "reach an
        // arbitrary host" is not a request this protocol can express.
        let identity = match self.authenticator.authenticate(&proxy_auth) {
            Ok(id) => id,
            Err(e) => {
                warn!(%peer, error = %e, "proxy authentication refused");
                return self.refuse(ws).await;
            }
        };

        let target = match self.catalogue.resolve(&identity, &target_id) {
            Ok(t) => t,
            Err(reason) => {
                // The log distinguishes these. The client does not: telling an unauthenticated
                // caller "no such target" builds them an enumeration oracle.
                let detail = match reason {
                    Denied::NoSuchTarget => "no such target",
                    Denied::NotPermitted => "not permitted for this identity",
                };
                warn!(%peer, subject = %identity.subject, target = %target_id, %detail, "refused");
                return self.refuse(ws).await;
            }
        };

        let addr = match resolve_one(&target.host, target.port).await {
            Ok(a) => a,
            Err(e) => {
                warn!(%peer, subject = %identity.subject, target = %target.id, error = %e, "resolution failed, failing closed");
                return self.refuse(ws).await;
            }
        };

        // Name AND address, together, because they are the two halves of "which machine was this".
        info!(
            %peer, subject = %identity.subject, target = %target.id,
            host = %target.host, %addr, verify = ?self.tls.mode,
            "opening session"
        );

        // 2. X.224, in the clear, exactly as the client sent it.
        let mut tcp = TcpStream::connect(addr).await?;
        tcp.write_all(x224.as_bytes()).await?;
        let confirm = read_tpkt(&mut tcp).await?;

        // 3. TLS, performed here so the client does not have to. RDCleanPath exists to remove this
        //    second encapsulation; the chain goes back to the client so it can still judge identity.
        let server_name = rustls_pki_types::ServerName::try_from(target.host.clone())
            .map_err(|e| SessionError::Tls(e.to_string()))?;
        let tls = self
            .tls
            .connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| SessionError::Tls(e.to_string()))?;

        let chain: Vec<Vec<u8>> = tls
            .get_ref()
            .1
            .peer_certificates()
            .map(|certs| certs.iter().map(|c| c.as_ref().to_vec()).collect())
            .unwrap_or_default();

        let response = RDCleanPathPdu::new_response(addr.ip().to_string(), confirm, chain)
            .map_err(|e| SessionError::Tls(e.to_string()))?;
        ws.send(Message::Binary(
            response
                .to_der()
                .map_err(|e| SessionError::Tls(e.to_string()))?,
        ))
        .await?;

        // 4. Bytes, both ways, until someone stops. Nothing below this line understands RDP.
        let (mut ws_tx, mut ws_rx) = ws.split();
        let (mut srv_rx, mut srv_tx) = tokio::io::split(tls);

        let to_server = async {
            while let Some(msg) = ws_rx.next().await {
                match msg? {
                    Message::Binary(b) => srv_tx.write_all(&b).await?,
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            Ok::<_, SessionError>(())
        };

        let to_client = async {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = srv_rx.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                ws_tx.send(Message::Binary(buf[..n].to_vec())).await?;
            }
            Ok::<_, SessionError>(())
        };

        let outcome = tokio::select! {
            r = to_server => r,
            r = to_client => r,
        };

        info!(%peer, subject = %identity.subject, target = %target.id, "session closed");
        outcome
    }

    /// One refusal shape for every denial, so the client learns nothing from which one it hit.
    async fn refuse(&self, mut ws: WebSocketStream<TcpStream>) -> Result<(), SessionError> {
        let err = RDCleanPathPdu::new_general_error();
        if let Ok(der) = err.to_der() {
            let _ = ws.send(Message::Binary(der)).await;
        }
        let _ = ws.close(None).await;
        Err(SessionError::Refused)
    }
}

/// Read one whole TPKT unit. A short read here would hand a truncated X.224 confirm to the client.
async fn read_tpkt(stream: &mut TcpStream) -> Result<Vec<u8>, std::io::Error> {
    let mut head = [0u8; TPKT_HEADER];
    stream.read_exact(&mut head).await?;
    let length = u16::from_be_bytes([head[2], head[3]]) as usize;
    if length < TPKT_HEADER || length > TPKT_MAX {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("implausible TPKT length {length}"),
        ));
    }
    let mut unit = vec![0u8; length];
    unit[..TPKT_HEADER].copy_from_slice(&head);
    stream.read_exact(&mut unit[TPKT_HEADER..]).await?;
    Ok(unit)
}

/// Build the TLS client side from config.
pub fn tls_setup(cfg: &Tls) -> Result<TlsSetup, SessionError> {
    let config = match cfg.verify {
        VerifyMode::Ca => {
            let path = cfg
                .ca_bundle
                .as_ref()
                .ok_or_else(|| SessionError::Tls("ca_bundle required".into()))?;
            let pem = std::fs::read(path)?;
            let mut roots = rustls::RootCertStore::empty();
            for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
                let cert = cert?;
                roots
                    .add(cert)
                    .map_err(|e| SessionError::Tls(e.to_string()))?;
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        VerifyMode::Insecure => {
            warn!("tls.verify = insecure: the target's certificate is NOT checked, so name resolution is the only thing deciding which machine this reaches");
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(insecure::AcceptAny))
                .with_no_client_auth()
        }
    };
    Ok(TlsSetup {
        connector: TlsConnector::from(Arc::new(config)),
        mode: cfg.verify,
    })
}

mod insecure {
    //! Kept in its own module so it is greppable and obvious in review.
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct AcceptAny;

    impl ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_tpkt_unit_is_read_whole() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // TPKT: version 3, reserved 0, length 7, then three payload bytes.
            s.write_all(&[0x03, 0x00, 0x00, 0x07, 0xaa, 0xbb, 0xcc])
                .await
                .unwrap();
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let unit = read_tpkt(&mut client).await.unwrap();
        assert_eq!(unit, vec![0x03, 0x00, 0x00, 0x07, 0xaa, 0xbb, 0xcc]);
    }

    #[tokio::test]
    async fn an_implausible_length_is_refused_rather_than_allocated() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(&[0x03, 0x00, 0x00, 0x02]).await.unwrap();
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        assert!(read_tpkt(&mut client).await.is_err());
    }
}
