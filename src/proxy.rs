//! The session: admission, the RDCleanPath handshake, then bytes.
//!
//! The proxy never decodes RDP. It performs the X.224 exchange and the TLS handshake on the
//! client's behalf, hands back the server's certificate chain so the CLIENT can judge who it
//! reached, and then moves bytes until one side stops.
//!
//! The connection is registered in the live registry at upgrade, before anything is read, so it can
//! be ended at every stage: while the client has not yet sent its request, during admission, while
//! the server is being reached, and once bytes flow.

use crate::app::App;
use crate::config::{Tls, VerifyMode};
use crate::policy::{resolve, Denied, PolicyError};
use crate::resolve::resolve_one;
use crate::store::{now, Server, User};

use futures_util::{SinkExt, StreamExt};
use ironrdp_rdcleanpath::{RDCleanPath, RDCleanPathPdu};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{info, warn};

/// A TPKT header is four bytes and carries the total length of the unit in bytes 2..4, big endian.
/// The X.224 connection confirm is one such unit and must be read whole before TLS begins.
const TPKT_HEADER: usize = 4;
const TPKT_MAX: usize = 65535;

/// Deadlines for setting a session up. Once bytes flow there is none: a desktop can sit idle.
const FIRST_MESSAGE: Duration = Duration::from_secs(30);
const NAME_RESOLUTION: Duration = Duration::from_secs(10);
const SERVER_CONNECT: Duration = Duration::from_secs(10);
const SERVER_HANDSHAKE: Duration = Duration::from_secs(20);

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
    #[error("timed out {0}")]
    Timeout(&'static str),
}

/// Why admission refused a connection. Logged; the client sees one refusal shape for all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    TicketUnknown,
    TicketOtherUser,
    SignInEnded,
    NoSuchServer,
    NotAssigned,
    WrongServer,
    Store,
}

impl Refusal {
    fn detail(self) -> &'static str {
        match self {
            Refusal::TicketUnknown => "connect ticket unknown, spent or expired",
            Refusal::TicketOtherUser => "connect ticket belongs to another user",
            Refusal::SignInEnded => "the sign-in session has ended",
            Refusal::NoSuchServer => "no such server",
            Refusal::NotAssigned => "not assigned to this user",
            Refusal::WrongServer => "ticket was minted for a different server",
            Refusal::Store => "store error during admission",
        }
    }
}

/// One RDP session for a signed-in user.
pub struct Session<'a> {
    pub app: &'a App,
    pub user: &'a User,
    /// The sign-in session the WebSocket was opened under, re-checked at admission.
    pub token_hash: &'a [u8],
    pub peer: SocketAddr,
    /// This connection's entry in the live registry, made at upgrade.
    pub live_id: u64,
}

pub struct TlsSetup {
    pub connector: TlsConnector,
    pub mode: VerifyMode,
}

impl Session<'_> {
    /// Run until either side stops or `ended` fires: revocation, sign-out, the assignment or server
    /// removed, or an import. Whatever happens, the registry entry is removed.
    pub async fn run<S>(&self, ws: WebSocketStream<S>, ended: oneshot::Receiver<()>) -> Result<(), SessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let outcome = tokio::select! {
            r = self.serve(ws) => r,
            _ = ended => {
                info!(peer = %self.peer, subject = %self.user.username, "connection ended by revocation, sign-out, unassignment or import");
                Ok(())
            }
        };
        if let Some(e) = self.app.live.remove(self.live_id) {
            // Closing the TCP connection is a DISCONNECT to Windows, not a sign-out: the desktop
            // stays, and the same account reconnecting to this server picks it up again.
            if let (true, Some(server_id)) = (e.established, e.server_id) {
                if let Err(err) = self.app.store.session_ended(e.user_id, server_id, now()) {
                    warn!(error = %err, "could not record the session end");
                }
            }
        }
        info!(peer = %self.peer, subject = %self.user.username, "connection closed");
        outcome
    }

    /// The admission decision, under the import gate so it cannot straddle a database swap. The
    /// connection was registered before this, so a revocation at any later moment still reaches it.
    pub async fn admit(&self, target_id: &str, proxy_auth: &str) -> Result<Server, Refusal> {
        let _gate = self.app.gate.read().await;
        // THE DESTINATION FIELD CARRIES A SERVER ID, NOT AN ADDRESS. The ticket must have been
        // minted for this user and this server, and is spent here whatever happens next.
        let ticket = match self.app.tickets.redeem(proxy_auth) {
            Some(t) if t.user_id == self.user.id => t,
            Some(_) => return Err(Refusal::TicketOtherUser),
            None => return Err(Refusal::TicketUnknown),
        };
        self.app.live.set_server(self.live_id, ticket.server_id);
        // The sign-in the WebSocket was opened under must still be live, or a ticket minted before
        // a revocation or a sign-out would still connect.
        match self.app.store.session_user(self.token_hash, now()) {
            Ok(Some(u)) if u.id == self.user.id => {}
            Ok(_) => return Err(Refusal::SignInEnded),
            Err(_) => return Err(Refusal::Store),
        }
        match resolve(&self.app.store, self.user.id, target_id) {
            Ok(t) if t.id == ticket.server_id => Ok(t),
            Ok(_) => Err(Refusal::WrongServer),
            Err(PolicyError::Denied(Denied::NoSuchTarget)) => Err(Refusal::NoSuchServer),
            Err(PolicyError::Denied(Denied::NotPermitted)) => Err(Refusal::NotAssigned),
            Err(PolicyError::Store(_)) => Err(Refusal::Store),
        }
    }

    async fn serve<S>(&self, mut ws: WebSocketStream<S>) -> Result<(), SessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let peer = self.peer;
        let subject = self.user.username.as_str();

        // 1. The client's RDCleanPath request, within a deadline.
        let first = match timeout(FIRST_MESSAGE, first_binary(&mut ws)).await {
            Ok(Ok(Some(b))) => b,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(SessionError::Timeout("waiting for the client's request")),
        };
        let pdu = RDCleanPathPdu::from_der(&first).map_err(|_| SessionError::NotARequest)?;
        let (target_id, proxy_auth, x224) = match pdu
            .into_enum()
            .map_err(|_| SessionError::NotARequest)?
        {
            RDCleanPath::Request {
                destination,
                proxy_auth,
                x224_connection_request,
                ..
            } => (destination, proxy_auth, x224_connection_request),
            RDCleanPath::Response { .. }
            | RDCleanPath::GeneralErr(_)
            | RDCleanPath::NegotiationErr { .. } => return Err(SessionError::NotARequest),
        };

        // 2. Admission.
        let target = match self.admit(&target_id, &proxy_auth).await {
            Ok(t) => t,
            Err(r) => {
                warn!(%peer, %subject, target = %target_id, detail = r.detail(), "refused");
                return self.refuse(ws).await;
            }
        };

        let addr = match timeout(NAME_RESOLUTION, resolve_one(&target.host, target.port)).await {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => {
                warn!(%peer, %subject, target = %target.name, error = %e, "resolution failed, failing closed");
                return self.refuse(ws).await;
            }
            Err(_) => {
                warn!(%peer, %subject, target = %target.name, "resolution timed out, failing closed");
                return self.refuse(ws).await;
            }
        };

        // Name AND address, together, because they are the two halves of "which machine was this".
        info!(
            %peer, %subject, target = %target.name,
            host = %target.host, %addr, verify = ?self.app.target_tls.mode,
            "opening session"
        );
        self.app.store.audit(
            subject,
            "session.open",
            &format!("{} ({} -> {addr})", target.name, target.host),
        );

        // 3. X.224, in the clear, exactly as the client sent it.
        let mut tcp = timeout(SERVER_CONNECT, TcpStream::connect(addr))
            .await
            .map_err(|_| SessionError::Timeout("connecting to the server"))??;
        let confirm = timeout(SERVER_HANDSHAKE, async {
            tcp.write_all(x224.as_bytes()).await?;
            read_tpkt(&mut tcp).await
        })
        .await
        .map_err(|_| SessionError::Timeout("waiting for the server's X.224 confirm"))??;

        // 4. TLS, performed here so the client does not have to. RDCleanPath exists to remove this
        //    second encapsulation; the chain goes back to the client so it can still judge identity.
        let server_name = rustls_pki_types::ServerName::try_from(target.host.clone())
            .map_err(|e| SessionError::Tls(e.to_string()))?;
        let tls = timeout(
            SERVER_HANDSHAKE,
            self.app.target_tls.connector.connect(server_name, tcp),
        )
        .await
        .map_err(|_| SessionError::Timeout("in the TLS handshake with the server"))?
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

        // 5. Bytes, both ways, until someone stops. Nothing below this line understands RDP.
        self.app.live.set_established(self.live_id);
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

        tokio::select! {
            r = to_server => r,
            r = to_client => r,
        }
    }

    /// One refusal shape for every denial, so the client learns nothing from which one it hit.
    async fn refuse<S>(&self, mut ws: WebSocketStream<S>) -> Result<(), SessionError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let err = RDCleanPathPdu::new_general_error();
        if let Ok(der) = err.to_der() {
            let _ = ws.send(Message::Binary(der)).await;
        }
        let _ = ws.close(None).await;
        Err(SessionError::Refused)
    }
}

/// The first binary message, answering pings. None if the client closed first.
async fn first_binary<S>(ws: &mut WebSocketStream<S>) -> Result<Option<Vec<u8>>, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(b))) => return Ok(Some(b)),
            Some(Ok(Message::Ping(p))) => ws.send(Message::Pong(p)).await?,
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(e.into()),
            None => return Ok(None),
        }
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
    use crate::web::tests::{signed_in, test_app};

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

    /// The token hash behind a `signed_in` cookie.
    fn hash_of(cookie: &str) -> Vec<u8> {
        crate::auth::token_hash(cookie.split_once('=').unwrap().1)
    }

    #[tokio::test]
    async fn admission_accepts_a_live_sign_in_with_its_ticket() {
        let app = test_app();
        let (uid, cookie) = signed_in(&app, "jdoe");
        let s = app.store.server_create("hist-01", "hist-01.example", 3389, None).unwrap();
        app.store.set_assignments(uid, &[s]).unwrap();
        let user = app.store.user_by_id(uid).unwrap().unwrap();
        let hash = hash_of(&cookie);
        let (live_id, _ended) = app.live.register(uid, hash.clone());
        let session = Session { app: &app, user: &user, token_hash: &hash, peer: "127.0.0.1:1".parse().unwrap(), live_id };
        let ticket = app.tickets.issue(uid, s);
        assert_eq!(session.admit(&s.to_string(), &ticket).await.unwrap().id, s);
    }

    /// A ticket minted before a revocation or sign-out must not connect afterwards.
    #[tokio::test]
    async fn admission_refuses_once_the_sign_in_has_ended() {
        let app = test_app();
        let (uid, cookie) = signed_in(&app, "jdoe");
        let s = app.store.server_create("hist-01", "hist-01.example", 3389, None).unwrap();
        app.store.set_assignments(uid, &[s]).unwrap();
        let user = app.store.user_by_id(uid).unwrap().unwrap();
        let hash = hash_of(&cookie);
        let (live_id, _ended) = app.live.register(uid, hash.clone());
        let session = Session { app: &app, user: &user, token_hash: &hash, peer: "127.0.0.1:1".parse().unwrap(), live_id };
        let ticket = app.tickets.issue(uid, s);
        app.store.sessions_delete_user(uid).unwrap();
        assert_eq!(session.admit(&s.to_string(), &ticket).await.unwrap_err(), Refusal::SignInEnded);
    }

    #[tokio::test]
    async fn admission_refuses_another_users_ticket_and_an_unassigned_server() {
        let app = test_app();
        let (uid, cookie) = signed_in(&app, "jdoe");
        let (other, _) = signed_in(&app, "asmith");
        let s = app.store.server_create("hist-01", "hist-01.example", 3389, None).unwrap();
        let user = app.store.user_by_id(uid).unwrap().unwrap();
        let hash = hash_of(&cookie);
        let (live_id, _ended) = app.live.register(uid, hash.clone());
        let session = Session { app: &app, user: &user, token_hash: &hash, peer: "127.0.0.1:1".parse().unwrap(), live_id };
        let theirs = app.tickets.issue(other, s);
        assert_eq!(session.admit(&s.to_string(), &theirs).await.unwrap_err(), Refusal::TicketOtherUser);
        let mine = app.tickets.issue(uid, s);
        assert_eq!(session.admit(&s.to_string(), &mine).await.unwrap_err(), Refusal::NotAssigned);
    }

    /// A connection that never sends its request is ended by revocation while it waits.
    #[tokio::test]
    async fn a_connection_still_setting_up_is_ended_by_revocation() {
        let app = test_app();
        let (uid, cookie) = signed_in(&app, "jdoe");
        let user = app.store.user_by_id(uid).unwrap().unwrap();
        let hash = hash_of(&cookie);
        let (client, server) = tokio::io::duplex(4096);
        let ws = WebSocketStream::from_raw_socket(server, tokio_tungstenite::tungstenite::protocol::Role::Server, None).await;
        let _client = client; // held open, silent
        let (live_id, ended) = app.live.register(uid, hash.clone());
        let session = Session { app: &app, user: &user, token_hash: &hash, peer: "127.0.0.1:1".parse().unwrap(), live_id };
        let app2 = Arc::clone(&app);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            app2.live.end_user(uid);
        });
        let finished = timeout(Duration::from_secs(5), session.run(ws, ended)).await;
        assert!(finished.is_ok(), "the pending connection was not ended");
        assert_eq!(app.live.count(), 0);
    }
}
