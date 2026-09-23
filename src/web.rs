//! Serving the browser client.
//!
//! "Clientless" means nothing is INSTALLED on the accessing machine, not that no client exists. The
//! RDP client is `ironrdp-web` compiled to WebAssembly, and it is delivered to the browser on
//! demand, per session. This module is what delivers it.
//!
//! The assets are EMBEDDED IN THE BINARY rather than served from a web root. The deployment story is
//! one MSI, one service, browse to it: a web root would add a second thing to install, a path to get
//! wrong, and a way for the served client to drift from the proxy it talks to.
//!
//! The HTTP handled here is deliberately tiny — GET on a fixed set of paths, nothing else. Anything
//! that is not one of those paths is a 404, and the WebSocket endpoint never reaches this code.

use crate::policy::Catalogue;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Where the browser opens its WebSocket. Everything else on the listener is a static asset.
pub const WS_PATH: &str = "/ws";

/// Where the launcher fetches its token and its list of systems.
pub const TARGETS_PATH: &str = "/api/targets";

/// (request path, content type, bytes).
pub const ASSETS: &[(&str, &str, &[u8])] = &[
    ("/", "text/html; charset=utf-8", include_bytes!("../web/index.html")),
    ("/index.html", "text/html; charset=utf-8", include_bytes!("../web/index.html")),
    ("/app.css", "text/css; charset=utf-8", include_bytes!("../web/app.css")),
    ("/app.js", "text/javascript; charset=utf-8", include_bytes!("../web/app.js")),
    ("/ironrdp_web.js", "text/javascript; charset=utf-8", include_bytes!("../web/ironrdp_web.js")),
    ("/ironrdp_web_bg.wasm", "application/wasm", include_bytes!("../web/ironrdp_web_bg.wasm")),
];

/// Peek at the request line without consuming it, so a WebSocket upgrade can still be handed to the
/// handshake code with its bytes intact. Routing is by PATH rather than by the Upgrade header: a
/// header block can be split across segments, a request line essentially never is.
pub async fn peek_path(stream: &TcpStream) -> io::Result<String> {
    let mut buf = [0u8; 512];
    let n = stream.peek(&mut buf).await?;
    let head = String::from_utf8_lossy(&buf[..n]);
    Ok(head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_owned())
}

/// The launcher's data: a freshly minted proxy token and the systems this caller may reach.
///
/// THE TOKEN IS NEVER TYPED BY A HUMAN. It is minted here and handed to the page, which sends it
/// back on the WebSocket. Asking a person to paste it would have been a password box that
/// authenticated nothing, since the page is served to whoever can reach the proxy anyway.
fn launcher_json(catalogue: &Catalogue, all_groups: &[String]) -> String {
    let identity = crate::auth::identify(all_groups);
    let token = crate::auth::Sessions::global().mint(identity.clone());

    let mut targets = catalogue.permitted(&identity);
    targets.sort_by(|a, b| a.id.cmp(&b.id));

    let items: Vec<String> = targets
        .iter()
        .map(|t| {
            format!(
                r#"{{"id":{},"tags":[{}]}}"#,
                json_string(&t.id),
                t.tags.iter().map(|s| json_string(s)).collect::<Vec<_>>().join(",")
            )
        })
        .collect();

    format!(
        r#"{{"token":{},"targets":[{}]}}"#,
        json_string(&token),
        items.join(",")
    )
}

/// Enough JSON string escaping for ids and tags, which the config author writes. Escapes the
/// characters that would break out of a string rather than assuming none are present.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Read the request off the socket and answer it. Only GET on a known path succeeds.
pub async fn serve(
    mut stream: TcpStream,
    path: &str,
    catalogue: &Catalogue,
    all_groups: &[String],
) -> io::Result<()> {
    drain_request(&mut stream).await?;

    if path == TARGETS_PATH {
        let body = launcher_json(catalogue, all_groups);
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
             Cache-Control: no-store\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes()).await?;
        stream.write_all(body.as_bytes()).await?;
        return stream.flush().await;
    }

    match ASSETS.iter().find(|(p, _, _)| *p == path) {
        Some((_, content_type, body)) => {
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
                 Cache-Control: no-store\r\n\
                 X-Content-Type-Options: nosniff\r\n\
                 Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' ws: wss:\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).await?;
            stream.write_all(body).await?;
        }
        None => {
            let body = b"not found";
            let header = format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).await?;
            stream.write_all(body).await?;
        }
    }
    stream.flush().await
}

/// Consume the request head. Bounded, because an unbounded read here is a trivial memory exhaustion
/// from an unauthenticated peer.
async fn drain_request(stream: &mut TcpStream) -> io::Result<()> {
    const LIMIT: usize = 16 * 1024;
    let mut seen = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while seen.len() < LIMIT {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        seen.push(byte[0]);
        if seen.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_request_line_decides_the_route() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n")
                .await
                .unwrap();
            // Hold the connection open so the peek has something to look at.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        let (stream, _) = listener.accept().await.unwrap();
        assert_eq!(peek_path(&stream).await.unwrap(), WS_PATH);
    }

    #[tokio::test]
    async fn a_query_string_does_not_change_the_route() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(b"GET /index.html?v=2 HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        let (stream, _) = listener.accept().await.unwrap();
        assert_eq!(peek_path(&stream).await.unwrap(), "/index.html");
    }

    /// The page is served with `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'`, which
    /// permits neither an inline <style> nor an inline <script>. Inlining either produced a page
    /// that rendered unstyled and sat on "loading" forever, with the cause visible only in the
    /// browser console. The CSP and the page have to agree, so this asserts they do.
    #[test]
    fn the_page_inlines_nothing_the_csp_forbids() {
        let html = std::str::from_utf8(
            ASSETS
                .iter()
                .find(|(p, _, _)| *p == "/")
                .expect("index is served")
                .2,
        )
        .expect("index is utf-8");

        // Comments are stripped first. The page's own comment EXPLAINS that it must not inline a
        // style block, and the first version of this test matched that explanation and failed on a
        // page that was already correct.
        let mut stripped = String::with_capacity(html.len());
        let mut rest = html;
        while let Some(start) = rest.find("<!--") {
            stripped.push_str(&rest[..start]);
            rest = match rest[start..].find("-->") {
                Some(end) => &rest[start + end + 3..],
                None => "",
            };
        }
        stripped.push_str(rest);
        let html = stripped.as_str();

        assert!(!html.contains("<style"), "inline <style> is blocked by default-src 'self'");
        for fragment in html.split("<script").skip(1) {
            let tag = fragment.split('>').next().unwrap_or("");
            assert!(
                tag.contains("src="),
                "inline <script> is blocked by script-src 'self'; found <script{tag}>"
            );
        }
    }

    /// Every asset the page references must actually be served, or the CSP-safe split just moves the
    /// failure from "blocked" to "404".
    #[test]
    fn everything_the_page_references_is_served() {
        let html = std::str::from_utf8(ASSETS.iter().find(|(p, _, _)| *p == "/").unwrap().2).unwrap();
        for needle in ["./app.css", "./app.js"] {
            assert!(html.contains(needle), "index does not reference {needle}");
            let path = needle.trim_start_matches('.');
            assert!(
                ASSETS.iter().any(|(p, _, _)| *p == path),
                "{path} is referenced but not in ASSETS"
            );
        }
        // app.js imports the wasm glue, which pulls the .wasm itself.
        let app = std::str::from_utf8(ASSETS.iter().find(|(p, _, _)| *p == "/app.js").unwrap().2).unwrap();
        assert!(app.contains("./ironrdp_web.js"), "app.js does not import the client");
        assert!(ASSETS.iter().any(|(p, _, _)| *p == "/ironrdp_web_bg.wasm"));
    }

    #[test]
    fn every_asset_has_bytes() {
        for (path, ctype, body) in ASSETS {
            assert!(!body.is_empty(), "{path} is empty");
            assert!(!ctype.is_empty(), "{path} has no content type");
        }
    }
}
