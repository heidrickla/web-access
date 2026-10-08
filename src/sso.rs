//! The single sign-on routes. `saml.rs` checks the protocol; this signs the account in the way a
//! password sign-in does, through `finish_directory` and `start_session`.
//!
//! | Route | |
//! |---|---|
//! | `GET /api/sign-in-methods` | whether the sign-in page offers single sign-on |
//! | `GET /api/saml/start` | sets the flow cookie, redirects to the identity provider |
//! | `POST /api/saml/acs` | the identity provider's POST: signs in, answers with a page |
//! | `GET /api/saml/metadata` | this proxy's metadata, for IT |

use crate::app::App;
use crate::auth;
use crate::saml::{FLOW_COOKIE, FLOW_SECS};
use crate::store::now;
use crate::web::{self, ApiError, ApiResult, Shared};
use axum::extract::{Form, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{AppendHeaders, Html, IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

/// The activity log's name for a sign-in whose account is not known yet.
const WHO: &str = "(single sign-on)";

pub async fn methods(State(app): State<Shared>) -> Json<serde_json::Value> {
    Json(json!({ "sso": app.saml.is_some() }))
}

/// The identity provider's POST back is cross-site, which only SameSite=None carries a cookie on;
/// the config requires an https url, so Secure always holds where the browser sees the page.
fn flow_cookie(value: &str, max_age: i64) -> String {
    format!(
        "{FLOW_COOKIE}={value}; Path=/api/saml; Max-Age={max_age}; HttpOnly; Secure; SameSite=None"
    )
}

pub async fn start(State(app): State<Shared>) -> ApiResult<Response> {
    let sp = app.saml.as_ref().ok_or_else(ApiError::not_found)?;
    let (url, flow) = sp.start(sp.now());
    Ok((
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, url),
            (header::SET_COOKIE, flow_cookie(&flow, FLOW_SECS)),
        ],
    )
        .into_response())
}

pub async fn metadata(State(app): State<Shared>) -> ApiResult<Response> {
    let sp = app.saml.as_ref().ok_or_else(ApiError::not_found)?;
    Ok((
        [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
        sp.metadata(),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct AcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
}

/// Answers with a page, as the browser arrives here by navigation. On success the page moves on to
/// the server list itself: the session cookie is SameSite=Strict, and a redirect continuing the
/// identity provider's cross-site POST would not carry it, where a navigation this page starts does.
pub async fn acs(
    State(app): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<AcsForm>,
) -> Response {
    let spent = flow_cookie("", 0);
    match sign_in(&app, &headers, &form.saml_response).await {
        Ok(session) => (
            AppendHeaders([(header::SET_COOKIE, session), (header::SET_COOKIE, spent)]),
            Html(page(
                "<h2>Signed in</h2>\n<p><a href=\"/\">Continue to your servers</a></p>\n\
                 <script src=\"/saml-done.js\"></script>",
            )),
        )
            .into_response(),
        Err(e) => (
            e.status,
            AppendHeaders([(header::SET_COOKIE, spent)]),
            Html(page(&format!(
                "<h2>Single sign-on did not sign you in</h2>\n<p class=\"error\">{}</p>\n\
                 <p><a href=\"/api/saml/start\">Try again</a> or <a href=\"/\">sign in with your \
                 password</a></p>",
                html_escape(&e.message)
            ))),
        )
            .into_response(),
    }
}

fn page(body: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>web-access</title>\n<link rel=\"stylesheet\" href=\"/app.css\">\n\
         <script src=\"/theme.js\"></script>\n</head>\n<body>\n<main>\n\
         <section class=\"card signin-card\">\n{body}\n</section>\n</main>\n</body>\n</html>\n"
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn refuse(app: &App, who: &str, status: StatusCode, why: String) -> ApiError {
    let _shared = app.gate.read().await;
    app.store
        .audit(who, "signin.refused", &format!("single sign-on: {why}"));
    ApiError::new(status, why)
}

/// The session cookie for the account the identity provider vouched for.
async fn sign_in(app: &Shared, headers: &HeaderMap, response: &str) -> ApiResult<String> {
    let sp = app.saml.as_ref().ok_or_else(ApiError::not_found)?;
    let flow = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|h| auth::cookie_value(h, FLOW_COOKIE));
    // As in a password sign-in: read under a short hold, the slow part without the gate, and the
    // result recorded only in the database it was checked against.
    let (generation, password) = {
        let _shared = app.gate.read().await;
        (app.generation(), app.directory_password())
    };
    let verified = match sp.accept(response, flow, sp.now()) {
        Ok(v) => v,
        Err(e) => return Err(refuse(app, WHO, StatusCode::UNAUTHORIZED, e.to_string()).await),
    };
    let who = verified
        .name_id
        .clone()
        .unwrap_or_else(|| verified.sid.clone());
    let Some(directory) = app.lookup_directory() else {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "single sign-on needs the directory's service account",
        ));
    };
    let Some(password) = password? else {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "the directory service account's password is not set; an administrator sets it on \
             the Migration page",
        ));
    };
    let account = match directory.lookup_by_sid(&password, &verified.sid).await {
        Ok(Some(a)) if a.usable() => a,
        Ok(Some(_)) => {
            let why = format!(
                "the directory account with SID {} is disabled or expired",
                verified.sid
            );
            return Err(refuse(app, &who, StatusCode::FORBIDDEN, why).await);
        }
        Ok(None) => {
            let why = format!(
                "no account in the directory has the SID {} the identity provider sent",
                verified.sid
            );
            return Err(refuse(app, &who, StatusCode::FORBIDDEN, why).await);
        }
        Err(e) => {
            tracing::warn!(%who, error = %e, "single sign-on could not read the account");
            return Err(e.into());
        }
    };

    let _shared = app.gate.read().await;
    if app.generation() != generation {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "the proxy's data was replaced while you signed in; sign in again",
        ));
    }
    let user = web::finish_directory(app, &account)?;
    let (token, _, lasts) = web::start_session(app, &user)?;
    let _ = app.store.sessions_purge(now());
    app.store.audit(
        &user.username,
        "signin",
        &format!("single sign-on as {who}"),
    );
    Ok(auth::session_cookie(&token, lasts, app.secure_cookies))
}

#[cfg(test)]
mod tests {
    use crate::saml::{parse_instant, FLOW_COOKIE, FLOW_SECS};
    use crate::web::tests::{test_app, test_app_sso};
    use crate::web::{router, Shared};
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use std::sync::Arc;
    use tower::ServiceExt;

    const SIGNED: &str = include_str!("../tests/fixtures/saml/response-assertion-signed.xml");

    /// One minute after the fixtures were issued.
    fn at() -> i64 {
        parse_instant("2026-10-08T12:01:00Z").unwrap()
    }

    struct Answer {
        status: StatusCode,
        cookies: Vec<String>,
        location: Option<String>,
        content_type: Option<String>,
        body: String,
    }

    async fn send(app: &Shared, req: Request<Body>) -> Answer {
        let res = router(Arc::clone(app)).oneshot(req).await.unwrap();
        let header_text = |name| {
            res.headers()
                .get(name)
                .map(|v: &axum::http::HeaderValue| v.to_str().unwrap().to_owned())
        };
        let location = header_text(header::LOCATION);
        let content_type = header_text(header::CONTENT_TYPE);
        let cookies = res
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        Answer {
            status,
            cookies,
            location,
            content_type,
            body: String::from_utf8(bytes.to_vec()).unwrap(),
        }
    }

    fn get(path: &str) -> Request<Body> {
        Request::builder()
            .uri(path)
            .header(header::HOST, "access.example.test")
            .body(Body::empty())
            .unwrap()
    }

    /// The identity provider's POST: from its own origin, carrying no page's data instance.
    fn idp_post(response: &str, flow: Option<&str>) -> Request<Body> {
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("SAMLResponse", &STANDARD.encode(response))
            .append_pair("RelayState", "")
            .finish();
        let mut b = Request::builder()
            .method("POST")
            .uri("/api/saml/acs")
            .header(header::HOST, "access.example.test")
            .header(header::ORIGIN, "https://idp.example.test")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(f) = flow {
            b = b.header(header::COOKIE, format!("{FLOW_COOKIE}={f}"));
        }
        b.body(Body::from(body)).unwrap()
    }

    #[tokio::test]
    async fn the_sign_in_page_is_told_whether_single_sign_on_is_offered() {
        for (app, offered) in [(test_app(), false), (test_app_sso(None), true)] {
            let a = send(&app, get("/api/sign-in-methods")).await;
            assert_eq!(a.status, StatusCode::OK);
            let v: serde_json::Value = serde_json::from_str(&a.body).unwrap();
            assert_eq!(v["sso"], offered);
        }
    }

    #[tokio::test]
    async fn start_sends_the_browser_to_the_identity_provider_with_a_flow_cookie() {
        assert_eq!(
            send(&test_app(), get("/api/saml/start")).await.status,
            StatusCode::NOT_FOUND
        );
        let a = send(&test_app_sso(None), get("/api/saml/start")).await;
        assert_eq!(a.status, StatusCode::SEE_OTHER);
        assert!(a
            .location
            .unwrap()
            .starts_with("https://idp.example.test/adfs/ls/?SAMLRequest="));
        let [cookie] = &a.cookies[..] else {
            panic!("{:?}", a.cookies)
        };
        for part in [
            format!("{FLOW_COOKIE}=_"),
            format!("Max-Age={FLOW_SECS};"),
            "Path=/api/saml;".into(),
            "HttpOnly".into(),
            "Secure".into(),
            "SameSite=None".into(),
        ] {
            assert!(cookie.contains(&part), "{part} missing from {cookie}");
        }
    }

    #[tokio::test]
    async fn the_metadata_names_this_proxy() {
        let a = send(&test_app_sso(None), get("/api/saml/metadata")).await;
        assert_eq!(a.status, StatusCode::OK);
        assert_eq!(
            a.content_type.as_deref(),
            Some("application/samlmetadata+xml")
        );
        assert!(a
            .body
            .contains("entityID=\"https://access.example.test/api/saml/metadata\""));
        assert!(a
            .body
            .contains("Location=\"https://access.example.test/api/saml/acs\""));
    }

    #[tokio::test]
    async fn the_identity_providers_post_is_answered_with_a_page_and_logged() {
        let app = test_app_sso(Some(at()));
        let a = send(&app, idp_post(SIGNED, None)).await;
        // Past the origin and data-instance checks, refused by the SAML checks.
        assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.body);
        assert!(a.body.starts_with("<!DOCTYPE html>"));
        assert!(a.body.contains("did not start the sign-in"), "{}", a.body);
        assert!(
            a.cookies
                .iter()
                .any(|c| c.starts_with(&format!("{FLOW_COOKIE}=;")) && c.contains("Max-Age=0;")),
            "{:?}",
            a.cookies
        );
        assert!(!a.cookies.iter().any(|c| c.starts_with("wa_session=")));
        let logged = app.store.audit_list(10, None).unwrap();
        assert!(logged.iter().any(|r| r.action == "signin.refused"
            && r.actor == "(single sign-on)"
            && r.detail.contains("did not start")));
    }

    #[tokio::test]
    async fn an_accepted_response_goes_on_to_the_directory() {
        // The SAML checks pass; this proxy's directory has no service account password set.
        let app = test_app_sso(Some(at()));
        let flow = app
            .saml
            .as_ref()
            .unwrap()
            .flow_for("_req1", at() + FLOW_SECS);
        let a = send(&app, idp_post(SIGNED, Some(&flow))).await;
        assert_eq!(a.status, StatusCode::SERVICE_UNAVAILABLE, "{}", a.body);
        assert!(a.body.contains("password is not set"), "{}", a.body);
    }

    #[tokio::test]
    async fn the_page_escapes_what_the_identity_provider_said() {
        let app = test_app_sso(Some(at()));
        let flow = app
            .saml
            .as_ref()
            .unwrap()
            .flow_for("_req1", at() + FLOW_SECS);
        let refused = SIGNED.replace(
            "status:Success\"/>",
            "status:Responder\"/><samlp:StatusMessage>&lt;img src=x&gt;</samlp:StatusMessage>",
        );
        let a = send(&app, idp_post(&refused, Some(&flow))).await;
        assert_eq!(a.status, StatusCode::UNAUTHORIZED, "{}", a.body);
        assert!(a.body.contains("&lt;img src=x&gt;"), "{}", a.body);
        assert!(!a.body.contains("<img"), "{}", a.body);
    }
}
