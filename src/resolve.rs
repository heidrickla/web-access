//! Turning a target's name into one address, or refusing.
//!
//! Resolving by name puts DNS in the trust chain: a changed record sends the session to a different
//! machine while every log line still reads `historian-01`. That is why the address this returns is
//! logged beside the name, and why ambiguity is refused rather than resolved.

use std::net::SocketAddr;

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("{host}:{port} did not resolve: {source}")]
    Failed {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },
    #[error("{host}:{port} resolved to no address")]
    NoAddress { host: String, port: u16 },
    #[error("{host} resolved to {count} addresses ({shown}); ambiguity in a security control is refused, not resolved")]
    Ambiguous {
        host: String,
        count: usize,
        shown: String,
    },
}

/// Exactly one address, or an error. Never a guess.
///
/// Several A records is a legitimate load-balancing pattern and a bad property for a control that is
/// supposed to say which machine was reached. Refusing keeps the log honest; picking one would make
/// "connected to historian-01" mean whichever address happened to sort first that day.
pub async fn resolve_one(host: &str, port: u16) -> Result<SocketAddr, ResolveError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|source| ResolveError::Failed {
            host: host.to_owned(),
            port,
            source,
        })?
        .collect();

    match addrs.len() {
        0 => Err(ResolveError::NoAddress {
            host: host.to_owned(),
            port,
        }),
        1 => Ok(addrs[0]),
        count => Err(ResolveError::Ambiguous {
            host: host.to_owned(),
            count,
            shown: addrs
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_literal_address_resolves_to_itself() {
        let addr = resolve_one("127.0.0.1", 3389).await.expect("literal");
        assert_eq!(addr.to_string(), "127.0.0.1:3389");
    }

    #[tokio::test]
    async fn a_name_that_does_not_resolve_fails_closed() {
        // .invalid is reserved by RFC 2606 and must never resolve.
        let err = resolve_one("nothing.invalid", 3389).await.unwrap_err();
        assert!(
            matches!(err, ResolveError::Failed { .. } | ResolveError::NoAddress { .. }),
            "unexpected: {err}"
        );
    }
}
