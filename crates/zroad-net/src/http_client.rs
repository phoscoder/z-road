use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// Could not reach the peer at all (DNS, refused, handshake, timeout).
    /// Safe to retry: nothing was delivered.
    #[error("cannot connect: {0}")]
    Connect(String),
    /// The connection broke or timed out after the request may have been sent.
    #[error("request failed: {0}")]
    Io(String),
    #[error("invalid url: {0}")]
    Url(String),
    #[error("response too large")]
    TooLarge,
}

impl NetError {
    /// True if the peer may have processed the request.
    pub fn maybe_delivered(&self) -> bool {
        matches!(self, NetError::Io(_))
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_RESPONSE: usize = 8 * 1024 * 1024;

/// One-shot HTTP/1.1 request. `https://` URLs require `tls`.
pub async fn request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Bytes,
    tls: Option<&Arc<ClientConfig>>,
    timeout: Duration,
) -> Result<Response, NetError> {
    let uri: http::Uri = url
        .parse()
        .map_err(|e| NetError::Url(format!("{url}: {e}")))?;
    let https = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => {
            return Err(NetError::Url(format!(
                "{url}: scheme must be http or https"
            )))
        }
    };
    let host = uri
        .host()
        .ok_or_else(|| NetError::Url(format!("{url}: no host")))?
        .to_string();
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    let path = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let host_header = match uri.port_u16() {
        Some(p) => format!("{host}:{p}"),
        None => host.clone(),
    };

    let mut req = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header(http::header::HOST, host_header)
        .header(http::header::CONNECTION, "close");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req
        .body(Full::new(body))
        .map_err(|e| NetError::Url(e.to_string()))?;

    let fut = async {
        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| NetError::Connect(e.to_string()))?;
        if https {
            let cfg = tls.ok_or_else(|| NetError::Url("https needs a TLS config".into()))?;
            let name = ServerName::try_from(host.clone())
                .map_err(|e| NetError::Url(format!("bad server name: {e}")))?;
            let stream = TlsConnector::from(cfg.clone())
                .connect(name, tcp)
                .await
                .map_err(|e| NetError::Connect(format!("TLS handshake: {e}")))?;
            send(stream, req).await
        } else {
            send(tcp, req).await
        }
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(r) => r,
        Err(_) => Err(NetError::Io("timed out".into())),
    }
}

async fn send<I>(io: I, req: hyper::Request<Full<Bytes>>) -> Result<Response, NetError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|e| NetError::Connect(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| NetError::Io(e.to_string()))?;
    let (parts, body) = resp.into_parts();
    let body = Limited::new(body, MAX_RESPONSE)
        .collect()
        .await
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("length limit") {
                NetError::TooLarge
            } else {
                NetError::Io(s)
            }
        })?
        .to_bytes();
    Ok(Response {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body,
    })
}
