use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{Extension, Router};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

/// DER certificate presented by the TLS client, already verified against the CA.
#[derive(Clone, Debug)]
pub struct PeerCert(pub Vec<u8>);

pub const MAX_CONNECTIONS: usize = 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

pub struct ServerHandle {
    pub addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl ServerHandle {
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Wait until the server stops (after `shutdown`, or forever otherwise).
    pub async fn wait(self) {
        let _ = self.task.await;
    }
}

/// Bind `addr` and serve `app`. With `tls` the connection is TLS (mutual TLS if
/// the config demands client certificates) and handlers can extract
/// `Extension<Option<PeerCert>>`.
pub async fn spawn(
    addr: &str,
    tls: Option<Arc<ServerConfig>>,
    app: Router,
) -> std::io::Result<ServerHandle> {
    let listener = TcpListener::bind(addr).await?;
    let addr = listener.local_addr()?;
    let (tx, mut rx) = watch::channel(false);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let acceptor = tls.map(TlsAcceptor::from);

    let task = tokio::spawn(async move {
        loop {
            let (tcp, _) = tokio::select! {
                r = listener.accept() => match r {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!("accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
                _ = rx.changed() => break,
            };
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                tracing::warn!("connection limit reached, dropping connection");
                continue;
            };
            let app = app.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let mut builder = auto::Builder::new(TokioExecutor::new());
                builder
                    .http1()
                    .timer(TokioTimer::new())
                    .header_read_timeout(HEADER_TIMEOUT);
                match acceptor {
                    Some(acceptor) => {
                        let hs = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await;
                        let stream = match hs {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => {
                                tracing::debug!("TLS handshake failed: {e}");
                                return;
                            }
                            Err(_) => return,
                        };
                        let peer = stream
                            .get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|c| c.first())
                            .map(|c| PeerCert(c.as_ref().to_vec()));
                        let svc = TowerToHyperService::new(app.layer(Extension(peer)));
                        let _ = builder.serve_connection(TokioIo::new(stream), svc).await;
                    }
                    None => {
                        let svc = TowerToHyperService::new(app.layer(Extension(None::<PeerCert>)));
                        let _ = builder.serve_connection(TokioIo::new(tcp), svc).await;
                    }
                }
            });
        }
    });
    Ok(ServerHandle {
        addr,
        shutdown: tx,
        task,
    })
}
