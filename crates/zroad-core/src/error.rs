use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid identifier: {0}")]
    InvalidId(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("pki error: {0}")]
    Pki(String),
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("audit log error: {0}")]
    Audit(String),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
