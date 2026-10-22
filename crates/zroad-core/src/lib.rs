//! Protocol types and cryptographic helpers shared by every Z-Road component.

pub mod audit;
pub mod crypto;
pub mod directory;
pub mod error;
pub mod id;
pub mod msg;
pub mod pki;

pub use error::{Error, Result};

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A random 128-bit identifier rendered as 32 hex characters.
pub fn random_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// A random 256-bit secret rendered as 64 hex characters.
pub fn random_secret() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
