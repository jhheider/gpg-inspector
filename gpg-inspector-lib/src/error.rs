use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid armor format: {0}")]
    InvalidArmor(String),

    #[error("Base64 decode error: {0}")]
    Base64Error(String),

    #[error("Unexpected end of data at position {0}")]
    UnexpectedEnd(usize),

    #[error("Invalid packet header at position {0}")]
    InvalidPacketHeader(usize),

    #[error("Unknown packet tag: {0}")]
    UnknownPacketTag(u8),

    #[error("Invalid packet format at position {0}: {1}")]
    InvalidPacketFormat(usize, String),

    #[error("Checksum mismatch: expected {expected:06x}, got {actual:06x}")]
    ChecksumMismatch { expected: u32, actual: u32 },

    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(u32),
}

pub type Result<T> = std::result::Result<T, Error>;
