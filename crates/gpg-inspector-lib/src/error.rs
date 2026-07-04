//! Error types for GPG packet parsing.
//!
//! This module provides the [`enum@Error`] enum for all parsing failures
//! and the [`Result`] type alias for convenient error handling.

use thiserror::Error;

/// Errors that can occur during GPG packet parsing.
///
/// These errors cover armor decoding failures, binary parsing errors,
/// and data validation issues.
#[derive(Error, Debug)]
pub enum Error {
    /// The ASCII armor format is invalid (missing headers, malformed structure).
    #[error("Invalid armor format: {0}")]
    InvalidArmor(String),

    /// Base64 decoding failed (invalid characters or padding).
    #[error("Base64 decode error: {0}")]
    Base64Error(String),

    /// Reached end of data unexpectedly while parsing.
    ///
    /// The `usize` indicates the byte position where more data was expected.
    #[error("Unexpected end of data at position {0}")]
    UnexpectedEnd(usize),

    /// The packet header byte is invalid (bit 7 not set).
    ///
    /// The `usize` indicates the byte position of the invalid header.
    #[error("Invalid packet header at position {0}")]
    InvalidPacketHeader(usize),

    /// The packet tag value is not recognized.
    #[error("Unknown packet tag: {0}")]
    UnknownPacketTag(u8),

    /// The packet body format is invalid.
    ///
    /// Contains the byte position and a description of the error.
    #[error("Invalid packet format at position {0}: {1}")]
    InvalidPacketFormat(usize, String),

    /// The CRC24 checksum in the armor doesn't match the computed checksum.
    #[error("Checksum mismatch: expected {expected:06x}, got {actual:06x}")]
    ChecksumMismatch {
        /// The checksum value from the armor footer.
        expected: u32,
        /// The computed checksum of the decoded data.
        actual: u32,
    },

    /// A timestamp value could not be converted to a valid date/time.
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(u32),
}

/// A specialized `Result` type for GPG parsing operations.
pub type Result<T> = std::result::Result<T, Error>;
