//! A library for parsing and inspecting OpenPGP (GPG) packets.
//!
//! This crate provides tools for decoding ASCII-armored PGP data and parsing
//! the binary packet structure according to RFC 4880 and RFC 9580.
//!
//! # Quick Start
//!
//! ```
//! use gpg_inspector_lib::{parse, Packet, PacketBody};
//!
//! let armored_key = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----
//!
//! mDMEZ... (your armored data)
//! -----END PGP PUBLIC KEY BLOCK-----"#;
//!
//! // Parse returns an error for invalid/incomplete data
//! // For real usage, provide valid armored PGP data
//! ```
//!
//! # Modules
//!
//! - [`armor`] - ASCII armor decoding (Base64 + CRC24 checksum)
//! - [`error`] - Error types for parsing failures
//! - [`lookup`] - Algorithm and format lookup tables
//! - [`packet`] - Packet parsing and type definitions
//! - [`stream`] - Binary stream reader abstraction

#![warn(missing_docs)]

pub mod armor;
pub mod error;
pub mod lookup;
pub mod packet;
pub mod stream;

use std::sync::Arc;

pub use armor::{ArmorResult, decode_armor};
pub use error::{Error, Result};
pub use packet::{Field, Packet, PacketBody};
pub use stream::ByteStream;

/// Parses ASCII-armored PGP data into a vector of packets.
///
/// This is the main entry point for parsing armored PGP data such as
/// public keys, secret keys, signatures, and encrypted messages.
///
/// # Arguments
///
/// * `input` - ASCII-armored PGP data (e.g., `-----BEGIN PGP PUBLIC KEY BLOCK-----`)
///
/// # Errors
///
/// Returns an error if:
/// - The armor format is invalid (missing headers, bad base64, checksum mismatch)
/// - The packet structure is malformed
///
/// # Example
///
/// ```ignore
/// let packets = gpg_inspector_lib::parse(armored_data)?;
/// for packet in packets {
///     println!("Packet: {} ({} bytes)", packet.tag, packet.end - packet.start);
/// }
/// ```
pub fn parse(input: &str) -> Result<Vec<Packet>> {
    let armor_result = decode_armor(input)?;
    packet::parse_packets(armor_result.bytes)
}

/// Parses raw binary PGP data into a vector of packets.
///
/// Use this when you have already decoded the armor or are working
/// with raw binary PGP data.
///
/// # Arguments
///
/// * `bytes` - Raw binary PGP packet data
///
/// # Errors
///
/// Returns an error if the packet structure is malformed.
pub fn parse_bytes(bytes: impl Into<Arc<[u8]>>) -> Result<Vec<Packet>> {
    packet::parse_packets(bytes.into())
}
