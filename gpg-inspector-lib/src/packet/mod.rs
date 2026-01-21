//! OpenPGP packet parsing and type definitions.
//!
//! This module provides the core packet parsing functionality, including
//! the [`Packet`] container, [`PacketBody`] enum for typed packet data,
//! and the [`Field`] struct for hierarchical field representation.
//!
//! # Packet Structure
//!
//! OpenPGP data consists of a sequence of packets, each with:
//! - A header (tag + length)
//! - A body containing packet-specific data
//!
//! This module parses both old-format and new-format packet headers
//! as defined in RFC 4880 and RFC 9580.

/// Compressed Data packet parsing.
pub mod compressed_data;
/// Literal Data packet parsing.
pub mod literal_data;
/// Modification Detection Code packet parsing.
pub mod mdc;
/// Miscellaneous simple packet types (Marker, SED, AEAD, Padding).
pub mod misc;
/// One-Pass Signature packet parsing.
pub mod one_pass_signature;
/// Public-Key Encrypted Session Key packet parsing.
pub mod pkesk;
/// Public key and subkey packet parsing.
pub mod public_key;
/// Secret key and subkey packet parsing.
pub mod secret_key;
/// Symmetrically Encrypted Integrity Protected Data packet parsing.
pub mod seipd;
/// Signature packet parsing.
pub mod signature;
/// Symmetric-Key Encrypted Session Key packet parsing.
pub mod skesk;
/// Signature subpacket parsing.
pub mod subpackets;
/// Packet tag definitions.
pub mod tags;
/// User Attribute packet parsing.
pub mod user_attribute;
/// User ID packet parsing.
pub mod user_id;

use std::sync::Arc;

use crate::error::{Error, Result};
use crate::stream::ByteStream;
use tags::PacketTag;

/// A field with its name, value, byte span, and indent level.
///
/// Fields represent individual pieces of parsed data within a packet.
/// They form a hierarchy with three indent levels:
/// - Level 0: Packet headers
/// - Level 1: Top-level fields within a packet
/// - Level 2: Nested subfields (e.g., signature subpackets)
///
/// # Visualization
///
/// The `span` field supports hex dump visualization, allowing UI code
/// to highlight the corresponding bytes and assign colors as needed.
#[derive(Debug, Clone)]
pub struct Field {
    /// The field name (e.g., "Version", "Algorithm", "Creation Time").
    pub name: Arc<str>,
    /// The field value as a human-readable string.
    pub value: Arc<str>,
    /// Indentation level: 0 = packet, 1 = field, 2 = subfield.
    pub indent: u8,
    /// Byte range `(start, end)` in the original data.
    pub span: (usize, usize),
}

impl Field {
    /// Creates a new field with all parameters specified.
    pub fn new(
        name: impl Into<Arc<str>>,
        value: impl Into<Arc<str>>,
        indent: u8,
        span: (usize, usize),
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            indent,
            span,
        }
    }

    /// Creates a packet-level field (indent 0).
    ///
    /// Used for packet type headers like "Packet: Public Key".
    pub fn packet(
        name: impl Into<Arc<str>>,
        value: impl Into<Arc<str>>,
        span: (usize, usize),
    ) -> Self {
        Self::new(name, value, 0, span)
    }

    /// Creates a regular field (indent 1).
    ///
    /// Used for top-level packet fields like "Version", "Algorithm".
    #[allow(clippy::self_named_constructors)]
    pub fn field(
        name: impl Into<Arc<str>>,
        value: impl Into<Arc<str>>,
        span: (usize, usize),
    ) -> Self {
        Self::new(name, value, 1, span)
    }

    /// Creates a subfield (indent 2).
    ///
    /// Used for nested data like signature subpackets.
    pub fn subfield(
        name: impl Into<Arc<str>>,
        value: impl Into<Arc<str>>,
        span: (usize, usize),
    ) -> Self {
        Self::new(name, value, 2, span)
    }
}

/// A parsed OpenPGP packet with metadata and fields.
///
/// Contains the raw packet boundaries, parsed body, and a list of
/// human-readable fields.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Byte offset where this packet starts in the original data.
    pub start: usize,
    /// Byte offset where this packet ends (exclusive).
    pub end: usize,
    /// The packet type tag.
    pub tag: PacketTag,
    /// The parsed packet body.
    pub body: PacketBody,
    /// Parsed fields for display.
    pub fields: Vec<Field>,
}

/// The typed body of a parsed packet.
///
/// Each variant contains the parsed structure for that packet type.
/// Unknown or unsupported packet types are stored as raw bytes.
#[derive(Debug, Clone)]
pub enum PacketBody {
    /// Public-Key Encrypted Session Key packet (tag 1).
    Pkesk(pkesk::PkeskPacket),
    /// Signature packet (tag 2).
    Signature(signature::SignaturePacket),
    /// Symmetric-Key Encrypted Session Key packet (tag 3).
    Skesk(skesk::SkeskPacket),
    /// One-Pass Signature packet (tag 4).
    OnePassSignature(one_pass_signature::OnePassSignaturePacket),
    /// Secret key packet (tag 5).
    SecretKey(secret_key::SecretKeyPacket),
    /// Public key packet (tag 6).
    PublicKey(public_key::PublicKeyPacket),
    /// Secret subkey packet (tag 7).
    SecretSubkey(secret_key::SecretKeyPacket),
    /// Compressed Data packet (tag 8).
    CompressedData(compressed_data::CompressedDataPacket),
    /// Symmetrically Encrypted Data packet (tag 9, legacy).
    SymmetricallyEncryptedData(misc::SymmetricallyEncryptedDataPacket),
    /// Marker packet (tag 10, obsolete).
    Marker(misc::MarkerPacket),
    /// Literal Data packet (tag 11).
    LiteralData(literal_data::LiteralDataPacket),
    /// User ID packet (tag 13).
    UserId(user_id::UserIdPacket),
    /// Public subkey packet (tag 14).
    PublicSubkey(public_key::PublicKeyPacket),
    /// User Attribute packet (tag 17).
    UserAttribute(user_attribute::UserAttributePacket),
    /// Symmetrically Encrypted Integrity Protected Data packet (tag 18).
    Seipd(seipd::SeipdPacket),
    /// Modification Detection Code packet (tag 19).
    Mdc(mdc::MdcPacket),
    /// AEAD Encrypted Data packet (tag 20, RFC 9580).
    AeadEncryptedData(misc::AeadEncryptedDataPacket),
    /// Padding packet (tag 21, RFC 9580).
    Padding(misc::PaddingPacket),
    /// Unknown or unsupported packet type.
    Unknown(Vec<u8>),
}

/// Parses binary PGP data into a vector of packets.
///
/// This is the main entry point for parsing raw (non-armored) PGP data.
/// For armored data, use [`crate::parse`] which handles decoding first.
///
/// # Errors
///
/// Returns an error if any packet has an invalid structure.
pub fn parse_packets(bytes: Arc<[u8]>) -> Result<Vec<Packet>> {
    let mut stream = ByteStream::from_arc(bytes);
    let mut packets = Vec::new();

    while !stream.is_empty() {
        let packet = parse_packet(&mut stream)?;
        packets.push(packet);
    }

    Ok(packets)
}

fn parse_packet(stream: &mut ByteStream) -> Result<Packet> {
    let packet_start = stream.abs_pos();
    let mut fields = Vec::new();

    let header_start = stream.abs_pos();
    let header_byte = stream.octet()?;

    if header_byte & 0x80 == 0 {
        return Err(Error::InvalidPacketHeader(packet_start));
    }

    let new_format = header_byte & 0x40 != 0;
    let (tag, body_length) = if new_format {
        let tag = PacketTag::from_u8(header_byte & 0x3F);
        let len = parse_new_length(stream)?;
        (tag, len)
    } else {
        let tag = PacketTag::from_u8((header_byte >> 2) & 0x0F);
        let len_type = header_byte & 0x03;
        let len = parse_old_length(stream, len_type)?;
        (tag, len)
    };

    let header_end = stream.abs_pos();
    let packet_name: Arc<str> = format!("Packet: {}", tag).into();
    fields.push(Field::packet(
        packet_name,
        format!("{} bytes", body_length),
        (header_start, header_end),
    ));

    let body_start = stream.abs_pos();
    let mut body_stream = stream.slice(stream.pos(), stream.pos() + body_length);
    stream.skip(body_length)?;
    let packet_end = stream.abs_pos();

    let body = parse_packet_body(tag, &mut body_stream, &mut fields, body_start)?;

    Ok(Packet {
        start: packet_start,
        end: packet_end,
        tag,
        body,
        fields,
    })
}

fn parse_new_length(stream: &mut ByteStream) -> Result<usize> {
    let first = stream.octet()? as usize;
    if first < 192 {
        Ok(first)
    } else if first < 224 {
        let second = stream.octet()? as usize;
        Ok(((first - 192) << 8) + second + 192)
    } else if first == 255 {
        Ok(stream.uint32()? as usize)
    } else {
        Ok(1 << (first & 0x1F))
    }
}

fn parse_old_length(stream: &mut ByteStream, len_type: u8) -> Result<usize> {
    match len_type {
        0 => Ok(stream.octet()? as usize),
        1 => Ok(stream.uint16()? as usize),
        2 => Ok(stream.uint32()? as usize),
        3 => Ok(stream.remaining()),
        _ => unreachable!(),
    }
}

fn parse_packet_body(
    tag: PacketTag,
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    body_offset: usize,
) -> Result<PacketBody> {
    match tag {
        PacketTag::PublicKeyEncryptedSessionKey => {
            let pkesk = pkesk::parse_pkesk(stream, fields, body_offset)?;
            Ok(PacketBody::Pkesk(pkesk))
        }
        PacketTag::Signature => {
            let sig = signature::parse_signature(stream, fields, body_offset)?;
            Ok(PacketBody::Signature(sig))
        }
        PacketTag::SymmetricKeyEncryptedSessionKey => {
            let skesk = skesk::parse_skesk(stream, fields, body_offset)?;
            Ok(PacketBody::Skesk(skesk))
        }
        PacketTag::OnePassSignature => {
            let ops = one_pass_signature::parse_one_pass_signature(stream, fields, body_offset)?;
            Ok(PacketBody::OnePassSignature(ops))
        }
        PacketTag::SecretKey => {
            let sk = secret_key::parse_secret_key(stream, fields, body_offset)?;
            Ok(PacketBody::SecretKey(sk))
        }
        PacketTag::PublicKey => {
            let pk = public_key::parse_public_key(stream, fields, body_offset)?;
            Ok(PacketBody::PublicKey(pk))
        }
        PacketTag::SecretSubkey => {
            let sk = secret_key::parse_secret_key(stream, fields, body_offset)?;
            Ok(PacketBody::SecretSubkey(sk))
        }
        PacketTag::CompressedData => {
            let cd = compressed_data::parse_compressed_data(stream, fields, body_offset)?;
            Ok(PacketBody::CompressedData(cd))
        }
        PacketTag::SymmetricallyEncryptedData => {
            let sed = misc::parse_symmetrically_encrypted_data(stream, fields, body_offset)?;
            Ok(PacketBody::SymmetricallyEncryptedData(sed))
        }
        PacketTag::Marker => {
            let marker = misc::parse_marker(stream, fields, body_offset)?;
            Ok(PacketBody::Marker(marker))
        }
        PacketTag::LiteralData => {
            let ld = literal_data::parse_literal_data(stream, fields, body_offset)?;
            Ok(PacketBody::LiteralData(ld))
        }
        PacketTag::UserId => {
            let uid = user_id::parse_user_id(stream, fields, body_offset)?;
            Ok(PacketBody::UserId(uid))
        }
        PacketTag::PublicSubkey => {
            let pk = public_key::parse_public_key(stream, fields, body_offset)?;
            Ok(PacketBody::PublicSubkey(pk))
        }
        PacketTag::UserAttribute => {
            let ua = user_attribute::parse_user_attribute(stream, fields, body_offset)?;
            Ok(PacketBody::UserAttribute(ua))
        }
        PacketTag::SymmetricallyEncryptedIntegrityProtectedData => {
            let seipd = seipd::parse_seipd(stream, fields, body_offset)?;
            Ok(PacketBody::Seipd(seipd))
        }
        PacketTag::ModificationDetectionCode => {
            let mdc = mdc::parse_mdc(stream, fields, body_offset)?;
            Ok(PacketBody::Mdc(mdc))
        }
        PacketTag::AeadEncryptedData => {
            let aead = misc::parse_aead_encrypted_data(stream, fields, body_offset)?;
            Ok(PacketBody::AeadEncryptedData(aead))
        }
        PacketTag::Padding => {
            let padding = misc::parse_padding(stream, fields, body_offset)?;
            Ok(PacketBody::Padding(padding))
        }
        // Trust (tag 12) is implementation-specific and not exported
        // Reserved (tag 0) should never appear
        // Unknown tags are stored as raw bytes
        _ => {
            let data = stream.rest();
            if !data.is_empty() {
                let data_start = body_offset + stream.pos() - data.len();
                let data_end = body_offset + stream.pos();
                fields.push(Field::field(
                    "Data",
                    format!("{} bytes", data.len()),
                    (data_start, data_end),
                ));
            }
            Ok(PacketBody::Unknown(data))
        }
    }
}
