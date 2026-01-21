//! Signature packet parsing.
//!
//! This module parses Signature packets (tag 2), which contain cryptographic
//! signatures over data or other packets. Signatures include metadata like
//! the signing algorithm, hash algorithm, and various subpackets.

use crate::error::Result;
use crate::lookup::{
    get_v6_signature_salt_len, lookup_hash_algorithm, lookup_public_key_algorithm,
    lookup_signature_type,
};
use crate::packet::Field;
use crate::packet::subpackets::parse_subpackets;
use crate::stream::ByteStream;

/// A parsed signature packet.
///
/// Contains the signature metadata (version, type, algorithms) and
/// the cryptographic signature data.
#[derive(Debug, Clone)]
pub struct SignaturePacket {
    /// Signature packet version (3, 4, or 5).
    pub version: u8,
    /// Signature type (binary, text, certification, etc.).
    pub signature_type: u8,
    /// Public-key algorithm used for signing.
    pub pub_algorithm: u8,
    /// Hash algorithm used.
    pub hash_algorithm: u8,
    /// First two bytes of the hash (for verification).
    pub hash_prefix: [u8; 2],
    /// The cryptographic signature data.
    pub signature: Vec<u8>,
}

/// Parses a signature packet body.
pub fn parse_signature(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<SignaturePacket> {
    let version_start = offset + stream.pos();
    let version = stream.octet()?;
    let version_end = offset + stream.pos();
    fields.push(Field::field(
        "Version",
        version.to_string(),
        (version_start, version_end),
    ));

    match version {
        3 => parse_v3_signature(stream, version, fields, offset),
        6 => parse_v6_signature(stream, version, fields, offset),
        _ => parse_v4_signature(stream, version, fields, offset),
    }
}

/// Parses a V4 signature packet body.
fn parse_v4_signature(
    stream: &mut ByteStream,
    version: u8,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<SignaturePacket> {
    let sig_type_start = offset + stream.pos();
    let signature_type = stream.octet()?;
    let sig_type_end = offset + stream.pos();
    let sig_type_info = lookup_signature_type(signature_type);
    fields.push(Field::field(
        "Signature Type",
        sig_type_info.display(),
        (sig_type_start, sig_type_end),
    ));

    let pub_algo_start = offset + stream.pos();
    let pub_algorithm = stream.octet()?;
    let pub_algo_end = offset + stream.pos();
    let pub_algo_info = lookup_public_key_algorithm(pub_algorithm);
    fields.push(Field::field(
        "Public Key Algorithm",
        pub_algo_info.display(),
        (pub_algo_start, pub_algo_end),
    ));

    let hash_algo_start = offset + stream.pos();
    let hash_algorithm = stream.octet()?;
    let hash_algo_end = offset + stream.pos();
    let hash_algo_info = lookup_hash_algorithm(hash_algorithm);
    fields.push(Field::field(
        "Hash Algorithm",
        hash_algo_info.display(),
        (hash_algo_start, hash_algo_end),
    ));

    let hashed_len_start = offset + stream.pos();
    let hashed_len = stream.uint16()? as usize;
    let hashed_len_end = offset + stream.pos();
    fields.push(Field::field(
        "Hashed Subpackets",
        format!("{} bytes", hashed_len),
        (hashed_len_start, hashed_len_end),
    ));

    let hashed_start = offset + stream.pos();
    let hashed_subpacket_data = stream.bytes(hashed_len)?;

    let mut hashed_stream = ByteStream::new(hashed_subpacket_data);
    parse_subpackets(&mut hashed_stream, fields, "Hashed", hashed_start)?;

    let unhashed_len_start = offset + stream.pos();
    let unhashed_len = stream.uint16()? as usize;
    let unhashed_len_end = offset + stream.pos();
    fields.push(Field::field(
        "Unhashed Subpackets",
        format!("{} bytes", unhashed_len),
        (unhashed_len_start, unhashed_len_end),
    ));

    let unhashed_start = offset + stream.pos();
    let unhashed_subpacket_data = stream.bytes(unhashed_len)?;

    let mut unhashed_stream = ByteStream::new(unhashed_subpacket_data);
    parse_subpackets(&mut unhashed_stream, fields, "Unhashed", unhashed_start)?;

    let prefix_start = offset + stream.pos();
    let hash_prefix = [stream.octet()?, stream.octet()?];
    let prefix_end = offset + stream.pos();
    fields.push(Field::field(
        "Hash Prefix",
        format!("{:02X}{:02X}", hash_prefix[0], hash_prefix[1]),
        (prefix_start, prefix_end),
    ));

    let sig_start = offset + stream.pos();
    let signature = parse_signature_data(stream, pub_algorithm)?;
    let sig_end = offset + stream.pos();

    let sig_desc = format_signature_desc(pub_algorithm, &signature, stream);
    fields.push(Field::field("Signature", sig_desc, (sig_start, sig_end)));

    Ok(SignaturePacket {
        version,
        signature_type,
        pub_algorithm,
        hash_algorithm,
        hash_prefix,
        signature,
    })
}

/// Parses a V6 signature packet body (RFC 9580).
///
/// V6 signatures have:
/// - Signature type, pub algorithm, hash algorithm (same as V4)
/// - Salt (16-32 bytes depending on hash algorithm)
/// - 4-byte hashed subpacket length (vs 2-byte in V4)
/// - 4-byte unhashed subpacket length (vs 2-byte in V4)
fn parse_v6_signature(
    stream: &mut ByteStream,
    version: u8,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<SignaturePacket> {
    let sig_type_start = offset + stream.pos();
    let signature_type = stream.octet()?;
    let sig_type_end = offset + stream.pos();
    let sig_type_info = lookup_signature_type(signature_type);
    fields.push(Field::field(
        "Signature Type",
        sig_type_info.display(),
        (sig_type_start, sig_type_end),
    ));

    let pub_algo_start = offset + stream.pos();
    let pub_algorithm = stream.octet()?;
    let pub_algo_end = offset + stream.pos();
    let pub_algo_info = lookup_public_key_algorithm(pub_algorithm);
    fields.push(Field::field(
        "Public Key Algorithm",
        pub_algo_info.display(),
        (pub_algo_start, pub_algo_end),
    ));

    let hash_algo_start = offset + stream.pos();
    let hash_algorithm = stream.octet()?;
    let hash_algo_end = offset + stream.pos();
    let hash_algo_info = lookup_hash_algorithm(hash_algorithm);
    fields.push(Field::field(
        "Hash Algorithm",
        hash_algo_info.display(),
        (hash_algo_start, hash_algo_end),
    ));

    // V6: Salt field (length depends on hash algorithm)
    let salt_len = get_v6_signature_salt_len(hash_algorithm);
    let salt_start = offset + stream.pos();
    let _salt = stream.bytes(salt_len)?;
    let salt_end = offset + stream.pos();
    fields.push(Field::field(
        "Salt",
        format!("{} bytes", salt_len),
        (salt_start, salt_end),
    ));

    // V6: 4-byte hashed subpacket length
    let hashed_len_start = offset + stream.pos();
    let hashed_len = stream.uint32()? as usize;
    let hashed_len_end = offset + stream.pos();
    fields.push(Field::field(
        "Hashed Subpackets",
        format!("{} bytes", hashed_len),
        (hashed_len_start, hashed_len_end),
    ));

    let hashed_start = offset + stream.pos();
    let hashed_subpacket_data = stream.bytes(hashed_len)?;

    let mut hashed_stream = ByteStream::new(hashed_subpacket_data);
    parse_subpackets(&mut hashed_stream, fields, "Hashed", hashed_start)?;

    // V6: 4-byte unhashed subpacket length
    let unhashed_len_start = offset + stream.pos();
    let unhashed_len = stream.uint32()? as usize;
    let unhashed_len_end = offset + stream.pos();
    fields.push(Field::field(
        "Unhashed Subpackets",
        format!("{} bytes", unhashed_len),
        (unhashed_len_start, unhashed_len_end),
    ));

    let unhashed_start = offset + stream.pos();
    let unhashed_subpacket_data = stream.bytes(unhashed_len)?;

    let mut unhashed_stream = ByteStream::new(unhashed_subpacket_data);
    parse_subpackets(&mut unhashed_stream, fields, "Unhashed", unhashed_start)?;

    let prefix_start = offset + stream.pos();
    let hash_prefix = [stream.octet()?, stream.octet()?];
    let prefix_end = offset + stream.pos();
    fields.push(Field::field(
        "Hash Prefix",
        format!("{:02X}{:02X}", hash_prefix[0], hash_prefix[1]),
        (prefix_start, prefix_end),
    ));

    let sig_start = offset + stream.pos();
    let signature = parse_signature_data(stream, pub_algorithm)?;
    let sig_end = offset + stream.pos();

    let sig_desc = format_signature_desc(pub_algorithm, &signature, stream);
    fields.push(Field::field("Signature", sig_desc, (sig_start, sig_end)));

    Ok(SignaturePacket {
        version,
        signature_type,
        pub_algorithm,
        hash_algorithm,
        hash_prefix,
        signature,
    })
}

fn parse_v3_signature(
    stream: &mut ByteStream,
    version: u8,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<SignaturePacket> {
    let _hashed_len = stream.octet()?;

    let sig_type_start = offset + stream.pos();
    let signature_type = stream.octet()?;
    let sig_type_end = offset + stream.pos();
    let sig_type_info = lookup_signature_type(signature_type);
    fields.push(Field::field(
        "Signature Type",
        sig_type_info.display(),
        (sig_type_start, sig_type_end),
    ));

    let time_start = offset + stream.pos();
    let creation_time = stream.uint32()?;
    let time_end = offset + stream.pos();
    fields.push(Field::field(
        "Creation Time",
        creation_time.to_string(),
        (time_start, time_end),
    ));

    let key_id_start = offset + stream.pos();
    let key_id = stream.hex(8)?;
    let key_id_end = offset + stream.pos();
    fields.push(Field::field("Key ID", key_id, (key_id_start, key_id_end)));

    let pub_algo_start = offset + stream.pos();
    let pub_algorithm = stream.octet()?;
    let pub_algo_end = offset + stream.pos();
    let pub_algo_info = lookup_public_key_algorithm(pub_algorithm);
    fields.push(Field::field(
        "Public Key Algorithm",
        pub_algo_info.display(),
        (pub_algo_start, pub_algo_end),
    ));

    let hash_algo_start = offset + stream.pos();
    let hash_algorithm = stream.octet()?;
    let hash_algo_end = offset + stream.pos();
    let hash_algo_info = lookup_hash_algorithm(hash_algorithm);
    fields.push(Field::field(
        "Hash Algorithm",
        hash_algo_info.display(),
        (hash_algo_start, hash_algo_end),
    ));

    let prefix_start = offset + stream.pos();
    let hash_prefix = [stream.octet()?, stream.octet()?];
    let prefix_end = offset + stream.pos();
    fields.push(Field::field(
        "Hash Prefix",
        format!("{:02X}{:02X}", hash_prefix[0], hash_prefix[1]),
        (prefix_start, prefix_end),
    ));

    let sig_start = offset + stream.pos();
    let signature = parse_signature_data(stream, pub_algorithm)?;
    let sig_end = offset + stream.pos();

    let sig_desc = format_signature_desc(pub_algorithm, &signature, stream);
    fields.push(Field::field("Signature", sig_desc, (sig_start, sig_end)));

    Ok(SignaturePacket {
        version,
        signature_type,
        pub_algorithm,
        hash_algorithm,
        hash_prefix,
        signature,
    })
}

fn parse_signature_data(stream: &mut ByteStream, pub_algorithm: u8) -> Result<Vec<u8>> {
    match pub_algorithm {
        1..=3 => {
            let (_bits, _hex) = stream.multi_precision_integer()?;
        }
        17 | 19 | 22 => {
            let (_r_bits, _) = stream.multi_precision_integer()?;
            let (_s_bits, _) = stream.multi_precision_integer()?;
        }
        27 => {
            // Ed25519: 64-byte native signature
            let _sig = stream.hex(64)?;
        }
        28 => {
            // Ed448: 114-byte native signature
            let _sig = stream.hex(114)?;
        }
        _ => {
            let _ = stream.rest();
        }
    }
    Ok(Vec::new())
}

fn format_signature_desc(pub_algorithm: u8, _signature: &[u8], _stream: &ByteStream) -> String {
    match pub_algorithm {
        1..=3 => "RSA signature".to_string(),
        17 => "DSA (r,s) signature".to_string(),
        19 | 22 => "ECDSA/EdDSA (r,s) signature".to_string(),
        27 => "512 bits (Ed25519)".to_string(),
        28 => "912 bits (Ed448)".to_string(),
        _ => "Unknown signature format".to_string(),
    }
}
