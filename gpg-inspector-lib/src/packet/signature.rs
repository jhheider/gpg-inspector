//! Signature packet parsing.
//!
//! This module parses Signature packets (tag 2), which contain cryptographic
//! signatures over data or other packets. Signatures include metadata like
//! the signing algorithm, hash algorithm, and various subpackets.

use crate::color::ColorTracker;
use crate::error::Result;
use crate::lookup::{lookup_hash_algorithm, lookup_public_key_algorithm, lookup_signature_type};
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
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<SignaturePacket> {
    let version_start = offset + stream.pos();
    let version = stream.octet()?;
    let version_end = offset + stream.pos();
    let color = colors.set_field(version_start, version_end);
    fields.push(Field::field(
        "Version",
        version.to_string(),
        (version_start, version_end),
        color,
    ));

    if version == 3 {
        return parse_v3_signature(stream, version, colors, fields, offset);
    }

    let sig_type_start = offset + stream.pos();
    let signature_type = stream.octet()?;
    let sig_type_end = offset + stream.pos();
    let color = colors.set_field(sig_type_start, sig_type_end);
    let sig_type_info = lookup_signature_type(signature_type);
    fields.push(Field::field(
        "Signature Type",
        sig_type_info.display(),
        (sig_type_start, sig_type_end),
        color,
    ));

    let pub_algo_start = offset + stream.pos();
    let pub_algorithm = stream.octet()?;
    let pub_algo_end = offset + stream.pos();
    let color = colors.set_field(pub_algo_start, pub_algo_end);
    let pub_algo_info = lookup_public_key_algorithm(pub_algorithm);
    fields.push(Field::field(
        "Public Key Algorithm",
        pub_algo_info.display(),
        (pub_algo_start, pub_algo_end),
        color,
    ));

    let hash_algo_start = offset + stream.pos();
    let hash_algorithm = stream.octet()?;
    let hash_algo_end = offset + stream.pos();
    let color = colors.set_field(hash_algo_start, hash_algo_end);
    let hash_algo_info = lookup_hash_algorithm(hash_algorithm);
    fields.push(Field::field(
        "Hash Algorithm",
        hash_algo_info.display(),
        (hash_algo_start, hash_algo_end),
        color,
    ));

    let hashed_len_start = offset + stream.pos();
    let hashed_len = stream.uint16()? as usize;
    let hashed_len_end = offset + stream.pos();
    let color = colors.set_field(hashed_len_start, hashed_len_end);
    fields.push(Field::field(
        "Hashed Subpackets",
        format!("{} bytes", hashed_len),
        (hashed_len_start, hashed_len_end),
        color,
    ));

    let hashed_start = offset + stream.pos();
    let hashed_subpacket_data = stream.bytes(hashed_len)?;

    let mut hashed_stream = ByteStream::new(hashed_subpacket_data);
    parse_subpackets(&mut hashed_stream, colors, fields, "Hashed", hashed_start)?;

    let unhashed_len_start = offset + stream.pos();
    let unhashed_len = stream.uint16()? as usize;
    let unhashed_len_end = offset + stream.pos();
    let color = colors.set_field(unhashed_len_start, unhashed_len_end);
    fields.push(Field::field(
        "Unhashed Subpackets",
        format!("{} bytes", unhashed_len),
        (unhashed_len_start, unhashed_len_end),
        color,
    ));

    let unhashed_start = offset + stream.pos();
    let unhashed_subpacket_data = stream.bytes(unhashed_len)?;

    let mut unhashed_stream = ByteStream::new(unhashed_subpacket_data);
    parse_subpackets(
        &mut unhashed_stream,
        colors,
        fields,
        "Unhashed",
        unhashed_start,
    )?;

    let prefix_start = offset + stream.pos();
    let hash_prefix = [stream.octet()?, stream.octet()?];
    let prefix_end = offset + stream.pos();
    let color = colors.set_field(prefix_start, prefix_end);
    fields.push(Field::field(
        "Hash Prefix",
        format!("{:02X}{:02X}", hash_prefix[0], hash_prefix[1]),
        (prefix_start, prefix_end),
        color,
    ));

    let sig_start = offset + stream.pos();
    let signature = parse_signature_data(stream, pub_algorithm)?;
    let sig_end = offset + stream.pos();
    let color = colors.set_field(sig_start, sig_end);

    let sig_desc = format_signature_desc(pub_algorithm, &signature, stream);
    fields.push(Field::field(
        "Signature",
        sig_desc,
        (sig_start, sig_end),
        color,
    ));

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
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<SignaturePacket> {
    let _hashed_len = stream.octet()?;

    let sig_type_start = offset + stream.pos();
    let signature_type = stream.octet()?;
    let sig_type_end = offset + stream.pos();
    let color = colors.set_field(sig_type_start, sig_type_end);
    let sig_type_info = lookup_signature_type(signature_type);
    fields.push(Field::field(
        "Signature Type",
        sig_type_info.display(),
        (sig_type_start, sig_type_end),
        color,
    ));

    let time_start = offset + stream.pos();
    let creation_time = stream.uint32()?;
    let time_end = offset + stream.pos();
    let color = colors.set_field(time_start, time_end);
    fields.push(Field::field(
        "Creation Time",
        creation_time.to_string(),
        (time_start, time_end),
        color,
    ));

    let key_id_start = offset + stream.pos();
    let key_id = stream.hex(8)?;
    let key_id_end = offset + stream.pos();
    let color = colors.set_field(key_id_start, key_id_end);
    fields.push(Field::field(
        "Key ID",
        key_id,
        (key_id_start, key_id_end),
        color,
    ));

    let pub_algo_start = offset + stream.pos();
    let pub_algorithm = stream.octet()?;
    let pub_algo_end = offset + stream.pos();
    let color = colors.set_field(pub_algo_start, pub_algo_end);
    let pub_algo_info = lookup_public_key_algorithm(pub_algorithm);
    fields.push(Field::field(
        "Public Key Algorithm",
        pub_algo_info.display(),
        (pub_algo_start, pub_algo_end),
        color,
    ));

    let hash_algo_start = offset + stream.pos();
    let hash_algorithm = stream.octet()?;
    let hash_algo_end = offset + stream.pos();
    let color = colors.set_field(hash_algo_start, hash_algo_end);
    let hash_algo_info = lookup_hash_algorithm(hash_algorithm);
    fields.push(Field::field(
        "Hash Algorithm",
        hash_algo_info.display(),
        (hash_algo_start, hash_algo_end),
        color,
    ));

    let prefix_start = offset + stream.pos();
    let hash_prefix = [stream.octet()?, stream.octet()?];
    let prefix_end = offset + stream.pos();
    let color = colors.set_field(prefix_start, prefix_end);
    fields.push(Field::field(
        "Hash Prefix",
        format!("{:02X}{:02X}", hash_prefix[0], hash_prefix[1]),
        (prefix_start, prefix_end),
        color,
    ));

    let sig_start = offset + stream.pos();
    let signature = parse_signature_data(stream, pub_algorithm)?;
    let sig_end = offset + stream.pos();
    let color = colors.set_field(sig_start, sig_end);

    let sig_desc = format_signature_desc(pub_algorithm, &signature, stream);
    fields.push(Field::field(
        "Signature",
        sig_desc,
        (sig_start, sig_end),
        color,
    ));

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
            let _sig = stream.hex(64)?;
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
        _ => "Unknown signature format".to_string(),
    }
}
