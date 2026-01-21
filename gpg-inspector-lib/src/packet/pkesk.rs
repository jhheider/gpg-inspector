//! Public-Key Encrypted Session Key packet parsing.
//!
//! This module parses PKESK packets (tag 1), which contain a session key
//! encrypted to a recipient's public key. These packets are used at the
//! start of encrypted messages to deliver the symmetric session key.

use crate::error::Result;
use crate::lookup::lookup_public_key_algorithm;
use crate::packet::Field;
use crate::stream::ByteStream;

/// A parsed Public-Key Encrypted Session Key packet.
///
/// Contains the recipient's key ID, the encryption algorithm, and
/// the encrypted session key data.
#[derive(Debug, Clone)]
pub struct PkeskPacket {
    /// Packet version (typically 3).
    pub version: u8,
    /// Key ID of the recipient's public key (8 hex characters).
    pub key_id: String,
    /// Public-key algorithm used to encrypt the session key.
    pub algorithm: u8,
    /// The encrypted session key data.
    pub encrypted_session_key: Vec<u8>,
}

/// Parses a PKESK packet body.
pub fn parse_pkesk(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<PkeskPacket> {
    let version_start = offset + stream.pos();
    let version = stream.octet()?;
    let version_end = offset + stream.pos();
    fields.push(Field::field(
        "Version",
        version.to_string(),
        (version_start, version_end),
    ));

    match version {
        6 => parse_pkesk_v6(stream, version, fields, offset),
        _ => parse_pkesk_v3(stream, version, fields, offset),
    }
}

/// Parses a V3 PKESK packet body.
fn parse_pkesk_v3(
    stream: &mut ByteStream,
    version: u8,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<PkeskPacket> {
    let key_id_start = offset + stream.pos();
    let key_id = stream.hex(8)?;
    let key_id_end = offset + stream.pos();
    fields.push(Field::field(
        "Key ID",
        key_id.clone(),
        (key_id_start, key_id_end),
    ));

    let algo_start = offset + stream.pos();
    let algorithm = stream.octet()?;
    let algo_end = offset + stream.pos();
    let algo_info = lookup_public_key_algorithm(algorithm);
    fields.push(Field::field(
        "Algorithm",
        algo_info.display(),
        (algo_start, algo_end),
    ));

    let esk_start = offset + stream.pos();
    let encrypted_session_key = match algorithm {
        1..=3 => {
            let (bits, _hex) = stream.multi_precision_integer()?;
            let esk_end = offset + stream.pos();
            fields.push(Field::field(
                "Encrypted Session Key",
                format!("{} bits", bits),
                (esk_start, esk_end),
            ));
            stream.rest()
        }
        16 => {
            let (bits1, _) = stream.multi_precision_integer()?;
            let (bits2, _) = stream.multi_precision_integer()?;
            let esk_end = offset + stream.pos();
            fields.push(Field::field(
                "Encrypted Session Key",
                format!("{} + {} bits", bits1, bits2),
                (esk_start, esk_end),
            ));
            stream.rest()
        }
        18 => {
            let (bits, _) = stream.multi_precision_integer()?;
            let wrapped = stream.rest();
            let esk_end = offset + stream.pos();
            fields.push(Field::field(
                "Encrypted Session Key",
                format!("{} bits ephemeral + {} bytes wrapped", bits, wrapped.len()),
                (esk_start, esk_end),
            ));
            wrapped
        }
        25 => {
            let ephemeral = stream.bytes(32)?;
            let eph_end = offset + stream.pos();
            fields.push(Field::field(
                "Ephemeral Key",
                format!("{} bytes", ephemeral.len()),
                (esk_start, eph_end),
            ));
            let wrap_start = offset + stream.pos();
            let wrapped = stream.rest();
            let wrap_end = offset + stream.pos();
            fields.push(Field::field(
                "Wrapped Session Key",
                format!("{} bytes", wrapped.len()),
                (wrap_start, wrap_end),
            ));
            wrapped
        }
        _ => {
            let data = stream.rest();
            let esk_end = offset + stream.pos();
            fields.push(Field::field(
                "Encrypted Session Key",
                format!("{} bytes", data.len()),
                (esk_start, esk_end),
            ));
            data
        }
    };

    Ok(PkeskPacket {
        version,
        key_id,
        algorithm,
        encrypted_session_key,
    })
}

/// Parses a V6 PKESK packet body (RFC 9580).
///
/// V6 PKESK has:
/// - 1-byte key version (0=anonymous, 4=V4 key ID, 6=V6 fingerprint)
/// - Variable key identification:
///   - Version 0: no key ID (anonymous recipient)
///   - Version 4: 8-byte key ID
///   - Version 6: 32-byte fingerprint
/// - 1-byte algorithm
/// - Algorithm-specific encrypted session key
fn parse_pkesk_v6(
    stream: &mut ByteStream,
    version: u8,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<PkeskPacket> {
    // V6: Key version field
    let key_ver_start = offset + stream.pos();
    let key_version = stream.octet()?;
    let key_ver_end = offset + stream.pos();
    let key_ver_desc = match key_version {
        0 => "0 (Anonymous recipient)",
        4 => "4 (V4 Key ID)",
        6 => "6 (V6 Fingerprint)",
        _ => "Unknown",
    };
    fields.push(Field::field(
        "Key Version",
        key_ver_desc,
        (key_ver_start, key_ver_end),
    ));

    // V6: Variable key identification based on key version
    let key_id = match key_version {
        0 => {
            // Anonymous recipient - no key ID
            String::new()
        }
        4 => {
            // V4 key: 8-byte key ID
            let key_id_start = offset + stream.pos();
            let key_id = stream.hex(8)?;
            let key_id_end = offset + stream.pos();
            fields.push(Field::field(
                "Key ID",
                key_id.clone(),
                (key_id_start, key_id_end),
            ));
            key_id
        }
        6 => {
            // V6 key: 32-byte fingerprint
            let fp_start = offset + stream.pos();
            let fingerprint = stream.hex(32)?;
            let fp_end = offset + stream.pos();
            fields.push(Field::field(
                "Fingerprint",
                fingerprint.clone(),
                (fp_start, fp_end),
            ));
            fingerprint
        }
        _ => {
            // Unknown key version - try to continue
            String::new()
        }
    };

    let algo_start = offset + stream.pos();
    let algorithm = stream.octet()?;
    let algo_end = offset + stream.pos();
    let algo_info = lookup_public_key_algorithm(algorithm);
    fields.push(Field::field(
        "Algorithm",
        algo_info.display(),
        (algo_start, algo_end),
    ));

    let esk_start = offset + stream.pos();
    let encrypted_session_key = match algorithm {
        1..=3 => {
            // RSA
            let (bits, _hex) = stream.multi_precision_integer()?;
            let esk_end = offset + stream.pos();
            fields.push(Field::field(
                "Encrypted Session Key",
                format!("{} bits", bits),
                (esk_start, esk_end),
            ));
            stream.rest()
        }
        25 => {
            // X25519: 32-byte ephemeral key
            let ephemeral = stream.bytes(32)?;
            let eph_end = offset + stream.pos();
            fields.push(Field::field(
                "Ephemeral Key",
                format!("{} bytes (X25519)", ephemeral.len()),
                (esk_start, eph_end),
            ));
            let wrap_start = offset + stream.pos();
            let wrapped = stream.rest();
            let wrap_end = offset + stream.pos();
            fields.push(Field::field(
                "Wrapped Session Key",
                format!("{} bytes", wrapped.len()),
                (wrap_start, wrap_end),
            ));
            wrapped
        }
        26 => {
            // X448: 56-byte ephemeral key
            let ephemeral = stream.bytes(56)?;
            let eph_end = offset + stream.pos();
            fields.push(Field::field(
                "Ephemeral Key",
                format!("{} bytes (X448)", ephemeral.len()),
                (esk_start, eph_end),
            ));
            let wrap_start = offset + stream.pos();
            let wrapped = stream.rest();
            let wrap_end = offset + stream.pos();
            fields.push(Field::field(
                "Wrapped Session Key",
                format!("{} bytes", wrapped.len()),
                (wrap_start, wrap_end),
            ));
            wrapped
        }
        _ => {
            let data = stream.rest();
            let esk_end = offset + stream.pos();
            fields.push(Field::field(
                "Encrypted Session Key",
                format!("{} bytes", data.len()),
                (esk_start, esk_end),
            ));
            data
        }
    };

    Ok(PkeskPacket {
        version,
        key_id,
        algorithm,
        encrypted_session_key,
    })
}
