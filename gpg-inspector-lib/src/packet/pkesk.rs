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
