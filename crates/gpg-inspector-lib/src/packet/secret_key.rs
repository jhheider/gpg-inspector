//! Secret key packet parsing.
//!
//! This module parses Secret Key (tag 5) and Secret Subkey (tag 7) packets,
//! which contain the public key data plus encrypted (or unencrypted) private
//! key material.

use crate::error::Result;
use crate::lookup::{lookup_s2k_type, lookup_symmetric_algorithm};
use crate::packet::Field;
use crate::packet::public_key::{PublicKeyPacket, parse_public_key};
use crate::stream::ByteStream;

/// A parsed secret key or secret subkey packet.
///
/// Contains the public key portion plus the secret key data,
/// which may be encrypted with a passphrase.
#[derive(Debug, Clone)]
pub struct SecretKeyPacket {
    /// The public key portion (version, creation time, algorithm, key material).
    pub public_key: PublicKeyPacket,
    /// String-to-Key usage byte indicating encryption method.
    pub s2k_usage: u8,
    /// Encryption parameters, if the key is encrypted.
    pub encryption_info: Option<EncryptionInfo>,
    /// The secret key data (encrypted or plaintext).
    pub secret_key_data: Vec<u8>,
}

/// Encryption parameters for a secret key.
///
/// Describes how the secret key material is encrypted, including
/// the cipher, S2K (string-to-key) parameters, and IV.
#[derive(Debug, Clone)]
pub struct EncryptionInfo {
    /// Symmetric cipher algorithm used for encryption.
    pub cipher_algo: u8,
    /// S2K specifier type (Simple, Salted, Iterated, Argon2).
    pub s2k_type: u8,
    /// Hash algorithm used in S2K.
    pub s2k_hash: u8,
    /// 8-byte salt for Salted and Iterated S2K.
    pub s2k_salt: Option<Vec<u8>>,
    /// Iteration count byte for Iterated S2K.
    pub s2k_count: Option<u8>,
    /// Initialization vector for the cipher.
    pub iv: Vec<u8>,
}

/// Parses a secret key packet body.
///
/// This function is called for both Secret Key (tag 5) and Secret Subkey (tag 7)
/// packets, as they share the same format.
pub fn parse_secret_key(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<SecretKeyPacket> {
    let public_key = parse_public_key(stream, fields, offset)?;

    let s2k_start = offset + stream.pos();
    let s2k_usage = stream.octet()?;
    let s2k_end = offset + stream.pos();

    let s2k_desc = match s2k_usage {
        0 => "Unencrypted".to_string(),
        254 => "SHA-1 checksum, encrypted".to_string(),
        255 => "Checksum, encrypted".to_string(),
        n => format!("Symmetric algorithm {}", n),
    };
    fields.push(Field::field("S2K Usage", s2k_desc, (s2k_start, s2k_end)));

    let encryption_info = if s2k_usage == 254 || s2k_usage == 255 {
        let cipher_start = offset + stream.pos();
        let cipher_algo = stream.octet()?;
        let cipher_end = offset + stream.pos();
        let cipher_info = lookup_symmetric_algorithm(cipher_algo);
        fields.push(Field::field(
            "Cipher",
            cipher_info.display(),
            (cipher_start, cipher_end),
        ));

        let s2k_type_start = offset + stream.pos();
        let s2k_type = stream.octet()?;
        let s2k_type_end = offset + stream.pos();
        fields.push(Field::field(
            "S2K Type",
            lookup_s2k_type(s2k_type).to_string(),
            (s2k_type_start, s2k_type_end),
        ));

        let _s2k_hash_start = offset + stream.pos();
        let s2k_hash = stream.octet()?;
        let _s2k_hash_end = offset + stream.pos();

        let (s2k_salt, s2k_count) = if s2k_type == 1 || s2k_type == 3 {
            let salt_start = offset + stream.pos();
            let salt = stream.bytes(8)?;
            let salt_end = offset + stream.pos();
            fields.push(Field::field("S2K Salt", "8 bytes", (salt_start, salt_end)));

            let count = if s2k_type == 3 {
                let count_start = offset + stream.pos();
                let c = stream.octet()?;
                let count_end = offset + stream.pos();
                let iterations = (16u32 + (c as u32 & 15)) << ((c >> 4) + 6);
                fields.push(Field::field(
                    "S2K Iterations",
                    iterations.to_string(),
                    (count_start, count_end),
                ));
                Some(c)
            } else {
                None
            };

            (Some(salt), count)
        } else {
            (None, None)
        };

        let iv_size = match cipher_algo {
            7..=9 => 16,
            _ => 8,
        };
        let iv_start = offset + stream.pos();
        let iv = stream.bytes(iv_size)?;
        let iv_end = offset + stream.pos();
        fields.push(Field::field(
            "IV",
            format!("{} bytes", iv.len()),
            (iv_start, iv_end),
        ));

        Some(EncryptionInfo {
            cipher_algo,
            s2k_type,
            s2k_hash,
            s2k_salt,
            s2k_count,
            iv,
        })
    } else if s2k_usage != 0 {
        let iv_size = match s2k_usage {
            7..=9 => 16,
            _ => 8,
        };
        let _iv_start = offset + stream.pos();
        let iv = stream.bytes(iv_size)?;
        let _iv_end = offset + stream.pos();

        Some(EncryptionInfo {
            cipher_algo: s2k_usage,
            s2k_type: 0,
            s2k_hash: 0,
            s2k_salt: None,
            s2k_count: None,
            iv,
        })
    } else {
        None
    };

    let data_start = offset + stream.pos();
    let secret_key_data = stream.rest();
    if !secret_key_data.is_empty() {
        let data_end = offset + stream.pos();
        fields.push(Field::field(
            "Secret Key Data",
            format!("{} bytes (encrypted)", secret_key_data.len()),
            (data_start, data_end),
        ));
    }

    Ok(SecretKeyPacket {
        public_key,
        s2k_usage,
        encryption_info,
        secret_key_data,
    })
}
