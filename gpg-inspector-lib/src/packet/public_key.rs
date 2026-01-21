//! Public key packet parsing.
//!
//! This module parses Public Key (tag 6) and Public Subkey (tag 14) packets,
//! extracting the key version, creation time, algorithm, and key material.

use crate::error::{Error, Result};
use crate::lookup::{lookup_curve_oid, lookup_public_key_algorithm};
use crate::packet::Field;
use crate::stream::ByteStream;
use chrono::{DateTime, TimeZone, Utc};

fn format_timestamp(ts: u32) -> Result<String> {
    Utc.timestamp_opt(ts as i64, 0)
        .single()
        .map(|dt: DateTime<Utc>| dt.to_rfc3339())
        .ok_or(Error::InvalidTimestamp(ts))
}

/// A parsed public key or public subkey packet.
///
/// Contains the common key metadata (version, creation time, algorithm)
/// and the algorithm-specific key material.
#[derive(Debug, Clone)]
pub struct PublicKeyPacket {
    /// Key packet version (typically 4 or 5).
    pub version: u8,
    /// Unix timestamp of key creation.
    pub creation_time: u32,
    /// Public-key algorithm identifier.
    pub algorithm: u8,
    /// Algorithm-specific public key data.
    pub key_material: KeyMaterial,
}

/// Algorithm-specific public key material.
///
/// Different key algorithms use different mathematical structures.
/// Each variant contains the public components needed for that algorithm.
#[derive(Debug, Clone)]
pub enum KeyMaterial {
    /// RSA public key (algorithms 1-3).
    Rsa {
        /// RSA modulus n (product of two primes).
        n: String,
        /// RSA public exponent e.
        e: String,
    },
    /// DSA public key (algorithm 17).
    Dsa {
        /// Prime modulus.
        p: String,
        /// Prime divisor of p-1.
        q: String,
        /// Generator of the subgroup of order q.
        g: String,
        /// Public key value g^x mod p.
        y: String,
    },
    /// Elgamal public key (algorithm 16).
    Elgamal {
        /// Prime modulus.
        p: String,
        /// Generator.
        g: String,
        /// Public key value.
        y: String,
    },
    /// ECDSA public key (algorithm 19).
    Ecdsa {
        /// OID identifying the elliptic curve.
        curve_oid: Vec<u8>,
        /// Encoded public point on the curve.
        public_key: String,
    },
    /// ECDH public key (algorithm 18).
    Ecdh {
        /// OID identifying the elliptic curve.
        curve_oid: Vec<u8>,
        /// Encoded public point on the curve.
        public_key: String,
        /// Key Derivation Function parameters.
        kdf_params: Vec<u8>,
    },
    /// EdDSA public key (legacy algorithm 22).
    EdDsa {
        /// OID identifying the curve (typically Ed25519).
        curve_oid: Vec<u8>,
        /// Encoded public key.
        public_key: String,
    },
    /// X25519 public key (algorithm 25, RFC 9580).
    X25519 {
        /// 32-byte public key.
        public_key: String,
    },
    /// Ed25519 public key (algorithm 27, RFC 9580).
    Ed25519 {
        /// 32-byte public key.
        public_key: String,
    },
    /// X448 public key (algorithm 26, RFC 9580).
    X448 {
        /// 56-byte public key.
        public_key: String,
    },
    /// Ed448 public key (algorithm 28, RFC 9580).
    Ed448 {
        /// 57-byte public key.
        public_key: String,
    },
    /// Unknown or unsupported algorithm.
    Unknown {
        /// Raw key material bytes.
        data: Vec<u8>,
    },
}

/// Parses a public key packet body.
///
/// This function is called for both Public Key (tag 6) and Public Subkey (tag 14)
/// packets, as they share the same format.
pub fn parse_public_key(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<PublicKeyPacket> {
    let version_start = offset + stream.pos();
    let version = stream.octet()?;
    let version_end = offset + stream.pos();
    fields.push(Field::field(
        "Version",
        version.to_string(),
        (version_start, version_end),
    ));

    match version {
        6 => parse_public_key_v6(stream, version, fields, offset),
        _ => parse_public_key_v4(stream, version, fields, offset),
    }
}

/// Parses a V4 public key packet body.
fn parse_public_key_v4(
    stream: &mut ByteStream,
    version: u8,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<PublicKeyPacket> {
    let time_start = offset + stream.pos();
    let creation_time = stream.uint32()?;
    let time_end = offset + stream.pos();
    fields.push(Field::field(
        "Creation Time",
        format_timestamp(creation_time)?,
        (time_start, time_end),
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

    let key_material = match algorithm {
        1..=3 => parse_rsa_key(stream, fields, offset)?,
        16 => parse_elgamal_key(stream, fields, offset)?,
        17 => parse_dsa_key(stream, fields, offset)?,
        18 => parse_ecdh_key(stream, fields, offset)?,
        19 => parse_ecdsa_key(stream, fields, offset)?,
        22 => parse_eddsa_key(stream, fields, offset)?,
        25 => parse_x25519_key(stream, fields, offset)?,
        27 => parse_ed25519_key(stream, fields, offset)?,
        _ => {
            let data = stream.rest();
            KeyMaterial::Unknown { data }
        }
    };

    Ok(PublicKeyPacket {
        version,
        creation_time,
        algorithm,
        key_material,
    })
}

/// Parses a V6 public key packet body (RFC 9580).
///
/// V6 keys have:
/// - 4-byte creation time
/// - 1-byte algorithm
/// - 4-byte key material length (new in V6)
/// - Algorithm-specific key material
fn parse_public_key_v6(
    stream: &mut ByteStream,
    version: u8,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<PublicKeyPacket> {
    let time_start = offset + stream.pos();
    let creation_time = stream.uint32()?;
    let time_end = offset + stream.pos();
    fields.push(Field::field(
        "Creation Time",
        format_timestamp(creation_time)?,
        (time_start, time_end),
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

    // V6 has a 4-byte key material length field
    let len_start = offset + stream.pos();
    let key_material_len = stream.uint32()?;
    let len_end = offset + stream.pos();
    fields.push(Field::field(
        "Key Material Length",
        format!("{} bytes", key_material_len),
        (len_start, len_end),
    ));

    let key_material = match algorithm {
        1..=3 => parse_rsa_key(stream, fields, offset)?,
        16 => parse_elgamal_key(stream, fields, offset)?,
        17 => parse_dsa_key(stream, fields, offset)?,
        18 => parse_ecdh_key(stream, fields, offset)?,
        19 => parse_ecdsa_key(stream, fields, offset)?,
        22 => parse_eddsa_key(stream, fields, offset)?,
        25 => parse_x25519_key(stream, fields, offset)?,
        26 => parse_x448_key(stream, fields, offset)?,
        27 => parse_ed25519_key(stream, fields, offset)?,
        28 => parse_ed448_key(stream, fields, offset)?,
        _ => {
            let data = stream.rest();
            KeyMaterial::Unknown { data }
        }
    };

    Ok(PublicKeyPacket {
        version,
        creation_time,
        algorithm,
        key_material,
    })
}

fn parse_rsa_key(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let n_start = offset + stream.pos();
    let (n_bits, n) = stream.multi_precision_integer()?;
    let n_end = offset + stream.pos();
    fields.push(Field::field(
        "RSA n",
        format!("{} bits", n_bits),
        (n_start, n_end),
    ));

    let e_start = offset + stream.pos();
    let (e_bits, e) = stream.multi_precision_integer()?;
    let e_end = offset + stream.pos();
    fields.push(Field::field(
        "RSA e",
        format!("{} bits: {}", e_bits, e),
        (e_start, e_end),
    ));

    Ok(KeyMaterial::Rsa { n, e })
}

fn parse_dsa_key(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let p_start = offset + stream.pos();
    let (p_bits, p) = stream.multi_precision_integer()?;
    let p_end = offset + stream.pos();
    fields.push(Field::field(
        "DSA p",
        format!("{} bits", p_bits),
        (p_start, p_end),
    ));

    let q_start = offset + stream.pos();
    let (q_bits, q) = stream.multi_precision_integer()?;
    let q_end = offset + stream.pos();
    fields.push(Field::field(
        "DSA q",
        format!("{} bits", q_bits),
        (q_start, q_end),
    ));

    let g_start = offset + stream.pos();
    let (g_bits, g) = stream.multi_precision_integer()?;
    let g_end = offset + stream.pos();
    fields.push(Field::field(
        "DSA g",
        format!("{} bits", g_bits),
        (g_start, g_end),
    ));

    let y_start = offset + stream.pos();
    let (y_bits, y) = stream.multi_precision_integer()?;
    let y_end = offset + stream.pos();
    fields.push(Field::field(
        "DSA y",
        format!("{} bits", y_bits),
        (y_start, y_end),
    ));

    Ok(KeyMaterial::Dsa { p, q, g, y })
}

fn parse_elgamal_key(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let p_start = offset + stream.pos();
    let (p_bits, p) = stream.multi_precision_integer()?;
    let p_end = offset + stream.pos();
    fields.push(Field::field(
        "Elgamal p",
        format!("{} bits", p_bits),
        (p_start, p_end),
    ));

    let g_start = offset + stream.pos();
    let (g_bits, g) = stream.multi_precision_integer()?;
    let g_end = offset + stream.pos();
    fields.push(Field::field(
        "Elgamal g",
        format!("{} bits", g_bits),
        (g_start, g_end),
    ));

    let y_start = offset + stream.pos();
    let (y_bits, y) = stream.multi_precision_integer()?;
    let y_end = offset + stream.pos();
    fields.push(Field::field(
        "Elgamal y",
        format!("{} bits", y_bits),
        (y_start, y_end),
    ));

    Ok(KeyMaterial::Elgamal { p, g, y })
}

fn parse_ecdsa_key(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let oid_start = offset + stream.pos();
    let oid_len = stream.octet()? as usize;
    let curve_oid = stream.bytes(oid_len)?;
    let oid_end = offset + stream.pos();
    let curve_name = lookup_curve_oid(&curve_oid);
    fields.push(Field::field("Curve", curve_name, (oid_start, oid_end)));

    let pk_start = offset + stream.pos();
    let (pk_bits, public_key) = stream.multi_precision_integer()?;
    let pk_end = offset + stream.pos();
    fields.push(Field::field(
        "Public Key",
        format!("{} bits", pk_bits),
        (pk_start, pk_end),
    ));

    Ok(KeyMaterial::Ecdsa {
        curve_oid,
        public_key,
    })
}

fn parse_ecdh_key(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let oid_start = offset + stream.pos();
    let oid_len = stream.octet()? as usize;
    let curve_oid = stream.bytes(oid_len)?;
    let oid_end = offset + stream.pos();
    let curve_name = lookup_curve_oid(&curve_oid);
    fields.push(Field::field("Curve", curve_name, (oid_start, oid_end)));

    let pk_start = offset + stream.pos();
    let (pk_bits, public_key) = stream.multi_precision_integer()?;
    let pk_end = offset + stream.pos();
    fields.push(Field::field(
        "Public Key",
        format!("{} bits", pk_bits),
        (pk_start, pk_end),
    ));

    let kdf_start = offset + stream.pos();
    let kdf_len = stream.octet()? as usize;
    let kdf_params = stream.bytes(kdf_len)?;
    let kdf_end = offset + stream.pos();
    fields.push(Field::field(
        "KDF Parameters",
        format!("{} bytes", kdf_params.len()),
        (kdf_start, kdf_end),
    ));

    Ok(KeyMaterial::Ecdh {
        curve_oid,
        public_key,
        kdf_params,
    })
}

fn parse_eddsa_key(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let oid_start = offset + stream.pos();
    let oid_len = stream.octet()? as usize;
    let curve_oid = stream.bytes(oid_len)?;
    let oid_end = offset + stream.pos();
    let curve_name = lookup_curve_oid(&curve_oid);
    fields.push(Field::field("Curve", curve_name, (oid_start, oid_end)));

    let pk_start = offset + stream.pos();
    let (pk_bits, public_key) = stream.multi_precision_integer()?;
    let pk_end = offset + stream.pos();
    fields.push(Field::field(
        "Public Key",
        format!("{} bits", pk_bits),
        (pk_start, pk_end),
    ));

    Ok(KeyMaterial::EdDsa {
        curve_oid,
        public_key,
    })
}

fn parse_x25519_key(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let pk_start = offset + stream.pos();
    let public_key = stream.hex(32)?;
    let pk_end = offset + stream.pos();
    fields.push(Field::field(
        "Public Key",
        "256 bits (X25519)",
        (pk_start, pk_end),
    ));

    Ok(KeyMaterial::X25519 { public_key })
}

fn parse_ed25519_key(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let pk_start = offset + stream.pos();
    let public_key = stream.hex(32)?;
    let pk_end = offset + stream.pos();
    fields.push(Field::field(
        "Public Key",
        "256 bits (Ed25519)",
        (pk_start, pk_end),
    ));

    Ok(KeyMaterial::Ed25519 { public_key })
}

fn parse_x448_key(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let pk_start = offset + stream.pos();
    let public_key = stream.hex(56)?;
    let pk_end = offset + stream.pos();
    fields.push(Field::field(
        "Public Key",
        "448 bits (X448)",
        (pk_start, pk_end),
    ));

    Ok(KeyMaterial::X448 { public_key })
}

fn parse_ed448_key(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let pk_start = offset + stream.pos();
    let public_key = stream.hex(57)?;
    let pk_end = offset + stream.pos();
    fields.push(Field::field(
        "Public Key",
        "456 bits (Ed448)",
        (pk_start, pk_end),
    ));

    Ok(KeyMaterial::Ed448 { public_key })
}
