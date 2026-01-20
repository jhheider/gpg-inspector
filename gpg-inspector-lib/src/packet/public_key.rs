use crate::color::ColorTracker;
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

#[derive(Debug, Clone)]
pub struct PublicKeyPacket {
    pub version: u8,
    pub creation_time: u32,
    pub algorithm: u8,
    pub key_material: KeyMaterial,
}

#[derive(Debug, Clone)]
pub enum KeyMaterial {
    Rsa { n: String, e: String },
    Dsa { p: String, q: String, g: String, y: String },
    Elgamal { p: String, g: String, y: String },
    Ecdsa { curve_oid: Vec<u8>, public_key: String },
    Ecdh { curve_oid: Vec<u8>, public_key: String, kdf_params: Vec<u8> },
    EdDsa { curve_oid: Vec<u8>, public_key: String },
    X25519 { public_key: String },
    Ed25519 { public_key: String },
    Unknown { data: Vec<u8> },
}

pub fn parse_public_key(
    stream: &mut ByteStream,
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<PublicKeyPacket> {
    let version_start = offset + stream.pos();
    let version = stream.octet()?;
    let version_end = offset + stream.pos();
    let color = colors.set_field(version_start, version_end);
    fields.push(Field::field("Version", version.to_string(), (version_start, version_end), color));

    let time_start = offset + stream.pos();
    let creation_time = stream.uint32()?;
    let time_end = offset + stream.pos();
    let color = colors.set_field(time_start, time_end);
    fields.push(Field::field("Creation Time", format_timestamp(creation_time)?, (time_start, time_end), color));

    let algo_start = offset + stream.pos();
    let algorithm = stream.octet()?;
    let algo_end = offset + stream.pos();
    let color = colors.set_field(algo_start, algo_end);
    let algo_info = lookup_public_key_algorithm(algorithm);
    fields.push(Field::field("Algorithm", algo_info.display(), (algo_start, algo_end), color));

    let key_material = match algorithm {
        1..=3 => parse_rsa_key(stream, colors, fields, offset)?,
        16 => parse_elgamal_key(stream, colors, fields, offset)?,
        17 => parse_dsa_key(stream, colors, fields, offset)?,
        18 => parse_ecdh_key(stream, colors, fields, offset)?,
        19 => parse_ecdsa_key(stream, colors, fields, offset)?,
        22 => parse_eddsa_key(stream, colors, fields, offset)?,
        25 => parse_x25519_key(stream, colors, fields, offset)?,
        27 => parse_ed25519_key(stream, colors, fields, offset)?,
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
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let n_start = offset + stream.pos();
    let (n_bits, n) = stream.multi_precision_integer()?;
    let n_end = offset + stream.pos();
    let color = colors.set_field(n_start, n_end);
    fields.push(Field::field("RSA n", format!("{} bits", n_bits), (n_start, n_end), color));

    let e_start = offset + stream.pos();
    let (e_bits, e) = stream.multi_precision_integer()?;
    let e_end = offset + stream.pos();
    let color = colors.set_field(e_start, e_end);
    fields.push(Field::field("RSA e", format!("{} bits: {}", e_bits, e), (e_start, e_end), color));

    Ok(KeyMaterial::Rsa { n, e })
}

fn parse_dsa_key(
    stream: &mut ByteStream,
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let p_start = offset + stream.pos();
    let (p_bits, p) = stream.multi_precision_integer()?;
    let p_end = offset + stream.pos();
    let color = colors.set_field(p_start, p_end);
    fields.push(Field::field("DSA p", format!("{} bits", p_bits), (p_start, p_end), color));

    let q_start = offset + stream.pos();
    let (q_bits, q) = stream.multi_precision_integer()?;
    let q_end = offset + stream.pos();
    let color = colors.set_field(q_start, q_end);
    fields.push(Field::field("DSA q", format!("{} bits", q_bits), (q_start, q_end), color));

    let g_start = offset + stream.pos();
    let (g_bits, g) = stream.multi_precision_integer()?;
    let g_end = offset + stream.pos();
    let color = colors.set_field(g_start, g_end);
    fields.push(Field::field("DSA g", format!("{} bits", g_bits), (g_start, g_end), color));

    let y_start = offset + stream.pos();
    let (y_bits, y) = stream.multi_precision_integer()?;
    let y_end = offset + stream.pos();
    let color = colors.set_field(y_start, y_end);
    fields.push(Field::field("DSA y", format!("{} bits", y_bits), (y_start, y_end), color));

    Ok(KeyMaterial::Dsa { p, q, g, y })
}

fn parse_elgamal_key(
    stream: &mut ByteStream,
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let p_start = offset + stream.pos();
    let (p_bits, p) = stream.multi_precision_integer()?;
    let p_end = offset + stream.pos();
    let color = colors.set_field(p_start, p_end);
    fields.push(Field::field("Elgamal p", format!("{} bits", p_bits), (p_start, p_end), color));

    let g_start = offset + stream.pos();
    let (g_bits, g) = stream.multi_precision_integer()?;
    let g_end = offset + stream.pos();
    let color = colors.set_field(g_start, g_end);
    fields.push(Field::field("Elgamal g", format!("{} bits", g_bits), (g_start, g_end), color));

    let y_start = offset + stream.pos();
    let (y_bits, y) = stream.multi_precision_integer()?;
    let y_end = offset + stream.pos();
    let color = colors.set_field(y_start, y_end);
    fields.push(Field::field("Elgamal y", format!("{} bits", y_bits), (y_start, y_end), color));

    Ok(KeyMaterial::Elgamal { p, g, y })
}

fn parse_ecdsa_key(
    stream: &mut ByteStream,
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let oid_start = offset + stream.pos();
    let oid_len = stream.octet()? as usize;
    let curve_oid = stream.bytes(oid_len)?;
    let oid_end = offset + stream.pos();
    let color = colors.set_field(oid_start, oid_end);
    let curve_name = lookup_curve_oid(&curve_oid);
    fields.push(Field::field("Curve", curve_name, (oid_start, oid_end), color));

    let pk_start = offset + stream.pos();
    let (pk_bits, public_key) = stream.multi_precision_integer()?;
    let pk_end = offset + stream.pos();
    let color = colors.set_field(pk_start, pk_end);
    fields.push(Field::field("Public Key", format!("{} bits", pk_bits), (pk_start, pk_end), color));

    Ok(KeyMaterial::Ecdsa { curve_oid, public_key })
}

fn parse_ecdh_key(
    stream: &mut ByteStream,
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let oid_start = offset + stream.pos();
    let oid_len = stream.octet()? as usize;
    let curve_oid = stream.bytes(oid_len)?;
    let oid_end = offset + stream.pos();
    let color = colors.set_field(oid_start, oid_end);
    let curve_name = lookup_curve_oid(&curve_oid);
    fields.push(Field::field("Curve", curve_name, (oid_start, oid_end), color));

    let pk_start = offset + stream.pos();
    let (pk_bits, public_key) = stream.multi_precision_integer()?;
    let pk_end = offset + stream.pos();
    let color = colors.set_field(pk_start, pk_end);
    fields.push(Field::field("Public Key", format!("{} bits", pk_bits), (pk_start, pk_end), color));

    let kdf_start = offset + stream.pos();
    let kdf_len = stream.octet()? as usize;
    let kdf_params = stream.bytes(kdf_len)?;
    let kdf_end = offset + stream.pos();
    let color = colors.set_field(kdf_start, kdf_end);
    fields.push(Field::field("KDF Parameters", format!("{} bytes", kdf_params.len()), (kdf_start, kdf_end), color));

    Ok(KeyMaterial::Ecdh { curve_oid, public_key, kdf_params })
}

fn parse_eddsa_key(
    stream: &mut ByteStream,
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let oid_start = offset + stream.pos();
    let oid_len = stream.octet()? as usize;
    let curve_oid = stream.bytes(oid_len)?;
    let oid_end = offset + stream.pos();
    let color = colors.set_field(oid_start, oid_end);
    let curve_name = lookup_curve_oid(&curve_oid);
    fields.push(Field::field("Curve", curve_name, (oid_start, oid_end), color));

    let pk_start = offset + stream.pos();
    let (pk_bits, public_key) = stream.multi_precision_integer()?;
    let pk_end = offset + stream.pos();
    let color = colors.set_field(pk_start, pk_end);
    fields.push(Field::field("Public Key", format!("{} bits", pk_bits), (pk_start, pk_end), color));

    Ok(KeyMaterial::EdDsa { curve_oid, public_key })
}

fn parse_x25519_key(
    stream: &mut ByteStream,
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let pk_start = offset + stream.pos();
    let public_key = stream.hex(32)?;
    let pk_end = offset + stream.pos();
    let color = colors.set_field(pk_start, pk_end);
    fields.push(Field::field("Public Key", "256 bits (X25519)", (pk_start, pk_end), color));

    Ok(KeyMaterial::X25519 { public_key })
}

fn parse_ed25519_key(
    stream: &mut ByteStream,
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<KeyMaterial> {
    let pk_start = offset + stream.pos();
    let public_key = stream.hex(32)?;
    let pk_end = offset + stream.pos();
    let color = colors.set_field(pk_start, pk_end);
    fields.push(Field::field("Public Key", "256 bits (Ed25519)", (pk_start, pk_end), color));

    Ok(KeyMaterial::Ed25519 { public_key })
}
