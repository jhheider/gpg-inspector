use crate::color::ColorTracker;
use crate::error::Result;
use crate::lookup::{lookup_s2k_type, lookup_symmetric_algorithm};
use crate::packet::public_key::{parse_public_key, PublicKeyPacket};
use crate::packet::Field;
use crate::stream::ByteStream;

#[derive(Debug, Clone)]
pub struct SecretKeyPacket {
    pub public_key: PublicKeyPacket,
    pub s2k_usage: u8,
    pub encryption_info: Option<EncryptionInfo>,
    pub secret_key_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EncryptionInfo {
    pub cipher_algo: u8,
    pub s2k_type: u8,
    pub s2k_hash: u8,
    pub s2k_salt: Option<Vec<u8>>,
    pub s2k_count: Option<u8>,
    pub iv: Vec<u8>,
}

pub fn parse_secret_key(
    stream: &mut ByteStream,
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<SecretKeyPacket> {
    let public_key = parse_public_key(stream, colors, fields, offset)?;

    let s2k_start = offset + stream.pos();
    let s2k_usage = stream.octet()?;
    let s2k_end = offset + stream.pos();
    let color = colors.set_field(s2k_start, s2k_end);

    let s2k_desc = match s2k_usage {
        0 => "Unencrypted".to_string(),
        254 => "SHA-1 checksum, encrypted".to_string(),
        255 => "Checksum, encrypted".to_string(),
        n => format!("Symmetric algorithm {}", n),
    };
    fields.push(Field::field("S2K Usage", s2k_desc, (s2k_start, s2k_end), color));

    let encryption_info = if s2k_usage == 254 || s2k_usage == 255 {
        let cipher_start = offset + stream.pos();
        let cipher_algo = stream.octet()?;
        let cipher_end = offset + stream.pos();
        let color = colors.set_field(cipher_start, cipher_end);
        let cipher_info = lookup_symmetric_algorithm(cipher_algo);
        fields.push(Field::field("Cipher", cipher_info.display(), (cipher_start, cipher_end), color));

        let s2k_type_start = offset + stream.pos();
        let s2k_type = stream.octet()?;
        let s2k_type_end = offset + stream.pos();
        let color = colors.set_field(s2k_type_start, s2k_type_end);
        fields.push(Field::field("S2K Type", lookup_s2k_type(s2k_type).to_string(), (s2k_type_start, s2k_type_end), color));

        let s2k_hash_start = offset + stream.pos();
        let s2k_hash = stream.octet()?;
        let s2k_hash_end = offset + stream.pos();
        let _color = colors.set_field(s2k_hash_start, s2k_hash_end);

        let (s2k_salt, s2k_count) = if s2k_type == 1 || s2k_type == 3 {
            let salt_start = offset + stream.pos();
            let salt = stream.bytes(8)?;
            let salt_end = offset + stream.pos();
            let color = colors.set_field(salt_start, salt_end);
            fields.push(Field::field("S2K Salt", "8 bytes", (salt_start, salt_end), color));

            let count = if s2k_type == 3 {
                let count_start = offset + stream.pos();
                let c = stream.octet()?;
                let count_end = offset + stream.pos();
                let color = colors.set_field(count_start, count_end);
                let iterations = (16u32 + (c as u32 & 15)) << ((c >> 4) + 6);
                fields.push(Field::field("S2K Iterations", iterations.to_string(), (count_start, count_end), color));
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
        let color = colors.set_field(iv_start, iv_end);
        fields.push(Field::field("IV", format!("{} bytes", iv.len()), (iv_start, iv_end), color));

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
        let iv_start = offset + stream.pos();
        let iv = stream.bytes(iv_size)?;
        let iv_end = offset + stream.pos();
        let _color = colors.set_field(iv_start, iv_end);

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
        let color = colors.set_field(data_start, data_end);
        fields.push(Field::field(
            "Secret Key Data",
            format!("{} bytes (encrypted)", secret_key_data.len()),
            (data_start, data_end),
            color,
        ));
    }

    Ok(SecretKeyPacket {
        public_key,
        s2k_usage,
        encryption_info,
        secret_key_data,
    })
}
