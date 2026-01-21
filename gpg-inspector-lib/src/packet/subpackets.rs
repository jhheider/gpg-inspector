use crate::color::ColorTracker;
use crate::error::{Error, Result};
use crate::lookup::{
    lookup_compression_algorithm, lookup_hash_algorithm, lookup_key_flags,
    lookup_public_key_algorithm, lookup_revocation_reason, lookup_subpacket_type,
    lookup_symmetric_algorithm,
};
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
pub struct Subpacket {
    pub packet_type: u8,
    pub critical: bool,
    pub data: SubpacketData,
}

#[derive(Debug, Clone)]
pub enum SubpacketData {
    SignatureCreationTime(u32),
    SignatureExpirationTime(u32),
    KeyExpirationTime(u32),
    Exportable(bool),
    Trust {
        level: u8,
        amount: u8,
    },
    Revocable(bool),
    PreferredSymmetric(Vec<u8>),
    RevocationKey {
        class: u8,
        algo: u8,
        fingerprint: String,
    },
    IssuerKeyId(String),
    NotationData {
        name: String,
        value: String,
    },
    PreferredHash(Vec<u8>),
    PreferredCompression(Vec<u8>),
    KeyServerPreferences(Vec<u8>),
    PreferredKeyServer(String),
    PrimaryUserId(bool),
    PolicyUri(String),
    KeyFlags(Vec<u8>),
    SignerUserId(String),
    RevocationReason {
        code: u8,
        reason: String,
    },
    Features(Vec<u8>),
    SignatureTarget {
        algo: u8,
        hash_algo: u8,
        hash: String,
    },
    EmbeddedSignature(Vec<u8>),
    IssuerFingerprint {
        version: u8,
        fingerprint: String,
    },
    PreferredAead(Vec<u8>),
    IntendedRecipient {
        version: u8,
        fingerprint: String,
    },
    Unknown(Vec<u8>),
}

pub fn parse_subpackets(
    stream: &mut ByteStream,
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    prefix: &str,
    base_offset: usize,
) -> Result<Vec<Subpacket>> {
    let mut subpackets = Vec::new();
    let mut count = 0;

    while !stream.is_empty() {
        count += 1;
        let sp_start = base_offset + stream.pos();

        let len = stream.variable_length()?;
        if len == 0 {
            continue;
        }

        let type_byte = stream.octet()?;
        let critical = (type_byte & 0x80) != 0;
        let packet_type = type_byte & 0x7F;

        let data_len = len - 1;
        let mut sp_stream = stream.slice(stream.pos(), stream.pos() + data_len);
        stream.skip(data_len)?;
        let sp_end = base_offset + stream.pos();

        let type_info = lookup_subpacket_type(packet_type);
        let field_name = format!("{} #{}: {}", prefix, count, type_info.name);

        let (data, value) = parse_subpacket_data(packet_type, &mut sp_stream)?;

        let color = colors.set_field(sp_start, sp_end);
        fields.push(Field::subfield(
            field_name,
            value,
            (sp_start, sp_end),
            color,
        ));

        subpackets.push(Subpacket {
            packet_type,
            critical,
            data,
        });
    }

    Ok(subpackets)
}

fn parse_subpacket_data(
    packet_type: u8,
    stream: &mut ByteStream,
) -> Result<(SubpacketData, String)> {
    let (data, value) = match packet_type {
        2 => {
            let time = stream.uint32()?;
            (
                SubpacketData::SignatureCreationTime(time),
                format_timestamp(time)?,
            )
        }
        3 => {
            let time = stream.uint32()?;
            (
                SubpacketData::SignatureExpirationTime(time),
                format_duration(time),
            )
        }
        4 => {
            let exportable = stream.octet()? != 0;
            (
                SubpacketData::Exportable(exportable),
                exportable.to_string(),
            )
        }
        5 => {
            let level = stream.octet()?;
            let amount = stream.octet()?;
            (
                SubpacketData::Trust { level, amount },
                format!("level={}, amount={}", level, amount),
            )
        }
        7 => {
            let revocable = stream.octet()? != 0;
            (SubpacketData::Revocable(revocable), revocable.to_string())
        }
        9 => {
            let time = stream.uint32()?;
            (
                SubpacketData::KeyExpirationTime(time),
                format_duration(time),
            )
        }
        11 => {
            let prefs = stream.rest();
            let names: Vec<String> = prefs
                .iter()
                .map(|&id| lookup_symmetric_algorithm(id).name)
                .collect();
            (SubpacketData::PreferredSymmetric(prefs), names.join(", "))
        }
        12 => {
            let class = stream.octet()?;
            let algo = stream.octet()?;
            let fingerprint = stream.hex(20)?;
            let algo_name = lookup_public_key_algorithm(algo).name;
            (
                SubpacketData::RevocationKey {
                    class,
                    algo,
                    fingerprint: fingerprint.clone(),
                },
                format!("{} ({})", fingerprint, algo_name),
            )
        }
        16 => {
            let key_id = stream.hex(8)?;
            (SubpacketData::IssuerKeyId(key_id.clone()), key_id)
        }
        20 => {
            let flags = stream.uint32()?;
            let name_len = stream.uint16()? as usize;
            let value_len = stream.uint16()? as usize;
            let name = stream.utf8(name_len)?;
            let value = if flags & 0x80000000 != 0 {
                stream.utf8(value_len)?
            } else {
                stream.hex(value_len)?
            };
            let display = format!("{}={}", name, value);
            (SubpacketData::NotationData { name, value }, display)
        }
        21 => {
            let prefs = stream.rest();
            let names: Vec<String> = prefs
                .iter()
                .map(|&id| lookup_hash_algorithm(id).name)
                .collect();
            (SubpacketData::PreferredHash(prefs), names.join(", "))
        }
        22 => {
            let prefs = stream.rest();
            let names: Vec<String> = prefs
                .iter()
                .map(|&id| lookup_compression_algorithm(id).name)
                .collect();
            (SubpacketData::PreferredCompression(prefs), names.join(", "))
        }
        23 => {
            let prefs = stream.rest();
            (
                SubpacketData::KeyServerPreferences(prefs.clone()),
                format!("{} bytes", prefs.len()),
            )
        }
        24 => {
            let server = stream.utf8(stream.remaining())?;
            (SubpacketData::PreferredKeyServer(server.clone()), server)
        }
        25 => {
            let primary = stream.octet()? != 0;
            (SubpacketData::PrimaryUserId(primary), primary.to_string())
        }
        26 => {
            let uri = stream.utf8(stream.remaining())?;
            (SubpacketData::PolicyUri(uri.clone()), uri)
        }
        27 => {
            let flags_data = stream.rest();
            let flags = if !flags_data.is_empty() {
                flags_data[0]
            } else {
                0
            };
            let flag_names = lookup_key_flags(flags);
            (SubpacketData::KeyFlags(flags_data), flag_names.join(", "))
        }
        28 => {
            let user_id = stream.utf8(stream.remaining())?;
            (SubpacketData::SignerUserId(user_id.clone()), user_id)
        }
        29 => {
            let code = stream.octet()?;
            let reason = stream.utf8(stream.remaining())?;
            let code_name = lookup_revocation_reason(code);
            (
                SubpacketData::RevocationReason {
                    code,
                    reason: reason.clone(),
                },
                format!("{}: {}", code_name, reason),
            )
        }
        30 => {
            let features = stream.rest();
            let mut feat_names = Vec::new();
            if !features.is_empty() {
                if features[0] & 0x01 != 0 {
                    feat_names.push("Modification Detection");
                }
                if features[0] & 0x02 != 0 {
                    feat_names.push("AEAD");
                }
                if features[0] & 0x04 != 0 {
                    feat_names.push("Version 5 Public Keys");
                }
            }
            (SubpacketData::Features(features), feat_names.join(", "))
        }
        31 => {
            let algo = stream.octet()?;
            let hash_algo = stream.octet()?;
            let hash = stream.rest_as_hex();
            let algo_name = lookup_public_key_algorithm(algo).name;
            let hash_name = lookup_hash_algorithm(hash_algo).name;
            (
                SubpacketData::SignatureTarget {
                    algo,
                    hash_algo,
                    hash: hash.clone(),
                },
                format!("{}/{}: {}", algo_name, hash_name, hash),
            )
        }
        32 => {
            let sig_data = stream.rest();
            (
                SubpacketData::EmbeddedSignature(sig_data.clone()),
                format!("{} bytes", sig_data.len()),
            )
        }
        33 => {
            let version = stream.octet()?;
            let fp_len = if version == 4 { 20 } else { 32 };
            let fingerprint = stream.hex(fp_len.min(stream.remaining()))?;
            (
                SubpacketData::IssuerFingerprint {
                    version,
                    fingerprint: fingerprint.clone(),
                },
                format!("v{}: {}", version, fingerprint),
            )
        }
        34 => {
            let prefs = stream.rest();
            (
                SubpacketData::PreferredAead(prefs.clone()),
                format!("{} algorithms", prefs.len()),
            )
        }
        35 => {
            let version = stream.octet()?;
            let fp_len = if version == 4 { 20 } else { 32 };
            let fingerprint = stream.hex(fp_len.min(stream.remaining()))?;
            (
                SubpacketData::IntendedRecipient {
                    version,
                    fingerprint: fingerprint.clone(),
                },
                format!("v{}: {}", version, fingerprint),
            )
        }
        _ => {
            let data = stream.rest();
            (
                SubpacketData::Unknown(data.clone()),
                format!("{} bytes", data.len()),
            )
        }
    };

    Ok((data, value))
}

fn format_duration(seconds: u32) -> String {
    if seconds == 0 {
        return "never expires".to_string();
    }

    let days = seconds / 86400;
    let years = days / 365;

    if years > 0 {
        format!("{} years", years)
    } else if days > 0 {
        format!("{} days", days)
    } else {
        format!("{} seconds", seconds)
    }
}
