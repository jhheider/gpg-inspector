pub mod pkesk;
pub mod public_key;
pub mod secret_key;
pub mod seipd;
pub mod signature;
pub mod subpackets;
pub mod tags;
pub mod user_id;

use std::sync::Arc;

use crate::color::ColorTracker;
use crate::error::{Error, Result};
use crate::stream::ByteStream;
use tags::PacketTag;

/// A field with its name, value, byte span, color, and indent level for hierarchy display
#[derive(Debug, Clone)]
pub struct Field {
    pub name: Arc<str>,
    pub value: Arc<str>,
    pub indent: u8,
    pub span: (usize, usize),
    pub color: Option<u8>, // None = white (header)
}

impl Field {
    pub fn new(
        name: impl Into<Arc<str>>,
        value: impl Into<Arc<str>>,
        indent: u8,
        span: (usize, usize),
        color: Option<u8>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            indent,
            span,
            color,
        }
    }

    pub fn packet(
        name: impl Into<Arc<str>>,
        value: impl Into<Arc<str>>,
        span: (usize, usize),
    ) -> Self {
        Self::new(name, value, 0, span, None)
    }

    #[allow(clippy::self_named_constructors)]
    pub fn field(
        name: impl Into<Arc<str>>,
        value: impl Into<Arc<str>>,
        span: (usize, usize),
        color: u8,
    ) -> Self {
        Self::new(name, value, 1, span, Some(color))
    }

    pub fn subfield(
        name: impl Into<Arc<str>>,
        value: impl Into<Arc<str>>,
        span: (usize, usize),
        color: u8,
    ) -> Self {
        Self::new(name, value, 2, span, Some(color))
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub start: usize,
    pub end: usize,
    pub tag: PacketTag,
    pub body: PacketBody,
    pub colors: ColorTracker,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone)]
pub enum PacketBody {
    PublicKey(public_key::PublicKeyPacket),
    PublicSubkey(public_key::PublicKeyPacket),
    SecretKey(secret_key::SecretKeyPacket),
    SecretSubkey(secret_key::SecretKeyPacket),
    UserId(user_id::UserIdPacket),
    Signature(signature::SignaturePacket),
    Pkesk(pkesk::PkeskPacket),
    Seipd(seipd::SeipdPacket),
    Unknown(Vec<u8>),
}

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
    let mut colors = ColorTracker::new(stream.remaining() + packet_start);
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
    colors.set_header(header_start, header_end);
    fields.push(Field::packet(
        packet_name,
        format!("{} bytes", body_length),
        (header_start, header_end),
    ));

    let body_start = stream.abs_pos();
    let mut body_stream = stream.slice(stream.pos(), stream.pos() + body_length);
    stream.skip(body_length)?;
    let packet_end = stream.abs_pos();

    let body = parse_packet_body(tag, &mut body_stream, &mut colors, &mut fields, body_start)?;

    colors.byte_colors.truncate(packet_end);

    Ok(Packet {
        start: packet_start,
        end: packet_end,
        tag,
        body,
        colors,
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
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    body_offset: usize,
) -> Result<PacketBody> {
    match tag {
        PacketTag::PublicKey => {
            let pk = public_key::parse_public_key(stream, colors, fields, body_offset)?;
            Ok(PacketBody::PublicKey(pk))
        }
        PacketTag::PublicSubkey => {
            let pk = public_key::parse_public_key(stream, colors, fields, body_offset)?;
            Ok(PacketBody::PublicSubkey(pk))
        }
        PacketTag::SecretKey => {
            let sk = secret_key::parse_secret_key(stream, colors, fields, body_offset)?;
            Ok(PacketBody::SecretKey(sk))
        }
        PacketTag::SecretSubkey => {
            let sk = secret_key::parse_secret_key(stream, colors, fields, body_offset)?;
            Ok(PacketBody::SecretSubkey(sk))
        }
        PacketTag::UserId => {
            let uid = user_id::parse_user_id(stream, colors, fields, body_offset)?;
            Ok(PacketBody::UserId(uid))
        }
        PacketTag::Signature => {
            let sig = signature::parse_signature(stream, colors, fields, body_offset)?;
            Ok(PacketBody::Signature(sig))
        }
        PacketTag::PublicKeyEncryptedSessionKey => {
            let pkesk = pkesk::parse_pkesk(stream, colors, fields, body_offset)?;
            Ok(PacketBody::Pkesk(pkesk))
        }
        PacketTag::SymmetricallyEncryptedIntegrityProtectedData => {
            let seipd = seipd::parse_seipd(stream, colors, fields, body_offset)?;
            Ok(PacketBody::Seipd(seipd))
        }
        _ => {
            let data = stream.rest();
            if !data.is_empty() {
                let data_start = body_offset + stream.pos() - data.len();
                let data_end = body_offset + stream.pos();
                let color = colors.set_field(data_start, data_end);
                fields.push(Field::field(
                    "Data",
                    format!("{} bytes", data.len()),
                    (data_start, data_end),
                    color,
                ));
            }
            Ok(PacketBody::Unknown(data))
        }
    }
}
