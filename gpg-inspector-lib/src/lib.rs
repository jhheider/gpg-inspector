pub mod armor;
pub mod color;
pub mod error;
pub mod lookup;
pub mod packet;
pub mod stream;

use std::sync::Arc;

pub use armor::{ArmorResult, decode_armor};
pub use color::{ColorTracker, PALETTE};
pub use error::{Error, Result};
pub use packet::{Field, Packet, PacketBody};
pub use stream::ByteStream;

pub fn parse(input: &str) -> Result<Vec<Packet>> {
    let armor_result = decode_armor(input)?;
    packet::parse_packets(armor_result.bytes)
}

pub fn parse_bytes(bytes: impl Into<Arc<[u8]>>) -> Result<Vec<Packet>> {
    packet::parse_packets(bytes.into())
}
