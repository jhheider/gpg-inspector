//! User ID packet parsing.
//!
//! This module parses User ID packets (tag 13), which contain a UTF-8
//! string identifying the key owner. The typical format is
//! "Name (Comment) <email@example.com>".

use crate::error::Result;
use crate::packet::Field;
use crate::stream::ByteStream;

/// A parsed User ID packet.
///
/// Contains a single UTF-8 string identifying the key owner.
#[derive(Debug, Clone)]
pub struct UserIdPacket {
    /// The user ID string (typically "Name \<email\>").
    pub user_id: String,
}

/// Parses a User ID packet body.
pub fn parse_user_id(
    stream: &mut ByteStream,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<UserIdPacket> {
    let start = offset + stream.pos();
    let user_id = stream.utf8(stream.remaining())?;
    let end = offset + stream.pos();

    fields.push(Field::field("User ID", user_id.clone(), (start, end)));

    Ok(UserIdPacket { user_id })
}
