use crate::color::ColorTracker;
use crate::error::Result;
use crate::packet::Field;
use crate::stream::ByteStream;

#[derive(Debug, Clone)]
pub struct UserIdPacket {
    pub user_id: String,
}

pub fn parse_user_id(
    stream: &mut ByteStream,
    colors: &mut ColorTracker,
    fields: &mut Vec<Field>,
    offset: usize,
) -> Result<UserIdPacket> {
    let start = offset + stream.pos();
    let user_id = stream.utf8(stream.remaining())?;
    let end = offset + stream.pos();

    let color = colors.set_field(start, end);
    fields.push(Field::field(
        "User ID",
        user_id.clone(),
        (start, end),
        color,
    ));

    Ok(UserIdPacket { user_id })
}
