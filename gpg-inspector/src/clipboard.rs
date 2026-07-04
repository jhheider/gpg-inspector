//! Clipboard support via the OSC 52 escape sequence.
//!
//! OSC 52 asks the terminal emulator itself to set the clipboard, so
//! it needs no native dependencies and works over SSH and inside tmux
//! (`set-clipboard on`). Terminals that don't support it silently
//! ignore the sequence.

/// Copy payloads are truncated to this size: many terminals cap OSC 52
/// around 100 KB, and oversized sequences can be dropped entirely.
pub const MAX_COPY_BYTES: usize = 64 * 1024;
const _: () = assert!(MAX_COPY_BYTES <= 100 * 1024);

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (hand-rolled to match the crate's
/// dependency-free armor handling).
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(BASE64_CHARS[(n >> 18) as usize & 63] as char);
        out.push(BASE64_CHARS[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            BASE64_CHARS[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64_CHARS[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// The OSC 52 sequence that sets the system clipboard to `payload`.
pub fn osc52_sequence(payload: &[u8]) -> String {
    format!("\x1b]52;c;{}\x07", base64_encode(payload))
}

/// Writes the OSC 52 sequence to the terminal.
#[cfg(not(tarpaulin_include))]
pub fn copy(payload: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut stdout = std::io::stdout();
    stdout.write_all(osc52_sequence(payload).as_bytes())?;
    stdout.flush()
}
