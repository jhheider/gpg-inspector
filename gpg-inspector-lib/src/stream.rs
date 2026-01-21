//! Binary stream reader for parsing GPG packet data.
//!
//! The [`ByteStream`] struct provides position-tracked reading of binary data
//! with support for slicing (creating sub-streams) and OpenPGP-specific
//! data formats like multi-precision integers and variable-length values.

use std::sync::Arc;

use crate::error::{Error, Result};

/// A position-tracked binary stream reader.
///
/// `ByteStream` wraps binary data and provides sequential reading operations
/// while tracking the current position. It supports creating slices (views)
/// into the data for parsing nested structures without copying.
///
/// # Design
///
/// The stream uses `Arc<[u8]>` internally, allowing cheap cloning and slicing
/// without data duplication. Position tracking is relative to the slice,
/// with `abs_pos()` providing the absolute position in the original data.
///
/// # Example
///
/// ```
/// use gpg_inspector_lib::ByteStream;
///
/// let data = vec![0x01, 0x02, 0x03, 0x04];
/// let mut stream = ByteStream::new(data);
///
/// assert_eq!(stream.octet().unwrap(), 0x01);
/// assert_eq!(stream.pos(), 1);
/// assert_eq!(stream.remaining(), 3);
/// ```
#[derive(Clone)]
pub struct ByteStream {
    bytes: Arc<[u8]>,
    start: usize,
    end: usize,
    pos: usize,
}

impl ByteStream {
    /// Creates a new stream from a vector of bytes.
    ///
    /// The stream will own the data and start reading from position 0.
    pub fn new(bytes: Vec<u8>) -> Self {
        let end = bytes.len();
        Self {
            bytes: bytes.into(),
            start: 0,
            end,
            pos: 0,
        }
    }

    /// Creates a new stream from an `Arc<[u8]>`.
    ///
    /// Useful when sharing the same data across multiple streams or
    /// when the data is already in an `Arc`.
    pub fn from_arc(bytes: Arc<[u8]>) -> Self {
        let end = bytes.len();
        Self {
            bytes,
            start: 0,
            end,
            pos: 0,
        }
    }

    /// Creates a slice (view) into this stream's data.
    ///
    /// The slice shares the underlying data but has its own position tracker
    /// starting at 0. The `start` and `end` parameters are relative to the
    /// current stream's bounds.
    ///
    /// This is useful for parsing nested packet structures where you want
    /// to limit reads to a specific byte range.
    pub fn slice(&self, start: usize, end: usize) -> Self {
        let abs_start = self.start + start;
        let abs_end = (self.start + end).min(self.end);
        Self {
            bytes: Arc::clone(&self.bytes),
            start: abs_start,
            end: abs_end,
            pos: 0,
        }
    }

    /// Returns the current position within this stream (relative to start).
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Returns the absolute position in the original data.
    ///
    /// For slices, this accounts for the slice's offset from the beginning
    /// of the original data.
    pub fn abs_pos(&self) -> usize {
        self.start + self.pos
    }

    /// Returns the number of bytes remaining to read.
    pub fn remaining(&self) -> usize {
        self.end.saturating_sub(self.start + self.pos)
    }

    /// Returns `true` if there are no more bytes to read.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Returns the total length of this stream (or slice).
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Reads a single byte and advances the position.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnexpectedEnd` if no bytes remain.
    pub fn octet(&mut self) -> Result<u8> {
        if self.start + self.pos >= self.end {
            return Err(Error::UnexpectedEnd(self.abs_pos()));
        }
        let byte = self.bytes[self.start + self.pos];
        self.pos += 1;
        Ok(byte)
    }

    /// Returns the next byte without advancing the position.
    ///
    /// Returns `None` if no bytes remain.
    pub fn peek(&self) -> Option<u8> {
        if self.start + self.pos >= self.end {
            None
        } else {
            Some(self.bytes[self.start + self.pos])
        }
    }

    /// Reads a big-endian 16-bit unsigned integer.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnexpectedEnd` if fewer than 2 bytes remain.
    pub fn uint16(&mut self) -> Result<u16> {
        let b1 = self.octet()? as u16;
        let b2 = self.octet()? as u16;
        Ok((b1 << 8) | b2)
    }

    /// Reads a big-endian 32-bit unsigned integer.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnexpectedEnd` if fewer than 4 bytes remain.
    pub fn uint32(&mut self) -> Result<u32> {
        let b1 = self.octet()? as u32;
        let b2 = self.octet()? as u32;
        let b3 = self.octet()? as u32;
        let b4 = self.octet()? as u32;
        Ok((b1 << 24) | (b2 << 16) | (b3 << 8) | b4)
    }

    /// Reads `count` bytes and returns them as a vector.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnexpectedEnd` if fewer than `count` bytes remain.
    pub fn bytes(&mut self, count: usize) -> Result<Vec<u8>> {
        if self.remaining() < count {
            return Err(Error::UnexpectedEnd(self.abs_pos()));
        }
        let start = self.start + self.pos;
        let result = self.bytes[start..start + count].to_vec();
        self.pos += count;
        Ok(result)
    }

    /// Reads `count` bytes and returns them as an uppercase hex string.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnexpectedEnd` if fewer than `count` bytes remain.
    pub fn hex(&mut self, count: usize) -> Result<String> {
        let bytes = self.bytes(count)?;
        Ok(bytes.iter().map(|b| format!("{:02X}", b)).collect())
    }

    /// Reads `count` bytes and interprets them as UTF-8.
    ///
    /// Invalid UTF-8 sequences are replaced with the Unicode replacement character.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnexpectedEnd` if fewer than `count` bytes remain.
    pub fn utf8(&mut self, count: usize) -> Result<String> {
        let bytes = self.bytes(count)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Reads all remaining bytes and returns them as a vector.
    ///
    /// After this call, `remaining()` will return 0.
    pub fn rest(&mut self) -> Vec<u8> {
        let start = self.start + self.pos;
        let result = self.bytes[start..self.end].to_vec();
        self.pos = self.end - self.start;
        result
    }

    /// Reads all remaining bytes and returns them as an uppercase hex string.
    pub fn rest_as_hex(&mut self) -> String {
        let bytes = self.rest();
        bytes.iter().map(|b| format!("{:02X}", b)).collect()
    }

    /// Reads an OpenPGP Multi-Precision Integer (MPI).
    ///
    /// MPIs are stored as a 16-bit big-endian bit count followed by
    /// the integer bytes (big-endian, minimum length for the value).
    ///
    /// Returns the bit length and the value as a hex string.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnexpectedEnd` if the data is truncated.
    pub fn multi_precision_integer(&mut self) -> Result<(u16, String)> {
        let bit_length = self.uint16()?;
        let byte_length = bit_length.div_ceil(8) as usize;
        let hex = self.hex(byte_length)?;
        Ok((bit_length, hex))
    }

    /// Reads an OpenPGP variable-length value.
    ///
    /// This is the new-format packet length encoding:
    /// - 0-191: one byte, literal value
    /// - 192-254: two bytes, `((first - 192) << 8) + second + 192`
    /// - 255: five bytes, 32-bit big-endian length
    ///
    /// # Errors
    ///
    /// Returns `Error::UnexpectedEnd` if the data is truncated.
    pub fn variable_length(&mut self) -> Result<usize> {
        let first = self.octet()? as usize;
        if first < 192 {
            Ok(first)
        } else if first < 255 {
            let second = self.octet()? as usize;
            Ok(((first - 192) << 8) + second + 192)
        } else {
            Ok(self.uint32()? as usize)
        }
    }

    /// Skips `count` bytes without returning them.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnexpectedEnd` if fewer than `count` bytes remain.
    pub fn skip(&mut self, count: usize) -> Result<()> {
        if self.remaining() < count {
            return Err(Error::UnexpectedEnd(self.abs_pos()));
        }
        self.pos += count;
        Ok(())
    }

    /// Returns a reference to all bytes in this stream's range.
    ///
    /// Unlike `rest()`, this does not consume the bytes or advance the position.
    pub fn all_bytes(&self) -> &[u8] {
        &self.bytes[self.start..self.end]
    }
}
