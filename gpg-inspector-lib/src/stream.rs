use std::sync::Arc;

use crate::error::{Error, Result};

#[derive(Clone)]
pub struct ByteStream {
    bytes: Arc<[u8]>,
    start: usize,
    end: usize,
    pos: usize,
}

impl ByteStream {
    pub fn new(bytes: Vec<u8>) -> Self {
        let end = bytes.len();
        Self {
            bytes: bytes.into(),
            start: 0,
            end,
            pos: 0,
        }
    }

    pub fn from_arc(bytes: Arc<[u8]>) -> Self {
        let end = bytes.len();
        Self {
            bytes,
            start: 0,
            end,
            pos: 0,
        }
    }

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

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn abs_pos(&self) -> usize {
        self.start + self.pos
    }

    pub fn remaining(&self) -> usize {
        self.end.saturating_sub(self.start + self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn octet(&mut self) -> Result<u8> {
        if self.start + self.pos >= self.end {
            return Err(Error::UnexpectedEnd(self.abs_pos()));
        }
        let byte = self.bytes[self.start + self.pos];
        self.pos += 1;
        Ok(byte)
    }

    pub fn peek(&self) -> Option<u8> {
        if self.start + self.pos >= self.end {
            None
        } else {
            Some(self.bytes[self.start + self.pos])
        }
    }

    pub fn uint16(&mut self) -> Result<u16> {
        let b1 = self.octet()? as u16;
        let b2 = self.octet()? as u16;
        Ok((b1 << 8) | b2)
    }

    pub fn uint32(&mut self) -> Result<u32> {
        let b1 = self.octet()? as u32;
        let b2 = self.octet()? as u32;
        let b3 = self.octet()? as u32;
        let b4 = self.octet()? as u32;
        Ok((b1 << 24) | (b2 << 16) | (b3 << 8) | b4)
    }

    pub fn bytes(&mut self, count: usize) -> Result<Vec<u8>> {
        if self.remaining() < count {
            return Err(Error::UnexpectedEnd(self.abs_pos()));
        }
        let start = self.start + self.pos;
        let result = self.bytes[start..start + count].to_vec();
        self.pos += count;
        Ok(result)
    }

    pub fn hex(&mut self, count: usize) -> Result<String> {
        let bytes = self.bytes(count)?;
        Ok(bytes.iter().map(|b| format!("{:02X}", b)).collect())
    }

    pub fn utf8(&mut self, count: usize) -> Result<String> {
        let bytes = self.bytes(count)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub fn rest(&mut self) -> Vec<u8> {
        let start = self.start + self.pos;
        let result = self.bytes[start..self.end].to_vec();
        self.pos = self.end - self.start;
        result
    }

    pub fn rest_as_hex(&mut self) -> String {
        let bytes = self.rest();
        bytes.iter().map(|b| format!("{:02X}", b)).collect()
    }

    pub fn multi_precision_integer(&mut self) -> Result<(u16, String)> {
        let bit_length = self.uint16()?;
        let byte_length = bit_length.div_ceil(8) as usize;
        let hex = self.hex(byte_length)?;
        Ok((bit_length, hex))
    }

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

    pub fn skip(&mut self, count: usize) -> Result<()> {
        if self.remaining() < count {
            return Err(Error::UnexpectedEnd(self.abs_pos()));
        }
        self.pos += count;
        Ok(())
    }

    pub fn all_bytes(&self) -> &[u8] {
        &self.bytes[self.start..self.end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_reads() {
        let mut stream = ByteStream::new(vec![0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(stream.octet().unwrap(), 0x01);
        assert_eq!(stream.uint16().unwrap(), 0x0203);
        assert_eq!(stream.remaining(), 2);
    }

    #[test]
    fn test_slice() {
        let stream = ByteStream::new(vec![0x00, 0x01, 0x02, 0x03, 0x04]);
        let mut sliced = stream.slice(1, 4);
        assert_eq!(sliced.len(), 3);
        assert_eq!(sliced.octet().unwrap(), 0x01);
        assert_eq!(sliced.abs_pos(), 2);
    }

    #[test]
    fn test_variable_length() {
        let mut stream = ByteStream::new(vec![0x40]);
        assert_eq!(stream.variable_length().unwrap(), 64);

        let mut stream = ByteStream::new(vec![0xC0, 0x00]);
        assert_eq!(stream.variable_length().unwrap(), 192);
    }

    #[test]
    fn test_mpi() {
        let mut stream = ByteStream::new(vec![0x00, 0x11, 0xAB, 0xCD, 0xEF]);
        let (bits, hex) = stream.multi_precision_integer().unwrap();
        assert_eq!(bits, 17);
        assert_eq!(hex, "ABCDEF");
    }
}
