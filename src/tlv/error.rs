/*
 *     Copyright 2025 The Dragonfly Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::error::{Error as VortexError, Result};
use crate::tlv::Tag;
use crate::Message;
use bytes::BufMut;

/// The size of the error code in bytes.
const CODE_SIZE: usize = 1;

/// The error code.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// Unknown error.
    Unknown = 0,

    /// Invalid argument, such as an invalid task ID or piece number.
    InvalidArgument = 1,

    /// Resource not found, such as a missing piece.
    NotFound = 2,

    /// Internal error, such as an unexpected error.
    Internal = 3,

    /// Reserved for future use, for codes 4-255.
    Reserved(u8),
}

/// Implements the conversion from the wire byte.
impl From<u8> for Code {
    /// Converts the wire byte into the code.
    fn from(value: u8) -> Self {
        match value {
            0 => Code::Unknown,
            1 => Code::InvalidArgument,
            2 => Code::NotFound,
            3 => Code::Internal,
            4..=255 => Code::Reserved(value),
        }
    }
}

/// Implements the conversion into the wire byte.
impl From<Code> for u8 {
    /// Converts the code into the wire byte.
    fn from(code: Code) -> u8 {
        match code {
            Code::Unknown => 0,
            Code::InvalidArgument => 1,
            Code::NotFound => 2,
            Code::Internal => 3,
            Code::Reserved(value) => value,
        }
    }
}

/// The error message.
///
/// ```text
/// -------------------------------------------------
/// | Error Code (1 bytes) |      Error Message      |
/// -------------------------------------------------
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// The error code.
    pub code: Code,

    /// The human-readable error message.
    pub message: String,
}

/// Implements the error message.
impl Error {
    /// Creates an error message.
    pub fn new(code: Code, message: String) -> Self {
        Self { code, message }
    }
}

/// Implements the packet value.
impl Message for Error {
    /// The tag of the packets carrying the error message.
    const TAG: Tag = Tag::Error;

    /// Returns the encoded length of the error message.
    fn encoded_len(&self) -> usize {
        CODE_SIZE + self.message.len()
    }

    /// Appends the encoded error message to the buffer.
    fn encode(&self, buffer: &mut impl BufMut) {
        buffer.put_u8(self.code.into());
        buffer.put_slice(self.message.as_bytes());
    }

    /// Decodes the error message from the value of a packet.
    fn decode(buffer: &[u8]) -> Result<Self> {
        let (code, message) = buffer.split_first().ok_or_else(|| {
            VortexError::InvalidLength(format!(
                "expected at least {CODE_SIZE} bytes for Error, got {}",
                buffer.len()
            ))
        })?;

        Ok(Self {
            code: Code::from(*code),
            message: String::from_utf8(message.to_vec())?,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;
    use bytes::BytesMut;

    #[test]
    fn code_converts_from_and_into_every_range() {
        let test_cases = vec![
            (0, Code::Unknown),
            (1, Code::InvalidArgument),
            (2, Code::NotFound),
            (3, Code::Internal),
            (4, Code::Reserved(4)),
            (255, Code::Reserved(255)),
        ];

        for (value, code) in test_cases {
            assert_eq!(Code::from(value), code);
            assert_eq!(u8::from(code), value);
        }
    }

    #[test]
    fn encode_writes_the_wire_layout() {
        let error = Error::new(Code::Internal, "boom".to_string());
        let mut buffer = BytesMut::new();
        error.encode(&mut buffer);

        assert_eq!(buffer.len(), error.encoded_len());
        assert_eq!(buffer[0], 3);
        assert_eq!(&buffer[CODE_SIZE..], b"boom");
    }

    #[test]
    fn decode_roundtrips() {
        let test_cases = vec![
            Error::new(Code::NotFound, "piece not found".to_string()),
            Error::new(Code::Reserved(200), String::new()),
        ];

        for error in test_cases {
            let mut buffer = BytesMut::new();
            error.encode(&mut buffer);
            assert_eq!(Error::decode(&buffer).unwrap(), error);
        }
    }

    #[test]
    fn decode_rejects_malformed_input() {
        let test_cases: Vec<(&[u8], fn(Result<Error>))> = vec![
            (&[], |result| {
                assert!(matches!(result, Err(VortexError::InvalidLength(_))))
            }),
            (&[3, 0xFF], |result| {
                assert!(matches!(result, Err(VortexError::FromUtf8Error(_))))
            }),
        ];

        for (buffer, expect) in test_cases {
            expect(Error::decode(buffer));
        }
    }
}
