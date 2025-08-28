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

use crate::error::{Error as VortexError, Result as VortexResult};
use bytes::{BufMut, Bytes, BytesMut};

/// CODE_SIZE is the size of the error code in bytes.
const CODE_SIZE: usize = 1;

/// Code represents a error code.
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

    /// Reserved for future use.
    Reserved(u8), // For tags 4-253
}

/// Implement TryFrom<u8> for Code.
impl TryFrom<u8> for Code {
    type Error = VortexError;

    /// Converts a u8 to a Code enum.
    fn try_from(value: u8) -> VortexResult<Self> {
        match value {
            0 => Ok(Code::Unknown),
            1 => Ok(Code::InvalidArgument),
            2 => Ok(Code::NotFound),
            3 => Ok(Code::Internal),
            4..=255 => Ok(Code::Reserved(value)),
        }
    }
}

/// Implement From<Code> for u8.
impl From<Code> for u8 {
    /// Converts a Code enum to a u8.
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

/// Error represents a error request.
///
/// Value Format:
///  - Error Code (1 bytes): Error code.
///  - Error Message (variable): Error message.
///
/// ```text
/// -------------------------------------------------
/// | Error Code (1 bytes) |      Error Message      |
/// -------------------------------------------------
/// ```
#[derive(Debug, Clone)]
pub struct Error {
    code: Code,
    message: String,
}

/// Error implements the Error functions.
impl Error {
    /// new creates a new Error request.
    pub fn new(code: Code, message: String) -> Self {
        Self { code, message }
    }

    /// code returns the error code.
    pub fn code(&self) -> Code {
        self.code
    }

    /// message returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// len returns the length of the error request, including the error code, error
    /// message.
    pub fn len(&self) -> usize {
        self.message.len() + CODE_SIZE
    }

    /// is_empty returns whether the error request is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Implement From<Error> for Bytes.
impl From<Error> for Bytes {
    /// from converts the error request to a byte slice.
    fn from(err: Error) -> Self {
        let mut bytes = BytesMut::with_capacity(err.len());
        bytes.put_u8(err.code.into());
        bytes.extend_from_slice(err.message.as_bytes());
        bytes.freeze()
    }
}

/// Implement TryFrom<Bytes> for Error.
impl TryFrom<Bytes> for Error {
    type Error = VortexError;

    /// try_from decodes the error request from the byte slice.
    fn try_from(bytes: Bytes) -> VortexResult<Self> {
        if bytes.len() < CODE_SIZE {
            return Err(VortexError::InvalidLength(format!(
                "expected at least {} bytes for Error, got {}",
                CODE_SIZE,
                bytes.len()
            )));
        }

        Ok(Error {
            code: Code::try_from(bytes[0])?,
            message: String::from_utf8(bytes[CODE_SIZE..].to_vec())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_new() {
        let code = Code::InvalidArgument;
        let message = "Invalid argument".to_string();
        let error = Error::new(code, message.clone());

        assert_eq!(error.code(), code);
        assert_eq!(error.message(), message);
        assert_eq!(error.len(), message.len() + CODE_SIZE);
    }

    #[test]
    fn test_is_non_empty() {
        let error_non_empty = Error::new(Code::Unknown, "Error message".to_string());
        assert!(!error_non_empty.is_empty());
    }

    #[test]
    fn test_to_bytes_and_from_bytes() {
        let code = Code::NotFound;
        let message = "Resource not found".to_string();
        let error = Error::new(code, message.clone());

        let bytes: Bytes = error.into();
        let error = Error::try_from(bytes).unwrap();

        assert_eq!(error.code(), code);
        assert_eq!(error.message(), message);
    }

    #[test]
    fn test_from_bytes_invalid_input() {
        let invalid_bytes = Bytes::from("");
        assert!(Error::try_from(invalid_bytes).is_err());
    }
}
