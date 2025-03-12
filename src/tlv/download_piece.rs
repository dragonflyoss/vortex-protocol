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

use crate::error::{Error, Result};
use bytes::{BufMut, Bytes, BytesMut};
use std::convert::TryFrom;

/// SEPARATOR is the separator character used in the download piece request, separating the task ID
/// and piece number. It is a hyphen character '-'.
const SEPARATOR: u8 = b'-';

/// DOWNLOAD_PIECE_SIZE is the size of the download piece request, including the task ID, separator,
/// and piece number.
const DOWNLOAD_PIECE_SIZE: usize = 32 + 1 + 4;

/// DownloadPiece represents a download piece request.
///
/// Value Format:
///   - Task ID (32 bytes): SHA-256 hash of the task ID.
///   - Separator (1 byte): Separator character '-'.
///   - Piece Number (4 bytes): Piece number to download.
///
/// ```text
/// --------------------------------------------------------------------
/// | Task ID (32 bytes) | Separator (1 byte) | Piece Number (4 bytes) |
/// --------------------------------------------------------------------
/// ```
#[derive(Debug, Clone)]
pub struct DownloadPiece {
    task_id: String,
    piece_number: u32,
}

/// DownloadPiece implements the DownloadPiece functions.
impl DownloadPiece {
    /// new creates a new DownloadPiece request.
    pub fn new(task_id: String, piece_number: u32) -> Self {
        DownloadPiece {
            task_id,
            piece_number,
        }
    }

    /// task_id returns the task ID.
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    /// piece_number returns the piece number.
    pub fn piece_number(&self) -> u32 {
        self.piece_number
    }

    /// len returns the length of the download piece request.
    pub fn len(&self) -> usize {
        DOWNLOAD_PIECE_SIZE
    }

    /// is_empty returns whether the download piece request is empty.
    pub fn is_empty(&self) -> bool {
        self.task_id.is_empty()
    }
}

/// Implement TryFrom<Bytes> for DownloadPiece for conversion from a byte slice.
impl TryFrom<Bytes> for DownloadPiece {
    type Error = Error;

    /// try_from decodes the download piece request from the byte slice.
    fn try_from(bytes: Bytes) -> Result<Self> {
        let mut parts = bytes.splitn(2, |&b| b == SEPARATOR);
        let task_id = std::str::from_utf8(
            parts
                .next()
                .ok_or(Error::InvalidPacket("missing task id".to_string()))?,
        )?
        .to_string();

        let piece_number: u32 = std::str::from_utf8(
            parts
                .next()
                .ok_or(Error::InvalidPacket("missing piece number".to_string()))?,
        )?
        .trim()
        .parse()?;

        Ok(DownloadPiece {
            task_id,
            piece_number,
        })
    }
}

/// Implement From<DownloadPiece> for Bytes for conversion to a byte slice.
impl From<DownloadPiece> for Bytes {
    /// from converts the download piece request to a byte slice.
    fn from(piece: DownloadPiece) -> Self {
        let mut bytes = BytesMut::with_capacity(DOWNLOAD_PIECE_SIZE);
        bytes.extend_from_slice(piece.task_id.as_bytes());
        bytes.put_u8(SEPARATOR);
        bytes.extend_from_slice(piece.piece_number.to_string().as_bytes());
        bytes.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_new() {
        let task_id = "a".repeat(32);
        let piece_number = 42;
        let download_piece = DownloadPiece::new(task_id.clone(), piece_number);

        assert_eq!(download_piece.task_id(), task_id);
        assert_eq!(download_piece.piece_number(), piece_number);
        assert_eq!(download_piece.len(), DOWNLOAD_PIECE_SIZE);
    }

    #[test]
    fn test_is_empty() {
        let download_piece_empty = DownloadPiece::new("".to_string(), 0);
        let download_piece_non_empty = DownloadPiece::new("a".repeat(32), 1);

        assert!(download_piece_empty.is_empty());
        assert!(!download_piece_non_empty.is_empty());
    }

    #[test]
    fn test_valid_conversion() {
        let task_id = "a".repeat(32);
        let piece_number = 42;
        let download_piece = DownloadPiece::new(task_id.clone(), piece_number);

        let bytes: Bytes = download_piece.into();
        let download_piece = DownloadPiece::try_from(bytes).unwrap();

        assert_eq!(download_piece.task_id(), task_id);
        assert_eq!(download_piece.piece_number(), piece_number);
    }

    #[test]
    fn test_invalid_conversion() {
        // Test missing separator.
        let invalid_bytes = Bytes::from("invalid_input_without_separator");
        let result = DownloadPiece::try_from(invalid_bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidPacket(_)));

        // Test missing piece number.
        let invalid_bytes = Bytes::from("task_id-");
        let result = DownloadPiece::try_from(invalid_bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::ParseIntError(_)));

        // Test invalid piece number.
        let invalid_bytes = Bytes::from("task_id-invalid");
        let result = DownloadPiece::try_from(invalid_bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::ParseIntError(_)));
    }
}
