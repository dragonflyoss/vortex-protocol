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

/// TASK_ID_SIZE is the size of the task ID in bytes.
pub const TASK_ID_SIZE: usize = 64;

/// PIECE_NUMBER_SIZE is the size of the piece number in bytes.
pub const PIECE_NUMBER_SIZE: usize = 4;

/// DownloadCachePiece represents a download cache piece request.
///
/// Value Format:
///   - Task ID (64 bytes): SHA-256 hash of the task ID.
///   - Piece Number (4 bytes): Piece number to download.
///
/// ```text
/// -----------------------------------------------
/// | Task ID (64 bytes) | Piece Number (4 bytes) |
/// -----------------------------------------------
/// ```
#[derive(Debug, Clone)]
pub struct DownloadCachePiece {
    task_id: String,
    piece_number: u32,
}

/// DownloadCachePiece implements the DownloadCachePiece functions.
impl DownloadCachePiece {
    /// new creates a new DownloadPiece request.
    pub fn new(task_id: String, piece_number: u32) -> Self {
        Self {
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

    /// len returns the length of the download cache piece request.
    pub fn len(&self) -> usize {
        TASK_ID_SIZE + PIECE_NUMBER_SIZE
    }

    /// is_empty returns whether the download cache piece request is empty.
    pub fn is_empty(&self) -> bool {
        self.task_id.is_empty()
    }
}

/// Implement TryFrom<Bytes> for DownloadCachePiece for conversion from a byte slice.
impl TryFrom<Bytes> for DownloadCachePiece {
    type Error = Error;

    /// try_from decodes the download cache piece request from the byte slice.
    fn try_from(bytes: Bytes) -> Result<Self> {
        if bytes.len() != TASK_ID_SIZE + PIECE_NUMBER_SIZE {
            return Err(Error::InvalidLength(format!(
                "expected {} bytes for DownloadCachePiece, got {}",
                TASK_ID_SIZE + PIECE_NUMBER_SIZE,
                bytes.len()
            )));
        }

        Ok(DownloadCachePiece {
            task_id: String::from_utf8(
                bytes
                    .get(..TASK_ID_SIZE)
                    .ok_or(Error::InvalidPacket(
                        "insufficient bytes for task id".to_string(),
                    ))?
                    .to_vec(),
            )?,
            piece_number: u32::from_be_bytes(
                bytes
                    .get(TASK_ID_SIZE..TASK_ID_SIZE + PIECE_NUMBER_SIZE)
                    .ok_or(Error::InvalidPacket(
                        "insufficient bytes for piece number".to_string(),
                    ))?
                    .try_into()?,
            ),
        })
    }
}

/// Implement From<DownloadCachePiece> for Bytes for conversion to a byte slice.
impl From<DownloadCachePiece> for Bytes {
    /// from converts the download piece request to a byte slice.
    fn from(piece: DownloadCachePiece) -> Self {
        let mut bytes = BytesMut::with_capacity(piece.len());
        bytes.extend_from_slice(piece.task_id.as_bytes());
        bytes.put_u32(piece.piece_number);
        bytes.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_new() {
        let task_id = "a".repeat(64);
        let piece_number = 42;
        let download_cache_piece = DownloadCachePiece::new(task_id.clone(), piece_number);

        assert_eq!(download_cache_piece.task_id(), task_id);
        assert_eq!(download_cache_piece.piece_number(), piece_number);
        assert_eq!(download_cache_piece.len(), TASK_ID_SIZE + PIECE_NUMBER_SIZE);
    }

    #[test]
    fn test_is_empty() {
        let download_cache_piece_empty = DownloadCachePiece::new("".to_string(), 0);
        let download_cache_piece_non_empty = DownloadCachePiece::new("a".repeat(32), 1);

        assert!(download_cache_piece_empty.is_empty());
        assert!(!download_cache_piece_non_empty.is_empty());
    }

    #[test]
    fn test_valid_conversion() {
        let task_id = "a".repeat(64);
        let piece_number = 42;
        let download_cache_piece = DownloadCachePiece::new(task_id.clone(), piece_number);

        let bytes: Bytes = download_cache_piece.into();
        let download_cache_piece = DownloadCachePiece::try_from(bytes).unwrap();

        assert_eq!(download_cache_piece.task_id(), task_id);
        assert_eq!(download_cache_piece.piece_number(), piece_number);
    }

    #[test]
    fn test_invalid_conversion() {
        let invalid_bytes =
            Bytes::from("c993dfb0ecfbe1b4e158891bafff709e5d29d3fcd522e09b183aeb5db1db50111111111");
        let result = DownloadCachePiece::try_from(invalid_bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidLength(_)));

        let invalid_bytes = Bytes::from("task_id");
        let result = DownloadCachePiece::try_from(invalid_bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidLength(_)));

        let invalid_bytes = Bytes::from("");
        let result = DownloadCachePiece::try_from(invalid_bytes);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidLength(_)));
    }
}
