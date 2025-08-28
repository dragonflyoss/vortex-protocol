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
use chrono::{DateTime, NaiveDateTime};
use std::convert::TryFrom;
use std::time::Duration;

/// METADATA_LENGTH_SIZE is the size of the metadata length in bytes.
pub const METADATA_LENGTH_SIZE: usize = 8;

/// NUMBER_SIZE is the size of the piece number in bytes.
const NUMBER_SIZE: usize = 4;

/// OFFSET_SIZE is the size of the offest in bytes.
const OFFSET_SIZE: usize = 8;

/// LENGTH_SIZE is the size of the length in bytes.
const LENGTH_SIZE: usize = 8;

/// DIGEST_SIZE is the size of the digest in bytes.
const DIGEST_SIZE: usize = 32;

/// TRAFFIC_TYPE_SIZE is the size of the traffic type in bytes.
const TRAFFIC_TYPE_SIZE: usize = 1;

/// COST_SIZE is the size of the cost in bytes.
const COST_SIZE: usize = 64;

/// CREATED_AT_SIZE is the size of the created at in bytes.
const CREATED_AT_SIZE: usize = 64;

/// PieceContent represents a piece metadata and piece content request.
///
/// Value Format:
///   - Metadata Length (8 bytes): Length of the metadata section.
///   - Number (4 bytes): Piece number to download.
///   - Offset (8 bytes): Byte offset in the file.
///   - Length (8 bytes): Length of the piece in bytes.
///   - Digest (32 bytes): CRC32 hash of the piece content.
///   - Parent ID (variable): Parent task identifier.
///   - Traffic Type (1 byte): Network traffic classification type.
///   - Cost (64 bytes): Download cost in seconds.
///   - Created At (8 bytes): Creation timestamp as Unix epoch seconds.
///   - Content (variable): Piece content bytes.
///
/// ```text
/// --------------------------------------------------------------------------------------------------------------------------------------------------------
/// | Metadata Length (8 bytes) | Number (4 bytes) |  Offset (8 bytes) |  Length (8 bytes) |  Digest (32 bytes) | Traffic Type (1 byte) |  Cost (64 bytes) |
/// --------------------------------------------------------------------------------------------------------------------------------------------------------
/// | Created At (64 bytes) | Parent ID (variable) | Content (variable) |
/// ---------------------------------------------------------------------
/// ```
#[derive(Debug, Clone)]
pub struct PieceContent {
    metadata_length: u64,
    metadata: PieceMetadata,
}

/// PieceContent implements the PieceContent functions.
impl PieceContent {
    /// new creates a new PieceContent request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        number: u32,
        offset: u64,
        length: u64,
        digest: String,
        parent_id: String,
        traffic_type: u8,
        cost: Duration,
        created_at: NaiveDateTime,
    ) -> Self {
        Self {
            metadata_length: (METADATA_LENGTH_SIZE
                + NUMBER_SIZE
                + OFFSET_SIZE
                + LENGTH_SIZE
                + DIGEST_SIZE
                + TRAFFIC_TYPE_SIZE
                + COST_SIZE
                + CREATED_AT_SIZE
                + parent_id.len()) as u64,
            metadata: PieceMetadata {
                number,
                offset,
                length,
                digest,
                parent_id,
                traffic_type,
                cost,
                created_at,
            },
        }
    }

    ///  metadata returns the piece metadata.
    pub fn metadata(&self) -> PieceMetadata {
        self.metadata.clone()
    }

    /// metadata_len returns the length of the metadata section.
    pub fn metadata_len(&self) -> u64 {
        self.metadata_length
    }

    /// is_empty returns whether the piece content request is empty.
    pub fn is_empty(&self) -> bool {
        self.metadata.length == 0
    }
}

/// PieceMetadata holds the metadata information for a piece.
#[derive(Debug, Clone)]
pub struct PieceMetadata {
    number: u32,
    offset: u64,
    length: u64,
    digest: String,
    parent_id: String,
    traffic_type: u8,
    cost: Duration,
    created_at: NaiveDateTime,
}

/// Implement TryFrom<Bytes> for PieceMetadata for conversion from a byte slice.
impl TryFrom<(Bytes, u32)> for PieceMetadata {
    type Error = Error;

    /// try_from decodes the piece metadata request from the byte slice.
    fn try_from(input: (Bytes, u32)) -> Result<Self> {
        let (bytes, length) = input;
        if bytes.len() != length as usize {
            return Err(Error::InvalidLength(format!(
                "expected {} bytes for PieceMetadata, got {}",
                length,
                bytes.len()
            )));
        }

        let mut bytes_offset = 0;
        let number =
            u32::from_be_bytes(bytes[bytes_offset..bytes_offset + NUMBER_SIZE].try_into()?);
        bytes_offset += NUMBER_SIZE;

        let offset =
            u64::from_be_bytes(bytes[bytes_offset..bytes_offset + OFFSET_SIZE].try_into()?);
        bytes_offset += OFFSET_SIZE;

        let length =
            u64::from_be_bytes(bytes[bytes_offset..bytes_offset + LENGTH_SIZE].try_into()?);
        bytes_offset += LENGTH_SIZE;

        let digest = String::from_utf8(bytes[bytes_offset..bytes_offset + DIGEST_SIZE].to_vec())?;
        bytes_offset += DIGEST_SIZE;

        let traffic_type = bytes[bytes_offset];
        bytes_offset += TRAFFIC_TYPE_SIZE;

        let cost = Duration::from_secs(u64::from_be_bytes(
            bytes[bytes_offset..bytes_offset + COST_SIZE].try_into()?,
        ));
        bytes_offset += COST_SIZE;

        let created_at = DateTime::from_timestamp(
            i64::from_be_bytes(bytes[bytes_offset..bytes_offset + CREATED_AT_SIZE].try_into()?),
            0,
        )
        .ok_or_else(|| Error::InvalidPacket("invalid timestamp for created_at".to_string()))?
        .naive_utc();
        bytes_offset += CREATED_AT_SIZE;

        let parent_id = String::from_utf8(bytes[bytes_offset..].to_vec())?;
        Ok(PieceMetadata {
            number,
            offset,
            length,
            digest,
            parent_id,
            traffic_type,
            cost,
            created_at,
        })
    }
}

/// Implement From<PieceMetadata> for Bytes for conversion to a byte slice.
impl From<PieceMetadata> for (Bytes, u32) {
    /// from converts the piece metadata request to a byte slice.
    fn from(metadata: PieceMetadata) -> (Bytes, u32) {
        let PieceMetadata {
            number,
            offset,
            length,
            digest,
            parent_id,
            traffic_type,
            cost,
            created_at,
        } = metadata;

        let parent_id = parent_id.as_bytes();
        let bytes_length = NUMBER_SIZE
            + OFFSET_SIZE
            + LENGTH_SIZE
            + DIGEST_SIZE
            + TRAFFIC_TYPE_SIZE
            + COST_SIZE
            + CREATED_AT_SIZE
            + parent_id.len();

        let mut bytes = BytesMut::with_capacity(bytes_length);
        bytes.put_u32(number);
        bytes.put_u64(offset);
        bytes.put_u64(length);
        bytes.extend_from_slice(digest.as_bytes());
        bytes.put_u8(traffic_type);
        bytes.put_u64(cost.as_secs());
        bytes.put_i64(created_at.and_utc().timestamp());
        bytes.extend_from_slice(parent_id);
        (bytes.freeze(), bytes_length as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::time::Duration;

    fn create_test_metadata() -> PieceMetadata {
        PieceMetadata {
            number: 42,
            offset: 1024,
            length: 2048,
            digest: "a".repeat(32),
            parent_id: "test_parent_id".to_string(),
            traffic_type: 1,
            cost: Duration::from_secs(5),
            created_at: DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        }
    }

    #[test]
    fn test_piece_content_new() {
        let piece_content = PieceContent::new(
            42,
            1024,
            2048,
            "a".repeat(32),
            "test_parent_id".to_string(),
            1,
            Duration::from_secs(5),
            DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        );

        assert_eq!(piece_content.metadata().number, 42);
        assert_eq!(piece_content.metadata().offset, 1024);
        assert_eq!(piece_content.metadata().length, 2048);
        assert_eq!(piece_content.metadata().digest, "a".repeat(32));
        assert_eq!(piece_content.metadata().parent_id, "test_parent_id");
        assert_eq!(piece_content.metadata().traffic_type, 1);
        assert_eq!(piece_content.metadata().cost, Duration::from_secs(5));
        assert_eq!(
            piece_content.metadata_len(),
            (METADATA_LENGTH_SIZE
                + NUMBER_SIZE
                + OFFSET_SIZE
                + LENGTH_SIZE
                + DIGEST_SIZE
                + TRAFFIC_TYPE_SIZE
                + COST_SIZE
                + CREATED_AT_SIZE
                + "test_parent_id".len()) as u64
        );
    }

    #[test]
    fn test_piece_content_is_empty() {
        let empty_piece = PieceContent::new(
            0,
            0,
            0,
            "a".repeat(32),
            "test".to_string(),
            0,
            Duration::from_secs(0),
            DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        );

        let non_empty_piece = PieceContent::new(
            1,
            0,
            100,
            "a".repeat(32),
            "test".to_string(),
            0,
            Duration::from_secs(0),
            DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        );

        assert!(empty_piece.is_empty());
        assert!(!non_empty_piece.is_empty());
    }

    #[test]
    fn test_piece_metadata_conversion_roundtrip() {
        let metadata = create_test_metadata();
        let (bytes, length) = <(Bytes, u32)>::from(metadata.clone());
        let result = PieceMetadata::try_from((bytes, length)).unwrap();

        assert_eq!(result.number, metadata.number);
        assert_eq!(result.offset, metadata.offset);
        assert_eq!(result.length, metadata.length);
        assert_eq!(result.digest, metadata.digest);
        assert_eq!(result.parent_id, metadata.parent_id);
        assert_eq!(result.traffic_type, metadata.traffic_type);
        assert_eq!(result.cost, metadata.cost);
        assert_eq!(result.created_at, metadata.created_at);
    }

    #[test]
    fn test_piece_metadata_try_from_invalid_length() {
        let metadata = create_test_metadata();
        let (bytes, correct_length) = <(Bytes, u32)>::from(metadata);
        let wrong_length = correct_length + 10;
        let result = PieceMetadata::try_from((bytes, wrong_length));

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidLength(_)));
    }

    #[test]
    fn test_piece_metadata_try_from_too_short_bytes() {
        let short_bytes = Bytes::from(vec![0u8; 10]);
        let result = PieceMetadata::try_from((short_bytes, 10));
        assert!(result.is_err());
    }

    #[test]
    fn test_piece_metadata_with_empty_parent_id() {
        let metadata = PieceMetadata {
            number: 1,
            offset: 0,
            length: 100,
            digest: "b".repeat(32),
            parent_id: String::new(),
            traffic_type: 2,
            cost: Duration::from_secs(1),
            created_at: DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        };

        let (bytes, length) = <(Bytes, u32)>::from(metadata.clone());
        let result = PieceMetadata::try_from((bytes, length)).unwrap();

        assert_eq!(result.parent_id, "");
        assert_eq!(result.number, 1);
        assert_eq!(result.traffic_type, 2);
    }

    #[test]
    fn test_piece_metadata_with_long_parent_id() {
        let long_parent_id = "x".repeat(1000); // Very long parent_id
        let metadata = PieceMetadata {
            number: 999,
            offset: 12345,
            length: 67890,
            digest: "c".repeat(32),
            parent_id: long_parent_id.clone(),
            traffic_type: 255,
            cost: Duration::from_secs(3600),
            created_at: DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        };

        let (bytes, length) = <(Bytes, u32)>::from(metadata.clone());
        let result = PieceMetadata::try_from((bytes, length)).unwrap();

        assert_eq!(result.parent_id, long_parent_id);
        assert_eq!(result.number, 999);
        assert_eq!(result.traffic_type, 255);
    }

    #[test]
    fn test_piece_metadata_with_zero_cost() {
        let metadata = PieceMetadata {
            number: 0,
            offset: 0,
            length: 0,
            digest: "d".repeat(32),
            parent_id: "zero_cost_test".to_string(),
            traffic_type: 0,
            cost: Duration::from_secs(0),
            created_at: DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        };

        let (bytes, length) = <(Bytes, u32)>::from(metadata.clone());
        let result = PieceMetadata::try_from((bytes, length)).unwrap();

        assert_eq!(result.cost, Duration::from_secs(0));
        assert_eq!(result.parent_id, "zero_cost_test");
    }

    #[test]
    fn test_piece_metadata_with_max_values() {
        let metadata = PieceMetadata {
            number: u32::MAX,
            offset: u64::MAX,
            length: u64::MAX,
            digest: "e".repeat(32),
            parent_id: "max_values_test".to_string(),
            traffic_type: u8::MAX,
            cost: Duration::from_secs(u64::MAX),
            created_at: DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        };

        let (bytes, length) = <(Bytes, u32)>::from(metadata.clone());
        let result = PieceMetadata::try_from((bytes, length)).unwrap();

        assert_eq!(result.number, u32::MAX);
        assert_eq!(result.offset, u64::MAX);
        assert_eq!(result.length, u64::MAX);
        assert_eq!(result.traffic_type, u8::MAX);
        assert_eq!(result.cost, Duration::from_secs(u64::MAX));
    }

    #[test]
    fn test_piece_metadata_invalid_utf8_in_digest() {
        let metadata_with_short_digest = PieceMetadata {
            number: 1,
            offset: 0,
            length: 100,
            digest: "short".to_string(),
            parent_id: "test".to_string(),
            traffic_type: 1,
            cost: Duration::from_secs(1),
            created_at: DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        };

        let (bytes, length) = <(Bytes, u32)>::from(metadata_with_short_digest);
        let result = PieceMetadata::try_from((bytes, length));
        assert!(result.is_ok());
    }
}
