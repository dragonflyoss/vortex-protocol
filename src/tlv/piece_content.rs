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
pub const METADATA_LENGTH_SIZE: usize = 4;

/// NUMBER_SIZE is the size of the piece number in bytes.
const NUMBER_SIZE: usize = 4;

/// OFFSET_SIZE is the size of the offset in bytes.
const OFFSET_SIZE: usize = 8;

/// LENGTH_SIZE is the size of the length in bytes.
const LENGTH_SIZE: usize = 8;

/// DIGEST_LENGTH_SIZE is the size of the digest length in bytes.
const DIGEST_LENGTH_SIZE: usize = 4;

/// PARENT_ID_LENGTH_SIZE is the size of the parent ID length in bytes.
const PARENT_ID_LENGTH_SIZE: usize = 4;

/// TRAFFIC_TYPE_SIZE is the size of the traffic type in bytes.
const TRAFFIC_TYPE_SIZE: usize = 1;

/// COST_SIZE is the size of the cost in bytes.
const COST_SIZE: usize = 8;

/// CREATED_AT_SIZE is the size of the created at in bytes.
const CREATED_AT_SIZE: usize = 8;

/// PieceContent represents a piece metadata and piece content request.
///
/// Value Format:
///   - Metadata Length (4 bytes): Length of the metadata section.
///   - Number (4 bytes): Piece number to download.
///   - Offset (8 bytes): Byte offset in the file.
///   - Length (8 bytes): Length of the piece in bytes.
///   - Digest Length (4 bytes): Length of the digest field.
///   - Digest (variable): CRC32 hash of the piece content.
///   - Parent ID Length (4 bytes): Length of the parent task identifier.
///   - Parent ID (variable): Parent task identifier.
///   - Traffic Type (1 byte): Network traffic classification type.
///   - Cost (8 bytes): Download cost in seconds.
///   - Created At (8 bytes): Creation timestamp as Unix epoch seconds.
///   - Content (variable): Piece content bytes.
///
/// ```text
/// -------------------------------------------------------------------------------------------------------------------------------------
/// | Metadata Length (4 bytes) | Number (4 bytes) |  Offset (8 bytes) |  Length (8 bytes) | Digest Length(8 bytes) | Digest (variable) |
/// ------------------------------------------------------------------------------------------------------------------------------------------
/// | Parent ID Length(4 bytes) | Parent ID (variable) | Traffic Type (1 byte) | Cost (8 bytes) | Created At (8 bytes) |  Content (variable) |
/// ------------------------------------------------------------------------------------------------------------------------------------------
/// ```
#[derive(Debug, Clone)]
pub struct PieceContent {
    metadata_length: u32,
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
            metadata_length: (NUMBER_SIZE
                + OFFSET_SIZE
                + LENGTH_SIZE
                + DIGEST_LENGTH_SIZE
                + digest.len()
                + PARENT_ID_LENGTH_SIZE
                + parent_id.len()
                + TRAFFIC_TYPE_SIZE
                + COST_SIZE
                + CREATED_AT_SIZE) as u32,
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
    pub fn metadata_len(&self) -> u32 {
        self.metadata_length
    }

    /// is_empty returns whether the piece content request is empty.
    pub fn is_empty(&self) -> bool {
        self.metadata.length == 0
    }
}

/// Implement TryFrom<Bytes> for PieceContent for conversion from a byte slice.
impl TryFrom<Bytes> for PieceContent {
    type Error = Error;

    /// try_from decodes the piece content request from the byte slice.
    fn try_from(bytes: Bytes) -> Result<Self> {
        let metadata_length = u32::from_be_bytes(
            bytes
                .get(..METADATA_LENGTH_SIZE)
                .ok_or(Error::InvalidPacket(
                    "insufficient bytes for metadata length".to_string(),
                ))?
                .try_into()?,
        );

        if bytes.len() != METADATA_LENGTH_SIZE + metadata_length as usize {
            return Err(Error::InvalidPacket(format!(
                "expected {} bytes for PieceContent, got {}",
                METADATA_LENGTH_SIZE + metadata_length as usize,
                bytes.len()
            )));
        }

        let metadata = (
            bytes.slice(METADATA_LENGTH_SIZE..METADATA_LENGTH_SIZE + metadata_length as usize),
            metadata_length,
        )
            .try_into()?;
        Ok(PieceContent {
            metadata_length,
            metadata,
        })
    }
}

/// Implement From<PieceContent> for Bytes for conversion to a byte slice.
impl From<PieceContent> for Bytes {
    /// from converts the piece content request to a byte slice.
    fn from(content: PieceContent) -> Bytes {
        let (metadata_bytes, metadata_length) = content.metadata.into();
        let mut bytes = BytesMut::with_capacity(METADATA_LENGTH_SIZE + metadata_length as usize);
        bytes.put_u32(metadata_length);
        bytes.extend_from_slice(&metadata_bytes);
        bytes.freeze()
    }
}

/// PieceMetadata holds the metadata information for a piece.
#[derive(Debug, Clone)]
pub struct PieceMetadata {
    pub number: u32,
    pub offset: u64,
    pub length: u64,
    pub digest: String,
    pub parent_id: String,
    pub traffic_type: u8,
    pub cost: Duration,
    pub created_at: NaiveDateTime,
}

/// PieceMetadata implements the PieceMetadata functions.
impl PieceMetadata {
    /// new creates a new PieceMetadata.
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
            number,
            offset,
            length,
            digest,
            parent_id,
            traffic_type,
            cost,
            created_at,
        }
    }
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
        let number = u32::from_be_bytes(
            bytes
                .get(bytes_offset..bytes_offset + NUMBER_SIZE)
                .ok_or(Error::InvalidPacket(
                    "insufficient bytes for piece number".to_string(),
                ))?
                .try_into()?,
        );
        bytes_offset += NUMBER_SIZE;

        let offset = u64::from_be_bytes(
            bytes
                .get(bytes_offset..bytes_offset + OFFSET_SIZE)
                .ok_or(Error::InvalidPacket(
                    "insufficient bytes for piece offset".to_string(),
                ))?
                .try_into()?,
        );
        bytes_offset += OFFSET_SIZE;

        let length = u64::from_be_bytes(
            bytes
                .get(bytes_offset..bytes_offset + LENGTH_SIZE)
                .ok_or(Error::InvalidPacket(
                    "insufficient bytes for piece length".to_string(),
                ))?
                .try_into()?,
        );

        bytes_offset += LENGTH_SIZE;

        let digest_length = u32::from_be_bytes(
            bytes
                .get(bytes_offset..bytes_offset + DIGEST_LENGTH_SIZE)
                .ok_or(Error::InvalidPacket(
                    "insufficient bytes for digest length".to_string(),
                ))?
                .try_into()?,
        ) as usize;
        bytes_offset += DIGEST_LENGTH_SIZE;

        let digest = String::from_utf8(
            bytes
                .get(bytes_offset..bytes_offset + digest_length)
                .ok_or(Error::InvalidPacket(
                    "insufficient bytes for digest length".to_string(),
                ))?
                .to_vec(),
        )?;
        bytes_offset += digest_length;

        let parent_id_length = u32::from_be_bytes(
            bytes
                .get(bytes_offset..bytes_offset + PARENT_ID_LENGTH_SIZE)
                .ok_or(Error::InvalidPacket(
                    "insufficient bytes for parent id length".to_string(),
                ))?
                .try_into()?,
        ) as usize;
        bytes_offset += PARENT_ID_LENGTH_SIZE;

        let parent_id = String::from_utf8(
            bytes
                .get(bytes_offset..bytes_offset + parent_id_length)
                .ok_or(Error::InvalidPacket(
                    "insufficient bytes for parent id".to_string(),
                ))?
                .to_vec(),
        )?;
        bytes_offset += parent_id_length;

        let traffic_type = bytes
            .get(bytes_offset)
            .ok_or(Error::InvalidPacket(
                "insufficient bytes for traffic type".to_string(),
            ))?
            .to_owned();
        bytes_offset += TRAFFIC_TYPE_SIZE;

        let cost = Duration::from_secs(u64::from_be_bytes(
            bytes
                .get(bytes_offset..bytes_offset + COST_SIZE)
                .ok_or(Error::InvalidPacket(
                    "insufficient bytes for cost".to_string(),
                ))?
                .try_into()?,
        ));
        bytes_offset += COST_SIZE;

        let created_at = DateTime::from_timestamp(
            i64::from_be_bytes(
                bytes
                    .get(bytes_offset..bytes_offset + CREATED_AT_SIZE)
                    .ok_or(Error::InvalidPacket(
                        "insufficient bytes for created_at".to_string(),
                    ))?
                    .try_into()?,
            ),
            0,
        )
        .ok_or_else(|| Error::InvalidPacket("invalid timestamp for created_at".to_string()))?
        .naive_utc();
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
            + DIGEST_LENGTH_SIZE
            + digest.len()
            + PARENT_ID_LENGTH_SIZE
            + parent_id.len()
            + TRAFFIC_TYPE_SIZE
            + COST_SIZE
            + CREATED_AT_SIZE;

        let mut bytes = BytesMut::with_capacity(bytes_length);
        bytes.put_u32(number);
        bytes.put_u64(offset);
        bytes.put_u64(length);
        bytes.put_u32(digest.len() as u32);
        bytes.extend_from_slice(digest.as_bytes());
        bytes.put_u32(parent_id.len() as u32);
        bytes.extend_from_slice(parent_id);
        bytes.put_u8(traffic_type);
        bytes.put_u64(cost.as_secs());
        bytes.put_i64(created_at.and_utc().timestamp());
        (bytes.freeze(), bytes_length as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::time::Duration;

    fn create_test_piece_content() -> PieceContent {
        PieceContent::new(
            42,
            1024,
            2048,
            "a".repeat(32),
            "test_parent_id".to_string(),
            1,
            Duration::from_secs(5),
            DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        )
    }

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
    fn test_piece_content_conversion_roundtrip() {
        let original = create_test_piece_content();
        let bytes = Bytes::from(original.clone());
        let result = PieceContent::try_from(bytes).unwrap();

        assert_eq!(result.metadata().number, original.metadata().number);
        assert_eq!(result.metadata().offset, original.metadata().offset);
        assert_eq!(result.metadata().length, original.metadata().length);
        assert_eq!(result.metadata().digest, original.metadata().digest);
        assert_eq!(result.metadata().parent_id, original.metadata().parent_id);
        assert_eq!(
            result.metadata().traffic_type,
            original.metadata().traffic_type
        );
        assert_eq!(result.metadata().cost, original.metadata().cost);
        assert_eq!(result.metadata().created_at, original.metadata().created_at);
        assert_eq!(result.metadata_len(), original.metadata_len());
    }

    #[test]
    fn test_piece_content_try_from_insufficient_bytes_for_metadata_length() {
        let short_bytes = Bytes::from(vec![0u8; 4]); // Less than METADATA_LENGTH_SIZE (8)
        let result = PieceContent::try_from(short_bytes);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidPacket(_)));
    }

    #[test]
    fn test_piece_content_try_from_insufficient_metadata_bytes() {
        let mut bytes = BytesMut::new();
        bytes.put_u32(100); // metadata_length = 100
        bytes.put(&vec![0u8; 50][..]); // But only provide 50 bytes of metadata

        let result = PieceContent::try_from(bytes.freeze());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidPacket(_)));
    }

    #[test]
    fn test_piece_content_with_empty_parent_id() {
        let piece_content = PieceContent::new(
            1,
            0,
            100,
            "b".repeat(32),
            String::new(), // Empty parent_id
            2,
            Duration::from_secs(1),
            DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        );

        let bytes = Bytes::from(piece_content.clone());
        let result = PieceContent::try_from(bytes).unwrap();

        assert_eq!(result.metadata().parent_id, "");
        assert_eq!(result.metadata().number, 1);
        assert_eq!(result.metadata().traffic_type, 2);
        assert_eq!(result.metadata().length, 100);
    }

    #[test]
    fn test_piece_content_with_long_parent_id() {
        let long_parent_id = "x".repeat(1000);
        let piece_content = PieceContent::new(
            999,
            12345,
            67890,
            "c".repeat(32),
            long_parent_id.clone(),
            255,
            Duration::from_secs(3600),
            DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        );

        let bytes = Bytes::from(piece_content.clone());
        let result = PieceContent::try_from(bytes).unwrap();

        assert_eq!(result.metadata().parent_id, long_parent_id);
        assert_eq!(result.metadata().number, 999);
        assert_eq!(result.metadata().traffic_type, 255);
        assert_eq!(result.metadata().length, 67890);
    }

    #[test]
    fn test_piece_content_with_zero_values() {
        let piece_content = PieceContent::new(
            0,
            0,
            0,
            "d".repeat(32),
            "zero_test".to_string(),
            0,
            Duration::from_secs(0),
            DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        );

        let bytes = Bytes::from(piece_content.clone());
        let result = PieceContent::try_from(bytes).unwrap();

        assert_eq!(result.metadata().number, 0);
        assert_eq!(result.metadata().offset, 0);
        assert_eq!(result.metadata().length, 0);
        assert_eq!(result.metadata().traffic_type, 0);
        assert_eq!(result.metadata().cost, Duration::from_secs(0));
        assert!(result.is_empty());
    }

    #[test]
    fn test_piece_content_with_max_values() {
        let piece_content = PieceContent::new(
            u32::MAX,
            u64::MAX,
            u64::MAX,
            "e".repeat(32),
            "max_values_test".to_string(),
            u8::MAX,
            Duration::from_secs(u64::MAX),
            DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        );

        let bytes = Bytes::from(piece_content.clone());
        let result = PieceContent::try_from(bytes).unwrap();

        assert_eq!(result.metadata().number, u32::MAX);
        assert_eq!(result.metadata().offset, u64::MAX);
        assert_eq!(result.metadata().length, u64::MAX);
        assert_eq!(result.metadata().traffic_type, u8::MAX);
        assert_eq!(result.metadata().cost, Duration::from_secs(u64::MAX));
    }

    #[test]
    fn test_piece_content_metadata_length_calculation() {
        let piece_content = PieceContent::new(
            123,
            456,
            789,
            "f".repeat(32),
            "length_test".to_string(),
            42,
            Duration::from_secs(100),
            DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        );

        let expected_length = (NUMBER_SIZE
            + OFFSET_SIZE
            + LENGTH_SIZE
            + DIGEST_LENGTH_SIZE
            + 32 // digest length
            + PARENT_ID_LENGTH_SIZE
            + "length_test".len()
            + TRAFFIC_TYPE_SIZE
            + COST_SIZE
            + CREATED_AT_SIZE) as u32;

        assert_eq!(piece_content.metadata_len(), expected_length);

        let bytes = Bytes::from(piece_content.clone());
        let result = PieceContent::try_from(bytes).unwrap();
        assert_eq!(result.metadata_len(), expected_length);
    }

    #[test]
    fn test_piece_content_with_short_digest() {
        let piece_content = PieceContent::new(
            1,
            0,
            100,
            "short".to_string(), // Shorter than typical 32-char digest
            "test".to_string(),
            1,
            Duration::from_secs(1),
            DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        );

        let bytes = Bytes::from(piece_content.clone());
        let result = PieceContent::try_from(bytes).unwrap();

        assert_eq!(result.metadata().digest, "short");
        assert_eq!(result.metadata().number, 1);
    }

    #[test]
    fn test_piece_content_with_long_digest() {
        let long_digest = "g".repeat(128); // Longer than typical digest
        let piece_content = PieceContent::new(
            5,
            1000,
            2000,
            long_digest.clone(),
            "digest_test".to_string(),
            10,
            Duration::from_secs(50),
            DateTime::from_timestamp(1693152000, 0).unwrap().naive_utc(),
        );

        let bytes = Bytes::from(piece_content.clone());
        let result = PieceContent::try_from(bytes).unwrap();

        assert_eq!(result.metadata().digest, long_digest);
        assert_eq!(result.metadata().number, 5);
        assert_eq!(result.metadata().offset, 1000);
        assert_eq!(result.metadata().length, 2000);
    }

    #[test]
    fn test_piece_content_bytes_structure() {
        let piece_content = create_test_piece_content();
        let bytes: Bytes = piece_content.clone().into();

        let metadata_length_bytes = &bytes[..METADATA_LENGTH_SIZE];
        let metadata_length = u32::from_be_bytes(metadata_length_bytes.try_into().unwrap());
        assert_eq!(metadata_length, piece_content.metadata_len());
        assert_eq!(bytes.len(), METADATA_LENGTH_SIZE + metadata_length as usize);
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
            (NUMBER_SIZE
                + OFFSET_SIZE
                + LENGTH_SIZE
                + DIGEST_LENGTH_SIZE
                + piece_content.metadata().digest.len()
                + PARENT_ID_LENGTH_SIZE
                + piece_content.metadata().parent_id.len()
                + TRAFFIC_TYPE_SIZE
                + COST_SIZE
                + CREATED_AT_SIZE) as u32,
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
