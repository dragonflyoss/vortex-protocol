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
use crate::tlv::Tag;
use bytes::BufMut;
use chrono::{DateTime, NaiveDateTime};
use std::time::Duration;
use zerocopy::{
    byteorder::network_endian::{I64, U32, U64},
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
};

/// The size of the metadata length in bytes.
pub const METADATA_LENGTH_SIZE: usize = 4;

/// The size of the piece number in bytes.
const NUMBER_SIZE: usize = 4;

/// The size of the offset in bytes.
const OFFSET_SIZE: usize = 8;

/// The size of the length in bytes.
const LENGTH_SIZE: usize = 8;

/// The size of the digest length in bytes.
const DIGEST_LENGTH_SIZE: usize = 4;

/// The size of the parent ID length in bytes.
const PARENT_ID_LENGTH_SIZE: usize = 4;

/// The size of the traffic type in bytes.
const TRAFFIC_TYPE_SIZE: usize = 1;

/// The size of the cost in bytes.
const COST_SIZE: usize = 8;

/// The size of the creation time in bytes.
const CREATED_AT_SIZE: usize = 8;

/// The on-wire layout of the fixed fields preceding the digest.
///
/// The digest and the parent ID are variable-length, so the fixed fields around them are
/// described as a prefix and a suffix, with the parent ID length read as a bare integer in
/// between.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawMetadataPrefix {
    /// The piece number, in network byte order.
    number: U32,

    /// The offset of the piece in the task, in network byte order.
    offset: U64,

    /// The length of the piece content, in network byte order.
    length: U64,

    /// The length of the digest that follows, in network byte order.
    digest_length: U32,
}

/// The on-wire layout of the fixed fields following the parent ID, see [RawMetadataPrefix] for
/// why the layout is split.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawMetadataSuffix {
    /// The traffic type of the download.
    traffic_type: u8,

    /// The download cost in seconds, in network byte order.
    cost: U64,

    /// The creation time as Unix epoch seconds, in network byte order.
    created_at: I64,
}

// Verify at compile time that the layouts have no padding and match the documented field
// sizes.
const _: () = assert!(
    size_of::<RawMetadataPrefix>() == NUMBER_SIZE + OFFSET_SIZE + LENGTH_SIZE + DIGEST_LENGTH_SIZE
);
const _: () =
    assert!(size_of::<RawMetadataSuffix>() == TRAFFIC_TYPE_SIZE + COST_SIZE + CREATED_AT_SIZE);

/// The metadata of a piece, shared by every piece content response.
///
/// ```text
/// -----------------------------------------------------------------------------------------------
/// | Number (4 bytes) | Offset (8 bytes) | Length (8 bytes) | Digest Length (4 bytes) | Digest   |
/// -----------------------------------------------------------------------------------------------
/// | Parent ID Length (4 bytes) | Parent ID | Traffic Type (1 byte) | Cost (8 bytes) | Created At |
/// -----------------------------------------------------------------------------------------------
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PieceMetadata {
    /// The piece number.
    pub number: u32,

    /// The offset of the piece in the task.
    pub offset: u64,

    /// The length of the piece content in bytes.
    pub length: u64,

    /// The digest of the piece content.
    pub digest: String,

    /// The ID of the parent the piece was downloaded from.
    pub parent_id: String,

    /// The traffic type of the download.
    pub traffic_type: u8,

    /// The download cost, truncated to whole seconds.
    pub cost: Duration,

    /// The creation time, truncated to whole seconds.
    pub created_at: NaiveDateTime,
}

/// Implements the piece metadata.
impl PieceMetadata {
    /// Returns the number of bytes appended by [PieceMetadata::encode].
    pub(crate) fn encoded_len(&self) -> usize {
        METADATA_LENGTH_SIZE + self.fields_len()
    }

    /// Returns the encoded length of the fields following the metadata length.
    fn fields_len(&self) -> usize {
        NUMBER_SIZE
            + OFFSET_SIZE
            + LENGTH_SIZE
            + DIGEST_LENGTH_SIZE
            + self.digest.len()
            + PARENT_ID_LENGTH_SIZE
            + self.parent_id.len()
            + TRAFFIC_TYPE_SIZE
            + COST_SIZE
            + CREATED_AT_SIZE
    }

    /// Appends the metadata, preceded by its length, to the buffer.
    pub(crate) fn encode(&self, buffer: &mut impl BufMut) {
        let prefix = RawMetadataPrefix {
            number: U32::new(self.number),
            offset: U64::new(self.offset),
            length: U64::new(self.length),
            digest_length: U32::new(self.digest.len() as u32),
        };
        let parent_id_length = U32::new(self.parent_id.len() as u32);
        let suffix = RawMetadataSuffix {
            traffic_type: self.traffic_type,
            cost: U64::new(self.cost.as_secs()),
            created_at: I64::new(self.created_at.and_utc().timestamp()),
        };

        buffer.put_u32(self.fields_len() as u32);
        buffer.put_slice(prefix.as_bytes());
        buffer.put_slice(self.digest.as_bytes());
        buffer.put_slice(parent_id_length.as_bytes());
        buffer.put_slice(self.parent_id.as_bytes());
        buffer.put_slice(suffix.as_bytes());
    }

    /// Decodes the length-prefixed metadata of a piece content response.
    pub(crate) fn decode(buffer: &[u8], tag: Tag) -> Result<Self> {
        let (metadata_length, metadata) = U32::read_from_prefix(buffer).map_err(|_| {
            Error::InvalidPacket(format!("insufficient bytes for {tag:?} metadata length"))
        })?;

        if metadata.len() != metadata_length.get() as usize {
            return Err(Error::InvalidPacket(format!(
                "expected {} bytes for {tag:?} metadata, got {}",
                metadata_length.get(),
                metadata.len()
            )));
        }

        let (prefix, rest) = RawMetadataPrefix::ref_from_prefix(metadata).map_err(|_| {
            Error::InvalidPacket("insufficient bytes for piece metadata prefix".to_string())
        })?;

        let (digest, rest) = rest
            .split_at_checked(prefix.digest_length.get() as usize)
            .ok_or_else(|| Error::InvalidPacket("insufficient bytes for digest".to_string()))?;
        let digest = String::from_utf8(digest.to_vec())?;

        let (parent_id_length, rest) = U32::read_from_prefix(rest).map_err(|_| {
            Error::InvalidPacket("insufficient bytes for parent id length".to_string())
        })?;

        let (parent_id, rest) = rest
            .split_at_checked(parent_id_length.get() as usize)
            .ok_or_else(|| Error::InvalidPacket("insufficient bytes for parent id".to_string()))?;
        let parent_id = String::from_utf8(parent_id.to_vec())?;

        // Ignore any bytes following the suffix within the declared length, so a peer may
        // append fields without breaking older decoders.
        let (suffix, _) = RawMetadataSuffix::ref_from_prefix(rest).map_err(|_| {
            Error::InvalidPacket("insufficient bytes for piece metadata suffix".to_string())
        })?;

        Ok(Self {
            number: prefix.number.get(),
            offset: prefix.offset.get(),
            length: prefix.length.get(),
            digest,
            parent_id,
            traffic_type: suffix.traffic_type,
            cost: Duration::from_secs(suffix.cost.get()),
            created_at: DateTime::from_timestamp(suffix.created_at.get(), 0)
                .ok_or_else(|| {
                    Error::InvalidPacket("invalid timestamp for created_at".to_string())
                })?
                .naive_utc(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;
    use bytes::BytesMut;

    const FIXED_SIZE: usize = NUMBER_SIZE
        + OFFSET_SIZE
        + LENGTH_SIZE
        + DIGEST_LENGTH_SIZE
        + PARENT_ID_LENGTH_SIZE
        + TRAFFIC_TYPE_SIZE
        + COST_SIZE
        + CREATED_AT_SIZE;

    #[test]
    fn encode_writes_the_wire_layout() {
        let metadata = PieceMetadata {
            number: 42,
            offset: 1024,
            length: 2048,
            digest: "short".to_string(),
            parent_id: String::new(),
            traffic_type: 1,
            cost: Duration::from_secs(30),
            created_at: DateTime::from_timestamp(1_700_000_000, 0)
                .unwrap()
                .naive_utc(),
        };
        let mut buffer = BytesMut::new();
        metadata.encode(&mut buffer);

        assert_eq!(buffer.len(), metadata.encoded_len());
        assert_eq!(buffer.len(), METADATA_LENGTH_SIZE + FIXED_SIZE + 5);
        assert_eq!(&buffer[..4], ((FIXED_SIZE + 5) as u32).to_be_bytes());
        assert_eq!(&buffer[4..8], 42u32.to_be_bytes());
        assert_eq!(&buffer[8..16], 1024u64.to_be_bytes());
        assert_eq!(&buffer[16..24], 2048u64.to_be_bytes());
        assert_eq!(&buffer[24..28], 5u32.to_be_bytes());
        assert_eq!(&buffer[28..33], b"short");
        assert_eq!(&buffer[33..37], 0u32.to_be_bytes());
        assert_eq!(buffer[37], 1);
        assert_eq!(&buffer[38..46], 30u64.to_be_bytes());
        assert_eq!(&buffer[46..54], 1_700_000_000i64.to_be_bytes());
    }

    #[test]
    fn decode_roundtrips() {
        let test_cases = vec![
            PieceMetadata {
                number: 42,
                offset: 1024,
                length: 2048,
                digest: "crc32:864bbb04".to_string(),
                parent_id: "127.0.0.1-foo".to_string(),
                traffic_type: 1,
                cost: Duration::from_secs(30),
                created_at: DateTime::from_timestamp(1_700_000_000, 0)
                    .unwrap()
                    .naive_utc(),
            },
            PieceMetadata {
                number: 0,
                offset: 0,
                length: 0,
                digest: String::new(),
                parent_id: String::new(),
                traffic_type: 0,
                cost: Duration::ZERO,
                created_at: DateTime::from_timestamp(0, 0).unwrap().naive_utc(),
            },
            PieceMetadata {
                number: 7,
                offset: 7,
                length: 7,
                digest: "x".repeat(1000),
                parent_id: "y".repeat(1000),
                traffic_type: 7,
                cost: Duration::from_secs(7),
                created_at: DateTime::from_timestamp(7, 0).unwrap().naive_utc(),
            },
            PieceMetadata {
                number: u32::MAX,
                offset: u64::MAX,
                length: u64::MAX,
                digest: String::new(),
                parent_id: String::new(),
                traffic_type: u8::MAX,
                cost: Duration::from_secs(u64::MAX),
                created_at: DateTime::from_timestamp(253_402_300_799, 0)
                    .unwrap()
                    .naive_utc(),
            },
        ];

        for metadata in test_cases {
            let mut buffer = BytesMut::new();
            metadata.encode(&mut buffer);
            let decoded = PieceMetadata::decode(&buffer, Tag::PieceContent).unwrap();

            assert_eq!(decoded, metadata);
            assert_eq!(decoded.encoded_len(), buffer.len());
        }
    }

    #[test]
    fn decode_ignores_trailing_bytes_within_the_declared_length() {
        let metadata = PieceMetadata {
            number: 42,
            offset: 1024,
            length: 2048,
            digest: "crc32:864bbb04".to_string(),
            parent_id: "127.0.0.1-foo".to_string(),
            traffic_type: 1,
            cost: Duration::from_secs(30),
            created_at: DateTime::from_timestamp(1_700_000_000, 0)
                .unwrap()
                .naive_utc(),
        };
        let mut buffer = BytesMut::new();
        metadata.encode(&mut buffer);
        buffer.extend_from_slice(&[0xAB; 7]);
        let metadata_length = (buffer.len() - METADATA_LENGTH_SIZE) as u32;
        buffer[..METADATA_LENGTH_SIZE].copy_from_slice(&metadata_length.to_be_bytes());

        assert_eq!(
            PieceMetadata::decode(&buffer, Tag::PieceContent).unwrap(),
            metadata
        );
    }

    #[test]
    fn decode_rejects_malformed_input() {
        let mut buffer = BytesMut::new();
        PieceMetadata {
            number: 42,
            offset: 1024,
            length: 2048,
            digest: "crc32:864bbb04".to_string(),
            parent_id: "127.0.0.1-foo".to_string(),
            traffic_type: 1,
            cost: Duration::from_secs(30),
            created_at: DateTime::from_timestamp(1_700_000_000, 0)
                .unwrap()
                .naive_utc(),
        }
        .encode(&mut buffer);
        let mut oversized_digest = buffer.to_vec();
        oversized_digest[24..28].copy_from_slice(&1000u32.to_be_bytes());
        let mut invalid_utf8 = buffer.to_vec();
        invalid_utf8[28] = 0xFF;
        let mut invalid_timestamp = buffer.to_vec();
        let created_at = buffer.len() - CREATED_AT_SIZE;
        invalid_timestamp[created_at..].copy_from_slice(&i64::MAX.to_be_bytes());
        let mut beyond_declared_length = buffer.to_vec();
        beyond_declared_length.push(0);

        let test_cases: Vec<(Vec<u8>, fn(Result<PieceMetadata>))> = vec![
            (vec![], |result| {
                assert!(matches!(result, Err(Error::InvalidPacket(_))))
            }),
            (buffer[..METADATA_LENGTH_SIZE - 1].to_vec(), |result| {
                assert!(matches!(result, Err(Error::InvalidPacket(_))))
            }),
            (buffer[..buffer.len() - 1].to_vec(), |result| {
                assert!(matches!(result, Err(Error::InvalidPacket(_))))
            }),
            (beyond_declared_length, |result| {
                assert!(matches!(result, Err(Error::InvalidPacket(_))))
            }),
            (oversized_digest, |result| {
                assert!(matches!(result, Err(Error::InvalidPacket(_))))
            }),
            (invalid_timestamp, |result| {
                assert!(matches!(result, Err(Error::InvalidPacket(_))))
            }),
            (invalid_utf8, |result| {
                assert!(matches!(result, Err(Error::FromUtf8Error(_))))
            }),
        ];

        for (buffer, expect) in test_cases {
            expect(PieceMetadata::decode(&buffer, Tag::PieceContent));
        }
    }
}
