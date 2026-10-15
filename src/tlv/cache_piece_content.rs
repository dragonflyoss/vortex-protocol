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

use crate::error::Result;
use crate::tlv::piece_metadata::PieceMetadata;
use crate::tlv::Tag;
use crate::Message;
use bytes::BufMut;

/// The cache piece content response: the length-prefixed metadata, followed on the connection by the
/// piece content itself, which is streamed outside of the packet.
///
/// ```text
/// -----------------------------------------------------------------------
/// | Metadata Length (4 bytes) | Metadata (variable) | Content (variable) |
/// -----------------------------------------------------------------------
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachePieceContent {
    /// The metadata of the piece.
    pub metadata: PieceMetadata,
}

/// Implements the packet value.
impl Message for CachePieceContent {
    /// The tag of the packets carrying the cache piece content response.
    const TAG: Tag = Tag::CachePieceContent;

    /// Returns the encoded length of the cache piece content response.
    fn encoded_len(&self) -> usize {
        self.metadata.encoded_len()
    }

    /// Appends the encoded cache piece content response to the buffer.
    fn encode(&self, buffer: &mut impl BufMut) {
        self.metadata.encode(buffer);
    }

    /// Decodes the cache piece content response from the value of a packet.
    fn decode(buffer: &[u8]) -> Result<Self> {
        Ok(Self {
            metadata: PieceMetadata::decode(buffer, Self::TAG)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::tlv::piece_metadata::METADATA_LENGTH_SIZE;
    use bytes::BytesMut;
    use chrono::DateTime;
    use std::time::Duration;

    #[test]
    fn decode_roundtrips() {
        let content = CachePieceContent {
            metadata: PieceMetadata {
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
        };
        let mut buffer = BytesMut::new();
        content.encode(&mut buffer);

        assert_eq!(buffer.len(), content.encoded_len());
        assert_eq!(CachePieceContent::decode(&buffer).unwrap(), content);
    }

    #[test]
    fn decode_rejects_truncated_input() {
        let mut buffer = BytesMut::new();
        CachePieceContent {
            metadata: PieceMetadata {
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
        }
        .encode(&mut buffer);
        let test_cases = vec![0, METADATA_LENGTH_SIZE, buffer.len() - 1];

        for len in test_cases {
            assert!(matches!(
                CachePieceContent::decode(&buffer[..len]),
                Err(Error::InvalidPacket(_))
            ));
        }
    }
}
