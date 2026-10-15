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
use crate::tlv::{Tag, PIECE_NUMBER_SIZE, TASK_ID_SIZE};
use crate::Message;
use bytes::BufMut;
use zerocopy::{byteorder::network_endian::U32, FromBytes, Immutable, KnownLayout, Unaligned};

/// The on-wire layout of the download piece request.
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawDownloadPiece {
    /// The task ID, the hex SHA-256 digest.
    task_id: [u8; TASK_ID_SIZE],

    /// The piece number, in network byte order.
    piece_number: U32,
}

// Verify at compile time that the layout has no padding and matches the documented field
// sizes.
const _: () = assert!(size_of::<RawDownloadPiece>() == TASK_ID_SIZE + PIECE_NUMBER_SIZE);

/// The download piece request.
///
/// ```text
/// -----------------------------------------------
/// | Task ID (64 bytes) | Piece Number (4 bytes) |
/// -----------------------------------------------
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadPiece {
    /// The task ID, the hex SHA-256 digest of [TASK_ID_SIZE] bytes.
    pub task_id: String,

    /// The number of the piece to download.
    pub piece_number: u32,
}

/// Implements the download piece request.
impl DownloadPiece {
    /// Creates a download piece request.
    pub fn new(task_id: String, piece_number: u32) -> Self {
        Self {
            task_id,
            piece_number,
        }
    }
}

/// Implements the packet value.
impl Message for DownloadPiece {
    /// The tag of the packets carrying the download piece request.
    const TAG: Tag = Tag::DownloadPiece;

    /// Returns the encoded length of the download piece request.
    fn encoded_len(&self) -> usize {
        self.task_id.len() + PIECE_NUMBER_SIZE
    }

    /// Appends the encoded download piece request to the buffer.
    fn encode(&self, buffer: &mut impl BufMut) {
        buffer.put_slice(self.task_id.as_bytes());
        buffer.put_u32(self.piece_number);
    }

    /// Decodes the download piece request from the value of a packet.
    fn decode(buffer: &[u8]) -> Result<Self> {
        let raw = RawDownloadPiece::ref_from_bytes(buffer).map_err(|_| {
            Error::InvalidLength(format!(
                "expected {} bytes for {:?}, got {}",
                TASK_ID_SIZE + PIECE_NUMBER_SIZE,
                Self::TAG,
                buffer.len()
            ))
        })?;

        Ok(Self {
            task_id: String::from_utf8(raw.task_id.to_vec())?,
            piece_number: raw.piece_number.get(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;
    use bytes::BytesMut;

    #[test]
    fn encode_writes_the_wire_layout() {
        let request = DownloadPiece::new("a".repeat(TASK_ID_SIZE), 0x0102_0304);
        let mut buffer = BytesMut::new();
        request.encode(&mut buffer);

        assert_eq!(buffer.len(), request.encoded_len());
        assert_eq!(&buffer[..TASK_ID_SIZE], "a".repeat(TASK_ID_SIZE).as_bytes());
        assert_eq!(&buffer[TASK_ID_SIZE..], [1, 2, 3, 4]);
    }

    #[test]
    fn decode_roundtrips() {
        let test_cases = vec![
            DownloadPiece::new("a".repeat(TASK_ID_SIZE), 0),
            DownloadPiece::new("f".repeat(TASK_ID_SIZE), u32::MAX),
        ];

        for request in test_cases {
            let mut buffer = BytesMut::new();
            request.encode(&mut buffer);
            assert_eq!(DownloadPiece::decode(&buffer).unwrap(), request);
        }
    }

    #[test]
    fn decode_rejects_malformed_input() {
        let mut invalid_utf8 = vec![0xFF; TASK_ID_SIZE];
        invalid_utf8.extend_from_slice(&[0; PIECE_NUMBER_SIZE]);

        let test_cases: Vec<(Vec<u8>, fn(Result<DownloadPiece>))> = vec![
            (vec![], |result| {
                assert!(matches!(result, Err(Error::InvalidLength(_))))
            }),
            (vec![b'a'; TASK_ID_SIZE + PIECE_NUMBER_SIZE - 1], |result| {
                assert!(matches!(result, Err(Error::InvalidLength(_))))
            }),
            (vec![b'a'; TASK_ID_SIZE + PIECE_NUMBER_SIZE + 1], |result| {
                assert!(matches!(result, Err(Error::InvalidLength(_))))
            }),
            (invalid_utf8, |result| {
                assert!(matches!(result, Err(Error::FromUtf8Error(_))))
            }),
        ];

        for (buffer, expect) in test_cases {
            expect(DownloadPiece::decode(&buffer));
        }
    }
}
