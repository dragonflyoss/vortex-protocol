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
use crate::tlv::cache_piece_content::CachePieceContent;
use crate::tlv::download_cache_piece::DownloadCachePiece;
use crate::tlv::download_persistent_cache_piece::DownloadPersistentCachePiece;
use crate::tlv::download_persistent_piece::DownloadPersistentPiece;
use crate::tlv::download_piece::DownloadPiece;
use crate::tlv::persistent_cache_piece_content::PersistentCachePieceContent;
use crate::tlv::persistent_piece_content::PersistentPieceContent;
use crate::tlv::piece_content::PieceContent;
use crate::tlv::Tag;
use bytes::BufMut;
use zerocopy::{
    byteorder::network_endian::U32, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
};

pub mod error;
pub mod tlv;

/// The size of the packet header: the packet identifier, the tag and the value length.
pub const HEADER_SIZE: usize = 6;

/// The on-wire layout of the packet header.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawHeader {
    /// The packet identifier.
    id: u8,

    /// The tag of the value.
    tag: u8,

    /// The length of the value, in network byte order.
    length: U32,
}

// Verify at compile time that the layout has no padding and matches HEADER_SIZE.
const _: () = assert!(size_of::<RawHeader>() == HEADER_SIZE);

/// A value carried by a Vortex packet, encoded to and decoded from the wire.
pub trait Message: Sized {
    /// The tag of the packets carrying this message.
    const TAG: Tag;

    /// Returns the number of bytes appended by [Message::encode].
    fn encoded_len(&self) -> usize;

    /// Appends the encoded message to the buffer.
    fn encode(&self, buffer: &mut impl BufMut);

    /// Decodes the message from the value of a packet.
    fn decode(buffer: &[u8]) -> Result<Self>;

    /// Appends a packet header followed by the encoded message to the buffer.
    fn encode_packet(&self, buffer: &mut impl BufMut) {
        Header::new(Self::TAG, self.encoded_len() as u32).encode(buffer);
        self.encode(buffer);
    }
}

/// The packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The packet identifier.
    id: u8,

    /// The tag of the value.
    tag: Tag,

    /// The length of the value.
    length: u32,
}

/// Implements the packet header.
impl Header {
    /// Creates a header with a random packet identifier.
    pub fn new(tag: Tag, length: u32) -> Self {
        Self {
            id: rand::random(),
            tag,
            length,
        }
    }

    /// Returns the packet identifier.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the tag of the value.
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// Returns the length of the value.
    pub fn length(&self) -> u32 {
        self.length
    }

    /// Appends the encoded header to the buffer.
    pub fn encode(&self, buffer: &mut impl BufMut) {
        buffer.put_slice(RawHeader::from(self).as_bytes());
    }

    /// Decodes the header from exactly [HEADER_SIZE] bytes.
    pub fn decode(buffer: &[u8]) -> Result<Self> {
        let raw = RawHeader::ref_from_bytes(buffer).map_err(|_| {
            Error::InvalidPacket(format!(
                "expected {HEADER_SIZE} bytes for header, got {}",
                buffer.len()
            ))
        })?;

        Ok(raw.into())
    }
}

/// Implements the conversion from the on-wire layout.
impl From<&RawHeader> for Header {
    /// Converts the on-wire layout into the header.
    fn from(raw: &RawHeader) -> Self {
        Header {
            id: raw.id,
            tag: raw.tag.into(),
            length: raw.length.get(),
        }
    }
}

/// Implements the conversion into the on-wire layout.
impl From<&Header> for RawHeader {
    /// Converts the header into the on-wire layout.
    fn from(header: &Header) -> Self {
        RawHeader {
            id: header.id,
            tag: header.tag.into(),
            length: U32::new(header.length),
        }
    }
}

/// A Vortex packet: the header and the decoded value.
///
/// The Vortex protocol is a peer-to-peer (P2P) file transfer protocol using the TLV
/// (Tag-Length-Value) format.
///
/// ```text
/// ---------------------------------------------------------------------------------------------------
/// |                             |                    |                    |                         |
/// | Packet Identifier (1 bytes) |    Tag (1 bytes)   |  Length (4 bytes)  |   Value (up to 4 GiB)   |
/// |                             |                    |                    |                         |
/// ---------------------------------------------------------------------------------------------------
/// ```
///
/// For more information, refer to the [Vortex Protocol](https://github.com/dragonflyoss/vortex-protocol/blob/main/docs/README.md).
///
/// # Examples
///
/// ```
/// use bytes::BytesMut;
/// use vortex_protocol::tlv::download_piece::DownloadPiece;
/// use vortex_protocol::{Message, Vortex};
///
/// # fn main() -> vortex_protocol::error::Result<()> {
/// let request = DownloadPiece::new("a".repeat(64), 1);
/// let mut buffer = BytesMut::with_capacity(vortex_protocol::HEADER_SIZE + request.encoded_len());
/// request.encode_packet(&mut buffer);
///
/// match Vortex::decode(&buffer)? {
///     Vortex::DownloadPiece(header, decoded) => {
///         assert_eq!(header.length() as usize, request.encoded_len());
///         assert_eq!(decoded, request);
///     }
///     packet => panic!("unexpected packet {packet:?}"),
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Vortex {
    /// The download piece request.
    DownloadPiece(Header, DownloadPiece),

    /// The piece content response.
    PieceContent(Header, PieceContent),

    /// The download cache piece request.
    DownloadCachePiece(Header, DownloadCachePiece),

    /// The cache piece content response.
    CachePieceContent(Header, CachePieceContent),

    /// The download persistent piece request.
    DownloadPersistentPiece(Header, DownloadPersistentPiece),

    /// The persistent piece content response.
    PersistentPieceContent(Header, PersistentPieceContent),

    /// The download persistent cache piece request.
    DownloadPersistentCachePiece(Header, DownloadPersistentCachePiece),

    /// The persistent cache piece content response.
    PersistentCachePieceContent(Header, PersistentCachePieceContent),

    /// A packet with a reserved tag, whose value is ignored.
    Reserved(Header),

    /// The close message.
    Close(Header),

    /// The error message.
    Error(Header, tlv::error::Error),
}

/// Implements the Vortex packet.
impl Vortex {
    /// Returns the packet header.
    pub fn header(&self) -> &Header {
        match self {
            Vortex::DownloadPiece(header, _)
            | Vortex::PieceContent(header, _)
            | Vortex::DownloadCachePiece(header, _)
            | Vortex::CachePieceContent(header, _)
            | Vortex::DownloadPersistentPiece(header, _)
            | Vortex::PersistentPieceContent(header, _)
            | Vortex::DownloadPersistentCachePiece(header, _)
            | Vortex::PersistentCachePieceContent(header, _)
            | Vortex::Reserved(header)
            | Vortex::Close(header)
            | Vortex::Error(header, _) => header,
        }
    }

    /// Returns the number of bytes appended by [Vortex::encode].
    pub fn encoded_len(&self) -> usize {
        HEADER_SIZE + self.value_len()
    }

    /// Appends the encoded packet to the buffer.
    ///
    /// The tag and the length are derived from the carried value, so a header built with a
    /// placeholder length encodes correctly. Only the packet identifier is taken from the header.
    pub fn encode(&self, buffer: &mut impl BufMut) {
        let raw = RawHeader {
            id: self.header().id,
            tag: self.tag().into(),
            length: U32::new(self.value_len() as u32),
        };
        buffer.put_slice(raw.as_bytes());

        match self {
            Vortex::DownloadPiece(_, value) => value.encode(buffer),
            Vortex::PieceContent(_, value) => value.encode(buffer),
            Vortex::DownloadCachePiece(_, value) => value.encode(buffer),
            Vortex::CachePieceContent(_, value) => value.encode(buffer),
            Vortex::DownloadPersistentPiece(_, value) => value.encode(buffer),
            Vortex::PersistentPieceContent(_, value) => value.encode(buffer),
            Vortex::DownloadPersistentCachePiece(_, value) => value.encode(buffer),
            Vortex::PersistentCachePieceContent(_, value) => value.encode(buffer),
            Vortex::Reserved(_) | Vortex::Close(_) => {}
            Vortex::Error(_, value) => value.encode(buffer),
        }
    }

    /// Decodes a whole packet, the header followed by exactly the declared value length.
    pub fn decode(buffer: &[u8]) -> Result<Self> {
        let (raw, value) = RawHeader::ref_from_prefix(buffer).map_err(|_| {
            Error::InvalidPacket(format!(
                "expected at least {HEADER_SIZE} bytes for header, got {}",
                buffer.len()
            ))
        })?;

        let header = Header::from(raw);
        if value.len() != header.length as usize {
            return Err(Error::InvalidLength(format!(
                "expected {} bytes for value, got {}",
                header.length,
                value.len()
            )));
        }

        Ok(match header.tag {
            Tag::DownloadPiece => Vortex::DownloadPiece(header, DownloadPiece::decode(value)?),
            Tag::PieceContent => Vortex::PieceContent(header, PieceContent::decode(value)?),
            Tag::DownloadCachePiece => {
                Vortex::DownloadCachePiece(header, DownloadCachePiece::decode(value)?)
            }
            Tag::CachePieceContent => {
                Vortex::CachePieceContent(header, CachePieceContent::decode(value)?)
            }
            Tag::DownloadPersistentPiece => {
                Vortex::DownloadPersistentPiece(header, DownloadPersistentPiece::decode(value)?)
            }
            Tag::PersistentPieceContent => {
                Vortex::PersistentPieceContent(header, PersistentPieceContent::decode(value)?)
            }
            Tag::DownloadPersistentCachePiece => Vortex::DownloadPersistentCachePiece(
                header,
                DownloadPersistentCachePiece::decode(value)?,
            ),
            Tag::PersistentCachePieceContent => Vortex::PersistentCachePieceContent(
                header,
                PersistentCachePieceContent::decode(value)?,
            ),
            Tag::Reserved(_) => Vortex::Reserved(header),
            Tag::Close => Vortex::Close(header),
            Tag::Error => Vortex::Error(header, tlv::error::Error::decode(value)?),
        })
    }

    /// Returns the tag of the carried value.
    fn tag(&self) -> Tag {
        match self {
            Vortex::DownloadPiece(..) => DownloadPiece::TAG,
            Vortex::PieceContent(..) => PieceContent::TAG,
            Vortex::DownloadCachePiece(..) => DownloadCachePiece::TAG,
            Vortex::CachePieceContent(..) => CachePieceContent::TAG,
            Vortex::DownloadPersistentPiece(..) => DownloadPersistentPiece::TAG,
            Vortex::PersistentPieceContent(..) => PersistentPieceContent::TAG,
            Vortex::DownloadPersistentCachePiece(..) => DownloadPersistentCachePiece::TAG,
            Vortex::PersistentCachePieceContent(..) => PersistentCachePieceContent::TAG,
            Vortex::Reserved(header) => header.tag,
            Vortex::Close(_) => Tag::Close,
            Vortex::Error(..) => tlv::error::Error::TAG,
        }
    }

    /// Returns the encoded length of the carried value.
    fn value_len(&self) -> usize {
        match self {
            Vortex::DownloadPiece(_, value) => value.encoded_len(),
            Vortex::PieceContent(_, value) => value.encoded_len(),
            Vortex::DownloadCachePiece(_, value) => value.encoded_len(),
            Vortex::CachePieceContent(_, value) => value.encoded_len(),
            Vortex::DownloadPersistentPiece(_, value) => value.encoded_len(),
            Vortex::PersistentPieceContent(_, value) => value.encoded_len(),
            Vortex::DownloadPersistentCachePiece(_, value) => value.encoded_len(),
            Vortex::PersistentCachePieceContent(_, value) => value.encoded_len(),
            Vortex::Reserved(_) | Vortex::Close(_) => 0,
            Vortex::Error(_, value) => value.encoded_len(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;
    use crate::tlv::error::Code;
    use crate::tlv::piece_metadata::PieceMetadata;
    use crate::tlv::{PIECE_NUMBER_SIZE, TASK_ID_SIZE};
    use bytes::BytesMut;
    use chrono::DateTime;
    use proptest::prelude::*;
    use std::time::Duration;

    fn arb_metadata() -> impl Strategy<Value = PieceMetadata> {
        (
            any::<u32>(),
            any::<u64>(),
            any::<u64>(),
            "[a-z0-9:]{0,80}",
            "[a-z0-9.-]{0,80}",
            any::<u8>(),
            any::<u64>(),
            0i64..253_402_300_799,
        )
            .prop_map(
                |(number, offset, length, digest, parent_id, traffic_type, cost, created_at)| {
                    PieceMetadata {
                        number,
                        offset,
                        length,
                        digest,
                        parent_id,
                        traffic_type,
                        cost: Duration::from_secs(cost),
                        created_at: DateTime::from_timestamp(created_at, 0).unwrap().naive_utc(),
                    }
                },
            )
    }

    fn arb_packet() -> impl Strategy<Value = Vortex> {
        prop_oneof![
            ("[0-9a-f]{64}", any::<u32>()).prop_map(|(task_id, piece_number)| {
                let request = DownloadPiece::new(task_id, piece_number);
                let header = Header::new(DownloadPiece::TAG, request.encoded_len() as u32);
                Vortex::DownloadPiece(header, request)
            }),
            arb_metadata().prop_map(|metadata| {
                let content = PieceContent { metadata };
                let header = Header::new(PieceContent::TAG, content.encoded_len() as u32);
                Vortex::PieceContent(header, content)
            }),
            (8u8..=253).prop_map(|tag| Vortex::Reserved(Header::new(Tag::Reserved(tag), 0))),
            Just(Vortex::Close(Header::new(Tag::Close, 0))),
            (any::<u8>(), ".{0,64}").prop_map(|(code, message)| {
                let error = tlv::error::Error::new(Code::from(code), message);
                let header = Header::new(tlv::error::Error::TAG, error.encoded_len() as u32);
                Vortex::Error(header, error)
            }),
        ]
    }

    #[test]
    fn header_encode_writes_the_wire_layout() {
        let header = Header::new(Tag::Close, 0x0102_0304);
        let mut buffer = BytesMut::new();
        header.encode(&mut buffer);

        assert_eq!(buffer.len(), HEADER_SIZE);
        assert_eq!(buffer[0], header.id());
        assert_eq!(buffer[1], 254);
        assert_eq!(&buffer[2..], [1, 2, 3, 4]);
    }

    #[test]
    fn header_decode_roundtrips_every_tag() {
        let test_cases = vec![
            (Tag::DownloadPiece, 0),
            (Tag::PieceContent, 1024),
            (Tag::Reserved(42), u32::MAX),
            (Tag::Close, 0),
            (Tag::Error, 7),
        ];

        for (tag, length) in test_cases {
            let header = Header::new(tag, length);
            let mut buffer = BytesMut::new();
            header.encode(&mut buffer);
            assert_eq!(Header::decode(&buffer).unwrap(), header);
        }
    }

    #[test]
    fn header_decode_rejects_other_sizes() {
        let test_cases = vec![0, HEADER_SIZE - 1, HEADER_SIZE + 1];

        for len in test_cases {
            assert!(matches!(
                Header::decode(&vec![0; len]),
                Err(Error::InvalidPacket(_))
            ));
        }
    }

    #[test]
    fn encode_packet_prepends_the_header() {
        let request = DownloadPiece::new("a".repeat(TASK_ID_SIZE), 7);
        let mut buffer = BytesMut::new();
        request.encode_packet(&mut buffer);

        let header = Header::decode(&buffer[..HEADER_SIZE]).unwrap();
        assert_eq!(header.tag(), Tag::DownloadPiece);
        assert_eq!(header.length() as usize, TASK_ID_SIZE + PIECE_NUMBER_SIZE);
        assert_eq!(
            DownloadPiece::decode(&buffer[HEADER_SIZE..]).unwrap(),
            request
        );
    }

    #[test]
    fn vortex_encode_derives_the_tag_and_length_from_the_value() {
        let request = DownloadPiece::new("a".repeat(TASK_ID_SIZE), 7);
        let packet = Vortex::DownloadPiece(Header::new(Tag::Close, 0), request.clone());
        let mut buffer = BytesMut::new();
        packet.encode(&mut buffer);

        assert_eq!(buffer.len(), packet.encoded_len());
        let header = Header::decode(&buffer[..HEADER_SIZE]).unwrap();
        assert_eq!(header.id(), packet.header().id());
        assert_eq!(header.tag(), Tag::DownloadPiece);
        assert_eq!(header.length() as usize, request.encoded_len());
    }

    #[test]
    fn vortex_decode_roundtrips_every_variant() {
        let request = DownloadPiece::new("a".repeat(TASK_ID_SIZE), 7);
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
        let error = tlv::error::Error::new(Code::NotFound, "missing".to_string());
        let test_cases = vec![
            Vortex::DownloadPiece(Header::new(Tag::DownloadPiece, 68), request.clone()),
            Vortex::PieceContent(
                Header::new(Tag::PieceContent, 0),
                PieceContent {
                    metadata: metadata.clone(),
                },
            ),
            Vortex::DownloadCachePiece(
                Header::new(Tag::DownloadCachePiece, 68),
                DownloadCachePiece::new(request.task_id.clone(), 8),
            ),
            Vortex::CachePieceContent(
                Header::new(Tag::CachePieceContent, 0),
                CachePieceContent {
                    metadata: metadata.clone(),
                },
            ),
            Vortex::DownloadPersistentPiece(
                Header::new(Tag::DownloadPersistentPiece, 68),
                DownloadPersistentPiece::new(request.task_id.clone(), 9),
            ),
            Vortex::PersistentPieceContent(
                Header::new(Tag::PersistentPieceContent, 0),
                PersistentPieceContent {
                    metadata: metadata.clone(),
                },
            ),
            Vortex::DownloadPersistentCachePiece(
                Header::new(Tag::DownloadPersistentCachePiece, 68),
                DownloadPersistentCachePiece::new(request.task_id.clone(), 10),
            ),
            Vortex::PersistentCachePieceContent(
                Header::new(Tag::PersistentCachePieceContent, 0),
                PersistentCachePieceContent {
                    metadata: metadata.clone(),
                },
            ),
            Vortex::Reserved(Header::new(Tag::Reserved(42), 0)),
            Vortex::Close(Header::new(Tag::Close, 0)),
            Vortex::Error(Header::new(Tag::Error, 0), error),
        ];

        for packet in test_cases {
            let mut buffer = BytesMut::new();
            packet.encode(&mut buffer);
            let decoded = Vortex::decode(&buffer).unwrap();

            assert_eq!(buffer.len(), packet.encoded_len());
            assert_eq!(decoded.header().id(), packet.header().id());
            assert_eq!(decoded.header().tag(), packet.header().tag());
            assert_eq!(
                decoded.header().length() as usize,
                buffer.len() - HEADER_SIZE
            );
            assert_eq!(decoded.encoded_len(), packet.encoded_len());
        }
    }

    #[test]
    fn vortex_decode_rejects_malformed_packets() {
        let mut declared_but_missing = BytesMut::new();
        Header::new(Tag::Close, 1).encode(&mut declared_but_missing);
        let mut undersized_value = BytesMut::new();
        Header::new(Tag::DownloadPiece, 3).encode(&mut undersized_value);
        undersized_value.extend_from_slice(&[0; 3]);
        let mut invalid_value = BytesMut::new();
        Header::new(
            Tag::DownloadPiece,
            (TASK_ID_SIZE + PIECE_NUMBER_SIZE) as u32,
        )
        .encode(&mut invalid_value);
        invalid_value.extend_from_slice(&[0xFF; TASK_ID_SIZE + PIECE_NUMBER_SIZE]);

        let test_cases: Vec<(Vec<u8>, fn(Result<Vortex>))> = vec![
            (vec![0; HEADER_SIZE - 1], |result| {
                assert!(matches!(result, Err(Error::InvalidPacket(_))))
            }),
            (declared_but_missing.to_vec(), |result| {
                assert!(matches!(result, Err(Error::InvalidLength(_))))
            }),
            (undersized_value.to_vec(), |result| {
                assert!(matches!(result, Err(Error::InvalidLength(_))))
            }),
            (invalid_value.to_vec(), |result| {
                assert!(matches!(result, Err(Error::FromUtf8Error(_))))
            }),
        ];

        for (buffer, expect) in test_cases {
            expect(Vortex::decode(&buffer));
        }
    }

    #[test]
    fn vortex_decode_ignores_the_value_of_reserved_and_close_packets() {
        let test_cases = vec![(Tag::Reserved(42), 5), (Tag::Close, 3)];

        for (tag, length) in test_cases {
            let header = Header::new(tag, length);
            let mut buffer = BytesMut::new();
            header.encode(&mut buffer);
            buffer.extend_from_slice(&vec![0xAB; length as usize]);

            let packet = Vortex::decode(&buffer).unwrap();
            assert_eq!(packet.header(), &header);
            assert_eq!(packet.encoded_len(), HEADER_SIZE);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 200,
            max_shrink_iters: 0,
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn vortex_roundtrips_arbitrary_packets(packet in arb_packet()) {
            let mut buffer = BytesMut::new();
            packet.encode(&mut buffer);
            prop_assert_eq!(buffer.len(), packet.encoded_len());

            let header = Header::decode(&buffer[..HEADER_SIZE])?;
            prop_assert_eq!(header.id(), packet.header().id());
            prop_assert_eq!(header.length() as usize, buffer.len() - HEADER_SIZE);

            let decoded = Vortex::decode(&buffer)?;
            prop_assert_eq!(&decoded, &packet);

            let mut encoded = BytesMut::new();
            decoded.encode(&mut encoded);
            prop_assert_eq!(encoded, buffer);
        }

        #[test]
        fn vortex_decode_rejects_truncated_packets(packet in arb_packet(), cut in 1usize..64) {
            let mut buffer = BytesMut::new();
            packet.encode(&mut buffer);
            prop_assume!(cut <= buffer.len());
            prop_assert!(Vortex::decode(&buffer[..buffer.len() - cut]).is_err());
        }
    }
}
