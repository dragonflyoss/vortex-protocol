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
use rand::prelude::*;
use serde::{Deserialize, Serialize};

pub mod error;
pub mod tlv;

/// HEADER_SIZE is the size of the Vortex packet header including the packet identifier, tag, and
/// length.
pub const HEADER_SIZE: usize = 6;

/// MAX_VALUE_SIZE is the maximum size of the value field (4 GiB).
const MAX_VALUE_SIZE: usize = 4 * 1024 * 1024 * 1024;

/// Header represents the Vortex packet header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    id: u8,
    tag: tlv::Tag,
    length: u32,
}

/// Header implements the Header functions.
impl Header {
    /// new creates a new Vortex packet header.
    pub fn new(tag: tlv::Tag, value_length: u32) -> Self {
        let mut rng = thread_rng();
        Self {
            id: rng.gen(),
            tag,
            length: value_length,
        }
    }

    /// new_download_piece creates a new Vortex packet header for download piece request.
    pub fn new_download_piece() -> Self {
        let mut rng = thread_rng();
        Self {
            id: rng.gen(),
            tag: tlv::Tag::DownloadPiece,
            length: (tlv::download_piece::TASK_ID_SIZE + tlv::download_piece::PIECE_NUMBER_SIZE)
                as u32,
        }
    }

    /// new_close creates a new Vortex packet header for close message.
    pub fn new_close() -> Self {
        let mut rng = thread_rng();
        Self {
            id: rng.gen(),
            tag: tlv::Tag::Close,
            length: 0,
        }
    }

    /// new_piece_content creates a new Vortex packet header for piece content.
    pub fn new_piece_content(value_length: u32) -> Self {
        let mut rng = thread_rng();
        Self {
            id: rng.gen(),
            tag: tlv::Tag::PieceContent,
            length: value_length,
        }
    }

    /// new_error creates a new Vortex packet header for error.
    pub fn new_error(value_length: u32) -> Self {
        let mut rng = thread_rng();
        Self {
            id: rng.gen(),
            tag: tlv::Tag::Error,
            length: value_length,
        }
    }
}

/// Implement TryFrom<Bytes> for Header.
impl TryFrom<Bytes> for Header {
    type Error = Error;

    /// try_from converts a Bytes into a Header.
    fn try_from(bytes: Bytes) -> Result<Self> {
        if bytes.len() != HEADER_SIZE {
            return Err(Error::InvalidPacket(format!(
                "expected min {HEADER_SIZE} bytes, got {}",
                bytes.len()
            )));
        }

        let id = bytes
            .first()
            .ok_or(Error::InvalidPacket(
                "insufficient bytes for id".to_string(),
            ))?
            .to_owned();

        let tag = bytes
            .get(1)
            .ok_or(Error::InvalidPacket(
                "insufficient bytes for tag".to_string(),
            ))?
            .to_owned()
            .into();

        let length = u32::from_be_bytes(
            bytes
                .get(2..HEADER_SIZE)
                .ok_or(Error::InvalidPacket(
                    "insufficient bytes for length".to_string(),
                ))?
                .try_into()?,
        );
        Ok(Header { id, tag, length })
    }
}

/// Implement From<Header> for Bytes.
impl From<Header> for Bytes {
    /// from converts a Header into Bytes.
    fn from(header: Header) -> Self {
        let mut bytes = BytesMut::with_capacity(HEADER_SIZE);
        bytes.put_u8(header.id);
        bytes.put_u8(header.tag.into());
        bytes.put_u32(header.length);
        bytes.freeze()
    }
}

/// Vortex Protocol
///
/// Vortex is a peer-to-peer (P2P) file transfer protocol using TLV (Tag-Length-Value) format for
/// efficient and flexible data transmission. Designed for reliable and scalable file sharing.
///
/// Packet Format:
///     - Packet Identifier (1 bytes): Uniquely identifies each packet
///     - Tag (1 bytes): Specifies data type in value field
///     - Length (8 bytes): Indicates Value field length, up to 4 GiB
///     - Value (variable): Actual data content, maximum 1 GiB
///
/// Protocol Format:
///
/// ```text
/// ---------------------------------------------------------------------------------------------------
/// |                             |                    |                    |                         |
/// | Packet Identifier (1 bytes) |    Tag (1 bytes)   |  Length (8 bytes)  |   Value (up to 4 GiB)   |
/// |                             |                    |                    |                         |
/// ---------------------------------------------------------------------------------------------------
/// ```
///
/// For more information, please refer to the [Vortex Protocol](https://github.com/dragonflyoss/vortex/blob/main/docs/README.md).
#[derive(Debug, Clone)]
pub enum Vortex {
    DownloadPiece(Header, tlv::download_piece::DownloadPiece),
    PieceContent(Header, tlv::piece_content::PieceContent),
    DownloadPersistentCachePiece(Header, tlv::download_piece::DownloadPiece),
    Reserved(Header),
    Close(Header),
    Error(Header, tlv::error::Error),
}

/// Vortex implements the Vortex functions.
impl Vortex {
    /// Creates a new Vortex packet.
    pub fn new(tag: tlv::Tag, value: Bytes) -> Result<Self> {
        (tag, Header::new(tag, value.len() as u32), value).try_into()
    }

    /// id returns the packet identifier of the Vortex packet.
    #[inline]
    pub fn id(&self) -> u8 {
        match self {
            Vortex::DownloadPiece(header, _) => header.id,
            Vortex::PieceContent(header, _) => header.id,
            Vortex::DownloadPersistentCachePiece(header, _) => header.id,
            Vortex::Reserved(header) => header.id,
            Vortex::Close(header) => header.id,
            Vortex::Error(header, _) => header.id,
        }
    }

    /// tag returns the tag of the Vortex packet.
    #[inline]
    pub fn tag(&self) -> tlv::Tag {
        match self {
            Vortex::DownloadPiece(header, _) => header.tag,
            Vortex::PieceContent(header, _) => header.tag,
            Vortex::DownloadPersistentCachePiece(header, _) => header.tag,
            Vortex::Reserved(header) => header.tag,
            Vortex::Close(header) => header.tag,
            Vortex::Error(header, _) => header.tag,
        }
    }

    /// length returns the length of the value field.
    #[inline]
    pub fn length(&self) -> usize {
        match self {
            Vortex::DownloadPiece(header, _) => header.length as usize,
            Vortex::PieceContent(header, _) => header.length as usize,
            Vortex::DownloadPersistentCachePiece(header, _) => header.length as usize,
            Vortex::Reserved(header) => header.length as usize,
            Vortex::Close(header) => header.length as usize,
            Vortex::Error(header, _) => header.length as usize,
        }
    }

    /// header returns a reference to the packet header.
    #[inline]
    pub fn header(&self) -> &Header {
        match self {
            Vortex::DownloadPiece(header, _) => header,
            Vortex::PieceContent(header, _) => header,
            Vortex::Reserved(header) => header,
            Vortex::Close(header) => header,
            Vortex::Error(header, _) => header,
        }
    }
}

/// Implement TryFrom<Bytes> for Vortex.
impl TryFrom<Bytes> for Vortex {
    type Error = Error;

    /// try_from converts a Bytes into a Vortex packet.
    fn try_from(bytes: Bytes) -> Result<Self> {
        let mut bytes = BytesMut::from(bytes);
        let header = bytes.split_to(HEADER_SIZE);
        let value = bytes.freeze();
        let header: Header = header.freeze().try_into()?;

        // Check if the value length matches the specified length.
        if value.len() != header.length as usize {
            return Err(Error::InvalidLength(format!(
                "value len {} != declared length {}",
                value.len(),
                header.length
            )));
        }

        (header.tag, header, value).try_into()
    }
}

/// Implement From<PieceContent> for Bytes.
impl From<Vortex> for Bytes {
    /// from converts a Vortex packet to Bytes.
    fn from(packet: Vortex) -> Self {
        let (header, value) = match packet {
            Vortex::DownloadPiece(header, download_piece) => (header, download_piece.into()),
            Vortex::DownloadPersistentCachePiece(header, download_piece) => (header, download_piece.into()),
            Vortex::Reserved(header) => (header, Bytes::new()),
            Vortex::Close(header) => (header, Bytes::new()),
            Vortex::Error(header, err) => (header, err.into()),
            _ => panic!("unsupported packet type for conversion to Bytes"),
        };

        let mut bytes = BytesMut::with_capacity(HEADER_SIZE + value.len());
        bytes.put_u8(header.id);
        bytes.put_u8(header.tag.into());
        bytes.put_u32(value.len() as u32);
        bytes.extend_from_slice(&value);
        bytes.freeze()
    }
}

/// Implement TryFrom<(tlv::Tag, Header, Bytes)> for Vortex.
impl TryFrom<(tlv::Tag, Header, Bytes)> for Vortex {
    type Error = Error;

    /// try_from converts a tuple of Tag, Header, and Bytes into a Vortex packet.
    fn try_from((tag, header, value): (tlv::Tag, Header, Bytes)) -> Result<Self> {
        if value.len() > MAX_VALUE_SIZE {
            return Err(Error::InvalidLength(format!(
                "value length {} exceeds maximum allowed size of {} bytes",
                value.len(),
                MAX_VALUE_SIZE
            )));
        }

        match tag {
            tlv::Tag::DownloadPiece => {
                let download_piece = tlv::download_piece::DownloadPiece::try_from(value)?;
                Ok(Vortex::DownloadPiece(header, download_piece))
            }
            tlv::Tag::DownloadPersistentCachePiece => {
                let download_piece = tlv::download_piece::DownloadPiece::try_from(value)?;
                Ok(Vortex::DownloadPersistentCachePiece(header, download_piece))
            }
            tlv::Tag::Reserved(_) => Ok(Vortex::Reserved(header)),
            tlv::Tag::Close => Ok(Vortex::Close(header)),
            tlv::Tag::Error => {
                let err = tlv::error::Error::try_from(value)?;
                Ok(Vortex::Error(header, err))
            }
            _ => panic!("unsupported tag for Vortex packet"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::Tag;
    use bytes::Bytes;

    #[test]
    fn test_header_new() {
        let tag = Tag::DownloadPiece;
        let value_length = 1024;
        let header = Header::new(tag, value_length);

        assert_eq!(header.tag, tag);
        assert_eq!(header.length, value_length);
        assert!(header.id <= 254);
    }

    #[test]
    fn test_header_try_from_bytes_success() {
        let mut bytes = BytesMut::with_capacity(HEADER_SIZE);
        bytes.put_u8(42);
        bytes.put_u8(Tag::DownloadPiece.into());
        bytes.put_u32(1024);
        let bytes = bytes.freeze();
        let header = Header::try_from(bytes).unwrap();

        assert_eq!(header.id, 42);
        assert_eq!(header.tag, Tag::DownloadPiece);
        assert_eq!(header.length, 1024);
    }

    #[test]
    fn test_header_try_from_bytes_invalid_size() {
        let bytes = Bytes::from(vec![1, 2, 3]);
        let result = Header::try_from(bytes);
        assert!(matches!(result, Err(Error::InvalidPacket(_))));
    }

    #[test]
    fn test_header_to_bytes() {
        let tag = Tag::Close;
        let header = Header {
            id: 123,
            tag,
            length: 2048,
        };
        let bytes: Bytes = header.into();

        assert_eq!(bytes.len(), HEADER_SIZE);
        assert_eq!(bytes[0], 123);
        assert_eq!(bytes[1], tag.into());
        assert_eq!(
            u32::from_be_bytes(bytes[2..HEADER_SIZE].try_into().unwrap()),
            2048
        );
    }

    #[test]
    fn test_new_download_piece() {
        let tag = Tag::DownloadPiece;
        let mut value = BytesMut::with_capacity(68);
        value.extend_from_slice("a".repeat(64).as_bytes());
        value.put_u32(42);
        let packet = Vortex::new(tag, value.clone().freeze()).unwrap();

        assert_eq!(packet.id(), packet.id());
        assert_eq!(packet.tag(), tag);
        assert_eq!(packet.length(), value.len());
    }

    #[test]
    fn test_close() {
        let tag = Tag::Close;
        let value = Bytes::new();
        let packet = Vortex::new(tag, value.clone()).unwrap();

        assert_eq!(packet.tag(), tag);
        assert_eq!(packet.length(), value.len());
    }

    #[test]
    fn test_new_download_persistent_cache_piece() {
        let tag = Tag::DownloadPersistentCachePiece;
        let value = Bytes::from("a".repeat(32) + "-42");
        let packet = Vortex::new(tag, value.clone()).expect("Failed to create Vortex packet");

        assert_eq!(packet.id(), packet.id());
        assert_eq!(packet.tag(), &tag);
        assert_eq!(packet.length(), value.len());
    }

    #[test]
    fn test_error_handling() {
        let value = vec![0; MAX_VALUE_SIZE + 1];
        let result = Vortex::new(Tag::PieceContent, value.into());

        assert!(matches!(result, Err(Error::InvalidLength(_))));
    }

    #[test]
    fn test_vortex_try_from_bytes_success() {
        let tag = Tag::Close;
        let header = Header::new(tag, 0);
        let header_bytes: Bytes = header.clone().into();
        let value = Bytes::new();

        let mut packet_bytes = BytesMut::new();
        packet_bytes.extend_from_slice(&header_bytes);
        packet_bytes.extend_from_slice(&value);
        let packet = Vortex::try_from(packet_bytes.freeze()).unwrap();

        assert_eq!(packet.tag(), tag);
        assert_eq!(packet.length(), 0);
    }

    #[test]
    fn test_vortex_try_from_bytes_length_mismatch() {
        let tag = Tag::Close;
        let header = Header {
            id: 1,
            tag,
            length: 5,
        };
        let header_bytes: Bytes = header.into();
        let value = Bytes::from("test");

        let mut packet_bytes = BytesMut::new();
        packet_bytes.extend_from_slice(&header_bytes);
        packet_bytes.extend_from_slice(&value);
        let result = Vortex::try_from(packet_bytes.freeze());

        assert!(matches!(result, Err(Error::InvalidLength(_))));
    }

    #[test]
    fn test_vortex_to_bytes_download_piece() {
        let tag = Tag::DownloadPiece;
        let mut value = BytesMut::with_capacity(68);
        value.extend_from_slice("a".repeat(64).as_bytes());
        value.put_u32(42);
        let packet = Vortex::new(tag, value.clone().freeze()).unwrap();
        let bytes: Bytes = packet.into();

        assert_eq!(bytes.len(), HEADER_SIZE + value.len());
    }

    #[test]
    fn test_vortex_to_bytes_reserved() {
        let tag = Tag::Reserved(50);
        let packet = Vortex::new(tag, Bytes::new()).unwrap();
        let bytes: Bytes = packet.into();

        assert_eq!(bytes.len(), HEADER_SIZE);
    }

    #[test]
    fn test_vortex_to_bytes_close() {
        let tag = Tag::Close;
        let packet = Vortex::new(tag, Bytes::new()).unwrap();
        let bytes: Bytes = packet.into();

        assert_eq!(bytes.len(), HEADER_SIZE);
    }

    #[test]
    fn test_vortex_to_bytes_error() {
        let tag = Tag::Error;
        let value = Bytes::from("error details");
        let packet = Vortex::new(tag, value.clone()).unwrap();
        let bytes: Bytes = packet.into();

        assert_eq!(bytes.len(), HEADER_SIZE + value.len());
    }

    #[test]
    fn test_max_value_size_boundary() {
        let tag = Tag::Reserved(50);
        let value = vec![0; MAX_VALUE_SIZE];
        let result = Vortex::new(tag, value.into());

        assert!(result.is_ok());
    }
}
