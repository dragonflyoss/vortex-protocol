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

pub mod error;
pub mod tlv;

/// HEADER_SIZE is the size of the Vortex packet header including the packet identifier, tag, and
/// length.
pub const HEADER_SIZE: usize = 6;

/// MAX_VALUE_SIZE is the maximum size of the value field (4 GiB).
const MAX_VALUE_SIZE: usize = 4 * 1024 * 1024 * 1024;

/// Header represents the Vortex packet header.
#[derive(Debug, Clone)]
pub struct Header {
    id: u8,
    tag: tlv::Tag,
    length: usize,
}

/// Vortex Protocol
///
/// Vortex is a peer-to-peer (P2P) file transfer protocol using TLV (Tag-Length-Value) format for
/// efficient and flexible data transmission. Designed for reliable and scalable file sharing.
///
/// Packet Format:
///     - Packet Identifier (8 bits): Uniquely identifies each packet
///     - Tag (8 bits): Specifies data type in value field
///     - Length (32 bits): Indicates Value field length, up to 4 GiB
///     - Value (variable): Actual data content, maximum 1 GiB
///
/// Protocol Format:
///
/// ```text
/// -------------------------------------------------------------------------------------------------
/// |                            |                   |                    |                         |
/// | Packet Identifier (8 bits) |    Tag (8 bits)   |  Length (32 bits)  |   Value (up to 4 GiB)   |
/// |                            |                   |                    |                         |
/// -------------------------------------------------------------------------------------------------
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
        let mut rng = thread_rng();
        let header = Header {
            id: rng.gen(),
            tag,
            length: value.len(),
        };

        (tag, header, value).try_into()
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
    pub fn tag(&self) -> &tlv::Tag {
        match self {
            Vortex::DownloadPiece(header, _) => &header.tag,
            Vortex::PieceContent(header, _) => &header.tag,
            Vortex::DownloadPersistentCachePiece(header, _) => &header.tag,
            Vortex::Reserved(header) => &header.tag,
            Vortex::Close(header) => &header.tag,
            Vortex::Error(header, _) => &header.tag,
        }
    }

    /// length returns the length of the value field.
    #[inline]
    pub fn length(&self) -> usize {
        match self {
            Vortex::DownloadPiece(header, _) => header.length,
            Vortex::PieceContent(header, _) => header.length,
            Vortex::DownloadPersistentCachePiece(header, _) => header.length,
            Vortex::Reserved(header) => header.length,
            Vortex::Close(header) => header.length,
            Vortex::Error(header, _) => header.length,
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
        if bytes.len() < HEADER_SIZE {
            return Err(Error::InvalidPacket(format!(
                "expected min {HEADER_SIZE} bytes, got {}",
                bytes.len()
            )));
        }

        let mut bytes = BytesMut::from(bytes);
        let header = bytes.split_to(HEADER_SIZE);
        let value = bytes.freeze();
        let id = header[0];
        let tag = header[1]
            .try_into()
            .map_err(|err| Error::InvalidPacket(format!("invalid tag value: {:?}", err)))?;
        let length = u32::from_be_bytes(header[2..HEADER_SIZE].try_into()?) as usize;

        // Check if the value length matches the specified length.
        if value.len() != length {
            return Err(Error::InvalidLength(format!(
                "value len {} != declared length {}",
                value.len(),
                length
            )));
        }

        (tag, Header { id, tag, length }, value).try_into()
    }
}

/// Implement From<PieceContent> for Bytes.
impl From<Vortex> for Bytes {
    /// from converts a Vortex packet to Bytes.
    fn from(packet: Vortex) -> Self {
        let (header, value) = match packet {
            Vortex::DownloadPiece(header, download_piece) => {
                (header, Into::<Bytes>::into(download_piece.clone()))
            }
            Vortex::PieceContent(header, piece_content) => {
                (header, Into::<Bytes>::into(piece_content.clone()))
            }
            Vortex::DownloadPersistentCachePiece(header, download_piece) => {
                (header, Into::<Bytes>::into(download_piece.clone()))
            }
            Vortex::Reserved(header) => (header, Bytes::new()),
            Vortex::Close(header) => (header, Bytes::new()),
            Vortex::Error(header, err) => (header, Into::<Bytes>::into(err.clone())),
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
        match tag {
            tlv::Tag::DownloadPiece => {
                let download_piece = tlv::download_piece::DownloadPiece::try_from(value)?;
                Ok(Vortex::DownloadPiece(header, download_piece))
            }
            tlv::Tag::PieceContent => {
                let piece_content = tlv::piece_content::PieceContent::try_from(value)?;
                Ok(Vortex::PieceContent(header, piece_content))
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::Tag;
    use bytes::Bytes;

    #[test]
    fn test_new_download_piece() {
        let tag = Tag::DownloadPiece;
        let value = Bytes::from("a".repeat(32) + "-42");
        let packet = Vortex::new(tag, value.clone()).expect("Failed to create Vortex packet");

        assert_eq!(packet.id(), packet.id());
        assert_eq!(packet.tag(), &tag);
        assert_eq!(packet.length(), value.len());
    }

    #[test]
    fn test_new_piece_content() {
        let value = b"piece content";
        let packet = Vortex::new(Tag::PieceContent, Bytes::from_static(value))
            .expect("Failed to create packet");

        assert_eq!(packet.tag(), &Tag::PieceContent);
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
    fn test_vortex_from_bytes() {
        let value = b"test data";
        let packet = Vortex::new(Tag::PieceContent, Bytes::from_static(value))
            .expect("Failed to create packet");
        let tag = *packet.tag();
        let length = packet.length();

        let bytes: Bytes = packet.into();
        let deserialized: Vortex = bytes.try_into().expect("Failed to deserialize packet");

        assert_eq!(tag, deserialized.tag().clone());
        assert_eq!(length, deserialized.length());
    }

    #[test]
    fn test_vortex_to_bytes() {
        let value = b"test data";
        let packet = Vortex::new(Tag::PieceContent, Bytes::from_static(value))
            .expect("Failed to create packet");
        let bytes: Bytes = packet.into();

        assert_eq!(bytes.len(), HEADER_SIZE + value.len());
    }

    #[test]
    fn test_close() {
        let tag = Tag::Close;
        let value = Bytes::new();
        let packet = Vortex::new(tag, value.clone()).expect("Failed to create Vortex packet");

        assert_eq!(packet.tag(), &tag);
        assert_eq!(packet.length(), value.len());
    }

    #[test]
    fn test_error_handling() {
        let value = vec![0; MAX_VALUE_SIZE + 1];
        let result = Vortex::new(Tag::PieceContent, value.into());

        assert!(matches!(result, Err(Error::InvalidLength(_))));
    }
}
