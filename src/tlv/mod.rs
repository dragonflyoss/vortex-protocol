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

pub mod close;
pub mod download_piece;
pub mod error;
pub mod piece_content;

/// Tag Definitions
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    /// Download the content of a piece from a peer. It is composed of `{Task ID}-{Piece ID}`,
    /// where the Task ID is a 32-byte SHA-256 value and the Piece ID is a number.
    DownloadPiece = 0,

    /// The content of a piece, with a maximum size of 4 GiB per piece.
    PieceContent = 1,

    /// Download the content of a persistent_cache_piece from a peer. It is composed of `{Task ID}-{Piece ID}`,
    /// where the Task ID is a 32-byte SHA-256 value and the Piece ID is a number.
    DownloadPersistentCachePiece = 2,

    /// Reserved for future use, for tags 3-254.
    Reserved(u8),

    /// Close the connection. If server or client receives this tag, it will close the connection.
    Close = 254,

    /// Error message.
    Error = 255,
}

/// Implement TryFrom<u8> for Tag.
impl TryFrom<u8> for Tag {
    type Error = ();

    /// Converts a u8 to a Tag enum.
    fn try_from(value: u8) -> Result<Self, ()> {
        match value {
            0 => Ok(Tag::DownloadPiece),
            1 => Ok(Tag::PieceContent),
            2 => Ok(Tag::DownloadPersistentCachePiece),
            3..=253 => Ok(Tag::Reserved(value)),
            254 => Ok(Tag::Close),
            255 => Ok(Tag::Error),
        }
    }
}

/// Implement From<Tag> for u8.
impl From<Tag> for u8 {
    /// Converts a Tag enum to a u8.
    fn from(tag: Tag) -> Self {
        match tag {
            Tag::DownloadPiece => 0,
            Tag::PieceContent => 1,
            Tag::DownloadPersistentCachePiece => 2,
            Tag::Reserved(value) => value,
            Tag::Close => 254,
            Tag::Error => 255,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_try_from_u8() {
        assert_eq!(Tag::try_from(0), Ok(Tag::DownloadPiece));
        assert_eq!(Tag::try_from(1), Ok(Tag::PieceContent));
        assert_eq!(Tag::try_from(2), Ok(Tag::DownloadPersistentCachePiece));
        assert_eq!(Tag::try_from(3), Ok(Tag::Reserved(3)));
        assert_eq!(Tag::try_from(253), Ok(Tag::Reserved(253)));
        assert_eq!(Tag::try_from(254), Ok(Tag::Close));
        assert_eq!(Tag::try_from(255), Ok(Tag::Error));
    }

    #[test]
    fn test_from_tag() {
        assert_eq!(u8::from(Tag::DownloadPiece), 0);
        assert_eq!(u8::from(Tag::PieceContent), 1);
        assert_eq!(u8::from(Tag::DownloadPersistentCachePiece), 2);
        assert_eq!(u8::from(Tag::Reserved(3)), 3);
        assert_eq!(u8::from(Tag::Reserved(253)), 253);
        assert_eq!(u8::from(Tag::Close), 254);
        assert_eq!(u8::from(Tag::Error), 255);
    }
}
