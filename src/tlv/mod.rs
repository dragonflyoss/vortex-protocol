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
pub mod download_persistent_cache_piece;
pub mod download_piece;
pub mod error;
pub mod persistent_cache_piece_content;
pub mod piece_content;

/// Tag Definitions
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    /// Download the content of a piece from a peer. It is composed of `{Task ID}{Piece ID}`,
    /// where the Task ID is a SHA-256 value and the Piece ID is a number.
    DownloadPiece = 0,

    /// The content of a piece, with a maximum size of 4 GiB per piece.
    PieceContent = 1,

    /// Download the content of a persistent cache piece from a peer. It is composed of `{Task ID}{Piece ID}`,
    /// where the Task ID is a SHA-256 value and the Piece ID is a number.
    DownloadPersistentCachePiece = 2,

    /// The content of a persistent cache piece, with a maximum size of 4 GiB per piece.
    PersistentCachePieceContent = 3,

    /// Reserved for future use, for tags 4-254.
    Reserved(u8),

    /// Close the connection. If server or client receives this tag, it will close the connection.
    Close = 254,

    /// Error message.
    Error = 255,
}

/// Implement TryFrom<u8> for Tag.
impl From<u8> for Tag {
    /// Converts a u8 to a Tag enum.
    fn from(value: u8) -> Self {
        match value {
            0 => Tag::DownloadPiece,
            1 => Tag::PieceContent,
            2 => Tag::DownloadPersistentCachePiece,
            3 => Tag::PersistentCachePieceContent,
            4..=253 => Tag::Reserved(value),
            254 => Tag::Close,
            255 => Tag::Error,
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
            Tag::PersistentCachePieceContent => 3,
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
        assert_eq!(Tag::from(0), Tag::DownloadPiece);
        assert_eq!(Tag::from(1), Tag::PieceContent);
        assert_eq!(Tag::from(2), Tag::DownloadPersistentCachePiece);
        assert_eq!(Tag::from(3), Tag::PersistentCachePieceContent);
        assert_eq!(Tag::from(4), Tag::Reserved(4));
        assert_eq!(Tag::from(253), Tag::Reserved(253));
        assert_eq!(Tag::from(254), Tag::Close);
        assert_eq!(Tag::from(255), Tag::Error);
    }

    #[test]
    fn test_from_tag() {
        assert_eq!(u8::from(Tag::DownloadPiece), 0);
        assert_eq!(u8::from(Tag::PieceContent), 1);
        assert_eq!(u8::from(Tag::DownloadPersistentCachePiece), 2);
        assert_eq!(u8::from(Tag::PersistentCachePieceContent), 3);
        assert_eq!(u8::from(Tag::Reserved(4)), 4);
        assert_eq!(u8::from(Tag::Reserved(253)), 253);
        assert_eq!(u8::from(Tag::Close), 254);
        assert_eq!(u8::from(Tag::Error), 255);
    }
}
