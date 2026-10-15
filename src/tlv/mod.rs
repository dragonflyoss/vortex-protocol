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

pub mod cache_piece_content;
pub mod download_cache_piece;
pub mod download_persistent_cache_piece;
pub mod download_persistent_piece;
pub mod download_piece;
pub mod error;
pub mod persistent_cache_piece_content;
pub mod persistent_piece_content;
pub mod piece_content;
pub mod piece_metadata;

/// The size of the task ID in a download request, the hex SHA-256 digest of the task.
pub const TASK_ID_SIZE: usize = 64;

/// The size of the piece number in a download request.
pub const PIECE_NUMBER_SIZE: usize = 4;

/// The tag of a packet value.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    /// Download the content of a piece from a peer. It is composed of `{Task ID}{Piece ID}`,
    /// where the Task ID is a SHA-256 value and the Piece ID is a number.
    DownloadPiece = 0,

    /// The content of a piece, with a maximum size of 1 GiB per piece.
    PieceContent = 1,

    /// Download the content of a persistent piece from a peer. It is composed of `{Task ID}{Piece ID}`,
    /// where the Task ID is a SHA-256 value and the Piece ID is a number.
    DownloadPersistentPiece = 2,

    /// The content of a persistent piece, with a maximum size of 1 GiB per piece.
    PersistentPieceContent = 3,

    /// Download the content of a persistent cache piece from a peer. It is composed of `{Task ID}{Piece ID}`,
    /// where the Task ID is a SHA-256 value and the Piece ID is a number.
    DownloadPersistentCachePiece = 4,

    /// The content of a persistent cache piece, with a maximum size of 1 GiB per piece.
    PersistentCachePieceContent = 5,

    /// Download the content of a cache piece from a peer. It is composed of `{Task ID}{Piece ID}`,
    /// where the Task ID is a SHA-256 value and the Piece ID is a number.
    DownloadCachePiece = 6,

    /// The content of a cache piece, with a maximum size of 1 GiB per piece.
    CachePieceContent = 7,

    /// Reserved for future use, for tags 8-253.
    Reserved(u8),

    /// Close the connection. If server or client receives this tag, it will close the connection.
    Close = 254,

    /// Error message.
    Error = 255,
}

/// Implements the conversion from the wire byte.
impl From<u8> for Tag {
    /// Converts the wire byte into the tag.
    fn from(value: u8) -> Self {
        match value {
            0 => Tag::DownloadPiece,
            1 => Tag::PieceContent,
            2 => Tag::DownloadPersistentPiece,
            3 => Tag::PersistentPieceContent,
            4 => Tag::DownloadPersistentCachePiece,
            5 => Tag::PersistentCachePieceContent,
            6 => Tag::DownloadCachePiece,
            7 => Tag::CachePieceContent,
            8..=253 => Tag::Reserved(value),
            254 => Tag::Close,
            255 => Tag::Error,
        }
    }
}

/// Implements the conversion into the wire byte.
impl From<Tag> for u8 {
    /// Converts the tag into the wire byte.
    fn from(tag: Tag) -> Self {
        match tag {
            Tag::DownloadPiece => 0,
            Tag::PieceContent => 1,
            Tag::DownloadPersistentPiece => 2,
            Tag::PersistentPieceContent => 3,
            Tag::DownloadPersistentCachePiece => 4,
            Tag::PersistentCachePieceContent => 5,
            Tag::DownloadCachePiece => 6,
            Tag::CachePieceContent => 7,
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
    fn tag_converts_from_and_into_every_range() {
        let test_cases = vec![
            (0, Tag::DownloadPiece),
            (1, Tag::PieceContent),
            (2, Tag::DownloadPersistentPiece),
            (3, Tag::PersistentPieceContent),
            (4, Tag::DownloadPersistentCachePiece),
            (5, Tag::PersistentCachePieceContent),
            (6, Tag::DownloadCachePiece),
            (7, Tag::CachePieceContent),
            (8, Tag::Reserved(8)),
            (253, Tag::Reserved(253)),
            (254, Tag::Close),
            (255, Tag::Error),
        ];

        for (value, tag) in test_cases {
            assert_eq!(Tag::from(value), tag);
            assert_eq!(u8::from(tag), value);
        }
    }
}
