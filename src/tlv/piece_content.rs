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
use bytes::Bytes;

/// PieceContent represents the content of a piece.
#[derive(Debug, Clone)]
pub struct PieceContent(bytes::Bytes);

/// PieceContent implements the PieceContent functions.
impl PieceContent {
    /// new creates a new PieceContent request.
    pub fn new(content: Bytes) -> Self {
        PieceContent(content)
    }

    /// len returns the length of the piece content request.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// is_empty returns whether the piece content request is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// from_bytes creates a piece content request from a byte slice.
    pub fn from_bytes(bytes: Bytes) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::InvalidLength("piece content is empty".to_string()));
        }

        Ok(PieceContent(bytes))
    }

    /// to_bytes converts the piece content request to a byte slice.
    pub fn to_bytes(&self) -> bytes::Bytes {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_new() {
        let content = Bytes::from("test content");
        let piece_content = PieceContent::new(content.clone());

        assert_eq!(piece_content.len(), content.len());
        assert_eq!(piece_content.to_bytes(), content);
    }

    #[test]
    fn test_is_empty() {
        let empty_content = PieceContent::new(Bytes::new());
        let non_empty_content = PieceContent::new(Bytes::from("test content"));

        assert!(empty_content.is_empty());
        assert!(!non_empty_content.is_empty());
    }

    #[test]
    fn test_to_bytes_and_from_bytes() {
        let content = Bytes::from("test content");
        let piece_content = PieceContent::new(content.clone());

        let bytes = piece_content.to_bytes();
        let piece_content_decoded = PieceContent::from_bytes(bytes).unwrap();

        assert_eq!(piece_content_decoded.len(), content.len());
        assert_eq!(piece_content_decoded.to_bytes(), content);
    }

    #[test]
    fn test_from_bytes_invalid_input() {
        // Test empty content.
        let empty_bytes = Bytes::new();
        assert!(PieceContent::from_bytes(empty_bytes).is_err());
    }
}
