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
use std::convert::TryFrom;

/// MAX_PIECE_SIZE is the maximum size of a piece content (4 GiB).
const MAX_PIECE_SIZE: usize = crate::MAX_VALUE_SIZE;

/// PieceContent represents the content of a piece.
#[derive(Debug, Clone)]
pub struct PieceContent(Bytes);

/// PieceContent implements the PieceContent functions.
impl PieceContent {
    /// new creates a new piece content.
    pub fn new(content: Bytes) -> Result<Self> {
        // Check content length
        if content.len() > MAX_PIECE_SIZE {
            return Err(Error::InvalidLength(format!(
                "content length {} exceeds maximum size {}",
                content.len(),
                MAX_PIECE_SIZE
            )));
        }

        Ok(PieceContent(content))
    }

    /// len returns the length of the piece content.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// is_empty returns whether the piece content is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Implement TryFrom<Bytes> for PieceContent.
impl TryFrom<Bytes> for PieceContent {
    type Error = Error;

    fn try_from(bytes: Bytes) -> Result<Self> {
        Self::new(bytes)
    }
}

/// Implement From<PieceContent> for Bytes.
impl From<PieceContent> for Bytes {
    fn from(piece: PieceContent) -> Self {
        piece.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let content = vec![1, 2, 3, 4];
        let result = PieceContent::new(content.into());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 4);
    }

    #[test]
    fn test_is_empty() {
        let content = Bytes::new();
        let result = PieceContent::new(content);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_valid_conversion() {
        let content = vec![1, 2, 3, 4];
        let bytes = Bytes::from(content.clone());

        // Test TryFrom<Bytes>
        let piece_content = PieceContent::try_from(bytes.clone()).unwrap();

        // Test From<PieceContent> for Bytes
        let bytes_back: Bytes = piece_content.clone().into();
        assert_eq!(bytes_back, content);
    }

    #[test]
    fn test_invalid_conversion() {
        // Create bytes larger than MAX_PIECE_SIZE
        let large_content = vec![0; MAX_PIECE_SIZE + 1];
        let bytes = Bytes::from(large_content);

        // Test conversion fails
        let result = PieceContent::try_from(bytes);
        assert!(result.is_err());
        match result {
            Err(Error::InvalidLength(_)) => (),
            _ => panic!("Expected InvalidLength error"),
        }
    }
}
