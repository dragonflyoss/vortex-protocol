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

/// Close represents a close message.
#[derive(Debug, Clone)]
pub struct Close();

/// Close implements the Close functions.
impl Close {
    /// new creates a new close.
    pub fn new() -> Result<Self> {
        Ok(Close())
    }

    /// len returns zero, because close message is empty.
    pub fn len(&self) -> usize {
        0
    }

    /// is_empty returns true, because close message is empty.
    pub fn is_empty(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let result = Close::new();

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_is_empty() {
        let result = Close::new();

        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
