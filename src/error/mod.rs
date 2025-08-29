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

/// Error is the error type for the Vortex protocol.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// InvalidPacket indicates an invalid Vortex packet.
    #[error("invalid vortex packet, cause: {0}")]
    InvalidPacket(String),

    /// InvalidLength indicates an invalid length.
    #[error("invalid length, cause: {0}")]
    InvalidLength(String),

    /// InvalidTag indicates an invalid tag.
    #[error("invalid tag: {0}")]
    InvalidTag(String),

    /// TryFromSliceError indicates a conversion error.
    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),

    /// Utf8Error indicates a conversion error.
    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),

    /// ParseIntError indicates a conversion error.
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),

    /// FromUtf8Error indicates a conversion error.
    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
}

/// Result is the result type for the Vortex protocol.
pub type Result<T> = std::result::Result<T, Error>;
