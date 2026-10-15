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

/// The error of the Vortex protocol.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The error when a packet or a value is malformed.
    #[error("invalid vortex packet, cause: {0}")]
    InvalidPacket(String),

    /// The error when a length does not match the declared or expected size.
    #[error("invalid length, cause: {0}")]
    InvalidLength(String),

    /// The error when a text field is not valid UTF-8.
    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
}

/// The result of the Vortex protocol.
pub type Result<T> = std::result::Result<T, Error>;
