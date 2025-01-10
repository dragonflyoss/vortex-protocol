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

/// Vortex Protocol
///
/// Vortex is a peer-to-peer (P2P) file transfer protocol using TLV (Tag-Length-Value) format for
/// efficient and flexible data transmission. Designed for reliable and scalable file sharing.
///
/// Packet Format:
///     - Packet Identifier (8 bits): Uniquely identifies each packet
///     - Tag (7 bits): Specifies data type in value field
///     - Length (30 bits): Indicates Value field length, up to 1 GiB
///     - Value (variable): Actual data content, maximum 1 GiB
///
/// Protocol Format:
///
/// ```text
/// -------------------------------------------------------------------------------------------------
/// |                            |                   |                    |                         |
/// | Packet Identifier (8 bits) |    Tag (7 bits)   |  Length (30 bits)  |   Value (up to 1 GiB)   |
/// |                            |                   |                    |                         |
/// -------------------------------------------------------------------------------------------------
/// ```
///
/// For more information, please refer to the [Vortex Protocol](https://github.com/dragonflyoss/vortex/blob/main/docs/README.md).
#[derive(Debug, Clone)]
pub struct Vortex {}
