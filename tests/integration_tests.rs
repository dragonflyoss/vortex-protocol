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

use bytes::Bytes;
use chrono::Utc;
use std::time::Duration;
use vortex_protocol::error::{Error, Result};
use vortex_protocol::tlv::download_piece::DownloadPiece;
use vortex_protocol::tlv::piece_content::PieceContent;
use vortex_protocol::tlv::Tag;
use vortex_protocol::{Header, Vortex};

pub fn handle_packet(bytes: Bytes) -> Result<Vortex> {
    match bytes.try_into()? {
        Vortex::DownloadPiece(_header, download_piece) => {
            let content = "piece content".as_bytes();
            let piece_content = PieceContent::new(
                download_piece.piece_number(),
                1,
                content.len() as u64,
                "crc32:864bbb04".to_string(),
                "127.0.0.1-foo".to_string(),
                1,
                Duration::from_secs(30),
                Utc::now().naive_utc(),
            );

            let piece_content_bytes: Bytes = piece_content.clone().into();
            let header = Header::new(
                Tag::PieceContent,
                (piece_content_bytes.len() + content.len()) as u32,
            );

            Ok(Vortex::PieceContent(header, piece_content))
        }
        _ => Err(Error::InvalidPacket("unexpected tag".to_string())),
    }
}

#[test]
fn test_piece_download_flow() {
    let download_piece_packet = Vortex::DownloadPiece(
        Header::new_download_piece(),
        DownloadPiece::new("a".repeat(64), 1),
    );

    match handle_packet(download_piece_packet.into()).unwrap() {
        Vortex::PieceContent(_header, piece_content) => {
            assert_eq!(piece_content.metadata().number, 1);
            assert_eq!(piece_content.metadata().offset, 1);
            assert_eq!(piece_content.metadata().length, 13);
            assert_eq!(piece_content.metadata().digest, "crc32:864bbb04");
            assert_eq!(piece_content.metadata().parent_id, "127.0.0.1-foo");
            assert_eq!(piece_content.metadata().traffic_type, 1);
            assert_eq!(piece_content.metadata().cost, Duration::from_secs(30));
            assert!(piece_content.metadata().created_at <= Utc::now().naive_utc());
            assert_eq!(piece_content.metadata_len(), 72);
        }
        _ => panic!("expected PieceContent packet"),
    }
}
