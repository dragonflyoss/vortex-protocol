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
use vortex_protocol::tlv::cache_piece_content::CachePieceContent;
use vortex_protocol::tlv::download_cache_piece::DownloadCachePiece;
use vortex_protocol::tlv::download_persistent_cache_piece::DownloadPersistentCachePiece;
use vortex_protocol::tlv::download_persistent_piece::DownloadPersistentPiece;
use vortex_protocol::tlv::download_piece::DownloadPiece;
use vortex_protocol::tlv::persistent_cache_piece_content::PersistentCachePieceContent;
use vortex_protocol::tlv::persistent_piece_content::PersistentPieceContent;
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
        Vortex::DownloadPersistentPiece(_header, download_persistent_piece) => {
            let content = "persistent piece content".as_bytes();
            let persistent_piece_content = PersistentPieceContent::new(
                download_persistent_piece.piece_number(),
                1,
                content.len() as u64,
                "crc32:864bbb04".to_string(),
                "127.0.0.1-foo".to_string(),
                1,
                Duration::from_secs(30),
                Utc::now().naive_utc(),
            );

            let persistent_piece_content_bytes: Bytes = persistent_piece_content.clone().into();
            let header = Header::new(
                Tag::PersistentPieceContent,
                (persistent_piece_content_bytes.len() + content.len()) as u32,
            );

            Ok(Vortex::PersistentPieceContent(
                header,
                persistent_piece_content,
            ))
        }
        Vortex::DownloadPersistentCachePiece(_header, download_persistent_cache_piece) => {
            let content = "persistent cache piece content".as_bytes();
            let persistent_cache_piece_content = PersistentCachePieceContent::new(
                download_persistent_cache_piece.piece_number(),
                1,
                content.len() as u64,
                "crc32:864bbb04".to_string(),
                "127.0.0.1-foo".to_string(),
                1,
                Duration::from_secs(30),
                Utc::now().naive_utc(),
            );

            let persistent_cache_piece_content_bytes: Bytes =
                persistent_cache_piece_content.clone().into();
            let header = Header::new(
                Tag::PersistentCachePieceContent,
                (persistent_cache_piece_content_bytes.len() + content.len()) as u32,
            );

            Ok(Vortex::PersistentCachePieceContent(
                header,
                persistent_cache_piece_content,
            ))
        }
        Vortex::DownloadCachePiece(_header, download_cache_piece) => {
            let content = "cache piece content".as_bytes();
            let cache_piece_content = CachePieceContent::new(
                download_cache_piece.piece_number(),
                1,
                content.len() as u64,
                "crc32:864bbb04".to_string(),
                "127.0.0.1-foo".to_string(),
                1,
                Duration::from_secs(30),
                Utc::now().naive_utc(),
            );

            let cache_piece_content_bytes: Bytes = cache_piece_content.clone().into();
            let header = Header::new(
                Tag::CachePieceContent,
                (cache_piece_content_bytes.len() + content.len()) as u32,
            );

            Ok(Vortex::CachePieceContent(header, cache_piece_content))
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

#[test]
fn test_persistent_piece_download_flow() {
    let download_persistent_piece_packet = Vortex::DownloadPersistentPiece(
        Header::new_download_persistent_piece(),
        DownloadPersistentPiece::new("a".repeat(64), 1),
    );

    match handle_packet(download_persistent_piece_packet.into()).unwrap() {
        Vortex::PersistentPieceContent(_header, persistent_piece_content) => {
            assert_eq!(persistent_piece_content.metadata().number, 1);
            assert_eq!(persistent_piece_content.metadata().offset, 1);
            assert_eq!(persistent_piece_content.metadata().length, 24);
            assert_eq!(persistent_piece_content.metadata().digest, "crc32:864bbb04");
            assert_eq!(
                persistent_piece_content.metadata().parent_id,
                "127.0.0.1-foo"
            );
            assert_eq!(persistent_piece_content.metadata().traffic_type, 1);
            assert_eq!(
                persistent_piece_content.metadata().cost,
                Duration::from_secs(30)
            );
            assert!(persistent_piece_content.metadata().created_at <= Utc::now().naive_utc());
            assert_eq!(persistent_piece_content.metadata_len(), 72);
        }
        _ => panic!("expected PersistentPieceContent packet"),
    }
}

#[test]
fn test_persistent_cache_piece_download_flow() {
    let download_persistent_cache_piece_packet = Vortex::DownloadPersistentCachePiece(
        Header::new_download_persistent_cache_piece(),
        DownloadPersistentCachePiece::new("a".repeat(64), 1),
    );

    match handle_packet(download_persistent_cache_piece_packet.into()).unwrap() {
        Vortex::PersistentCachePieceContent(_header, persistent_cache_piece_content) => {
            assert_eq!(persistent_cache_piece_content.metadata().number, 1);
            assert_eq!(persistent_cache_piece_content.metadata().offset, 1);
            assert_eq!(persistent_cache_piece_content.metadata().length, 30);
            assert_eq!(
                persistent_cache_piece_content.metadata().digest,
                "crc32:864bbb04"
            );
            assert_eq!(
                persistent_cache_piece_content.metadata().parent_id,
                "127.0.0.1-foo"
            );
            assert_eq!(persistent_cache_piece_content.metadata().traffic_type, 1);
            assert_eq!(
                persistent_cache_piece_content.metadata().cost,
                Duration::from_secs(30)
            );
            assert!(persistent_cache_piece_content.metadata().created_at <= Utc::now().naive_utc());
            assert_eq!(persistent_cache_piece_content.metadata_len(), 72);
        }
        _ => panic!("expected PersistentCachePieceContent packet"),
    }
}

#[test]
fn test_cache_piece_download_flow() {
    let download_cache_piece_packet = Vortex::DownloadCachePiece(
        Header::new_download_cache_piece(),
        DownloadCachePiece::new("a".repeat(64), 1),
    );

    match handle_packet(download_cache_piece_packet.into()).unwrap() {
        Vortex::CachePieceContent(_header, cache_piece_content) => {
            assert_eq!(cache_piece_content.metadata().number, 1);
            assert_eq!(cache_piece_content.metadata().offset, 1);
            assert_eq!(cache_piece_content.metadata().length, 19);
            assert_eq!(cache_piece_content.metadata().digest, "crc32:864bbb04");
            assert_eq!(cache_piece_content.metadata().parent_id, "127.0.0.1-foo");
            assert_eq!(cache_piece_content.metadata().traffic_type, 1);
            assert_eq!(cache_piece_content.metadata().cost, Duration::from_secs(30));
            assert!(cache_piece_content.metadata().created_at <= Utc::now().naive_utc());
            assert_eq!(cache_piece_content.metadata_len(), 72);
        }
        _ => panic!("expected CachePieceContent packet"),
    }
}
