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

#![allow(clippy::type_complexity)]

use bytes::BytesMut;
use chrono::DateTime;
use std::time::Duration;
use vortex_protocol::tlv::download_cache_piece::DownloadCachePiece;
use vortex_protocol::tlv::download_persistent_cache_piece::DownloadPersistentCachePiece;
use vortex_protocol::tlv::download_persistent_piece::DownloadPersistentPiece;
use vortex_protocol::tlv::download_piece::DownloadPiece;
use vortex_protocol::tlv::error::{Code, Error};
use vortex_protocol::tlv::piece_content::PieceContent;
use vortex_protocol::tlv::piece_metadata::PieceMetadata;
use vortex_protocol::tlv::{Tag, TASK_ID_SIZE};
use vortex_protocol::{Message, Vortex, HEADER_SIZE};

const DOWNLOAD_PIECE: [u8; 68] = [
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x01, 0x02, 0x03, 0x04,
];

const PIECE_CONTENT: [u8; 76] = [
    0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x63, 0x72, 0x63, 0x33,
    0x32, 0x3A, 0x38, 0x36, 0x34, 0x62, 0x62, 0x62, 0x30, 0x34, 0x00, 0x00, 0x00, 0x0D, 0x31, 0x32,
    0x37, 0x2E, 0x30, 0x2E, 0x30, 0x2E, 0x31, 0x2D, 0x66, 0x6F, 0x6F, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x65, 0x53, 0xF1, 0x00,
];

const ERROR: [u8; 16] = [
    0x02, 0x70, 0x69, 0x65, 0x63, 0x65, 0x20, 0x6E, 0x6F, 0x74, 0x20, 0x66, 0x6F, 0x75, 0x6E, 0x64,
];

#[test]
fn messages_encode_to_the_bytes_of_previous_releases() {
    let piece_content = PieceContent {
        metadata: PieceMetadata {
            number: 42,
            offset: 1024,
            length: 2048,
            digest: "crc32:864bbb04".to_string(),
            parent_id: "127.0.0.1-foo".to_string(),
            traffic_type: 1,
            cost: Duration::from_secs(30),
            created_at: DateTime::from_timestamp(1_700_000_000, 0)
                .unwrap()
                .naive_utc(),
        },
    };

    let mut download_piece = BytesMut::new();
    DownloadPiece::new("a".repeat(TASK_ID_SIZE), 0x0102_0304).encode(&mut download_piece);
    let mut download_cache_piece = BytesMut::new();
    DownloadCachePiece::new("a".repeat(TASK_ID_SIZE), 0x0102_0304)
        .encode(&mut download_cache_piece);
    let mut download_persistent_piece = BytesMut::new();
    DownloadPersistentPiece::new("a".repeat(TASK_ID_SIZE), 0x0102_0304)
        .encode(&mut download_persistent_piece);
    let mut download_persistent_cache_piece = BytesMut::new();
    DownloadPersistentCachePiece::new("a".repeat(TASK_ID_SIZE), 0x0102_0304)
        .encode(&mut download_persistent_cache_piece);
    let mut encoded_piece_content = BytesMut::new();
    piece_content.encode(&mut encoded_piece_content);
    let mut error = BytesMut::new();
    Error::new(Code::NotFound, "piece not found".to_string()).encode(&mut error);

    let test_cases: Vec<(BytesMut, &[u8])> = vec![
        (download_piece, &DOWNLOAD_PIECE),
        (download_cache_piece, &DOWNLOAD_PIECE),
        (download_persistent_piece, &DOWNLOAD_PIECE),
        (download_persistent_cache_piece, &DOWNLOAD_PIECE),
        (encoded_piece_content, &PIECE_CONTENT),
        (error, &ERROR),
    ];

    for (encoded, expected) in test_cases {
        assert_eq!(&encoded[..], expected);
    }
}

#[test]
fn packets_decode_from_the_bytes_of_previous_releases() {
    let mut download_piece = vec![0x2A, 0x00, 0x00, 0x00, 0x00, 0x44];
    download_piece.extend_from_slice(&DOWNLOAD_PIECE);
    let mut download_cache_piece = vec![0x2A, 0x06, 0x00, 0x00, 0x00, 0x44];
    download_cache_piece.extend_from_slice(&DOWNLOAD_PIECE);
    let mut piece_content = vec![0x2A, 0x01, 0x00, 0x00, 0x00, 0x4C];
    piece_content.extend_from_slice(&PIECE_CONTENT);
    let mut error = vec![0x2A, 0xFF, 0x00, 0x00, 0x00, 0x10];
    error.extend_from_slice(&ERROR);
    let close = vec![0x2A, 0xFE, 0x00, 0x00, 0x00, 0x00];

    let test_cases: Vec<(Vec<u8>, Tag, fn(Vortex))> = vec![
        (download_piece, Tag::DownloadPiece, |packet| match packet {
            Vortex::DownloadPiece(_, request) => {
                assert_eq!(request.task_id, "a".repeat(TASK_ID_SIZE));
                assert_eq!(request.piece_number, 0x0102_0304);
            }
            packet => panic!("unexpected packet {packet:?}"),
        }),
        (
            download_cache_piece,
            Tag::DownloadCachePiece,
            |packet| match packet {
                Vortex::DownloadCachePiece(_, request) => {
                    assert_eq!(request.task_id, "a".repeat(TASK_ID_SIZE));
                    assert_eq!(request.piece_number, 0x0102_0304);
                }
                packet => panic!("unexpected packet {packet:?}"),
            },
        ),
        (piece_content, Tag::PieceContent, |packet| match packet {
            Vortex::PieceContent(_, content) => {
                assert_eq!(content.metadata.number, 42);
                assert_eq!(content.metadata.offset, 1024);
                assert_eq!(content.metadata.length, 2048);
                assert_eq!(content.metadata.digest, "crc32:864bbb04");
                assert_eq!(content.metadata.parent_id, "127.0.0.1-foo");
                assert_eq!(content.metadata.traffic_type, 1);
                assert_eq!(content.metadata.cost, Duration::from_secs(30));
                assert_eq!(
                    content.metadata.created_at.and_utc().timestamp(),
                    1_700_000_000
                );
            }
            packet => panic!("unexpected packet {packet:?}"),
        }),
        (error, Tag::Error, |packet| match packet {
            Vortex::Error(_, error) => {
                assert_eq!(error.code, Code::NotFound);
                assert_eq!(error.message, "piece not found");
            }
            packet => panic!("unexpected packet {packet:?}"),
        }),
        (close, Tag::Close, |packet| {
            assert!(matches!(packet, Vortex::Close(_)))
        }),
    ];

    for (bytes, expected_tag, expect) in test_cases {
        let packet = Vortex::decode(&bytes).unwrap();
        assert_eq!(packet.header().id(), 0x2A);
        assert_eq!(packet.header().tag(), expected_tag);
        assert_eq!(packet.header().length() as usize, bytes.len() - HEADER_SIZE);

        let mut encoded = BytesMut::new();
        packet.encode(&mut encoded);
        assert_eq!(&encoded[..], &bytes[..]);
        expect(packet);
    }
}
