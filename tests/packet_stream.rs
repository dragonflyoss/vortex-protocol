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
use vortex_protocol::tlv::cache_piece_content::CachePieceContent;
use vortex_protocol::tlv::download_cache_piece::DownloadCachePiece;
use vortex_protocol::tlv::download_persistent_cache_piece::DownloadPersistentCachePiece;
use vortex_protocol::tlv::download_persistent_piece::DownloadPersistentPiece;
use vortex_protocol::tlv::download_piece::DownloadPiece;
use vortex_protocol::tlv::persistent_cache_piece_content::PersistentCachePieceContent;
use vortex_protocol::tlv::persistent_piece_content::PersistentPieceContent;
use vortex_protocol::tlv::piece_content::PieceContent;
use vortex_protocol::tlv::piece_metadata::PieceMetadata;
use vortex_protocol::tlv::{Tag, TASK_ID_SIZE};
use vortex_protocol::{Header, Message, Vortex, HEADER_SIZE};

#[test]
fn every_download_request_is_answered_with_the_matching_content() {
    let mut download_piece = BytesMut::new();
    DownloadPiece::new("a".repeat(TASK_ID_SIZE), 1).encode_packet(&mut download_piece);
    let mut download_cache_piece = BytesMut::new();
    DownloadCachePiece::new("b".repeat(TASK_ID_SIZE), 2).encode_packet(&mut download_cache_piece);
    let mut download_persistent_piece = BytesMut::new();
    DownloadPersistentPiece::new("c".repeat(TASK_ID_SIZE), 3)
        .encode_packet(&mut download_persistent_piece);
    let mut download_persistent_cache_piece = BytesMut::new();
    DownloadPersistentCachePiece::new("d".repeat(TASK_ID_SIZE), 4)
        .encode_packet(&mut download_persistent_cache_piece);

    let test_cases: Vec<(BytesMut, Tag, fn(Vortex) -> PieceMetadata)> = vec![
        (download_piece, Tag::PieceContent, |packet| match packet {
            Vortex::PieceContent(_, content) => content.metadata,
            packet => panic!("unexpected packet {packet:?}"),
        }),
        (
            download_cache_piece,
            Tag::CachePieceContent,
            |packet| match packet {
                Vortex::CachePieceContent(_, content) => content.metadata,
                packet => panic!("unexpected packet {packet:?}"),
            },
        ),
        (
            download_persistent_piece,
            Tag::PersistentPieceContent,
            |packet| match packet {
                Vortex::PersistentPieceContent(_, content) => content.metadata,
                packet => panic!("unexpected packet {packet:?}"),
            },
        ),
        (
            download_persistent_cache_piece,
            Tag::PersistentCachePieceContent,
            |packet| match packet {
                Vortex::PersistentCachePieceContent(_, content) => content.metadata,
                packet => panic!("unexpected packet {packet:?}"),
            },
        ),
    ];

    for (request, expected_tag, into_metadata) in test_cases {
        let header = Header::decode(&request[..HEADER_SIZE]).unwrap();
        let piece_number =
            match Vortex::decode(&request[..HEADER_SIZE + header.length() as usize]).unwrap() {
                Vortex::DownloadPiece(_, request) => request.piece_number,
                Vortex::DownloadCachePiece(_, request) => request.piece_number,
                Vortex::DownloadPersistentPiece(_, request) => request.piece_number,
                Vortex::DownloadPersistentCachePiece(_, request) => request.piece_number,
                packet => panic!("unexpected packet {packet:?}"),
            };
        let metadata = PieceMetadata {
            number: piece_number,
            offset: piece_number as u64 * 4096,
            length: 4096,
            digest: "crc32:864bbb04".to_string(),
            parent_id: "127.0.0.1-foo".to_string(),
            traffic_type: 1,
            cost: Duration::from_secs(30),
            created_at: DateTime::from_timestamp(1_700_000_000, 0)
                .unwrap()
                .naive_utc(),
        };

        let mut response = BytesMut::new();
        match expected_tag {
            Tag::PieceContent => PieceContent {
                metadata: metadata.clone(),
            }
            .encode_packet(&mut response),
            Tag::CachePieceContent => CachePieceContent {
                metadata: metadata.clone(),
            }
            .encode_packet(&mut response),
            Tag::PersistentPieceContent => PersistentPieceContent {
                metadata: metadata.clone(),
            }
            .encode_packet(&mut response),
            Tag::PersistentCachePieceContent => PersistentCachePieceContent {
                metadata: metadata.clone(),
            }
            .encode_packet(&mut response),
            tag => panic!("unexpected tag {tag:?}"),
        }

        let header = Header::decode(&response[..HEADER_SIZE]).unwrap();
        assert_eq!(header.tag(), expected_tag);
        assert_eq!(header.length() as usize, response.len() - HEADER_SIZE);

        let packet = Vortex::decode(&response).unwrap();
        assert_eq!(packet.header(), &header);
        assert_eq!(into_metadata(packet), metadata);
    }
}

#[test]
fn pipelined_packets_are_framed_by_the_header_length() {
    let mut wire = BytesMut::new();
    DownloadPiece::new("a".repeat(TASK_ID_SIZE), 1).encode_packet(&mut wire);
    Header::new(Tag::Reserved(200), 3).encode(&mut wire);
    wire.extend_from_slice(&[0xAB; 3]);
    DownloadPersistentPiece::new("b".repeat(TASK_ID_SIZE), 2).encode_packet(&mut wire);
    Header::new(Tag::Close, 0).encode(&mut wire);
    let complete = wire.len();
    DownloadCachePiece::new("c".repeat(TASK_ID_SIZE), 3).encode_packet(&mut wire);
    wire.truncate(wire.len() - 1);

    let mut tags = Vec::new();
    let mut rest = &wire[..];
    while rest.len() >= HEADER_SIZE {
        let header = Header::decode(&rest[..HEADER_SIZE]).unwrap();
        let end = HEADER_SIZE + header.length() as usize;
        if rest.len() < end {
            break;
        }

        tags.push(Vortex::decode(&rest[..end]).unwrap().header().tag());
        rest = &rest[end..];
    }

    assert_eq!(
        tags,
        vec![
            Tag::DownloadPiece,
            Tag::Reserved(200),
            Tag::DownloadPersistentPiece,
            Tag::Close
        ]
    );
    assert_eq!(rest, &wire[complete..]);
    assert!(Vortex::decode(rest).is_err());
}
