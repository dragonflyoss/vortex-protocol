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
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;
use vortex_protocol::tlv::cache_piece_content::CachePieceContent;
use vortex_protocol::tlv::download_cache_piece::DownloadCachePiece;
use vortex_protocol::tlv::download_persistent_cache_piece::DownloadPersistentCachePiece;
use vortex_protocol::tlv::download_persistent_piece::DownloadPersistentPiece;
use vortex_protocol::tlv::download_piece::DownloadPiece;
use vortex_protocol::tlv::persistent_cache_piece_content::PersistentCachePieceContent;
use vortex_protocol::tlv::persistent_piece_content::PersistentPieceContent;
use vortex_protocol::tlv::piece_content::PieceContent;
use vortex_protocol::tlv::Tag;
use vortex_protocol::Vortex;

fn vortex_packet_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Vortex Packet Creation");

    group.bench_function("Create DownloadPiece Vortex", |b| {
        b.iter(|| {
            let tag = black_box(Tag::DownloadPiece);
            let value = black_box(
                DownloadPiece::new(
                    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                    42,
                )
                .into(),
            );

            let _ = Vortex::new(tag, value);
        });
    });

    group.bench_function("Create DownloadCachePiece Vortex", |b| {
        b.iter(|| {
            let tag = black_box(Tag::DownloadCachePiece);
            let value = black_box(
                DownloadCachePiece::new(
                    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                    42,
                )
                .into(),
            );

            let _ = Vortex::new(tag, value);
        });
    });

    group.bench_function("Create DownloadPersistentPiece Vortex", |b| {
        b.iter(|| {
            let tag = black_box(Tag::DownloadPersistentPiece);
            let value = black_box(
                DownloadPersistentPiece::new(
                    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                    42,
                )
                .into(),
            );

            let _ = Vortex::new(tag, value);
        });
    });

    group.bench_function("Create DownloadPersistentCachePiece Vortex", |b| {
        b.iter(|| {
            let tag = black_box(Tag::DownloadPersistentCachePiece);
            let value = black_box(
                DownloadPersistentCachePiece::new(
                    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                    42,
                )
                .into(),
            );

            let _ = Vortex::new(tag, value);
        });
    });

    group.finish();
}

fn vortex_packet_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("Vortex Packet Serialization");

    group.bench_function("Serialize PieceContent Packet", |b| {
        b.iter(|| {
            let piece_content = black_box(PieceContent::new(
                1,
                1,
                10,
                "crc32:864bbb04".to_string(),
                "127.0.0.1-foo".to_string(),
                1,
                Duration::from_secs(30),
                Utc::now().naive_utc(),
            ));

            let _bytes: Bytes = piece_content.into();
        });
    });

    group.bench_function("Serialize DownloadPiece Packet", |b| {
        b.iter(|| {
            let download_piece = black_box(DownloadPiece::new(
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                42,
            ));

            let _bytes: Bytes = download_piece.into();
        });
    });

    group.bench_function("Serialize CachePieceContent Packet", |b| {
        b.iter(|| {
            let cache_piece_content = black_box(CachePieceContent::new(
                1,
                1,
                10,
                "crc32:864bbb04".to_string(),
                "127.0.0.1-foo".to_string(),
                1,
                Duration::from_secs(30),
                Utc::now().naive_utc(),
            ));

            let _bytes: Bytes = cache_piece_content.into();
        });
    });

    group.bench_function("Serialize DownloadCachePiece Packet", |b| {
        b.iter(|| {
            let download_cache_piece = black_box(DownloadCachePiece::new(
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                42,
            ));

            let _bytes: Bytes = download_cache_piece.into();
        });
    });

    group.bench_function("Serialize PersistentPieceContent Packet", |b| {
        b.iter(|| {
            let persistent_piece_content = black_box(PersistentPieceContent::new(
                1,
                1,
                10,
                "crc32:864bbb04".to_string(),
                "127.0.0.1-foo".to_string(),
                1,
                Duration::from_secs(30),
                Utc::now().naive_utc(),
            ));

            let _bytes: Bytes = persistent_piece_content.into();
        });
    });

    group.bench_function("Serialize DownloadPersistentPiece Packet", |b| {
        b.iter(|| {
            let download_persistent_piece = black_box(DownloadPersistentPiece::new(
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                42,
            ));

            let _bytes: Bytes = download_persistent_piece.into();
        });
    });

    group.bench_function("Serialize PersistentCachePieceContent Packet", |b| {
        b.iter(|| {
            let persistent_cache_piece_content = black_box(PersistentCachePieceContent::new(
                1,
                1,
                10,
                "crc32:864bbb04".to_string(),
                "127.0.0.1-foo".to_string(),
                1,
                Duration::from_secs(30),
                Utc::now().naive_utc(),
            ));

            let _bytes: Bytes = persistent_cache_piece_content.into();
        });
    });

    group.bench_function("Serialize DownloadPersistentCachePiece Packet", |b| {
        b.iter(|| {
            let download_persistent_cache_piece = black_box(DownloadPersistentCachePiece::new(
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                42,
            ));

            let _bytes: Bytes = download_persistent_cache_piece.into();
        });
    });

    group.finish();
}

fn vortex_packet_deserialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("Vortex Packet Deserialization");

    group.bench_function("Deserialize PieceContent Packet", |b| {
        b.iter(|| {
            let bytes: Bytes = black_box(
                PieceContent::new(
                    1,
                    1,
                    10,
                    "crc32:864bbb04".to_string(),
                    "127.0.0.1-foo".to_string(),
                    1,
                    Duration::from_secs(30),
                    Utc::now().naive_utc(),
                )
                .into(),
            );

            let _piece_content: PieceContent = bytes.try_into().unwrap();
        });
    });

    group.bench_function("Deserialize DownloadPiece Packet", |b| {
        b.iter(|| {
            let bytes: Bytes = black_box(
                DownloadPiece::new(
                    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                    42,
                )
                .into(),
            );

            let _download_piece: DownloadPiece = bytes.try_into().unwrap();
        });
    });

    group.bench_function("Deserialize CachePieceContent Packet", |b| {
        b.iter(|| {
            let bytes: Bytes = black_box(
                CachePieceContent::new(
                    1,
                    1,
                    10,
                    "crc32:864bbb04".to_string(),
                    "127.0.0.1-foo".to_string(),
                    1,
                    Duration::from_secs(30),
                    Utc::now().naive_utc(),
                )
                .into(),
            );

            let _cache_piece_content: CachePieceContent = bytes.try_into().unwrap();
        });
    });

    group.bench_function("Deserialize DownloadCachePiece Packet", |b| {
        b.iter(|| {
            let bytes: Bytes = black_box(
                DownloadCachePiece::new(
                    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                    42,
                )
                .into(),
            );

            let _download_cache_piece: DownloadCachePiece = bytes.try_into().unwrap();
        });
    });

    group.bench_function("Deserialize PersistentPieceContent Packet", |b| {
        b.iter(|| {
            let bytes: Bytes = black_box(
                PersistentPieceContent::new(
                    1,
                    1,
                    10,
                    "crc32:864bbb04".to_string(),
                    "127.0.0.1-foo".to_string(),
                    1,
                    Duration::from_secs(30),
                    Utc::now().naive_utc(),
                )
                .into(),
            );

            let _persistent_piece_content: PersistentPieceContent = bytes.try_into().unwrap();
        });
    });

    group.bench_function("Deserialize DownloadPersistentPiece Packet", |b| {
        b.iter(|| {
            let bytes: Bytes = black_box(
                DownloadPersistentPiece::new(
                    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                    42,
                )
                .into(),
            );

            let _download_persistent_piece: DownloadPersistentPiece = bytes.try_into().unwrap();
        });
    });

    group.bench_function("Deserialize PersistentCachePieceContent Packet", |b| {
        b.iter(|| {
            let bytes: Bytes = black_box(
                PersistentCachePieceContent::new(
                    1,
                    1,
                    10,
                    "crc32:864bbb04".to_string(),
                    "127.0.0.1-foo".to_string(),
                    1,
                    Duration::from_secs(30),
                    Utc::now().naive_utc(),
                )
                .into(),
            );

            let _persistent_cache_piece_content: PersistentCachePieceContent =
                bytes.try_into().unwrap();
        });
    });

    group.bench_function("Deserialize DownloadPersistentCachePiece Packet", |b| {
        b.iter(|| {
            let bytes: Bytes = black_box(
                DownloadPersistentCachePiece::new(
                    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
                    42,
                )
                .into(),
            );

            let _download_persistent_cache_piece: DownloadPersistentCachePiece =
                bytes.try_into().unwrap();
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    vortex_packet_creation,
    vortex_packet_serialization,
    vortex_packet_deserialization
);

criterion_main!(benches);
