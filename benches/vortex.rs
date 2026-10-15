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

use bytes::BytesMut;
use chrono::DateTime;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;
use vortex_protocol::tlv::download_piece::DownloadPiece;
use vortex_protocol::tlv::error::{Code, Error};
use vortex_protocol::tlv::piece_content::PieceContent;
use vortex_protocol::tlv::piece_metadata::PieceMetadata;
use vortex_protocol::tlv::Tag;
use vortex_protocol::tlv::TASK_ID_SIZE;
use vortex_protocol::{Header, Message, Vortex};

fn piece_content() -> PieceContent {
    PieceContent {
        metadata: PieceMetadata {
            number: 1,
            offset: 1,
            length: 10,
            digest: "crc32:864bbb04".to_string(),
            parent_id: "127.0.0.1-foo".to_string(),
            traffic_type: 1,
            cost: Duration::from_secs(30),
            created_at: DateTime::from_timestamp(1_700_000_000, 0)
                .unwrap()
                .naive_utc(),
        },
    }
}

fn bench_message<M: Message + Clone>(c: &mut Criterion, name: &str, message: M) {
    let mut group = c.benchmark_group(name);
    let mut buffer = BytesMut::with_capacity(message.encoded_len());

    group.bench_function("encode", |b| {
        b.iter(|| {
            buffer.clear();
            black_box(&message).encode(&mut buffer);
            black_box(&buffer);
        })
    });

    group.bench_function("encode_packet", |b| {
        b.iter(|| {
            buffer.clear();
            black_box(&message).encode_packet(&mut buffer);
            black_box(&buffer);
        })
    });

    buffer.clear();
    message.encode(&mut buffer);
    group.bench_function("decode", |b| {
        b.iter(|| black_box(M::decode(black_box(&buffer))).unwrap())
    });
    group.finish();
}

fn messages(c: &mut Criterion) {
    bench_message(
        c,
        "DownloadPiece",
        DownloadPiece::new("a".repeat(TASK_ID_SIZE), 42),
    );
    bench_message(c, "PieceContent", piece_content());
    bench_message(
        c,
        "Error",
        Error::new(Code::NotFound, "piece not found".to_string()),
    );
}

fn packets(c: &mut Criterion) {
    let mut group = c.benchmark_group("Vortex");
    let packet = Vortex::PieceContent(Header::new(Tag::PieceContent, 0), piece_content());
    let mut buffer = BytesMut::with_capacity(packet.encoded_len());

    group.bench_function("encode", |b| {
        b.iter(|| {
            buffer.clear();
            black_box(&packet).encode(&mut buffer);
            black_box(&buffer);
        })
    });

    buffer.clear();
    packet.encode(&mut buffer);
    group.bench_function("decode", |b| {
        b.iter(|| black_box(Vortex::decode(black_box(&buffer))).unwrap())
    });
    group.finish();
}

criterion_group!(benches, messages, packets);
criterion_main!(benches);
