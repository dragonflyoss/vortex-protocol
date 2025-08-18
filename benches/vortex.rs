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
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vortex_protocol::tlv::Tag;
use vortex_protocol::Vortex;

fn vortex_packet_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Vortex Packet Creation");

    group.bench_function("Create Small Packet (32 bytes)", |b| {
        b.iter(|| {
            let tag = black_box(Tag::PieceContent);
            let value = black_box(Bytes::from("a".repeat(32)));
            let _ = Vortex::new(tag, value);
        });
    });

    group.bench_function("Create Medium Packet (1 KB)", |b| {
        b.iter(|| {
            let tag = black_box(Tag::PieceContent);
            let value = black_box(Bytes::from("a".repeat(1024)));
            let _ = Vortex::new(tag, value);
        });
    });

    group.bench_function("Create Large Packet (1 MB)", |b| {
        b.iter(|| {
            let tag = black_box(Tag::PieceContent);
            let value = black_box(Bytes::from("a".repeat(1024 * 1024)));
            let _ = Vortex::new(tag, value);
        });
    });

    group.bench_function("Create XLarge Packet (16 MB)", |b| {
        b.iter(|| {
            let tag = black_box(Tag::PieceContent);
            let value = black_box(Bytes::from("a".repeat(16 * 1024 * 1024)));
            let _ = Vortex::new(tag, value);
        });
    });

    group.bench_function("Create XXLarge Packet (128 MB)", |b| {
        b.iter(|| {
            let tag = black_box(Tag::PieceContent);
            let value = black_box(Bytes::from("a".repeat(128 * 1024 * 1024)));
            let _ = Vortex::new(tag, value);
        });
    });

    group.finish();
}

fn vortex_packet_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("Vortex Packet Serialization");

    group.bench_function("Serialize Small Packet (32 bytes)", |b| {
        let tag = Tag::PieceContent;
        let value = Bytes::from("a".repeat(32));
        let packet = Vortex::new(tag, value).unwrap();
        b.iter(|| {
            black_box(Bytes::from(packet.clone()));
        });
    });

    group.bench_function("Serialize Medium Packet (1 KB)", |b| {
        let tag = Tag::PieceContent;
        let value = Bytes::from("a".repeat(1024));
        let packet = Vortex::new(tag, value).unwrap();
        b.iter(|| {
            black_box(Bytes::from(packet.clone()));
        });
    });

    group.bench_function("Serialize Large Packet (1 MB)", |b| {
        let tag = Tag::PieceContent;
        let value = Bytes::from("a".repeat(1024 * 1024));
        let packet = Vortex::new(tag, value).unwrap();
        b.iter(|| {
            black_box(Bytes::from(packet.clone()));
        });
    });

    group.bench_function("Serialize XLarge Packet (16 MB)", |b| {
        let tag = Tag::PieceContent;
        let value = Bytes::from("a".repeat(16 * 1024 * 1024));
        let packet = Vortex::new(tag, value).unwrap();
        b.iter(|| {
            black_box(Bytes::from(packet.clone()));
        });
    });

    group.bench_function("Serialize XXLarge Packet (128 MB)", |b| {
        let tag = Tag::PieceContent;
        let value = Bytes::from("a".repeat(128 * 1024 * 1024));
        let packet = Vortex::new(tag, value).unwrap();
        b.iter(|| {
            black_box(Bytes::from(packet.clone()));
        });
    });

    group.finish();
}

fn vortex_packet_deserialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("Vortex Packet Deserialization");

    group.bench_function("Deserialize Small Packet (32 bytes)", |b| {
        let tag = Tag::PieceContent;
        let value = Bytes::from("a".repeat(32));
        let packet = Vortex::new(tag, value).unwrap();
        let bytes: Bytes = packet.into();
        b.iter(|| {
            black_box(Vortex::try_from(bytes.clone()).unwrap());
        });
    });

    group.bench_function("Deserialize Medium Packet (1 KB)", |b| {
        let tag = Tag::PieceContent;
        let value = Bytes::from("a".repeat(1024));
        let packet = Vortex::new(tag, value).unwrap();
        let bytes: Bytes = packet.into();
        b.iter(|| {
            black_box(Vortex::try_from(bytes.clone()).unwrap());
        });
    });

    group.bench_function("Deserialize Large Packet (1 MB)", |b| {
        let tag = Tag::PieceContent;
        let value = Bytes::from("a".repeat(1024 * 1024));
        let packet = Vortex::new(tag, value).unwrap();
        let bytes: Bytes = packet.into();
        b.iter(|| {
            black_box(Vortex::try_from(bytes.clone()).unwrap());
        });
    });

    group.bench_function("Deserialize XLarge Packet (16 MB)", |b| {
        let tag = Tag::PieceContent;
        let value = Bytes::from("a".repeat(16 * 1024 * 1024));
        let packet = Vortex::new(tag, value).unwrap();
        let bytes: Bytes = packet.into();
        b.iter(|| {
            black_box(Vortex::try_from(bytes.clone()).unwrap());
        });
    });

    group.bench_function("Deserialize XXLarge Packet (128 MB)", |b| {
        let tag = Tag::PieceContent;
        let value = Bytes::from("a".repeat(128 * 1024 * 1024));
        let packet = Vortex::new(tag, value).unwrap();
        let bytes: Bytes = packet.into();
        b.iter(|| {
            black_box(Vortex::try_from(bytes.clone()).unwrap());
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
