# Vortex Protocol

[![LICENSE](https://img.shields.io/github/license/dragonflyoss/vortex-protocol.svg?style=flat-square)](https://github.com/dragonflyoss/vortex-protocol/blob/main/LICENSE)
[![Discussions](https://img.shields.io/badge/discussions-on%20github-blue?style=flat-square)](https://github.com/dragonflyoss/dragonfly/discussions)

## Introduction

Vortex protocol is a high-performance peer-to-peer (P2P) file transfer protocol implementation in Rust,
designed as part of the Dragonfly project. It utilizes the TLV (Tag-Length-Value) format for
efficient and flexible data transmission, making it ideal for large-scale file distribution scenarios.

### Features

- **Efficient TLV Protocol**: Optimized for fast serialization and deserialization of data packets.
- **Large File Support**: Handles piece sizes up to 1 GiB and value fields up to 4 GiB.
- **Memory Safety**: Built in Rust with zero-cost abstractions and memory safety guarantees.
- **High Performance**: Designed for high-throughput file transfer scenarios.
- **Extensible Design**: Reserved tags for future protocol extensions like compression and encryption.

## Usage

Every TLV value implements `Message`, which encodes into any `BufMut` and decodes from a byte
slice. `encode_packet` prepends the packet header; `Vortex::decode` parses a whole packet.

```rust
use bytes::BytesMut;
use vortex_protocol::tlv::download_piece::DownloadPiece;
use vortex_protocol::{Message, Vortex, HEADER_SIZE};

let request = DownloadPiece::new("a".repeat(64), 1);
let mut buffer = BytesMut::with_capacity(HEADER_SIZE + request.encoded_len());
request.encode_packet(&mut buffer);

match Vortex::decode(&buffer)? {
    Vortex::DownloadPiece(header, request) => println!("{} {:?}", header.length(), request),
    packet => println!("unexpected packet {packet:?}"),
}
```

The wire format is stable across releases: peers running different versions of the crate
interoperate, and `tests/wire_format.rs` pins the bytes produced by earlier releases.

## Documentation

For details, please see [the specification](docs/README.md).

## Benchmarking

Vortex protocol includes benchmarks for encoding and decoding every message and whole packets:

```bash
# Run all benchmarks
cargo bench

# Run the benchmarks of one message
cargo bench PieceContent
```
