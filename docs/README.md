# Vortex Protocol

Vortex protocol is a peer-to-peer (P2P) file transfer protocol that utilizes the TLV (Tag-Length-Value) format
for efficient and flexible data transmission. This protocol is designed to provide reliable and
scalable file sharing capabilities.

## Protocol Fields

- **Packet Identifier (8 bits):** Uniquely identifies each packet.
- **Tag (T, 8 bits):** Specifies the type of data in the value field.
- **Length (L, 32 bits):** Indicates the length (in bytes) of the Value field, supporting up to 4GiB of data.
- **Value (V, variable length):** The actual data, up to 1GiB.

## Tag Definitions

<!-- markdownlint-disable -->

| Tag   | Name           | Description                                                                                                                                                       |
| ----- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0     | Download Piece | Download the content of a piece from a peer. It is composed of `{Task ID}-{Piece ID}`, where the Task ID is a 32-byte SHA-256 value and the Piece ID is a number. |
| 1     | Piece Content  | The content of a piece, with a maximum size of 1 GiB per piece.                                                                                                   |
| 2-253 | Reserved       | Reserved for future use.                                                                                                                                          |
| 254   | Close          | Close connection.                                                                                                                                                 |
| 255   | Error          | Error message.                                                                                                                                                    |

<!-- markdownlint-restore -->

## Packet Format

| Packet ID (8 bits) | Tag (8 bits) | Length (32 bits) | Value (up to 4GiB) |
| ------------------ | ------------ | ---------------- | ------------------ |
| 8-bit              | 8-bit        | 32-bit           | variable           |

- **Packet ID:** 8-bit unsigned integer.
- **Tag:** 8-bit field describing the content type.
- **Length:** 32-bit field specifying the size of the Value.
- **Value:** Actual data, size determined by Length.

## Behavior

- **Download Piece (Tag=0x00):** Download the content of a piece from a peer.
- **Piece Content (Tag=0x01):** Raw piece data or piece fragments.
- **Error (Tag=0xFF):** Conveys error.
- **Close (Tag=0xFE):** Indicates the end of a connection.
- **Reserved Tags:** Tags 2-253 may be allocated for metadata, compression, encryption, or future protocol extensions.

## Example

- **Packet ID:** 0x12
- **Tag:** 0x00 (Download Piece)
- **Length:** 10 (indicating "HelloWorld" is 10 bytes)
- **Value:** "HelloWorld"
