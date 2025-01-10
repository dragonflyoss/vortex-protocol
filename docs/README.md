# Vortex

Vortex is a peer-to-peer (P2P) file transfer protocol that utilizes the TLV (Tag-Length-Value) format
for efficient and flexible data transmission. This protocol is designed to provide reliable and
scalable file sharing capabilities.

## Protocol Fields

- **Packet Identifier (8 bits):** Uniquely identifies each packet.
- **Tag (T, 7 bits):** Specifies the type of data in the value field.
- **Length (L, 30 bits):** Indicates the length (in bytes) of the Value field, supporting up to 1GiB of data.
- **Value (V, variable length):** The actual data, up to 1GiB.

## Tag Definitions

<!-- markdownlint-disable -->

| Tag   | Name             | Description                                                                                                    |
| ----- | ---------------- | -------------------------------------------------------------------------------------------------------------- |
| 0     | Piece Identifier | Composed of `{Task ID}-{Piece ID}`, where the Task ID is a 32-byte SHA-256 value and the Piece ID is a number. |
| 1     | Piece Content    | The content of a piece, with a maximum size of 1 GiB per piece.                                                |
| 2-126 | Reserved         | Reserved for future use.                                                                                       |
| 127   | Error            | Error message.                                                                                                 |

<!-- markdownlint-restore -->

## Packet Format

| Packet ID (8 bits) | Tag (7 bits) | Length (30 bits) | Value (up to 1GiB) |
| ------------------ | ------------ | ---------------- | ------------------ |
| 8-bit              | 7-bit        | 30-bit           | variable           |

- **Packet ID:** 8-bit unsigned integer.
- **Tag:** 7-bit field describing the content type.
- **Length:** 30-bit field specifying the size of the Value.
- **Value:** Actual data, size determined by Length.

## Behavior

- **Piece ID (Tag=0x00):** Identifies the specific piece of the file.
- **Piece Content (Tag=0x01):** Raw piece data or piece fragments.
- **Error (Tag=0x7F):** Conveys error.
- **Reserved Tags:** May be allocated for metadata, compression, encryption, or future protocol extensions.

## Example

- **Packet ID:** 0x12
- **Tag:** 0x00 (piece content)
- **Length:** 10 (indicating "HelloWorld" is 10 bytes)
- **Value:** "HelloWorld"
