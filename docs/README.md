# Vortex Protocol

Vortex protocol is a peer-to-peer (P2P) file transfer protocol that utilizes the TLV (Tag-Length-Value) format
for efficient and flexible data transmission. This protocol is designed to provide reliable and
scalable file sharing capabilities.

## Protocol Fields

- **Packet Identifier (1 bytes):** Uniquely identifies each packet.
- **Tag (T, 1 bytes):** Specifies the type of data in the value field.
- **Length (L, 4 bytes):** Indicates the length (in bytes) of the Value field, supporting up to 4GiB of data.
- **Value (V, variable length):** The actual data, up to 4GiB.

## Tag Definitions

<!-- markdownlint-disable -->

| Tag   | Name                            | Description                                                                                                                                                               |
| ----- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0     | Download Piece                  | Download the content of a piece from a peer. It is composed of `{Task ID}{Piece ID}`, where the Task ID is a SHA-256 value and the Piece ID is a number.                  |
| 1     | Piece Content                   | The content of a piece, with a maximum size of 1 GiB per piece.                                                                                                           |
| 2     | Download Persistent Cache Piece | Download the content of a persistent cache piece from a peer. It is composed of `{Task ID}{Piece ID}`, where the Task ID is a SHA-256 value and the Piece ID is a number. |
| 3     | Persistent Cache Piece Content  | The content of a persistent cache piece, with a maximum size of 1 GiB per piece.                                                                                          |
| 4-253 | Reserved                        | Reserved for future use.                                                                                                                                                  |
| 254   | Close                           | Close connection.                                                                                                                                                         |
| 255   | Error                           | Error message.                                                                                                                                                            |

<!-- markdownlint-restore -->

## Packet Format

| Packet ID (1 bytes) | Tag (1 bytes) | Length (4 bytes) | Value (up to 4GiB) |
| ------------------- | ------------- | ---------------- | ------------------ |
| 1-bytes             | 1-bytes       | 4-bytes          | variable           |

- **Packet ID:** 1-bytes unsigned integer.
- **Tag:** 1-bytes field describing the content type.
- **Length:** 4-bytes field specifying the size of the Value.
- **Value:** Actual data, size determined by Length.

## Behavior

- **Download Piece (Tag=0x00):** Download the content of a piece from a peer.
- **Piece Content (Tag=0x01):** Raw piece data or piece fragments.
- **Download Persistent Cache Piece (Tag=0x02):** Download the content of a persistent cache piece from a peer.
- **Persistent Cache Piece Content (Tag=0x03):** Raw persistent cache piece data or persistent cache piece fragments.
- **Error (Tag=0xFF):** Conveys error.
- **Close (Tag=0xFE):** Indicates the end of a connection.
- **Reserved Tags:** Tags 4-253 may be allocated for metadata, compression, encryption, or future protocol extensions.

## Example

- **Packet ID:** 0x12
- **Tag:** 0x00 (Download Piece)
- **Length:** 10 (indicating "HelloWorld" is 10 bytes)
- **Value:** "HelloWorld"
