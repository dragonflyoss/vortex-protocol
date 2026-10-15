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
| 2     | Download Persistent Piece       | Download the content of a persistent piece from a peer. It is composed of `{Task ID}{Piece ID}`, where the Task ID is a SHA-256 value and the Piece ID is a number.       |
| 3     | Persistent Piece Content        | The content of a persistent piece, with a maximum size of 1 GiB per piece.                                                                                                |
| 4     | Download Persistent Cache Piece | Download the content of a persistent cache piece from a peer. It is composed of `{Task ID}{Piece ID}`, where the Task ID is a SHA-256 value and the Piece ID is a number. |
| 5     | Persistent Cache Piece Content  | The content of a persistent cache piece, with a maximum size of 1 GiB per piece.                                                                                          |
| 6     | Download Cache Piece            | Download the content of a cache piece from a peer. It is composed of `{Task ID}{Piece ID}`, where the Task ID is a SHA-256 value and the Piece ID is a number.            |
| 7     | Cache Piece Content             | The content of a cache piece, with a maximum size of 1 GiB per piece.                                                                                                     |
| 8-253 | Reserved                        | Reserved for future use.                                                                                                                                                  |
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

## Value Formats

All integers are unsigned and big-endian unless noted. Strings are UTF-8 and are not
terminated.

### Download Piece, Download Persistent Piece, Download Persistent Cache Piece, Download Cache Piece

| Task ID (64 bytes)                   | Piece Number (4 bytes) |
| ------------------------------------ | ---------------------- |
| hex SHA-256 digest of the task, text | unsigned integer       |

The value is exactly 68 bytes.

### Piece Content, Persistent Piece Content, Persistent Cache Piece Content, Cache Piece Content

| Field            | Size     | Description                                                   |
| ---------------- | -------- | ------------------------------------------------------------- |
| Metadata Length  | 4 bytes  | Length of the metadata that follows.                          |
| Number           | 4 bytes  | Piece number.                                                 |
| Offset           | 8 bytes  | Byte offset of the piece in the task.                         |
| Length           | 8 bytes  | Length of the piece content in bytes.                         |
| Digest Length    | 4 bytes  | Length of the digest.                                         |
| Digest           | variable | Digest of the piece content, such as `crc32:864bbb04`.        |
| Parent ID Length | 4 bytes  | Length of the parent ID.                                      |
| Parent ID        | variable | ID of the parent the piece was downloaded from, may be empty. |
| Traffic Type     | 1 byte   | Traffic type of the download.                                 |
| Cost             | 8 bytes  | Download cost in whole seconds.                               |
| Created At       | 8 bytes  | Creation time as signed Unix epoch seconds.                   |

The packet value carries only the metadata, and its Length field counts only the metadata.
The piece content itself, whose size is the Length field of the metadata, follows the packet
on the same connection. A decoder ignores any bytes between the end of the fields above and
the end of the declared Metadata Length, so later releases may append fields.

### Error

| Error Code (1 byte) | Error Message (variable) |
| ------------------- | ------------------------ |
| see below           | UTF-8 text, may be empty |

| Code  | Name             | Description                                                   |
| ----- | ---------------- | ------------------------------------------------------------- |
| 0     | Unknown          | Unknown error.                                                |
| 1     | Invalid Argument | Invalid argument, such as an invalid task ID or piece number. |
| 2     | Not Found        | Resource not found, such as a missing piece.                  |
| 3     | Internal         | Internal error.                                               |
| 4-255 | Reserved         | Reserved for future use.                                      |

### Close and Reserved

The value of a Close packet is empty. The value of a packet with a reserved tag is ignored,
so a peer can skip packets it does not understand by reading the Length field.

## Behavior

- **Download Piece (Tag=0x00):** Download the content of a piece from a peer.
- **Piece Content (Tag=0x01):** The metadata of a piece, followed by the piece content on the connection.
- **Download Persistent Piece (Tag=0x02):** Download the content of a persistent piece from a peer.
- **Persistent Piece Content (Tag=0x03):** The metadata of a persistent piece, followed by the piece content on the connection.
- **Download Persistent Cache Piece (Tag=0x04):** Download the content of a persistent cache piece from a peer.
- **Persistent Cache Piece Content (Tag=0x05):** The metadata of a persistent cache piece, followed by the piece content on the connection.
- **Download Cache Piece (Tag=0x06):** Download the content of a cache piece from a peer.
- **Cache Piece Content (Tag=0x07):** The metadata of a cache piece, followed by the piece content on the connection.
- **Error (Tag=0xFF):** Conveys an error code and message.
- **Close (Tag=0xFE):** Indicates the end of a connection.
- **Reserved Tags:** Tags 8-253 may be allocated for metadata, compression, encryption, or future protocol extensions.

## Example

A Download Piece packet for piece 1 of a task:

- **Packet ID:** 0x12
- **Tag:** 0x00 (Download Piece)
- **Length:** 68
- **Value:** the 64-byte hex task ID followed by the 4-byte piece number `00 00 00 01`
