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
use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use vortex_protocol::tlv::download_piece::DownloadPiece;
use vortex_protocol::tlv::Tag;
use vortex_protocol::Vortex;

/// Generate valid value bytes based on tag.
fn generate_value_bytes(tag: Tag) -> Bytes {
    match tag {
        Tag::DownloadPiece => {
            let task_id = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
            let piece_id = 42;
            let download_piece = DownloadPiece::new(task_id.to_string(), piece_id);

            download_piece.into()
        }
        Tag::Close => {
            // Close tag can be empty.
            vec![].into()
        }
        Tag::Error => {
            // Error format is "code:message".
            format!("{}test error", 1u8).into_bytes().into()
        }
        Tag::Reserved(_) => {
            // Reserved tags can have any format.
            vec![].into()
        }
        _ => {
            // For other tags, return empty bytes.
            vec![].into()
        }
    }
}

/// Generate arbitrary valid packets.
fn arb_packet() -> impl Strategy<Value = Vortex> {
    let arb_tag = prop_oneof![Just(Tag::DownloadPiece), Just(Tag::Close), Just(Tag::Error)];

    arb_tag.prop_map(|tag| {
        let value = generate_value_bytes(tag);
        Vortex::new(tag, value).expect("Failed to create packet")
    })
}

/// Run tests with custom configuration to minimize output.
fn run_test<F>(test: F)
where
    F: Fn(Vortex) -> Result<(), TestCaseError>,
{
    let config = ProptestConfig {
        max_shrink_iters: 0,       // Disable shrinking to reduce output
        cases: 100,                // Reduce number of test cases
        failure_persistence: None, // Don't persist failures
        ..Default::default()
    };

    let mut runner = TestRunner::new(config);
    runner.run(&arb_packet(), test).unwrap();
}

#[test]
fn test_roundtrip_serialization() {
    run_test(|packet| {
        let id = packet.id();
        let tag = packet.tag();
        let length = packet.length();

        let serialized: Bytes = packet.into();
        let deserialized: Vortex = serialized.try_into().expect("Failed to deserialize packet");

        prop_assert_eq!(id, deserialized.id());
        prop_assert_eq!(tag, deserialized.tag());
        prop_assert_eq!(length, deserialized.length());
        Ok(())
    });
}

#[test]
fn test_packet_length() {
    run_test(|packet| {
        let length = packet.length();

        let bytes: Bytes = packet.into();
        prop_assert_eq!(bytes.len(), length + 6); // header size is 6
        Ok(())
    });
}

#[test]
fn test_packet_value_constraints() {
    run_test(|packet| {
        let tag = packet.tag();

        let bytes: Bytes = packet.into();
        prop_assert!(bytes.len() >= 6);
        prop_assert!(matches!(
            tag,
            Tag::DownloadPiece | Tag::PieceContent | Tag::Error | Tag::Close
        ));
        Ok(())
    });
}
