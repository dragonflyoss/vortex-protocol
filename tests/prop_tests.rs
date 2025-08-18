use bytes::Bytes;
use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use vortex_protocol::tlv::Tag;
use vortex_protocol::Vortex;

/// Generate valid value bytes based on tag.
fn generate_value_bytes(tag: Tag) -> Bytes {
    match tag {
        Tag::DownloadPiece => {
            // Task ID must be 32 bytes (64 hex chars).
            let task_id = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
            let piece_id = 42;
            format!("{}-{}", task_id, piece_id).into_bytes().into()
        }
        Tag::PieceContent => {
            // PieceContent can be any bytes.
            vec![1, 2, 3, 4].into()
        }
        Tag::Close => {
            // Close tag can be empty.
            vec![].into()
        }
        Tag::Error => {
            // Error format is "code:message".
            format!("{}:test error", 1u8).into_bytes().into()
        }
        Tag::Reserved(_) => {
            // Reserved tags can have any format.
            vec![].into()
        }
    }
}

/// Generate arbitrary valid packets.
fn arb_packet() -> impl Strategy<Value = Vortex> {
    let arb_tag = prop_oneof![
        Just(Tag::DownloadPiece),
        Just(Tag::PieceContent),
        Just(Tag::Close),
        Just(Tag::Error)
    ];

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
        let tag = *packet.tag();
        let length = packet.length();

        let serialized: Bytes = packet.into();
        let deserialized: Vortex = serialized.try_into().expect("Failed to deserialize packet");

        prop_assert_eq!(id, deserialized.id());
        prop_assert_eq!(tag, *deserialized.tag());
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
        let tag = *packet.tag();

        let bytes: Bytes = packet.into();
        prop_assert!(bytes.len() >= 6);
        prop_assert!(matches!(
            tag,
            Tag::DownloadPiece | Tag::PieceContent | Tag::Error | Tag::Close
        ));
        Ok(())
    });
}
