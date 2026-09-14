use sandsurf_protocol::*;
use serde_json::json;
use std::io::{self, Read};

#[test]
fn identifiers_and_counters_are_strict() {
    for value in ["", ".", "..", "a/b", "a\\b", "hello world", "é", "a\0b"] {
        assert!(SandboxId::try_from(value).is_err());
    }
    assert!(SandboxId::try_from("x".repeat(129)).is_err());
    assert!(SandboxId::try_from("test-01_A").is_ok());
    assert!(Counter::try_from(Counter::MAX).unwrap().next().is_err());
    for invalid in [
        json!(-1),
        json!(1.5),
        json!(9_007_199_254_740_992u64),
        json!("1"),
    ] {
        assert!(serde_json::from_value::<Counter>(invalid).is_err());
    }
}

#[test]
fn digest_domains_are_disjoint_and_stable() {
    let domains = [
        Domain::Sandbox,
        Domain::Grant,
        Domain::Operation,
        Domain::Receipt,
        Domain::Output,
        Domain::Release,
        Domain::Image,
        Domain::Checkpoint,
        Domain::Transfer,
    ];
    let mut seen = std::collections::HashSet::new();
    for domain in domains {
        let first = digest(domain, &json!({"z":1,"a":[true,null,"é"]})).unwrap();
        let second = digest(domain, &json!({"a":[true,null,"é"],"z":1})).unwrap();
        assert_eq!(first, second);
        assert!(seen.insert(first.as_str().to_owned()));
    }
    assert!(digest(Domain::Operation, &json!(0.5)).is_err());
}

#[test]
fn unknown_mutation_fields_and_reference_only_release_are_rejected() {
    let mutation = json!({"sandboxId":"box","epoch":1,"operationId":"op","grantId":"grant","expectedRevision":1,"requestDigest":"a".repeat(64)});
    assert!(serde_json::from_value::<Mutation>(mutation.clone()).is_ok());
    let mut invalid = mutation;
    invalid["currentGrants"] = json!([]);
    assert!(serde_json::from_value::<Mutation>(invalid).is_err());
    assert!(
        serde_json::from_value::<ReleaseRequest>(json!({"receiptDigest":"a".repeat(64)})).is_err()
    );
}

#[test]
fn fragmented_binary_frames_roundtrip_and_reject_all_truncations() {
    let frame = Frame {
        kind: FrameKind::Data,
        stream: 19,
        sequence: Counter::ONE,
        payload: vec![0, 255, 128, 10, 13, 0],
    };
    let mut encoded = Vec::new();
    frame.write(&mut encoded).unwrap();
    struct Fragmented<'a>(&'a [u8]);
    impl Read for Fragmented<'_> {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let length = bytes.len().min(1);
            self.0.read(&mut bytes[..length])
        }
    }
    assert_eq!(Frame::read(&mut Fragmented(&encoded)).unwrap(), Some(frame));
    assert_eq!(Frame::read(&mut &b""[..]).unwrap(), None);
    for length in 1..encoded.len() {
        assert!(Frame::read(&mut &encoded[..length]).is_err());
    }
}

#[test]
fn reject_oversize_headers_without_reading_payload() {
    let frame = Frame {
        kind: FrameKind::Control,
        stream: 0,
        sequence: Counter::ZERO,
        payload: Vec::new(),
    };
    let mut encoded = Vec::new();
    frame.write(&mut encoded).unwrap();
    encoded[20..24].copy_from_slice(&u32::MAX.to_be_bytes());
    let error = Frame::read(&mut &encoded[..]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    for (offset, value) in [(0, b'X'), (5, 2), (6, 255), (7, 1), (11, 1)] {
        let mut invalid = Vec::new();
        frame.write(&mut invalid).unwrap();
        invalid[offset] = value;
        assert!(Frame::read(&mut &invalid[..]).is_err());
    }
}

#[test]
fn frame_kind_bounds_and_credit_are_independent() {
    let mut credits = Credits::default();
    credits.open(1).unwrap();
    credits.open(2).unwrap();
    assert!(credits.open(1).is_err());
    assert!(credits.open(0).is_err());
    credits.grant(1, 64).unwrap();
    assert!(credits.consume(2, 1).is_err());
    credits.consume(1, 64).unwrap();
    assert!(credits.consume(1, 1).is_err());
    assert!(credits.grant(1, MAX_CREDIT + 1).is_err());
    credits.grant(1, MAX_CREDIT).unwrap();
    assert!(credits.grant(1, u64::MAX).is_err());
    credits.close(1).unwrap();
    assert!(credits.consume(1, 1).is_err());
    let mut wire = Vec::new();
    Frame {
        kind: FrameKind::Control,
        stream: 0,
        sequence: Counter::ONE,
        payload: b"terminate".to_vec(),
    }
    .write(&mut wire)
    .unwrap();
    assert!(Frame::read(&mut &wire[..]).unwrap().is_some());
    for (kind, stream, payload) in [
        (FrameKind::Data, 0, vec![1]),
        (FrameKind::Data, 1, vec![]),
        (FrameKind::Data, 1, vec![0; MAX_STREAM_BYTES + 1]),
        (FrameKind::End, 1, vec![1]),
        (FrameKind::Credit, 1, vec![0; 7]),
    ] {
        assert!(
            Frame {
                kind,
                stream,
                sequence: Counter::ZERO,
                payload
            }
            .write(&mut Vec::new())
            .is_err()
        );
    }
}

#[test]
fn fuzz_bounded_headers_and_json_never_panic() {
    let mut seed = 0x9e3779b97f4a7c15u64;
    for length in 0..1024 {
        let mut bytes = vec![0; length];
        for byte in &mut bytes {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *byte = seed as u8;
        }
        let _ = Frame::read(&mut &bytes[..]);
        let _ = serde_json::from_slice::<Mutation>(&bytes);
        let _ = serde_json::from_slice::<ReleaseRequest>(&bytes);
    }
}
