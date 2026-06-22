//! Wire-protocol tests for `ce-drive/v1`: round-trip encode/decode of every request and reply
//! variant, error-code stability, malformed-input handling, and property/fuzz round-trips
//! (including money/size values above 2^53 which JSON could not carry but bincode can).
//!
//! The wire types are the contract between `ce-drive-serve` (host) and `ce-drive-client` (consumer);
//! a silent drift here corrupts every op, so they are pinned exhaustively.

use ce_drive_serve::{
    Beacon, Change, ChangeKind, ChunkRef, DriveErr, DriveOk, DriveOp, DriveReply, DriveReq, Entry,
    EntryKind, Quota, ReadPlan, ShareCaveats, changes_topic, decode_reply, decode_req,
    encode_reply, encode_req, DRIVE_TOPIC,
};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// constants / topics
// ---------------------------------------------------------------------------

#[test]
fn drive_topic_is_stable() {
    // This string is the libp2p AppRequest topic; changing it silently breaks all clients.
    assert_eq!(DRIVE_TOPIC, "ce-drive/v1");
}

#[test]
fn changes_topic_is_per_drive_and_stable() {
    assert_eq!(changes_topic("team"), "ce-drive/team/changes");
    assert_eq!(changes_topic(""), "ce-drive//changes");
    // Different drives never collide.
    assert_ne!(changes_topic("a"), changes_topic("b"));
}

// ---------------------------------------------------------------------------
// request round-trips: every DriveOp variant
// ---------------------------------------------------------------------------

fn rt_req(op: DriveOp) {
    let req = DriveReq { drive: "team".into(), cap: "deadbeef".into(), op };
    let bytes = encode_req(&req);
    assert!(!bytes.is_empty(), "encode produced no bytes");
    let back = decode_req(&bytes).expect("decode");
    // bincode is deterministic: re-encoding the decoded value must be byte-identical.
    assert_eq!(encode_req(&back), bytes);
    assert_eq!(back.drive, "team");
    assert_eq!(back.cap, "deadbeef");
}

#[test]
fn every_request_op_round_trips() {
    rt_req(DriveOp::Open);
    rt_req(DriveOp::Stat { path: "/a/b".into() });
    rt_req(DriveOp::List { path: "/a".into(), cursor: Some("x".into()), limit: 10 });
    rt_req(DriveOp::List { path: "/a".into(), cursor: None, limit: 0 });
    rt_req(DriveOp::Read { path: "/f".into(), offset: 0, len: None });
    rt_req(DriveOp::Read { path: "/f".into(), offset: u64::MAX, len: Some(u64::MAX) });
    rt_req(DriveOp::Write {
        path: "/f".into(),
        object_cid: "cid".into(),
        size: u64::MAX, // > 2^53, must survive bincode
        base_etag: Some("e".into()),
    });
    rt_req(DriveOp::Mkdir { path: "/d".into() });
    rt_req(DriveOp::Move { from: "/a".into(), to: "/b".into() });
    rt_req(DriveOp::Copy { from: "/a".into(), to: "/b".into() });
    rt_req(DriveOp::Delete { path: "/d".into(), recursive: true });
    rt_req(DriveOp::Delete { path: "/d".into(), recursive: false });
    rt_req(DriveOp::Share {
        path: "/d".into(),
        audience: "abcd".into(),
        abilities: vec!["drive:read".into(), "drive:write".into()],
        caveats: ShareCaveats {
            not_after: u64::MAX,
            max_bytes_read: Some(u64::MAX),
            max_bytes_write: None,
        },
    });
    rt_req(DriveOp::Poll { cursor: Some(u64::MAX), limit: 500 });
    rt_req(DriveOp::Poll { cursor: None, limit: 1 });
    rt_req(DriveOp::Watch);
}

// ---------------------------------------------------------------------------
// reply round-trips: every DriveOk + DriveErr variant
// ---------------------------------------------------------------------------

fn rt_reply(reply: DriveReply) {
    let bytes = encode_reply(&reply);
    assert!(!bytes.is_empty());
    let back = decode_reply(&bytes).expect("decode reply");
    assert_eq!(encode_reply(&back), bytes, "reply re-encode must be deterministic");
}

fn sample_entry() -> Entry {
    Entry {
        path: "/docs/spec.bin".into(),
        kind: EntryKind::File,
        size: u64::MAX, // > 2^53
        mtime_ms: 1_700_000_000_000,
        etag: "cid:123".into(),
        node_id: "n1".into(),
        object_cid: Some("cid".into()),
        doc_id: Some("doc".into()),
    }
}

#[test]
fn every_ok_reply_round_trips() {
    rt_reply(DriveReply::ok(DriveOk::Opened {
        drive_root_cid: "cid".into(),
        server_seq: u64::MAX,
        granted_abilities: vec!["drive:read".into(), "drive:admin".into()],
        quota: Quota {
            price_per_gib_month: "1000000000000000000000".into(), // > u64, decimal string
            price_per_gib_egress: "0".into(),
            free_tier_bytes: u64::MAX,
            channel_required: true,
        },
    }));
    rt_reply(DriveReply::ok(DriveOk::Entry(sample_entry())));
    rt_reply(DriveReply::ok(DriveOk::Listing {
        entries: vec![sample_entry(), sample_entry()],
        next_cursor: Some("c".into()),
    }));
    rt_reply(DriveReply::ok(DriveOk::Listing { entries: vec![], next_cursor: None }));
    rt_reply(DriveReply::ok(DriveOk::ReadPlan(ReadPlan {
        object_cid: "cid".into(),
        total_size: u64::MAX,
        chunk_size: 1 << 20,
        chunks: vec![ChunkRef { cid: "c0".into(), offset: 0, len: u64::MAX }],
        encrypted: true,
        key_hint: Some("gen-2".into()),
    })));
    rt_reply(DriveReply::ok(DriveOk::Written {
        etag: "e".into(),
        node_id: "n".into(),
        version_seq: u64::MAX,
    }));
    rt_reply(DriveReply::ok(DriveOk::Made { node_id: "n".into() }));
    rt_reply(DriveReply::ok(DriveOk::Deleted));
    rt_reply(DriveReply::ok(DriveOk::Shared { chain: "abcd".into() }));
    rt_reply(DriveReply::ok(DriveOk::Changes {
        changes: vec![Change {
            seq: u64::MAX,
            path: "/x".into(),
            node_id: "n".into(),
            kind: ChangeKind::Moved { from: "/y".into() },
            etag: "e".into(),
        }],
        new_cursor: u64::MAX,
    }));
    rt_reply(DriveReply::ok(DriveOk::Watching { topic: "t".into(), cursor: 7 }));
}

#[test]
fn every_err_reply_round_trips() {
    for e in [
        DriveErr::Unauthorized,
        DriveErr::Revoked,
        DriveErr::Expired,
        DriveErr::OutOfScope,
        DriveErr::NotFound,
        DriveErr::Conflict { current_etag: "etag".into() },
        DriveErr::QuotaExceeded,
        DriveErr::PaymentRequired,
        DriveErr::BadPath,
        DriveErr::Internal("boom".into()),
    ] {
        rt_reply(DriveReply::err(e.clone()));
        // The Result wrapper survives too.
        let bytes = encode_reply(&DriveReply::err(e.clone()));
        let back = decode_reply(&bytes).unwrap();
        assert_eq!(back.result.unwrap_err(), e);
    }
}

// ---------------------------------------------------------------------------
// error code + Display stability (clients key on these)
// ---------------------------------------------------------------------------

#[test]
fn error_codes_match_http_semantics_and_are_unique() {
    let pairs = [
        (DriveErr::Unauthorized, 401u16),
        (DriveErr::Revoked, 410),
        (DriveErr::Expired, 419),
        (DriveErr::OutOfScope, 403),
        (DriveErr::NotFound, 404),
        (DriveErr::Conflict { current_etag: "e".into() }, 409),
        (DriveErr::QuotaExceeded, 429),
        (DriveErr::PaymentRequired, 402),
        (DriveErr::BadPath, 400),
        (DriveErr::Internal("x".into()), 500),
    ];
    let mut seen = std::collections::HashSet::new();
    for (err, code) in &pairs {
        assert_eq!(err.code(), *code, "{err:?}");
        assert!(seen.insert(*code), "code {code} is duplicated");
        // Display never panics and is non-empty.
        assert!(!err.to_string().is_empty());
    }
}

#[test]
fn conflict_display_includes_etag() {
    let e = DriveErr::Conflict { current_etag: "cid:99".into() };
    assert!(e.to_string().contains("cid:99"));
}

// ---------------------------------------------------------------------------
// malformed / truncated input handling — must Err, never panic
// ---------------------------------------------------------------------------

#[test]
fn decode_empty_request_errs() {
    assert!(decode_req(&[]).is_err());
}

#[test]
fn decode_garbage_request_errs_not_panics() {
    // Random bytes are overwhelmingly not a valid bincode DriveReq.
    let garbage = vec![0xFFu8; 7];
    let _ = decode_req(&garbage); // must not panic
    assert!(decode_req(&[0xFF, 0xFF, 0xFF, 0xFF]).is_err());
}

#[test]
fn decode_truncated_request_errs() {
    let req = DriveReq {
        drive: "team".into(),
        cap: "deadbeef".into(),
        op: DriveOp::Stat { path: "/a/b/c".into() },
    };
    let bytes = encode_req(&req);
    // Truncate to half — bincode must reject the short buffer.
    let truncated = &bytes[..bytes.len() / 2];
    assert!(decode_req(truncated).is_err());
}

#[test]
fn decode_truncated_reply_errs() {
    let reply = DriveReply::ok(DriveOk::Entry(sample_entry()));
    let bytes = encode_reply(&reply);
    assert!(decode_reply(&bytes[..bytes.len() / 2]).is_err());
    assert!(decode_reply(&[]).is_err());
}

#[test]
fn beacon_round_trips() {
    let b = Beacon { drive: "team".into(), max_seq: u64::MAX };
    let bytes = bincode::serialize(&b).unwrap();
    let back: Beacon = bincode::deserialize(&bytes).unwrap();
    assert_eq!(back.drive, "team");
    assert_eq!(back.max_seq, u64::MAX);
}

// ---------------------------------------------------------------------------
// property/fuzz: arbitrary requests and replies always round-trip
// ---------------------------------------------------------------------------

fn arb_path() -> impl Strategy<Value = String> {
    // Mix of normal paths, empty, weird unicode, and big segment counts.
    prop_oneof![
        "/[a-z0-9/]{0,40}",
        Just("/".to_string()),
        Just(String::new()),
        "[\\PC]{0,20}",
    ]
}

fn arb_op() -> impl Strategy<Value = DriveOp> {
    prop_oneof![
        Just(DriveOp::Open),
        arb_path().prop_map(|path| DriveOp::Stat { path }),
        (arb_path(), proptest::option::of("[a-z]{0,8}"), any::<u32>())
            .prop_map(|(path, cursor, limit)| DriveOp::List { path, cursor, limit }),
        (arb_path(), any::<u64>(), proptest::option::of(any::<u64>()))
            .prop_map(|(path, offset, len)| DriveOp::Read { path, offset, len }),
        (arb_path(), "[a-f0-9]{0,64}", any::<u64>(), proptest::option::of("[a-z0-9:]{0,16}"))
            .prop_map(|(path, object_cid, size, base_etag)| DriveOp::Write {
                path,
                object_cid,
                size,
                base_etag,
            }),
        arb_path().prop_map(|path| DriveOp::Mkdir { path }),
        (arb_path(), arb_path()).prop_map(|(from, to)| DriveOp::Move { from, to }),
        (arb_path(), arb_path()).prop_map(|(from, to)| DriveOp::Copy { from, to }),
        (arb_path(), any::<bool>()).prop_map(|(path, recursive)| DriveOp::Delete { path, recursive }),
        (arb_path(), "[a-f0-9]{0,64}", proptest::collection::vec("[a-z:]{1,12}", 0..4))
            .prop_map(|(path, audience, abilities)| DriveOp::Share {
                path,
                audience,
                abilities,
                caveats: ShareCaveats::default(),
            }),
        (proptest::option::of(any::<u64>()), any::<u32>())
            .prop_map(|(cursor, limit)| DriveOp::Poll { cursor, limit }),
        Just(DriveOp::Watch),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn arbitrary_request_round_trips(drive in "[a-z0-9-]{0,24}", cap in "[a-f0-9]{0,80}", op in arb_op()) {
        let req = DriveReq { drive, cap, op };
        let bytes = encode_req(&req);
        let back = decode_req(&bytes).expect("decode arbitrary request");
        // Encode is canonical: decode(encode(x)) re-encodes to the same bytes (idempotent codec).
        prop_assert_eq!(encode_req(&back), bytes);
    }

    /// Fuzz: decoding arbitrary bytes never panics (returns Ok or Err, both fine).
    #[test]
    fn decode_random_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = decode_req(&bytes);
        let _ = decode_reply(&bytes);
    }
}
