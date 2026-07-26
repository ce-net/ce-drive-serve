//! Cross-language golden vectors for the `ce-drive/v1` wire.
//!
//! `wire_roundtrip.rs` proves the Rust encoder is self-consistent — it round-trips whatever it
//! produces. That cannot catch the failure that actually matters to a client: the Rust side
//! changing what it produces at all. Every non-Rust SDK hand-implements bincode (little-endian
//! fixed-width integers, `u64` sequence lengths, `u32` enum variant indices, `Option` as a leading
//! 0/1 byte), so a field reorder, an inserted enum variant, or a bincode config change is invisible
//! to a round-trip test and silently corrupts every op for every other language.
//!
//! The constants below are the SAME literals asserted by `sdk/py/test_cedrive.py`. They were
//! computed by hand from the encoding rules, not generated from either implementation, so neither
//! side can quietly ratify its own drift. If one encoder moves, exactly one of the two suites goes
//! red — which is the whole point.
//!
//! Adding an SDK means asserting these same vectors in that language. Do not regenerate them to
//! make a test pass: a diff here is a BREAKING WIRE CHANGE and every deployed client is affected.

use ce_drive_serve::{
    DriveErr, DriveOk, DriveOp, DriveReply, DriveReq, ShareCaveats, encode_reply, encode_req,
};

/// Every golden request carries drive `"team"` and cap `"deadbeef"`:
///   "team"     -> u64 len 4 + utf8 -> 0400000000000000 7465616d
///   "deadbeef" -> u64 len 8 + utf8 -> 0800000000000000 6465616462656566
const REQ_PREFIX: &str = "04000000000000007465616d08000000000000006465616462656566";

fn req(op: DriveOp) -> String {
    hex::encode(encode_req(&DriveReq {
        drive: "team".into(),
        cap: "deadbeef".into(),
        op,
    }))
}

fn golden(suffix: &str) -> String {
    format!("{REQ_PREFIX}{suffix}")
}

// ---------------------------------------------------------------------------
// requests: every DriveOp variant
// ---------------------------------------------------------------------------

#[test]
fn golden_open() {
    // A fieldless variant still costs a full u32 discriminant.
    assert_eq!(req(DriveOp::Open), golden("00000000"));
}

#[test]
fn golden_stat() {
    assert_eq!(
        req(DriveOp::Stat { path: "/a/b".into() }),
        golden("010000000400000000000000 2f612f62".replace(' ', "").as_str())
    );
}

#[test]
fn golden_list() {
    assert_eq!(
        req(DriveOp::List { path: "/a".into(), cursor: None, limit: 10 }),
        golden("02000000 0200000000000000 2f61 00 0a000000".replace(' ', "").as_str())
    );
    assert_eq!(
        req(DriveOp::List { path: "/a".into(), cursor: Some("x".into()), limit: 0 }),
        golden(
            "02000000 0200000000000000 2f61 01 0100000000000000 78 00000000"
                .replace(' ', "")
                .as_str()
        )
    );
}

#[test]
fn golden_read() {
    assert_eq!(
        req(DriveOp::Read { path: "/f".into(), offset: 0, len: None }),
        golden(
            "03000000 0200000000000000 2f66 0000000000000000 00"
                .replace(' ', "")
                .as_str()
        )
    );
}

#[test]
fn golden_write() {
    assert_eq!(
        req(DriveOp::Write {
            path: "/f".into(),
            object_cid: "cid".into(),
            size: 5,
            base_etag: Some("e".into()),
        }),
        golden(
            "04000000 0200000000000000 2f66 0300000000000000 636964 0500000000000000 01 0100000000000000 65"
                .replace(' ', "")
                .as_str()
        )
    );
}

#[test]
fn golden_mkdir_move_delete() {
    assert_eq!(
        req(DriveOp::Mkdir { path: "/d".into() }),
        golden("05000000 0200000000000000 2f64".replace(' ', "").as_str())
    );
    assert_eq!(
        req(DriveOp::Move { from: "/a".into(), to: "/b".into() }),
        golden(
            "06000000 0200000000000000 2f61 0200000000000000 2f62"
                .replace(' ', "")
                .as_str()
        )
    );
    assert_eq!(
        req(DriveOp::Delete { path: "/f".into(), recursive: true }),
        golden("08000000 0200000000000000 2f66 01".replace(' ', "").as_str())
    );
}

#[test]
fn golden_poll_and_watch() {
    assert_eq!(
        req(DriveOp::Poll { cursor: Some(7), limit: 500 }),
        golden("0a000000 01 0700000000000000 f4010000".replace(' ', "").as_str())
    );
    assert_eq!(req(DriveOp::Watch), golden("0b000000"));
}

#[test]
fn golden_metadata_ops() {
    // Metadata was APPENDED after Watch. Inserting anywhere else would silently repoint every later
    // op for every deployed client, which no round-trip test can catch.
    assert_eq!(
        req(DriveOp::Meta { path: "/a".into() }),
        golden(&["0c000000", "0200000000000000", "2f61"].concat())
    );
    assert_eq!(
        req(DriveOp::Tag { path: "/a".into(), tag: "x".into(), remove: true }),
        golden(&["0e000000", "0200000000000000", "2f61", "0100000000000000", "78", "01"].concat())
    );
}

#[test]
fn golden_share_caveats_field_order() {
    assert_eq!(
        req(DriveOp::Share {
            path: "/p".into(),
            audience: "aud".into(),
            abilities: vec!["read".into()],
            caveats: ShareCaveats { not_after: 1, max_bytes_read: None, max_bytes_write: Some(2) },
        }),
        // path, audience, Vec<String> abilities, then the caveats struct inline
        // (not_after, then Option max_bytes_read, then Option max_bytes_write).
        golden(
            &[
                "09000000",
                "0200000000000000", "2f70",
                "0300000000000000", "617564",
                "0100000000000000", "0400000000000000", "72656164",
                "0100000000000000", "00", "01", "0200000000000000",
            ]
            .concat(),
        )
    );
}

// ---------------------------------------------------------------------------
// replies: `DriveReply { result: Result<DriveOk, DriveErr> }` — Result is itself an enum,
// so every reply starts with its own u32 (0 = Ok, 1 = Err) before the payload variant.
// ---------------------------------------------------------------------------

fn reply(r: DriveReply) -> String {
    hex::encode(encode_reply(&r))
}

#[test]
fn golden_ok_replies() {
    assert_eq!(reply(DriveReply::ok(DriveOk::Deleted)), "0000000006000000");
    assert_eq!(
        reply(DriveReply::ok(DriveOk::Made { node_id: "n1".into() })),
        "00000000 05000000 0200000000000000 6e31".replace(' ', "")
    );
    assert_eq!(
        reply(DriveReply::ok(DriveOk::Written {
            etag: "e".into(),
            node_id: "n".into(),
            version_seq: 3,
        })),
        "00000000 04000000 0100000000000000 65 0100000000000000 6e 0300000000000000"
            .replace(' ', "")
    );
    assert_eq!(
        reply(DriveReply::ok(DriveOk::Watching { topic: "t".into(), cursor: 9 })),
        "00000000 09000000 0100000000000000 74 0900000000000000".replace(' ', "")
    );
}

#[test]
fn golden_err_replies() {
    assert_eq!(reply(DriveReply::err(DriveErr::Unauthorized)), "0100000000000000");
    assert_eq!(reply(DriveReply::err(DriveErr::OutOfScope)), "0100000003000000");
    assert_eq!(reply(DriveReply::err(DriveErr::NotFound)), "0100000004000000");
    assert_eq!(
        reply(DriveReply::err(DriveErr::Conflict { current_etag: "e".into() })),
        "01000000 05000000 0100000000000000 65".replace(' ', "")
    );
    assert_eq!(
        reply(DriveReply::err(DriveErr::Internal("boom".into()))),
        "01000000 09000000 0400000000000000 626f6f6d".replace(' ', "")
    );
}

#[test]
fn error_codes_are_stable_for_clients_that_do_not_decode_variants() {
    // A non-Rust SDK maps the variant INDEX to these codes; both must hold.
    assert_eq!(DriveErr::Unauthorized.code(), 401);
    assert_eq!(DriveErr::Revoked.code(), 410);
    assert_eq!(DriveErr::Expired.code(), 419);
    assert_eq!(DriveErr::OutOfScope.code(), 403);
    assert_eq!(DriveErr::NotFound.code(), 404);
    assert_eq!(DriveErr::Conflict { current_etag: String::new() }.code(), 409);
    assert_eq!(DriveErr::QuotaExceeded.code(), 429);
    assert_eq!(DriveErr::PaymentRequired.code(), 402);
    assert_eq!(DriveErr::BadPath.code(), 400);
    assert_eq!(DriveErr::Internal(String::new()).code(), 500);
}

#[test]
fn variant_indices_are_declaration_order() {
    // The discriminant IS the declaration order. Inserting a variant anywhere but the end
    // silently repoints every later op for every non-Rust client.
    let ops = [
        DriveOp::Open,
        DriveOp::Stat { path: String::new() },
        DriveOp::List { path: String::new(), cursor: None, limit: 0 },
        DriveOp::Read { path: String::new(), offset: 0, len: None },
        DriveOp::Write {
            path: String::new(),
            object_cid: String::new(),
            size: 0,
            base_etag: None,
        },
        DriveOp::Mkdir { path: String::new() },
        DriveOp::Move { from: String::new(), to: String::new() },
        DriveOp::Copy { from: String::new(), to: String::new() },
        DriveOp::Delete { path: String::new(), recursive: false },
        DriveOp::Share {
            path: String::new(),
            audience: String::new(),
            abilities: vec![],
            caveats: ShareCaveats::default(),
        },
        DriveOp::Poll { cursor: None, limit: 0 },
        DriveOp::Watch,
        DriveOp::Meta { path: String::new() },
        DriveOp::SetProp { path: String::new(), key: String::new(), value: None },
        DriveOp::Tag { path: String::new(), tag: String::new(), remove: false },
        DriveOp::Link {
            path: String::new(),
            rel: String::new(),
            to: String::new(),
            remove: false,
        },
        DriveOp::Backlinks { to: String::new() },
        DriveOp::Versions { path: String::new() },
    ];
    for (want, op) in ops.into_iter().enumerate() {
        let encoded = req(op);
        // The op discriminant is the u32 immediately after drive + cap.
        let disc = &encoded[REQ_PREFIX.len()..REQ_PREFIX.len() + 8];
        let got = u32::from_le_bytes(hex::decode(disc).unwrap().try_into().unwrap());
        assert_eq!(got as usize, want, "DriveOp variant {want} moved");
    }
}
