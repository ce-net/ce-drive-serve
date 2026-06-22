//! CRDT / snapshot-bootstrap property tests for the Drive substrate the server serves from.
//!
//! The host serves metadata from a `ce_drive_core::Drive`; `Open` publishes a serialized
//! `DriveState` snapshot that a client (`Mirror`) replays to bootstrap an identical replica. The
//! integrity of that path is load-bearing: if `serialize -> deserialize -> from_state` ever drifts
//! from the live tree, every mirror diverges. These tests pin it with random op sequences.
//!
//! Also exercised: idempotent + commutative application of CRDT move ops (apply the same op set in
//! different orders / twice -> identical tree), which is the core CRDT guarantee the change feed and
//! multi-writer merge rely on.

use ce_drive_core::{Drive, DriveState, FileContent, MoveOp, NodeKind, Timestamp};
use proptest::prelude::*;

/// Snapshot a drive the way `op_open` does (serde_json) and rebuild it the way `Mirror::bootstrap`
/// does (`from_state`). Returns the rebuilt drive.
fn snapshot_roundtrip(drive: &Drive) -> Drive {
    let bytes = serde_json::to_vec(drive.state()).expect("serialize DriveState");
    let state: DriveState = serde_json::from_slice(&bytes).expect("deserialize DriveState");
    Drive::from_state(state)
}

/// A stable, order-independent fingerprint of a drive's visible tree: every live path under root,
/// sorted, joined. Two drives with the same fingerprint present identically to `ls`.
fn fingerprint(drive: &Drive) -> Vec<String> {
    let mut out = Vec::new();
    walk(drive, "/", &mut out);
    out.sort();
    out
}

fn walk(drive: &Drive, path: &str, out: &mut Vec<String>) {
    let Ok(entries) = drive.ls(path) else { return };
    for e in entries {
        let child = if path == "/" { format!("/{}", e.name) } else { format!("{path}/{}", e.name) };
        let tag = if e.is_dir {
            format!("D {child}")
        } else {
            let cid = e.content.as_ref().map(|c| c.cid.clone()).unwrap_or_default();
            format!("F {child} {cid}")
        };
        out.push(tag);
        if e.is_dir {
            walk(drive, &child, out);
        }
    }
}

#[test]
fn empty_drive_snapshot_round_trips() {
    let d = Drive::init("team", "replica");
    let back = snapshot_roundtrip(&d);
    assert_eq!(fingerprint(&d), fingerprint(&back));
    assert!(fingerprint(&back).is_empty());
}

#[test]
fn populated_drive_snapshot_round_trips() {
    let mut d = Drive::init("team", "r");
    d.mkdir("/", "docs").unwrap();
    d.mkdir("/docs", "sub").unwrap();
    d.add_file("/docs", "a.txt", FileContent::new("cidA", 3, 0o644, 1)).unwrap();
    d.add_file("/docs/sub", "b.bin", FileContent::new("cidB", 9, 0o644, 2)).unwrap();
    d.mv("/docs/a.txt", "/docs/sub", "a-moved.txt").unwrap();
    d.rm("/docs/sub/b.bin").unwrap();

    let back = snapshot_roundtrip(&d);
    assert_eq!(fingerprint(&d), fingerprint(&back), "snapshot replay must reconstruct the exact tree");
}

// ---------------------------------------------------------------------------
// CRDT idempotence + commutativity of remote move-op application.
//
// The change feed / multi-writer merge replays remote ops; applying the same op set twice, or in a
// different order, must converge to the same tree (the LWW move-CRDT guarantee).
// ---------------------------------------------------------------------------

fn build_ops() -> Vec<MoveOp> {
    // Two replicas concurrently building disjoint + overlapping structure.
    vec![
        MoveOp { ts: Timestamp::new(1, "a"), child: "n1".into(), new_parent: "ROOT".into(), new_name: "docs".into(), kind: NodeKind::Dir },
        MoveOp { ts: Timestamp::new(1, "b"), child: "n2".into(), new_parent: "ROOT".into(), new_name: "media".into(), kind: NodeKind::Dir },
        MoveOp { ts: Timestamp::new(2, "a"), child: "n3".into(), new_parent: "n1".into(), new_name: "f.txt".into(), kind: NodeKind::File },
        MoveOp { ts: Timestamp::new(3, "b"), child: "n3".into(), new_parent: "n2".into(), new_name: "f.txt".into(), kind: NodeKind::File },
    ]
}

#[test]
fn applying_same_remote_op_twice_is_idempotent() {
    let mut d = Drive::init("team", "z");
    for op in build_ops() {
        d.apply_remote_move(op);
    }
    let once = fingerprint(&d);
    // Re-apply every op a second time (a duplicate gossip delivery).
    for op in build_ops() {
        d.apply_remote_move(op);
    }
    assert_eq!(fingerprint(&d), once, "duplicate op delivery must not change the tree");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(150))]

    /// Commutativity: the same set of remote move ops applied in any permutation converges to the
    /// same visible tree. (This is the CRDT property the cursor-based feed depends on.)
    #[test]
    fn remote_ops_converge_regardless_of_order(perm in Just(build_ops()).prop_shuffle()) {
        let baseline = {
            let mut d = Drive::init("team", "base");
            for op in build_ops() {
                d.apply_remote_move(op);
            }
            fingerprint(&d)
        };
        let mut d = Drive::init("team", "perm");
        for op in perm {
            d.apply_remote_move(op);
        }
        prop_assert_eq!(fingerprint(&d), baseline, "op order must not change convergent state");
    }

    /// Snapshot round-trip is order-stable too: build a random-permuted drive, snapshot it, and the
    /// rebuilt replica fingerprints identically.
    #[test]
    fn snapshot_round_trips_for_any_order(perm in Just(build_ops()).prop_shuffle()) {
        let mut d = Drive::init("team", "snap");
        for op in perm {
            d.apply_remote_move(op);
        }
        let back = snapshot_roundtrip(&d);
        prop_assert_eq!(fingerprint(&d), fingerprint(&back));
    }
}
