//! Authorization tests for the ce-drive/v1 serve gate — pure ce-cap verification, no node needed.
//!
//! These cover the M1/M2 contract: a cap authorizes read on its subtree; wrong-audience, expired,
//! and out-of-prefix requests are denied; attenuation cannot widen read -> write; a child prefix
//! cannot escape its parent; a revoked subtree is denied.

use std::collections::HashSet;

use ce_cap::{Caveats, Resource, SignedCapability};
use ce_drive_serve::{DriveErr, DriveOp, authorize_req, drive_caveat_prefix};
use ce_identity::{Identity, NodeId};

/// The drive id every cap in this file is bound to (matches the `drive` arg passed to authorize_req).
const DRIVE: &str = "default";

fn id(tag: &str) -> Identity {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ce-drive-serve-test-{}-{n}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

/// A second handle to the same on-disk key (so a holder can also issue sub-caps directly).
fn second_handle(of: &Identity) -> Identity {
    let dir = std::env::temp_dir().join(format!(
        "ce-drive-serve-2nd-{}-{}",
        std::process::id(),
        hex::encode(of.node_id())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("node.key");
    if !key.exists() {
        std::fs::write(&key, of.secret_bytes()).unwrap();
    }
    Identity::load_or_generate(&dir).unwrap()
}

fn read_op(path: &str) -> DriveOp {
    DriveOp::Read { path: path.to_string(), offset: 0, len: None }
}
fn write_op(path: &str) -> DriveOp {
    DriveOp::Write { path: path.to_string(), object_cid: "cid".into(), size: 1, base_etag: None }
}

fn no_revoked() -> HashSet<(NodeId, u64)> {
    HashSet::new()
}

/// Mint a self-issued cap from `host` to `audience` with the given abilities + path prefix.
fn grant(
    host: &Identity,
    audience: NodeId,
    abilities: &[&str],
    prefix: &str,
    not_after: u64,
) -> SignedCapability {
    SignedCapability::issue(
        host,
        audience,
        abilities.iter().map(|s| s.to_string()).collect(),
        Resource::Any,
        Caveats {
            not_after,
            path_prefix: Some(drive_caveat_prefix(DRIVE, prefix)),
            ..Default::default()
        },
        1,
        None,
    )
}

#[test]
fn cap_authorizes_read_on_subtree() {
    let host = id("host");
    let alice = id("alice");
    let cap = grant(&host, alice.node_id(), &["drive:read"], "/docs", 0);
    let r = authorize_req(
        &host.node_id(),
        &[],
        "default",
        &read_op("/docs/spec.md"),
        &alice.node_id(),
        &[cap],
        1000,
        &no_revoked(),
    );
    assert!(r.is_ok(), "{r:?}");
}

#[test]
fn wrong_audience_denied() {
    let host = id("host");
    let alice = id("alice");
    let mallory = id("mallory");
    let cap = grant(&host, alice.node_id(), &["drive:read"], "/docs", 0);
    // mallory presents alice's cap (confused-deputy / theft attempt).
    let r = authorize_req(
        &host.node_id(),
        &[],
        "default",
        &read_op("/docs/spec.md"),
        &mallory.node_id(),
        &[cap],
        1000,
        &no_revoked(),
    );
    assert_eq!(r.unwrap_err(), DriveErr::Unauthorized);
}

#[test]
fn expired_cap_denied() {
    let host = id("host");
    let alice = id("alice");
    let cap = grant(&host, alice.node_id(), &["drive:read"], "/docs", 500);
    let r = authorize_req(
        &host.node_id(),
        &[],
        "default",
        &read_op("/docs/spec.md"),
        &alice.node_id(),
        &[cap],
        1000, // now > not_after
        &no_revoked(),
    );
    assert_eq!(r.unwrap_err(), DriveErr::Expired);
}

#[test]
fn out_of_prefix_denied() {
    let host = id("host");
    let alice = id("alice");
    let cap = grant(&host, alice.node_id(), &["drive:read"], "/docs", 0);
    let r = authorize_req(
        &host.node_id(),
        &[],
        "default",
        &read_op("/secrets/x"),
        &alice.node_id(),
        &[cap],
        1000,
        &no_revoked(),
    );
    assert_eq!(r.unwrap_err(), DriveErr::OutOfScope);
}

#[test]
fn dotdot_traversal_denied() {
    let host = id("host");
    let alice = id("alice");
    let cap = grant(&host, alice.node_id(), &["drive:read"], "/docs", 0);
    let r = authorize_req(
        &host.node_id(),
        &[],
        "default",
        &read_op("/docs/../secrets"),
        &alice.node_id(),
        &[cap],
        1000,
        &no_revoked(),
    );
    assert_eq!(r.unwrap_err(), DriveErr::BadPath);
}

#[test]
fn read_cap_denied_for_write() {
    let host = id("host");
    let alice = id("alice");
    let cap = grant(&host, alice.node_id(), &["drive:read"], "/docs", 0);
    let r = authorize_req(
        &host.node_id(),
        &[],
        "default",
        &write_op("/docs/x"),
        &alice.node_id(),
        &[cap],
        1000,
        &no_revoked(),
    );
    assert_eq!(r.unwrap_err(), DriveErr::Unauthorized);
}

#[test]
fn attenuation_cannot_widen_read_to_write() {
    // host -> alice (read on /docs). alice re-shares to bob, trying to widen to write.
    let host = id("host");
    let alice = id("alice");
    let bob = id("bob");
    let root = grant(&host, alice.node_id(), &["drive:read"], "/docs", 0);
    let widened = SignedCapability::issue(
        &alice,
        bob.node_id(),
        vec!["drive:read".into(), "drive:write".into()],
        Resource::Any,
        Caveats { path_prefix: Some(drive_caveat_prefix(DRIVE, "/docs")), ..Default::default() },
        2,
        Some(root.id()),
    );
    let chain = vec![root, widened];
    let r = authorize_req(
        &host.node_id(),
        &[],
        "default",
        &write_op("/docs/x"),
        &bob.node_id(),
        &chain,
        1000,
        &no_revoked(),
    );
    assert_eq!(r.unwrap_err(), DriveErr::Unauthorized, "widening read->write must be rejected");
    let _ = second_handle; // keep helper referenced for future tests
}

#[test]
fn child_prefix_cannot_escape_parent() {
    // host -> alice (read on /docs). alice re-shares /secrets to bob (escaping the subtree).
    let host = id("host");
    let alice = id("alice");
    let bob = id("bob");
    let root = grant(&host, alice.node_id(), &["drive:read"], "/docs", 0);
    let escaping = SignedCapability::issue(
        &alice,
        bob.node_id(),
        vec!["drive:read".into()],
        Resource::Any,
        Caveats { path_prefix: Some(drive_caveat_prefix(DRIVE, "/secrets")), ..Default::default() },
        3,
        Some(root.id()),
    );
    let chain = vec![root, escaping];
    let r = authorize_req(
        &host.node_id(),
        &[],
        "default",
        &read_op("/secrets/x"),
        &bob.node_id(),
        &chain,
        1000,
        &no_revoked(),
    );
    // ce-cap rejects the link (caveats broader than parent) before path enforcement.
    assert_eq!(r.unwrap_err(), DriveErr::Unauthorized);
}

/// REGRESSION (finding C1): a capability is bound to ONE drive. A cap minted for drive A must be
/// rejected for the identical op+path on drive B/C on the same host, and accepted on drive A.
///
/// Before the fix, `authorize_req` ignored the `drive` argument (`let _ = drive;`) and the path
/// caveat carried no drive id, so this same cap authorized the read on EVERY drive on the host. This
/// test fails on that old behavior (drive_b would be `Ok`) and passes on the fix.
#[test]
fn cap_for_drive_a_is_rejected_on_drive_b() {
    let host = id("host");
    let alice = id("alice");
    // Mint a read cap bound to drive "alpha" (the helper binds to DRIVE = "default"; here we bind
    // explicitly to "alpha" to make the cross-drive boundary the subject under test).
    let cap = SignedCapability::issue(
        &host,
        alice.node_id(),
        vec!["drive:read".into()],
        Resource::Any,
        Caveats { path_prefix: Some(drive_caveat_prefix("alpha", "/docs")), ..Default::default() },
        1,
        None,
    );

    // Accepted on the drive it was issued for.
    let on_a = authorize_req(
        &host.node_id(),
        &[],
        "alpha",
        &read_op("/docs/spec.md"),
        &alice.node_id(),
        std::slice::from_ref(&cap),
        1000,
        &no_revoked(),
    );
    assert!(on_a.is_ok(), "cap must authorize on its own drive: {on_a:?}");

    // Rejected for the identical op+path on a DIFFERENT drive on the same host.
    let on_b = authorize_req(
        &host.node_id(),
        &[],
        "beta",
        &read_op("/docs/spec.md"),
        &alice.node_id(),
        std::slice::from_ref(&cap),
        1000,
        &no_revoked(),
    );
    assert_eq!(
        on_b.unwrap_err(),
        DriveErr::OutOfScope,
        "a cap for drive 'alpha' must NOT authorize the same op on drive 'beta'"
    );

    // And a third drive, just to be explicit it is a per-drive binding, not an alpha/beta toggle.
    let on_c = authorize_req(
        &host.node_id(),
        &[],
        "gamma",
        &read_op("/docs/spec.md"),
        &alice.node_id(),
        std::slice::from_ref(&cap),
        1000,
        &no_revoked(),
    );
    assert_eq!(on_c.unwrap_err(), DriveErr::OutOfScope);
}

/// REGRESSION (finding C1): a cap with a drive-unbound (legacy bare-path) `path_prefix` authorizes
/// nothing — the gate is fail-closed. Without this, an old-style cap would still be honored on any
/// drive, re-opening the hole.
#[test]
fn drive_unbound_cap_is_rejected() {
    let host = id("host");
    let alice = id("alice");
    let cap = SignedCapability::issue(
        &host,
        alice.node_id(),
        vec!["drive:read".into()],
        Resource::Any,
        // Bare path prefix, NOT the `ce-drive/<drive>/...` namespace.
        Caveats { path_prefix: Some("/docs".into()), ..Default::default() },
        1,
        None,
    );
    let r = authorize_req(
        &host.node_id(),
        &[],
        "default",
        &read_op("/docs/spec.md"),
        &alice.node_id(),
        &[cap],
        1000,
        &no_revoked(),
    );
    assert_eq!(r.unwrap_err(), DriveErr::Unauthorized, "an unbound cap must authorize nothing");
}

#[test]
fn revoked_subtree_denied() {
    let host = id("host");
    let alice = id("alice");
    let cap = grant(&host, alice.node_id(), &["drive:read"], "/docs", 0);
    let mut revoked = HashSet::new();
    revoked.insert((host.node_id(), 1)); // revoke the root link's (issuer, nonce)
    let r = authorize_req(
        &host.node_id(),
        &[],
        "default",
        &read_op("/docs/spec.md"),
        &alice.node_id(),
        &[cap],
        1000,
        &revoked,
    );
    assert_eq!(r.unwrap_err(), DriveErr::Revoked);
}
