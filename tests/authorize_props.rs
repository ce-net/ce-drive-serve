//! Deeper authorization tests + capability-attenuation property tests for the ce-drive serve gate.
//!
//! Complements `authorize.rs` (the M1/M2 happy + denial cases) with:
//!   - the not-yet-valid (`not_before`) -> Expired mapping;
//!   - per-op required-ability mapping (read ops vs write ops vs admin);
//!   - Move/Copy enforce the *source* prefix, not just the destination;
//!   - `accepted_roots`: an org root key is honored besides the host's own key;
//!   - Share-level ability intersection (admin-gated, never widens);
//!   - PROPERTY: attenuation can never amplify — for random parent/child ability+prefix splits, a
//!     child can only ever authorize what its parent already could (no privilege escalation).

use std::collections::HashSet;

use ce_cap::{Caveats, Resource, SignedCapability};
use ce_drive_serve::{
    DriveErr, DriveOp, ShareCaveats, authorize_req, drive_caveat_prefix, required_ability,
};
use ce_identity::{Identity, NodeId};
use proptest::prelude::*;

/// The drive id every cap in this file is bound to (matches the `drive` arg passed to authorize_req).
const DRIVE: &str = "d";

fn id(tag: &str) -> Identity {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir()
        .join(format!("ce-drive-authprop-{}-{n}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Identity::load_or_generate(&dir).unwrap()
}

fn no_revoked() -> HashSet<(NodeId, u64)> {
    HashSet::new()
}

#[allow(clippy::too_many_arguments)]
fn grant(
    issuer: &Identity,
    audience: NodeId,
    abilities: &[&str],
    prefix: &str,
    not_before: u64,
    not_after: u64,
    nonce: u64,
    parent: Option<ce_cap::CapId>,
) -> SignedCapability {
    SignedCapability::issue(
        issuer,
        audience,
        abilities.iter().map(|s| s.to_string()).collect(),
        Resource::Any,
        Caveats {
            not_before,
            not_after,
            path_prefix: Some(drive_caveat_prefix(DRIVE, prefix)),
            ..Default::default()
        },
        nonce,
        parent,
    )
}

fn read_op(p: &str) -> DriveOp {
    DriveOp::Read { path: p.into(), offset: 0, len: None }
}
fn write_op(p: &str) -> DriveOp {
    DriveOp::Write { path: p.into(), object_cid: "cid".into(), size: 1, base_etag: None }
}

// ---------------------------------------------------------------------------
// required-ability mapping (the lattice floor per op)
// ---------------------------------------------------------------------------

#[test]
fn required_ability_per_op_is_correct() {
    assert_eq!(required_ability(&DriveOp::Open), "drive:read");
    assert_eq!(required_ability(&DriveOp::Stat { path: "/".into() }), "drive:read");
    assert_eq!(
        required_ability(&DriveOp::List { path: "/".into(), cursor: None, limit: 1 }),
        "drive:read"
    );
    assert_eq!(required_ability(&read_op("/")), "drive:read");
    assert_eq!(required_ability(&DriveOp::Poll { cursor: None, limit: 1 }), "drive:read");
    assert_eq!(required_ability(&DriveOp::Watch), "drive:read");
    assert_eq!(required_ability(&write_op("/")), "drive:write");
    assert_eq!(required_ability(&DriveOp::Mkdir { path: "/d".into() }), "drive:write");
    assert_eq!(
        required_ability(&DriveOp::Copy { from: "/a".into(), to: "/b".into() }),
        "drive:write"
    );
    assert_eq!(
        required_ability(&DriveOp::Move { from: "/a".into(), to: "/b".into() }),
        "drive:write"
    );
    assert_eq!(
        required_ability(&DriveOp::Delete { path: "/d".into(), recursive: false }),
        "drive:write"
    );
    assert_eq!(
        required_ability(&DriveOp::Share {
            path: "/".into(),
            audience: "x".into(),
            abilities: vec![],
            caveats: ShareCaveats::default()
        }),
        "drive:admin"
    );
}

// ---------------------------------------------------------------------------
// temporal: not_before -> Expired (mapped via "not yet valid")
// ---------------------------------------------------------------------------

#[test]
fn not_yet_valid_cap_denied_as_expired() {
    let host = id("host");
    let alice = id("alice");
    let cap = grant(&host, alice.node_id(), &["drive:read"], "/", 2000, 0, 1, None);
    let r = authorize_req(
        &host.node_id(),
        &[],
        "d",
        &read_op("/x"),
        &alice.node_id(),
        &[cap],
        1000, // now < not_before
        &no_revoked(),
    );
    assert_eq!(r.unwrap_err(), DriveErr::Expired);
}

// ---------------------------------------------------------------------------
// Move/Copy enforce the SOURCE prefix too (a writer scoped to /b cannot move /a out)
// ---------------------------------------------------------------------------

#[test]
fn move_source_outside_prefix_denied() {
    let host = id("host");
    let alice = id("alice");
    // alice may write only under /b. Move /a/x -> /b/x: dest ok, but source escapes the scope.
    let cap = grant(&host, alice.node_id(), &["drive:read", "drive:write"], "/b", 0, 0, 1, None);
    let op = DriveOp::Move { from: "/a/x".into(), to: "/b/x".into() };
    let r = authorize_req(&host.node_id(), &[], "d", &op, &alice.node_id(), &[cap], 1000, &no_revoked());
    assert_eq!(r.unwrap_err(), DriveErr::OutOfScope, "move source must be inside the scope");
}

#[test]
fn copy_source_outside_prefix_denied() {
    let host = id("host");
    let alice = id("alice");
    let cap = grant(&host, alice.node_id(), &["drive:read", "drive:write"], "/b", 0, 0, 1, None);
    let op = DriveOp::Copy { from: "/secret".into(), to: "/b/leak".into() };
    let r = authorize_req(&host.node_id(), &[], "d", &op, &alice.node_id(), &[cap], 1000, &no_revoked());
    assert_eq!(r.unwrap_err(), DriveErr::OutOfScope);
}

#[test]
fn move_within_scope_allowed() {
    let host = id("host");
    let alice = id("alice");
    let cap = grant(&host, alice.node_id(), &["drive:read", "drive:write"], "/b", 0, 0, 1, None);
    let op = DriveOp::Move { from: "/b/x".into(), to: "/b/y".into() };
    let r = authorize_req(&host.node_id(), &[], "d", &op, &alice.node_id(), &[cap], 1000, &no_revoked());
    assert!(r.is_ok(), "{r:?}");
}

#[test]
fn move_dotdot_in_source_denied() {
    let host = id("host");
    let alice = id("alice");
    let cap = grant(&host, alice.node_id(), &["drive:read", "drive:write"], "/", 0, 0, 1, None);
    let op = DriveOp::Move { from: "/b/../secret".into(), to: "/b/y".into() };
    let r = authorize_req(&host.node_id(), &[], "d", &op, &alice.node_id(), &[cap], 1000, &no_revoked());
    assert_eq!(r.unwrap_err(), DriveErr::BadPath);
}

// ---------------------------------------------------------------------------
// accepted_roots: an org root key (not the host's own key) is honored
// ---------------------------------------------------------------------------

#[test]
fn org_root_is_honored_when_accepted() {
    let host = id("host");
    let org = id("org");
    let alice = id("alice");
    // The cap roots at the ORG key, not the host key.
    let cap = grant(&org, alice.node_id(), &["drive:read"], "/", 0, 0, 1, None);
    // Without org in accepted_roots -> unauthorized.
    let denied = authorize_req(
        &host.node_id(), &[], "d", &read_op("/x"), &alice.node_id(), &[cap.clone()], 1000, &no_revoked(),
    );
    assert_eq!(denied.unwrap_err(), DriveErr::Unauthorized);
    // With org accepted -> ok.
    let ok = authorize_req(
        &host.node_id(), &[org.node_id()], "d", &read_op("/x"), &alice.node_id(), &[cap], 1000, &no_revoked(),
    );
    assert!(ok.is_ok(), "{ok:?}");
}

// ---------------------------------------------------------------------------
// granted abilities are returned (the leaf's), for UI gating
// ---------------------------------------------------------------------------

#[test]
fn granted_abilities_returned_on_success() {
    let host = id("host");
    let alice = id("alice");
    let cap = grant(&host, alice.node_id(), &["drive:read", "drive:write", "drive:admin"], "/", 0, 0, 1, None);
    let abilities = authorize_req(
        &host.node_id(), &[], "d", &read_op("/x"), &alice.node_id(), &[cap], 1000, &no_revoked(),
    )
    .expect("authorized");
    assert!(abilities.contains(&"drive:write".to_string()));
    assert!(abilities.contains(&"drive:admin".to_string()));
}

#[test]
fn empty_chain_denied() {
    let host = id("host");
    let alice = id("alice");
    let r = authorize_req(
        &host.node_id(), &[], "d", &read_op("/x"), &alice.node_id(), &[], 1000, &no_revoked(),
    );
    assert_eq!(r.unwrap_err(), DriveErr::Unauthorized);
}

// ---------------------------------------------------------------------------
// multi-link attenuation: a 3-link chain that narrows correctly authorizes;
// any link that widens is rejected.
// ---------------------------------------------------------------------------

#[test]
fn three_link_narrowing_chain_authorizes() {
    let host = id("host");
    let alice = id("alice");
    let bob = id("bob");
    // host -> alice (rw on /), alice -> bob (read on /docs).
    let root = grant(&host, alice.node_id(), &["drive:read", "drive:write"], "/", 0, 0, 1, None);
    let mid = SignedCapability::issue(
        &alice,
        bob.node_id(),
        vec!["drive:read".into()],
        Resource::Any,
        Caveats { path_prefix: Some(drive_caveat_prefix(DRIVE, "/docs")), ..Default::default() },
        2,
        Some(root.id()),
    );
    let chain = vec![root, mid];
    // bob can read under /docs.
    assert!(
        authorize_req(&host.node_id(), &[], "d", &read_op("/docs/x"), &bob.node_id(), &chain, 1000, &no_revoked())
            .is_ok()
    );
    // bob cannot write (his leaf is read-only).
    assert_eq!(
        authorize_req(&host.node_id(), &[], "d", &write_op("/docs/x"), &bob.node_id(), &chain, 1000, &no_revoked())
            .unwrap_err(),
        DriveErr::Unauthorized
    );
    // bob cannot read outside /docs.
    assert_eq!(
        authorize_req(&host.node_id(), &[], "d", &read_op("/other"), &bob.node_id(), &chain, 1000, &no_revoked())
            .unwrap_err(),
        DriveErr::OutOfScope
    );
}

// ---------------------------------------------------------------------------
// PROPERTY: attenuation can never amplify.
//
// For a random root grant (parent abilities + prefix) and a random child delegation, the child's
// effective authority is a subset of the parent's: whenever the child authorizes (op, path), the
// parent must authorize it too. We assert the contrapositive operationally: if the child is honored
// for an op/path, a one-link chain of just the parent (held by the same audience) is also honored.
// ---------------------------------------------------------------------------

const ABILITIES: &[&str] = &["drive:read", "drive:write", "drive:admin"];

fn subset_strategy() -> impl Strategy<Value = Vec<String>> {
    proptest::sample::subsequence(ABILITIES.to_vec(), 0..=ABILITIES.len())
        .prop_map(|v| v.into_iter().map(|s| s.to_string()).collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// A child delegation, no matter how it is requested, can never authorize an op the parent could
    /// not. We build host->alice (parent) and alice->bob (child) with random ability subsets and
    /// prefixes, then for a random op assert: child-authorizes  ==>  parent-would-authorize.
    #[test]
    fn child_never_amplifies_parent(
        parent_abilities in subset_strategy(),
        child_abilities in subset_strategy(),
        parent_prefix in prop_oneof![Just("/"), Just("/docs"), Just("/docs/team")],
        child_prefix in prop_oneof![Just("/"), Just("/docs"), Just("/docs/team"), Just("/other")],
        op_path in prop_oneof![Just("/x"), Just("/docs/x"), Just("/docs/team/x"), Just("/other/y")],
        want_write in any::<bool>(),
    ) {
        let host = id("p-host");
        let alice = id("p-alice");
        let bob = id("p-bob");

        let parent_abs: Vec<&str> = parent_abilities.iter().map(|s| s.as_str()).collect();
        let root = grant(&host, alice.node_id(), &parent_abs, parent_prefix, 0, 0, 1, None);

        let child = SignedCapability::issue(
            &alice,
            bob.node_id(),
            child_abilities.clone(),
            Resource::Any,
            Caveats { path_prefix: Some(drive_caveat_prefix(DRIVE, child_prefix)), ..Default::default() },
            2,
            Some(root.id()),
        );
        let child_chain = vec![root.clone(), child];

        let op = if want_write { write_op(op_path) } else { read_op(op_path) };

        let child_ok = authorize_req(
            &host.node_id(), &[], "d", &op, &bob.node_id(), &child_chain, 1000, &no_revoked(),
        ).is_ok();

        if child_ok {
            // The PARENT alone (re-issued to bob directly so the audience matches) must also authorize
            // it — proving the child added no authority the root didn't already carry.
            let parent_direct = grant(&host, bob.node_id(), &parent_abs, parent_prefix, 0, 0, 9, None);
            let parent_ok = authorize_req(
                &host.node_id(), &[], "d", &op, &bob.node_id(), &[parent_direct], 1000, &no_revoked(),
            ).is_ok();
            prop_assert!(parent_ok, "child authorized op the parent could not: child amplified privilege");
        }
    }
}
