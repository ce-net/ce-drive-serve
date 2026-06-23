//! # ce-drive-serve
//!
//! The **host** side of the CE Drive mesh API: a server that exposes the `ce-drive/v1` AppRequest op
//! set (Open/Stat/List/Read/Write/Mkdir/Move/Copy/Delete/Share/Poll/Watch) over CE mesh
//! request/reply, verifying **every** request against a presented `ce-cap` chain.
//!
//! It is an **app over CE primitives** (`AppRequest` + content-addressed blobs + `ce-cap`), exactly
//! per `ce/docs/primitives.md`: no new node RPC variant, no new HTTP endpoint, no node changes. The
//! serve loop polls `/mesh/messages`, decodes each request, runs
//! `ce_cap::authorize(host_id, roots, &[], now, &from, ability, &chain, &is_revoked)` (the same
//! pattern `rdev::handle_inner` uses), enforces the drive-id + path-prefix caveats, then delegates to
//! the [`ce_drive_core`] `DriveTree` + content map.
//!
//! ## Layering
//! `ce-drive-serve -> {ce-rs (AppRequest/blobs), ce-cap (authorize), ce-drive-core (DriveTree CRDT)}`
//!
//! ## Standards
//! Edition 2024, `anyhow::Result`, `tracing` (no `println!` in the library), no `unsafe`, no
//! `unwrap()` on production paths. Money is `ce-rs::Amount` base units — decimal strings on the wire.

pub mod feed;
pub mod serve;
pub mod tenant;
pub mod wire;

pub use serve::{DriveServer, authorize_req, drive_caveat_prefix, read_plan, required_ability};
pub use tenant::{Registry, Tenant};
pub use wire::{
    Beacon, Change, ChangeKind, ChunkRef, DriveErr, DriveOk, DriveOp, DriveReply, DriveReq, Entry,
    EntryKind, Quota, ReadPlan, ShareCaveats, DRIVE_TOPIC, changes_topic, decode_reply, decode_req,
    encode_reply, encode_req,
};
