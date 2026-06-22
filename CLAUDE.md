# ce-drive-serve — AI agent context

The **host** side of the CE Drive mesh API. An app over CE primitives (no node changes).

## What this crate is
A server that exposes the `ce-drive/v1` AppRequest op set over the CE mesh and authorizes EVERY
request against a presented `ce-cap` chain via `ce_cap::authorize`, then enforces drive-id +
`path_prefix` caveats (fail-closed, `..`-guarded). Metadata is served from `ce-drive-core`'s
`DriveTree` CRDT + content map; bytes are content-addressed blobs (`Read` returns a `ReadPlan`, never
bytes; `Write` commits a `path -> object_cid` binding).

## Modules
- `wire.rs` — `DriveReq`/`DriveReply`/`DriveOp`/`Entry`/`Change`/`ReadPlan`/`DriveErr` (bincode). The
  shared protocol; `ce-drive-client` depends on it.
- `serve.rs` — `DriveServer`: poll `/mesh/messages`, `authorize_req` (the single gate), dispatch the
  op set, `read_plan` (ranged chunk intersection), publish the change beacon.
- `feed.rs` — per-drive monotonic seq change log (`Poll` source of truth).
- `tenant.rs` — `Registry`/`Tenant`: multi-drive, each a `Drive` + `Feed` + `Quota`; host key = root.

## Dependencies (all by path)
`ce-rs` (AppRequest/blobs), `ce-cap` (authorize), `ce-drive-core` (DriveTree), `ce-identity`.
The `[patch]` block redirects the git `ce-rs`/`ce-cap` (pulled via ce-coord/rdev transitively) onto
the local path copies so the graph collapses onto ONE `ce-rs`/`ce-cap`.

## Standards
Edition 2024, `anyhow::Result`, `tracing` (no `println!` in the lib), no `unsafe`/`unwrap()` in prod,
no emojis. Money = `Amount` base units, decimal strings. Author: Leif Rydenfalk. No co-author lines.

## Tests
- `cargo test` — unit (feed, read_plan, split_path) + `tests/authorize.rs` (cap gate: subtree read,
  wrong-audience/expired/out-of-prefix/`..` denied, attenuation can't widen, revoked subtree denied).
- `cargo test --test two_node_drive` — two in-process CE nodes, real `DriveServer`, full op set +
  mirror over the mesh (skips gracefully if the sandbox can't start nodes).

## Build/verify
Shared cargo target-dir is configured at `~/ce-net/.cargo-shared`; just run `cargo build`/`cargo test`.
