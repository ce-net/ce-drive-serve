# ce-drive-serve — AI agent context

The **host** side of the CE Drive mesh API. An app over CE primitives (no node changes).

## What this crate is
A server that exposes the `ce-drive/v1` AppRequest op set over the CE mesh and authorizes EVERY
request against a presented `ce-cap` chain via `ce_cap::authorize`, then enforces drive-id +
`path_prefix` caveats (fail-closed, `..`-guarded). The drive id is bound into the leaf cap's
`path_prefix` as `ce-drive/<drive>[/<subtree>]` (mirror of ce-db's `ce-db/<collection>`); a cap
minted for drive A cannot be replayed against drive B on the same host. Mint with
`drive_caveat_prefix(drive, path)`. Metadata is served from `ce-drive-core`'s
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
- `cargo test --lib` — unit: `feed` (gap-free/resumable/limit-clamp paging), `serve` (norm_path,
  no_dotdot, enforce_prefix subtree rules, read_plan boundaries incl. zero-len/empty/over-read,
  derive_nonce determinism, parse_node_id), `tenant` (create/dup/restore/quota/host-id).
- `tests/authorize.rs` — cap gate: subtree read, wrong-audience/expired/out-of-prefix/`..` denied,
  attenuation can't widen, revoked subtree denied.
- `tests/authorize_props.rs` — deeper gate + a PROPERTY test: a child delegation can never authorize
  an op its parent could not (no privilege amplification); plus not-yet-valid->Expired, Move/Copy
  source-prefix enforcement, accepted org roots, 3-link narrowing chains.
- `tests/wire_roundtrip.rs` — every `DriveOp`/`DriveOk`/`DriveErr` round-trips (incl. values >2^53);
  error-code/Display stability; malformed/truncated input Errs (never panics); proptest fuzz of the
  codec (arbitrary requests round-trip; random bytes never panic the decoder).
- `tests/crdt_snapshot.rs` — snapshot bootstrap (`serialize -> from_state`) reconstructs the exact
  tree; remote move-ops are idempotent + commutative (converge regardless of order) — proptest.
- `cargo test --test two_node_drive` — two in-process CE nodes, real `DriveServer`, full op set +
  mirror over the mesh (skips gracefully if the sandbox can't start nodes).
- `cargo test --test two_node_full` — COMPREHENSIVE live 2-node test: full op set, capability DENIAL
  on every op without a valid cap (bogus + wrong-root), SUCCESS with one, attenuated read-only cap
  rejects writes/mkdir/delete/share, large-file (3 MiB) streaming by CID (full + ranged), Poll
  gap-free + resumable, Watch beacon, snapshot bootstrap + Mirror convergence, owner-mediated Share
  mints an attenuated sub-cap that never widens. Skips only if nodes can't start / mesh can't
  converge; once up, every assertion is hard.

## Build/verify
Shared cargo target-dir is configured at `~/ce-net/.cargo-shared`; just run `cargo build`/`cargo test`.
