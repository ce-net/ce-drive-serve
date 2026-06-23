# ce-drive-serve

The **host** side of the CE Drive mesh API — the open-source, peer-to-peer equivalent of the
Google Drive API. A server that exposes the `ce-drive/v1` AppRequest op set
(Open/Stat/List/Read/Write/Mkdir/Move/Copy/Delete/Share/Poll/Watch) over the CE mesh
request/reply, verifying **every** request against a presented `ce-cap` capability chain.

It is an **app over CE primitives** (`AppRequest` + content-addressed blobs + `ce-cap`), per
`ce/docs/primitives.md`: no new node RPC variant, no new HTTP endpoint, no node changes.

## How it works

- The serve loop polls the local node's `/mesh/messages` for `ce-drive/v1` requests.
- Each request carries a hex `ce-cap` chain whose leaf audience equals the Noise-authenticated
  sender. The host runs the exact `rdev::handle_inner` pattern:
  `ce_cap::authorize(host_id, roots, &[], now, &from, ability, &chain, &is_revoked)`, then enforces
  the `drive_id` + `path_prefix` caveats (with a `..` traversal guard) — fail-closed.
- The **drive id is bound into the leaf cap's `path_prefix`** as the namespaced segment
  `ce-drive/<drive>[/<subtree>]` (the same pattern ce-db uses for `ce-db/<collection>`). The host
  recovers that drive id and rejects the request unless it equals the requested drive *before any
  op*, so a cap minted for one drive can never be replayed against another drive on the same host. A
  cap whose prefix is not in this namespace authorizes nothing. Mint these with
  `ce_drive_serve::drive_caveat_prefix(drive, path)`.
- Metadata is answered from the [`ce-drive-core`](../ce-drive) `DriveTree` CRDT + content map.
- **Bytes never travel on the metadata channel.** `Read` returns a `ReadPlan` (the manifest CID +
  the chunk refs covering the requested range); the client fetches those chunks directly from the
  content-addressed blob store and verifies each against its CID (content addressing *is* the
  integrity proof). `Write` commits a `path -> object_cid` binding after the client has uploaded the
  object via `put_object`.
- A monotonic per-drive change feed (`Poll{cursor}`) is the source of truth for sync; a pubsub
  beacon (`Watch`) is a best-effort wake-up hint.

## Run

```bash
# Host a drive named "team" on this node, discoverable as `acme-eng`.
ce-drive-serve --drive team --name acme-eng
```

The host key (which IS the capability root for every drive it serves) is loaded from `--key-dir`
(default: the CE data dir's `identity/`). To grant a peer access, the host self-issues a `ce-cap`
chain scoped by `drive:{read,write,share,...}` + a drive-bound `path_prefix`
(`ce_drive_serve::drive_caveat_prefix(drive, path)`, e.g. `ce-drive/team/docs`) + expiry, and the
peer presents it on every request.

## Authorization vocabulary

`drive:read ⊂ drive:comment ⊂ drive:write ⊂ {…+delete} ⊂ {…+share} ⊂ drive:admin`, `drive:watch`
orthogonal. Sharing = minting a strictly-attenuated sub-chain (`Share` op). Revocation = `not_after`
expiry + on-chain `RevokeCapability` (subtree kill within ~10s).

## Layering

`ce-drive-serve → { ce-rs (AppRequest/blobs), ce-cap (authorize), ce-drive-core (DriveTree CRDT) }`

See `PLAN/11-ce-drive-mesh-api.md` for the full design.
