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
- Metadata is answered from [`ce-drive-core`](https://github.com/ce-net/ce-drive)'s **`SyncedDrive`**
  — the `DriveTree` CRDT + content map + metadata map, each riding a `ce-coord` multi-writer log.
- **Every hosted drive is replicated, always.** There is no flag for it and there should not be one:
  a drive that syncs only when configured to is a local folder with extra steps. Peers come from
  DISCOVERY (everyone advertising `ce-drive`), so the replica set assembles itself; `--peer` only
  adds a node the DHT cannot see. Two devices writing the same drive now converge instead of racing.
- The drive is **also** written to `<state-dir>/<drive>.cedrive` after every mutation. That is not
  redundancy for its own sake: `ce-coord` deliberately does not persist to local disk, so on a drive
  with no reachable peers the merged log is durable only while this process lives. On boot the host
  LOADS that file and `restore_state`s it into the replicated drive — silently and locally, never by
  re-proposing history op by op.
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

### Drives are durable, and they are the SAME drives the CLI uses

State files live in `--state-dir` (default `$CE_DRIVE_DIR`, else the platform data dir +
`ce-drive`) as `<drive>.cedrive` — **exactly where the `ce-drive` CLI keeps them**. At boot the host
*loads* each requested drive if a state file exists and only creates one when it genuinely does not,
and it writes the state back after every mutating op, before replying.

That last paragraph describes a fix, not a feature. This host used to call `create()`
unconditionally, which builds a **new empty drive in memory**. So the drive published on the mesh
was empty and forgot everything on restart, while the real corpus sat untouched in a `.cedrive`
file next to it — two drives with the same name, one holding all the work and one visible over the
mesh. Pointing the host at the CLI's directory is what makes them one drive. If you deliberately
want the old throwaway behaviour, construct `DriveServer` without `with_state_dir`.

A persist failure is returned to the caller as `Internal` rather than logged and swallowed: a drive
that accepts a write and cannot record it must not answer "ok".

The on-disk container is versioned — see `ce_drive_core::persist`. Adding a field to `DriveState`
is a **breaking format change** (bincode is positional, and `#[serde(default)]` cannot save you),
so it requires a new magic plus a decoder for the old layout.

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

`ce-drive-serve → { ce-rs (AppRequest/blobs), ce-cap (authorize), ce-drive-core (SyncedDrive),
ce-coord (the multi-writer logs a SyncedDrive rides) }`
