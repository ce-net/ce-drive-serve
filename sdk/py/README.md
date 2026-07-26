# cedrive.py — the ce-drive/v1 Python SDK

The client half of the CE Drive mesh API. Stdlib only (`urllib` + `hashlib`); vendor this one
file next to your app like `ce.py` and import it.

```python
import cedrive

d = cedrive.connect(drive="default", cap=my_cap_chain_hex)

d.mkdir("/notes")
d.write_text("/notes/hello.md", "# hello\n")
print(d.read_text("/notes/hello.md"))

for e in d.ls("/notes"):
    print(e.path, e.size, e.node_id)      # node_id survives rename — link against it
```

## Why this file exists

The Rust tier is well served: [`ce-drive-client`](https://github.com/ce-net/ce-drive-client) is a
complete client — `RemoteDrive` over the op set, plus a `Mirror` that bootstraps a local
`ce-drive-core` replica from the `Open` snapshot and keeps it live via `Poll`. Nothing here
replaces it.

The **Python and JS tiers had nothing**, and it shows in what they did instead: `ce-files` — a
Python script-tier ceapp — shells out to the `ce-drive` CLI binary and re-materializes the whole
drive on a 60-second poll; `ce-drive-web` reimplements the tree over the wasm CRDT; `ocean` never
called the API at all. The blocker was never the API, which has been live and cap-gated the whole
time. It was that the wire is **bincode, not JSON**, so calling it from a non-Rust language meant
hand-rolling a codec — and each consumer decided that was someone else's job.

This is that codec for Python, written once.

## The two things worth knowing

**Bytes never ride the metadata channel.** `read()` asks the host for a *plan* — the object CID
plus the chunk refs covering your range — then fetches those chunks from the node's
content-addressed blob store and verifies every one against its CID before returning a byte.
Content addressing *is* the integrity proof; a mismatch raises rather than returning bad data.
`write()` uploads the object first (1 MiB chunks + a `ce-object-v1` manifest, byte-identical to
`ce.py`/`ce-rs`/`ce-go`, so object CIDs are portable) and then commits `path -> object_cid`.

**This SDK holds no keys and does no crypto.** `cap` is an opaque hex ce-cap chain you obtained
elsewhere (ce-iam); this file only carries it. The host verifies it per op, and the drive id is
bound into the leaf cap's `path_prefix` as `ce-drive/<drive>[/<subtree>]` — a cap minted for one
drive authorizes nothing on another, and a cap outside that namespace authorizes nothing at all.
Call `open()` to learn what your cap actually carries (`granted_abilities`) before offering an
action in a UI.

## Surface

| method | op | notes |
|---|---|---|
| `open()` | `Open` | root snapshot CID, change cursor, **granted abilities**, quota |
| `stat(path)` / `exists(path)` | `Stat` | `exists` maps 404 to False; other refusals still raise |
| `ls(path, pages=False)` | `List` | pages to the end by default; `pages=True` yields pages |
| `walk(path)` | `List` | every entry beneath a path, depth-first |
| `read(path, offset, length)` | `Read` | plan + verified chunk fetch; `read_text()` decodes UTF-8 |
| `write(path, data, base_etag)` | `Write` | uploads then commits; `write_text()` for str |
| `mkdir(path)` | `Mkdir` | returns the stable node id |
| `mv(src, dst)` / `cp(src, dst)` | `Move`/`Copy` | move is one O(1) edge flip; copy is free (dedup) |
| `rm(path, recursive)` | `Delete` | to TRASH — recoverable until GC |
| `share(path, audience, abilities, ...)` | `Share` | returns an attenuated chain; never widens |
| `poll(cursor, limit)` | `Poll` | the authoritative change feed — the source of truth for sync |
| `watch()` | `Watch` | beacon topic + cursor; the beacon is a lossy hint, then `poll()` |

Refusals raise `DriveError` carrying the host's stable code: 401 unauthorized, 402 payment,
403 out of scope, 404 not found, 409 conflict (with `.current_etag`), 410 revoked, 419 expired,
429 quota, 400 bad path, 500 internal.

Optimistic concurrency: pass the `etag` you last read as `base_etag` and a write that lost a race
raises 409 with the host's current etag, so you can re-read and retry. Pass `None` to overwrite
unconditionally.

## Environment

`CE_NODE_URL` (default `http://127.0.0.1:8844`), `CE_API_TOKEN` (else the node data dir's
`api.token`), `CE_DRIVE_CAP`, `CE_DRIVE_PROVIDER`. The provider is otherwise resolved by **service
name** (`ce-drive`) over the mesh, never by address, and is re-discovered after a transport failure.

## Tests

```bash
python3 -m unittest test_cedrive -v      # 43 tests, no node required
```

The important ones are the **golden vectors**: hex constants computed by hand from the bincode
rules (LE fixed-width ints, `u64` sequence lengths, `u32` enum variant indices, `Option` as a
leading 0/1 byte) rather than generated from this encoder, which would be circular.
`../../tests/wire_golden_py.rs` asserts the *same* constants from the Rust side — so if either
encoder drifts, exactly one suite goes red. A diff in those vectors is a breaking wire change:
do not regenerate them to make a test pass.

Verified against the live host (empty cap, so the gate refuses at the right place):

```
$ python3 -c "import cedrive; cedrive.connect().open()"
DriveError: unauthorized (code 401)
```

That 401 is the proof the codec is right in both directions — the host answers a request it could
not decode with `Internal("decode: …")` (500), so reaching the *authorize* gate means it parsed
the request, and parsing its reply means the decoder agrees too.

## Not yet done

- **`sdk/js`** — the browser/Node face, for `ocean-web` and `ce-drive-web`. Same vectors.
- The Rust golden test has **not been run** — `cargo test` on this repo is a heavy build and goes
  to the relay, not the laptop. It is written and pinned to the same constants; it is unproven.
- Props / tags / links / backlinks / search / versions exist in `ce-drive-core` but are **not on
  the wire**, so this SDK cannot reach them. That gap blocks kind-based handler dispatch.
