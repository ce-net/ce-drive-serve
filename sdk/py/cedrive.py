"""ce-drive/v1 Python SDK — the client for the CE Drive mesh API.

The consumer half of the contract `ce-drive-serve` hosts. Stdlib only (urllib +
hashlib); vendor this ONE file next to your app like `ce.py` and import it.

    import cedrive

    d = cedrive.connect(drive="default", cap=my_cap_chain_hex)
    d.mkdir("/notes")
    d.write_text("/notes/hello.md", "# hello\\n")
    print(d.read_text("/notes/hello.md"))
    for e in d.ls("/notes"):
        print(e.path, e.size, e.node_id)

THE WIRE IS BINCODE, NOT JSON. Every op is one `DriveReq` sent as an AppRequest
on topic `ce-drive/v1`; the host answers one `DriveReply`. The types are
bincode-encoded with bincode 1.x's legacy config — little-endian fixed-width
integers, `u64` sequence lengths, `u32` enum variant indices, `Option` as a
leading 0/1 byte. `_Enc`/`_Dec` below implement exactly that and nothing more.

That codec is the whole reason this file exists. Rust already has a good client
(`ce-drive-client`: `RemoteDrive` + a replica-backed `Mirror`); Python had none,
so `ce-files` shells out to the `ce-drive` CLI on a 60-second whole-drive poll
instead of calling an API that has been live and cap-gated all along. The wire
being bincode rather than JSON is what made each non-Rust consumer go around it.

Keep the wire types below in lockstep with `ce-drive-serve/src/wire.rs`: field
order and enum declaration order ARE the encoding.

BYTES NEVER RIDE THE METADATA CHANNEL. `Read` returns a `ReadPlan` — the object
CID plus the chunk refs covering the requested range — and this client fetches
those chunks straight from the node's content-addressed blob store and verifies
each against its CID before it returns a byte. `Write` uploads the object first
(1 MiB chunks + a `ce-object-v1` manifest, byte-identical to `ce.py`/`ce-rs`, so
object CIDs are portable across SDKs) and then commits `path -> object_cid`.
The metadata host therefore never holds your bytes.

THIS SDK HOLDS NO KEYS AND DOES NO CRYPTO. The `cap` is an opaque hex ce-cap
chain you obtained elsewhere (ce-iam); this file only carries it. The host
verifies it per op, and the drive id is bound into the leaf cap's `path_prefix`
as `ce-drive/<drive>[/<subtree>]`, so a cap minted for one drive authorizes
nothing on another. A refusal arrives as a `DriveError` carrying the host's
stable numeric code (401/403/404/409/...).

Discovery is by SERVICE NAME (`ce-drive`), never an address.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional, Sequence

SERVICE = "ce-drive"
DRIVE_TOPIC = "ce-drive/v1"

DEFAULT_NODE_URL = "http://127.0.0.1:8844"
DEFAULT_TIMEOUT_MS = 30000
CHUNK = 1 << 20          # 1 MiB — the ce-object-v1 chunk size, fixed across SDKs
LIST_PAGE = 500


def changes_topic(drive: str) -> str:
    """The per-drive pubsub beacon topic the host publishes on when a drive advances."""
    return f"ce-drive/{drive}/changes"


class DriveError(Exception):
    """A drive op was refused, or the transport failed.

    `code` is the host's stable numeric code when the refusal came from the host
    (401 unauthorized, 403 out of scope, 404 not found, 409 conflict, 410 revoked,
    419 expired, 429 quota, 402 payment, 400 bad path, 500 internal); it is None
    for a local/transport failure.
    """

    def __init__(self, message: str, code: Optional[int] = None,
                 current_etag: Optional[str] = None):
        super().__init__(message)
        self.code = code
        self.current_etag = current_etag       # set on 409 Conflict


# ---------------------------------------------------------------------------
# bincode 1.x legacy codec (LE fixint, u64 lengths, u32 enum variants)
# ---------------------------------------------------------------------------

class _Enc:
    """Encoder. Only the shapes the ce-drive/v1 types actually use."""

    def __init__(self):
        self.buf = bytearray()

    def u8(self, v: int) -> "_Enc":
        self.buf += struct.pack("<B", v & 0xFF)
        return self

    def u32(self, v: int) -> "_Enc":
        self.buf += struct.pack("<I", v)
        return self

    def u64(self, v: int) -> "_Enc":
        self.buf += struct.pack("<Q", v)
        return self

    def bool(self, v) -> "_Enc":
        return self.u8(1 if v else 0)

    def str(self, s) -> "_Enc":
        raw = str(s or "").encode("utf-8")
        self.u64(len(raw))
        self.buf += raw
        return self

    def variant(self, index: int) -> "_Enc":
        """An enum discriminant: a u32, always, even for a fieldless variant."""
        return self.u32(index)

    def opt_str(self, s) -> "_Enc":
        if s is None:
            return self.u8(0)
        return self.u8(1).str(s)

    def opt_u64(self, v) -> "_Enc":
        if v is None:
            return self.u8(0)
        return self.u8(1).u64(v)

    def seq_str(self, items) -> "_Enc":
        items = list(items or [])
        self.u64(len(items))
        for s in items:
            self.str(s)
        return self

    def bytes(self) -> bytes:
        return bytes(self.buf)


class _Dec:
    """Decoder. Trailing bytes are tolerated (the host encodes with
    `allow_trailing_bytes`), a short buffer is not."""

    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def _take(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise DriveError(
                f"truncated reply: wanted {n} bytes at offset {self.i}, have {len(self.d)}")
        out = self.d[self.i:self.i + n]
        self.i += n
        return out

    def u8(self) -> int:
        return struct.unpack("<B", self._take(1))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self._take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self._take(8))[0]

    def bool(self) -> bool:
        return self.u8() != 0

    def str(self) -> str:
        n = self.u64()
        return self._take(n).decode("utf-8", errors="replace")

    def variant(self) -> int:
        return self.u32()

    def opt_str(self) -> Optional[str]:
        return self.str() if self.u8() else None

    def opt_u64(self) -> Optional[int]:
        return self.u64() if self.u8() else None

    def seq(self, read_one):
        return [read_one() for _ in range(self.u64())]


# ---------------------------------------------------------------------------
# wire types — field order and variant order MUST match ce-drive-serve/src/wire.rs
# ---------------------------------------------------------------------------

# DriveOp variant indices, in declaration order.
OP_OPEN, OP_STAT, OP_LIST, OP_READ, OP_WRITE, OP_MKDIR = 0, 1, 2, 3, 4, 5
OP_MOVE, OP_COPY, OP_DELETE, OP_SHARE, OP_POLL, OP_WATCH = 6, 7, 8, 9, 10, 11
# Appended after Watch, so every index above is untouched and no deployed client's wire moves.
OP_META, OP_SETPROP, OP_TAG, OP_LINK, OP_BACKLINKS, OP_VERSIONS = 12, 13, 14, 15, 16, 17

# DriveOk variant indices, in declaration order.
OK_OPENED, OK_ENTRY, OK_LISTING, OK_READPLAN, OK_WRITTEN = 0, 1, 2, 3, 4
OK_MADE, OK_DELETED, OK_SHARED, OK_CHANGES, OK_WATCHING = 5, 6, 7, 8, 9
OK_META, OK_BACKLINKS, OK_VERSIONS = 10, 11, 12

# DriveErr variant index -> (code, message). Mirrors DriveErr::code()/Display.
_ERRS = {
    0: (401, "unauthorized"),
    1: (410, "capability revoked"),
    2: (419, "capability expired"),
    3: (403, "path outside granted scope"),
    4: (404, "not found"),
    5: (409, "conflict"),
    6: (429, "quota exceeded"),
    7: (402, "payment required"),
    8: (400, "bad path"),
    9: (500, "internal error"),
}

FILE, DIR = "file", "dir"


@dataclass
class Entry:
    """One directory entry. `node_id` is the stable DriveTree identity — it
    survives rename and move, which is why links are stored against it and never
    against the path."""
    path: str
    kind: str                       # FILE | DIR
    size: int
    mtime_ms: int
    etag: str                       # optimistic-concurrency token for write()
    node_id: str
    object_cid: Optional[str] = None
    doc_id: Optional[str] = None    # set for embedded document nodes

    @property
    def is_dir(self) -> bool:
        return self.kind == DIR

    @property
    def name(self) -> str:
        return self.path.rstrip("/").rsplit("/", 1)[-1]


@dataclass
class ChunkRef:
    cid: str
    offset: int
    len: int


@dataclass
class ReadPlan:
    object_cid: str
    total_size: int
    chunk_size: int
    chunks: list = field(default_factory=list)
    encrypted: bool = False
    key_hint: Optional[str] = None


@dataclass
class Meta:
    """A node's props, tags and typed links.

    Keyed by `node_id`, not by path: links are stored against the stable id, so a rename never
    breaks an edge. Anything indexing the drive should key on `node_id` for the same reason.
    `props["kind"]` is the conventional one — it says what a file IS, which is what lets a reader
    pick a parser for it."""
    node_id: str
    props: dict = field(default_factory=dict)
    tags: list = field(default_factory=list)
    links: list = field(default_factory=list)   # [(rel, target)]


@dataclass
class Version:
    set_at_ms: int
    locator: str            # "<app>:<id>" — which content app holds these bytes
    size: int
    conflict: bool = False


@dataclass
class Change:
    seq: int
    path: str
    node_id: str
    kind: str                       # created | modified | deleted | moved
    etag: str
    moved_from: Optional[str] = None


@dataclass
class Quota:
    price_per_gib_month: str = "0"
    price_per_gib_egress: str = "0"
    free_tier_bytes: int = 0
    channel_required: bool = False


@dataclass
class Opened:
    drive_root_cid: str
    server_seq: int
    granted_abilities: list = field(default_factory=list)
    quota: Quota = field(default_factory=Quota)


def _enc_req(drive: str, cap: str, op_index: int, write_fields=None) -> bytes:
    """DriveReq { drive: String, cap: String, op: DriveOp }."""
    e = _Enc().str(drive).str(cap).variant(op_index)
    if write_fields is not None:
        write_fields(e)
    return e.bytes()


def _dec_entry(d: _Dec) -> Entry:
    path = d.str()
    kind = DIR if d.variant() else FILE       # EntryKind: 0 File, 1 Dir
    size = d.u64()
    mtime_ms = d.u64()
    etag = d.str()
    node_id = d.str()
    return Entry(path=path, kind=kind, size=size, mtime_ms=mtime_ms, etag=etag,
                 node_id=node_id, object_cid=d.opt_str(), doc_id=d.opt_str())


def _dec_change(d: _Dec) -> Change:
    seq = d.u64()
    path = d.str()
    node_id = d.str()
    v = d.variant()                            # ChangeKind
    kind = ("created", "modified", "deleted", "moved")[v] if v < 4 else "unknown"
    moved_from = d.str() if v == 3 else None   # Moved { from }
    return Change(seq=seq, path=path, node_id=node_id, kind=kind, etag=d.str(),
                  moved_from=moved_from)


def _dec_reply(payload: bytes):
    """DriveReply { result: Result<DriveOk, DriveErr> } -> a value, or raise."""
    if not payload:
        raise DriveError("empty reply from drive host (no provider, or it dropped the request)")
    d = _Dec(payload)
    if d.variant() != 0:                       # Result: 0 Ok, 1 Err
        return _raise_err(d)
    ok = d.variant()
    if ok == OK_OPENED:
        return Opened(drive_root_cid=d.str(), server_seq=d.u64(),
                      granted_abilities=d.seq(d.str),
                      quota=Quota(price_per_gib_month=d.str(),
                                  price_per_gib_egress=d.str(),
                                  free_tier_bytes=d.u64(),
                                  channel_required=d.bool()))
    if ok == OK_ENTRY:
        return _dec_entry(d)
    if ok == OK_LISTING:
        return (d.seq(lambda: _dec_entry(d)), d.opt_str())
    if ok == OK_READPLAN:
        object_cid, total_size, chunk_size = d.str(), d.u64(), d.u64()
        chunks = d.seq(lambda: ChunkRef(cid=d.str(), offset=d.u64(), len=d.u64()))
        return ReadPlan(object_cid=object_cid, total_size=total_size,
                        chunk_size=chunk_size, chunks=chunks,
                        encrypted=d.bool(), key_hint=d.opt_str())
    if ok == OK_WRITTEN:
        return {"etag": d.str(), "node_id": d.str(), "version_seq": d.u64()}
    if ok == OK_MADE:
        return {"node_id": d.str()}
    if ok == OK_DELETED:
        return True
    if ok == OK_SHARED:
        return {"chain": d.str()}
    if ok == OK_CHANGES:
        return (d.seq(lambda: _dec_change(d)), d.u64())
    if ok == OK_WATCHING:
        return {"topic": d.str(), "cursor": d.u64()}
    if ok == OK_META:
        node_id = d.str()
        props = dict(d.seq(lambda: (d.str(), d.str())))
        tags = d.seq(d.str)
        links = d.seq(lambda: (d.str(), d.str()))
        return Meta(node_id=node_id, props=props, tags=tags, links=links)
    if ok == OK_BACKLINKS:
        return d.seq(lambda: (d.str(), d.str()))
    if ok == OK_VERSIONS:
        return d.seq(lambda: Version(set_at_ms=d.u64(), locator=d.str(), size=d.u64(),
                                     conflict=d.bool()))
    raise DriveError(f"unknown DriveOk variant {ok} (host is newer than this SDK)")


def _raise_err(d: _Dec):
    v = d.variant()
    code, msg = _ERRS.get(v, (500, f"unknown error variant {v}"))
    if v == 5:                                 # Conflict { current_etag }
        etag = d.str()
        raise DriveError(f"conflict (current etag {etag})", code=code, current_etag=etag)
    if v == 9:                                 # Internal(String)
        raise DriveError(f"internal error: {d.str()}", code=code)
    raise DriveError(msg, code=code)


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------

def _data_dir() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", "~")).expanduser() / "ce"
    home = Path("~").expanduser()
    mac = home / "Library" / "Application Support" / "ce"
    return mac if mac.exists() else home / ".local" / "share" / "ce"


def _discover_token() -> Optional[str]:
    tok = os.environ.get("CE_API_TOKEN")
    if tok:
        return tok.strip()
    try:
        return (_data_dir() / "api.token").read_text().strip() or None
    except OSError:
        return None


def cid(data: bytes) -> str:
    """The content address of raw bytes: lowercase hex SHA-256, exactly what the
    node's `POST /blobs` returns. Portable across every CE SDK."""
    return hashlib.sha256(data).hexdigest()


class Drive:
    """A client for one drive on one host. Ops raise `DriveError` on refusal."""

    def __init__(self, drive: str = "default", cap: str = "", node_url=None,
                 token=None, provider=None, timeout_ms: int = DEFAULT_TIMEOUT_MS):
        self.drive = drive or "default"
        self.cap = cap or os.environ.get("CE_DRIVE_CAP", "")
        self.node_url = (node_url or os.environ.get("CE_NODE_URL")
                         or DEFAULT_NODE_URL).rstrip("/")
        self.token = token if token is not None else _discover_token()
        self.provider = provider or os.environ.get("CE_DRIVE_PROVIDER") or None
        self.timeout_ms = timeout_ms

    # ---- node HTTP ----

    def _http(self, method: str, path: str, body=None, raw: bytes = None,
              timeout: float = 35.0) -> bytes:
        url = self.node_url + path
        data, ctype = None, None
        if raw is not None:
            data, ctype = raw, "application/octet-stream"
        elif body is not None:
            data, ctype = json.dumps(body).encode("utf-8"), "application/json"
        req = urllib.request.Request(url, data=data, method=method)
        if ctype:
            req.add_header("Content-Type", ctype)
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            detail = (e.read() or b"").decode("utf-8", "replace")[:300]
            raise DriveError(f"{method} {path} -> HTTP {e.code}: {detail}") from None
        # A urllib timeout surfaces as a bare TimeoutError, which `except DriveError`
        # would miss — precisely when a caller most needs to catch it.
        except (TimeoutError, OSError) as e:
            raise DriveError(f"{method} {path} -> {e}") from None

    def _json(self, method: str, path: str, body=None, timeout: float = 35.0):
        raw = self._http(method, path, body=body, timeout=timeout)
        try:
            return json.loads(raw or b"{}")
        except json.JSONDecodeError as e:
            raise DriveError(f"{method} {path} -> malformed reply: {e}") from None

    def resolve_provider(self) -> str:
        """The node hosting this drive, found by SERVICE NAME over the mesh."""
        if self.provider:
            return self.provider
        try:
            found = self._json("GET", "/discovery/find/" +
                               urllib.parse.quote(SERVICE, safe=""))
            provs = found.get("providers") or []
        except DriveError:
            provs = []
        # Prefer-self: on a node that hosts its own drive the DHT round trip is
        # pure latency, and a fresh host may not have propagated yet.
        self.provider = provs[0] if provs else self._json("GET", "/status")["node_id"]
        return self.provider

    def _call(self, op_index: int, write_fields=None):
        to = self.resolve_provider()
        payload = _enc_req(self.drive, self.cap, op_index, write_fields)
        try:
            out = self._json("POST", "/mesh/request",
                             {"to": to, "topic": DRIVE_TOPIC,
                              "payload_hex": payload.hex(),
                              "timeout_ms": self.timeout_ms},
                             timeout=self.timeout_ms / 1000.0 + 5.0)
        except DriveError:
            self.provider = None          # stale provider: re-discover next call
            raise
        return _dec_reply(bytes.fromhex(out.get("payload_hex") or ""))

    # ---- metadata ops ----

    def open(self) -> Opened:
        """Handshake: the root snapshot CID, the host's change cursor, the
        abilities this cap ACTUALLY carries, and the quota terms. Cheap and
        idempotent — call it to find out what you may do before offering it."""
        return self._call(OP_OPEN)

    def stat(self, path: str) -> Entry:
        return self._call(OP_STAT, lambda e: e.str(path))

    def exists(self, path: str) -> bool:
        try:
            self.stat(path)
            return True
        except DriveError as e:
            if e.code == 404:
                return False
            raise

    def ls(self, path: str = "/", limit: int = LIST_PAGE, pages: bool = False):
        """List a directory. Pages to the end by default and returns a list;
        `pages=True` yields (entries, cursor) pages instead."""
        if pages:
            return self._ls_pages(path, limit)
        out, cursor = [], None
        while True:
            entries, cursor = self._ls_one(path, cursor, limit)
            out.extend(entries)
            if not cursor:
                return out

    def _ls_pages(self, path: str, limit: int) -> Iterator:
        cursor = None
        while True:
            entries, cursor = self._ls_one(path, cursor, limit)
            yield entries, cursor
            if not cursor:
                return

    def _ls_one(self, path: str, cursor, limit: int):
        return self._call(
            OP_LIST,
            lambda e: e.str(path).opt_str(cursor).u32(max(0, min(int(limit), 2**32 - 1))))

    def mkdir(self, path: str) -> str:
        """Create a directory; returns its stable node id."""
        return self._call(OP_MKDIR, lambda e: e.str(path))["node_id"]

    def mv(self, src: str, dst: str) -> str:
        """Rename/move — one O(1) edge flip; descendants follow, and every
        node id (so every link pointing at them) survives."""
        return self._call(OP_MOVE, lambda e: e.str(src).str(dst))["node_id"]

    def cp(self, src: str, dst: str) -> str:
        """Server-side copy. Free: chunk CIDs are shared via global dedup."""
        return self._call(OP_COPY, lambda e: e.str(src).str(dst))["node_id"]

    def rm(self, path: str, recursive: bool = False) -> bool:
        """Move to TRASH. Content is retained until GC, so this is recoverable."""
        return self._call(OP_DELETE, lambda e: e.str(path).bool(recursive))

    def share(self, path: str, audience: str, abilities: Sequence[str],
              not_after: int = 0, max_bytes_read=None, max_bytes_write=None) -> str:
        """Mint an ATTENUATED sub-capability for `audience`, scoped to `path`.
        Returns the extended cap chain (hex). Attenuation never widens: the host
        intersects with what your own cap carries."""
        def w(e):
            (e.str(path).str(audience).seq_str(abilities)
             .u64(not_after).opt_u64(max_bytes_read).opt_u64(max_bytes_write))
        return self._call(OP_SHARE, w)["chain"]

    def poll(self, cursor: Optional[int] = None, limit: int = 500):
        """The authoritative change feed: (changes, new_cursor) since `cursor`.
        This — not the pubsub beacon — is the source of truth for sync."""
        return self._call(
            OP_POLL,
            lambda e: e.opt_u64(cursor).u32(max(0, min(int(limit), 2**32 - 1))))

    def watch(self) -> dict:
        """The pubsub beacon topic + your current cursor. The beacon is a
        best-effort wake-up hint (gossip is lossy by design); on wake, `poll()`."""
        return self._call(OP_WATCH)

    # ---- metadata: props, tags, typed links ----
    #
    # These reach the mesh, so a tag set here replicates and anything indexing the drive can read
    # it. They were core-only for a while, which made them a single-machine feature.

    def meta(self, path: str) -> Meta:
        """A path's props, tags and links. A node nobody has annotated returns empty sets."""
        return self._call(OP_META, lambda e: e.str(path))

    def set_prop(self, path: str, key: str, value) -> bool:
        """Set a prop, or clear it by passing None. `kind` is the conventional one."""
        return self._call(
            OP_SETPROP, lambda e: e.str(path).str(key).opt_str(value))

    def tag(self, path: str, tag: str, remove: bool = False) -> bool:
        return self._call(OP_TAG, lambda e: e.str(path).str(tag).bool(remove))

    def link(self, path: str, to: str, rel: str = "related", remove: bool = False) -> bool:
        """Link a path to a target under a relation. `to` is `node:<id>`, `cid:<hash>` or a URI;
        a `node:` link survives the target being renamed or moved."""
        return self._call(
            OP_LINK, lambda e: e.str(path).str(rel).str(to).bool(remove))

    def backlinks(self, to: str):
        """Everything linking TO a target, as (rel, node_id) pairs."""
        return self._call(OP_BACKLINKS, lambda e: e.str(to))

    def versions(self, path: str):
        """A file's version history, oldest first."""
        return self._call(OP_VERSIONS, lambda e: e.str(path))

    # ---- bytes: the blob layer, never the metadata channel ----

    def _put_object(self, data: bytes) -> str:
        """1 MiB chunks + a `ce-object-v1` manifest. Field order and separators
        must match ce.py/ce-rs/ce-go or the object CID stops being portable."""
        hashes = [self._put_blob(data[off:off + CHUNK])
                  for off in range(0, len(data), CHUNK)]
        manifest = {"kind": "ce-object-v1", "chunk_size": CHUNK,
                    "total_size": len(data), "chunks": hashes}
        return self._put_blob(json.dumps(manifest, separators=(",", ":")).encode("utf-8"))

    def _put_blob(self, data: bytes) -> str:
        raw = self._http("POST", "/blobs", raw=data, timeout=120.0)
        try:
            return json.loads(raw or b"{}").get("hash", "")
        except json.JSONDecodeError as e:
            raise DriveError(f"POST /blobs -> malformed reply: {e}") from None

    def _get_blob(self, h: str) -> bytes:
        return self._http("GET", "/blobs/" + h, timeout=120.0)

    def read(self, path: str, offset: int = 0, length: Optional[int] = None) -> bytes:
        """Read a byte range. The host returns a plan; the bytes come from the
        content-addressed store and EVERY chunk is verified against its CID
        before it reaches you — content addressing is the integrity proof."""
        plan = self._call(
            OP_READ, lambda e: e.str(path).u64(offset).opt_u64(length))
        if not plan.chunks:
            return b""
        buf = bytearray()
        for c in plan.chunks:
            data = self._get_blob(c.cid)
            if cid(data) != c.cid:
                raise DriveError(
                    f"chunk cid mismatch at offset {c.offset} of {path} "
                    f"(claimed {c.cid[:16]}…) — refusing corrupt data")
            buf += data
        # Chunks cover the range but start at a chunk boundary: trim to what was asked.
        start = offset - plan.chunks[0].offset
        end = len(buf) if length is None else start + length
        return bytes(buf[start:end])

    def read_text(self, path: str, encoding: str = "utf-8") -> str:
        return self.read(path).decode(encoding, errors="replace")

    def write(self, path: str, data, base_etag: Optional[str] = None) -> dict:
        """Upload the bytes, then commit `path -> object_cid`.

        `base_etag` is optimistic concurrency: pass the etag you last read and
        the write is refused with a 409 `DriveError` (carrying `current_etag`)
        if someone else wrote first. Pass None to overwrite unconditionally."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        data = bytes(data)
        object_cid = self._put_object(data)
        return self._call(
            OP_WRITE,
            lambda e: e.str(path).str(object_cid).u64(len(data)).opt_str(base_etag))

    def write_text(self, path: str, text: str, base_etag: Optional[str] = None) -> dict:
        return self.write(path, text.encode("utf-8"), base_etag=base_etag)

    # ---- convenience ----

    def walk(self, path: str = "/") -> Iterator[Entry]:
        """Every entry under `path`, directories first, depth-first."""
        stack = [path]
        while stack:
            here = stack.pop()
            for e in self.ls(here):
                yield e
                if e.is_dir:
                    stack.append(e.path)


def connect(drive: str = "default", cap: str = "", node_url=None, token=None,
            provider=None, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> Drive:
    """Open a drive client. Reads CE_NODE_URL / CE_API_TOKEN (or the node's
    api.token) / CE_DRIVE_CAP / CE_DRIVE_PROVIDER when not passed."""
    return Drive(drive=drive, cap=cap, node_url=node_url, token=token,
                 provider=provider, timeout_ms=timeout_ms)
