/**
 * ce-drive/v1 JavaScript SDK — the browser/Node client for the CE Drive mesh API.
 *
 * The third implementation of the same wire, after Rust (`ce-drive-client`) and Python
 * (`sdk/py/cedrive.py`). It exists because `ocean-web` and `ce-drive-web` had no way to call a live,
 * cap-gated API without hand-rolling bincode, so they reimplemented the tree over the wasm CRDT
 * instead — the same reason ce-files shelled out to a CLI.
 *
 * THE WIRE IS BINCODE, NOT JSON. bincode 1.x legacy config: little-endian fixed-width integers,
 * `u64` sequence lengths, `u32` enum variant indices, `Option` as a leading 0/1 byte.
 *
 * ## The trap this language has that the others do not
 *
 * JavaScript numbers are doubles, so anything above 2^53 loses precision silently. This wire carries
 * u64 sizes, offsets and cursors, and a 5 GiB file's offset is fine but a cursor or a large size is
 * not. So every u64 is read and written as **BigInt**, never as a Number. That is not defensive
 * style: the same class of bug already bit ce-ts once, where a `reply_token` was rounded and the
 * reply went to the wrong caller.
 *
 * Sizes come back as BigInt for that reason. `Number(entry.size)` is safe below 2^53 and is your
 * choice to make, not this SDK's.
 *
 * ## Bytes never ride the metadata channel
 *
 * `read()` asks the host for a plan — the object CID plus the chunk refs covering the range — then
 * fetches those chunks from the node's content-addressed blob store and verifies each against its
 * CID before returning a byte. Content addressing IS the integrity proof.
 *
 * ## This SDK holds no keys and does no crypto
 *
 * `cap` is an opaque hex ce-cap chain obtained elsewhere (ce-iam); this file only carries it.
 */

const DRIVE_TOPIC = 'ce-drive/v1';
const SERVICE = 'ce-drive';
const DEFAULT_NODE_URL = 'http://127.0.0.1:8844';
const CHUNK = 1 << 20; // 1 MiB — the ce-object-v1 chunk size, fixed across every SDK

// DriveOp variant indices, in declaration order. The discriminant IS the order.
const OP = {
  OPEN: 0, STAT: 1, LIST: 2, READ: 3, WRITE: 4, MKDIR: 5,
  MOVE: 6, COPY: 7, DELETE: 8, SHARE: 9, POLL: 10, WATCH: 11,
  // Appended after Watch, so every index above is untouched and no deployed client's wire moves.
  META: 12, SETPROP: 13, TAG: 14, LINK: 15, BACKLINKS: 16, VERSIONS: 17,
};

const OK = {
  OPENED: 0, ENTRY: 1, LISTING: 2, READPLAN: 3, WRITTEN: 4,
  MADE: 5, DELETED: 6, SHARED: 7, CHANGES: 8, WATCHING: 9,
  META: 10, BACKLINKS: 11, VERSIONS: 12,
};

// DriveErr variant index -> [code, message]. Mirrors DriveErr::code()/Display.
const ERRS = [
  [401, 'unauthorized'], [410, 'capability revoked'], [419, 'capability expired'],
  [403, 'path outside granted scope'], [404, 'not found'], [409, 'conflict'],
  [429, 'quota exceeded'], [402, 'payment required'], [400, 'bad path'], [500, 'internal error'],
];

export class DriveError extends Error {
  constructor(message, code = null, currentEtag = null) {
    super(message);
    this.name = 'DriveError';
    this.code = code;
    this.currentEtag = currentEtag; // set on 409
  }
}

// ---------------------------------------------------------------------------
// bincode 1.x legacy codec
// ---------------------------------------------------------------------------

class Enc {
  constructor() { this.parts = []; }
  u8(v) { this.parts.push(Uint8Array.of(v & 0xff)); return this; }
  u32(v) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v >>> 0, true);
    this.parts.push(b); return this;
  }
  /** Always BigInt on the wire: a Number above 2^53 would be silently wrong. */
  u64(v) {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(v), true);
    this.parts.push(b); return this;
  }
  bool(v) { return this.u8(v ? 1 : 0); }
  str(s) {
    const raw = new TextEncoder().encode(s == null ? '' : String(s));
    this.u64(raw.length);         // byte length, not character count
    this.parts.push(raw); return this;
  }
  variant(i) { return this.u32(i); }
  optStr(s) { return s == null ? this.u8(0) : this.u8(1).str(s); }
  optU64(v) { return v == null ? this.u8(0) : this.u8(1).u64(v); }
  seqStr(items) {
    const a = items || [];
    this.u64(a.length);
    for (const s of a) this.str(s);
    return this;
  }
  bytes() {
    const total = this.parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let o = 0;
    for (const p of this.parts) { out.set(p, o); o += p.length; }
    return out;
  }
}

class Dec {
  constructor(data) { this.d = data; this.i = 0; this.view = new DataView(data.buffer, data.byteOffset, data.byteLength); }
  take(n) {
    if (this.i + n > this.d.length) {
      throw new DriveError(`truncated reply: wanted ${n} bytes at ${this.i}, have ${this.d.length}`);
    }
    const o = this.i; this.i += n; return o;
  }
  u8() { return this.d[this.take(1)]; }
  u32() { return this.view.getUint32(this.take(4), true); }
  /** BigInt, always. Converting here would be the precision bug. */
  u64() { return this.view.getBigUint64(this.take(8), true); }
  bool() { return this.u8() !== 0; }
  str() {
    const n = Number(this.u64());
    const o = this.take(n);
    return new TextDecoder().decode(this.d.subarray(o, o + n));
  }
  variant() { return this.u32(); }
  optStr() { return this.u8() ? this.str() : null; }
  optU64() { return this.u8() ? this.u64() : null; }
  seq(readOne) {
    const n = Number(this.u64());
    const out = [];
    for (let i = 0; i < n; i++) out.push(readOne());
    return out;
  }
}

export function encodeReq(drive, cap, opIndex, writeFields) {
  const e = new Enc().str(drive).str(cap).variant(opIndex);
  if (writeFields) writeFields(e);
  return e.bytes();
}

function decodeEntry(d) {
  const path = d.str();
  const isDir = d.variant() === 1;      // EntryKind: 0 File, 1 Dir
  const size = d.u64();
  const mtimeMs = d.u64();
  const etag = d.str();
  const nodeId = d.str();
  return { path, kind: isDir ? 'dir' : 'file', isDir, size, mtimeMs, etag,
           nodeId, objectCid: d.optStr(), docId: d.optStr(),
           get name() { return path.replace(/\/+$/, '').split('/').pop(); } };
}

export function decodeReply(payload) {
  if (!payload || payload.length === 0) {
    throw new DriveError('empty reply from drive host (no provider, or it dropped the request)');
  }
  const d = new Dec(payload);
  if (d.variant() !== 0) return raiseErr(d);     // Result: 0 Ok, 1 Err
  const ok = d.variant();
  switch (ok) {
    case OK.OPENED: return {
      driveRootCid: d.str(), serverSeq: d.u64(), grantedAbilities: d.seq(() => d.str()),
      quota: { pricePerGibMonth: d.str(), pricePerGibEgress: d.str(),
               freeTierBytes: d.u64(), channelRequired: d.bool() },
    };
    case OK.ENTRY: return decodeEntry(d);
    case OK.LISTING: return { entries: d.seq(() => decodeEntry(d)), nextCursor: d.optStr() };
    case OK.READPLAN: {
      const objectCid = d.str(), totalSize = d.u64(), chunkSize = d.u64();
      const chunks = d.seq(() => ({ cid: d.str(), offset: d.u64(), len: d.u64() }));
      return { objectCid, totalSize, chunkSize, chunks, encrypted: d.bool(), keyHint: d.optStr() };
    }
    case OK.WRITTEN: return { etag: d.str(), nodeId: d.str(), versionSeq: d.u64() };
    case OK.MADE: return { nodeId: d.str() };
    case OK.DELETED: return true;
    case OK.SHARED: return { chain: d.str() };
    case OK.CHANGES: {
      const changes = d.seq(() => {
        const seq = d.u64(), path = d.str(), nodeId = d.str();
        const v = d.variant();
        const kind = ['created', 'modified', 'deleted', 'moved'][v] ?? 'unknown';
        const movedFrom = v === 3 ? d.str() : null;
        return { seq, path, nodeId, kind, etag: d.str(), movedFrom };
      });
      return { changes, newCursor: d.u64() };
    }
    case OK.WATCHING: return { topic: d.str(), cursor: d.u64() };
    case OK.META: return {
      nodeId: d.str(),
      props: Object.fromEntries(d.seq(() => [d.str(), d.str()])),
      tags: d.seq(() => d.str()),
      links: d.seq(() => ({ rel: d.str(), to: d.str() })),
    };
    case OK.BACKLINKS: return d.seq(() => [d.str(), d.str()]);
    case OK.VERSIONS: return d.seq(() => ({
      setAtMs: d.u64(), locator: d.str(), size: d.u64(), conflict: d.bool(),
    }));
    default:
      throw new DriveError(`unknown DriveOk variant ${ok} (host is newer than this SDK)`);
  }
}

function raiseErr(d) {
  const v = d.variant();
  const [code, msg] = ERRS[v] ?? [500, `unknown error variant ${v}`];
  if (v === 5) { const etag = d.str(); throw new DriveError(`conflict (current etag ${etag})`, code, etag); }
  if (v === 9) throw new DriveError(`internal error: ${d.str()}`, code);
  throw new DriveError(msg, code);
}

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (s) => {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
};

/** Lowercase hex SHA-256 — the node's blob hash, portable across every CE SDK. */
export async function cid(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return hex(new Uint8Array(digest));
}

export class Drive {
  constructor({ drive = 'default', cap = '', nodeUrl = DEFAULT_NODE_URL, token = null,
                provider = null, timeoutMs = 30000 } = {}) {
    this.drive = drive; this.cap = cap;
    this.nodeUrl = nodeUrl.replace(/\/+$/, '');
    this.token = token; this.provider = provider; this.timeoutMs = timeoutMs;
  }

  async _json(method, path, body) {
    const headers = {};
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const r = await fetch(this.nodeUrl + path, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!r.ok) throw new DriveError(`${method} ${path} -> HTTP ${r.status}`);
    return r.json();
  }

  async _raw(path) {
    const headers = {};
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    const r = await fetch(this.nodeUrl + path, { headers });
    if (!r.ok) throw new DriveError(`GET ${path} -> HTTP ${r.status}`);
    return new Uint8Array(await r.arrayBuffer());
  }

  /** The node hosting this drive, found by SERVICE NAME over the mesh, never by address. */
  async resolveProvider() {
    if (this.provider) return this.provider;
    try {
      const found = await this._json('GET', `/discovery/find/${encodeURIComponent(SERVICE)}`);
      if (found.providers?.length) { this.provider = found.providers[0]; return this.provider; }
    } catch { /* fall through to prefer-self */ }
    this.provider = (await this._json('GET', '/status')).node_id;
    return this.provider;
  }

  async _call(opIndex, writeFields) {
    const to = await this.resolveProvider();
    const payload = encodeReq(this.drive, this.cap, opIndex, writeFields);
    let out;
    try {
      out = await this._json('POST', '/mesh/request', {
        to, topic: DRIVE_TOPIC, payload_hex: hex(payload), timeout_ms: this.timeoutMs,
      });
    } catch (e) {
      this.provider = null;   // stale provider: re-discover next call
      throw e;
    }
    return decodeReply(unhex(out.payload_hex || ''));
  }

  open() { return this._call(OP.OPEN); }
  stat(path) { return this._call(OP.STAT, (e) => e.str(path)); }
  mkdir(path) { return this._call(OP.MKDIR, (e) => e.str(path)).then((r) => r.nodeId); }
  mv(from, to) { return this._call(OP.MOVE, (e) => e.str(from).str(to)); }
  cp(from, to) { return this._call(OP.COPY, (e) => e.str(from).str(to)); }
  rm(path, recursive = false) { return this._call(OP.DELETE, (e) => e.str(path).bool(recursive)); }
  watch() { return this._call(OP.WATCH); }
  poll(cursor = null, limit = 500) { return this._call(OP.POLL, (e) => e.optU64(cursor).u32(limit)); }

  meta(path) { return this._call(OP.META, (e) => e.str(path)); }
  setProp(path, key, value) { return this._call(OP.SETPROP, (e) => e.str(path).str(key).optStr(value)); }
  tag(path, tag, remove = false) { return this._call(OP.TAG, (e) => e.str(path).str(tag).bool(remove)); }
  link(path, to, rel = 'related', remove = false) {
    return this._call(OP.LINK, (e) => e.str(path).str(rel).str(to).bool(remove));
  }
  backlinks(to) { return this._call(OP.BACKLINKS, (e) => e.str(to)); }
  versions(path) { return this._call(OP.VERSIONS, (e) => e.str(path)); }

  /** List a directory, paging to the end. A single reply is one PAGE; stopping at the first
   *  silently reports a partial directory. */
  async ls(path = '/', limit = 500) {
    const out = [];
    let cursor = null;
    for (;;) {
      const page = await this._call(OP.LIST, (e) => e.str(path).optStr(cursor).u32(limit));
      out.push(...page.entries);
      cursor = page.nextCursor;
      if (!cursor) return out;
    }
  }

  /** Read a byte range. Every chunk is verified against its CID before it reaches you. */
  async read(path, offset = 0, length = null) {
    const plan = await this._call(OP.READ, (e) => e.str(path).u64(offset).optU64(length));
    if (!plan.chunks.length) return new Uint8Array(0);
    const parts = [];
    for (const c of plan.chunks) {
      const bytes = await this._raw(`/blobs/${c.cid}`);
      if (await cid(bytes) !== c.cid) {
        throw new DriveError(`chunk cid mismatch at offset ${c.offset} of ${path} — refusing corrupt data`);
      }
      parts.push(bytes);
    }
    const total = parts.reduce((n, p) => n + p.length, 0);
    const buf = new Uint8Array(total);
    let o = 0;
    for (const p of parts) { buf.set(p, o); o += p.length; }
    // Chunks start at boundaries, so trim to what was actually asked for.
    const start = Number(BigInt(offset) - plan.chunks[0].offset);
    const end = length == null ? buf.length : start + Number(length);
    return buf.subarray(start, end);
  }

  async readText(path) { return new TextDecoder().decode(await this.read(path)); }

  /** Upload the object, then commit `path -> object_cid`. */
  async write(path, data, baseEtag = null) {
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const objectCid = await this._putObject(bytes);
    return this._call(OP.WRITE, (e) => e.str(path).str(objectCid).u64(bytes.length).optStr(baseEtag));
  }

  async _putBlob(bytes) {
    const headers = { 'Content-Type': 'application/octet-stream' };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    const r = await fetch(`${this.nodeUrl}/blobs`, { method: 'POST', headers, body: bytes });
    if (!r.ok) throw new DriveError(`POST /blobs -> HTTP ${r.status}`);
    return (await r.json()).hash;
  }

  /** 1 MiB chunks + a `ce-object-v1` manifest. Field order and separators must match
   *  ce.py/ce-rs/ce-go, or the object CID stops being portable across SDKs. */
  async _putObject(bytes) {
    const chunks = [];
    for (let off = 0; off < bytes.length; off += CHUNK) {
      chunks.push(await this._putBlob(bytes.subarray(off, off + CHUNK)));
    }
    const manifest = JSON.stringify({
      kind: 'ce-object-v1', chunk_size: CHUNK, total_size: bytes.length, chunks,
    });
    return this._putBlob(new TextEncoder().encode(manifest));
  }
}

export function connect(opts) { return new Drive(opts); }
export { OP, OK, DRIVE_TOPIC, SERVICE };
