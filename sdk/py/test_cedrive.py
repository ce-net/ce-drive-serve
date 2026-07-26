"""Tests for the ce-drive/v1 Python SDK.

The important ones are the GOLDEN VECTORS. Every hex constant below was computed
BY HAND from the bincode 1.x legacy encoding rules (little-endian fixed-width
integers, u64 sequence lengths, u32 enum variant indices, Option as a leading
0/1 byte) — not by running this SDK's own encoder, which would make the test
circular and prove nothing.

`ce-drive-serve/tests/wire_golden_py.rs` asserts the SAME constants from the
Rust side. That is what makes them a contract: if either encoder drifts, one of
the two suites goes red, and a silent wire drift here would corrupt every op.

    python3 -m unittest test_cedrive -v
"""

from __future__ import annotations

import hashlib
import json
import unittest

import cedrive
from cedrive import DriveError, _Dec, _Enc

# The request prefix shared by every golden below: drive "team", cap "deadbeef".
#   "team"     -> u64 len 4  + utf8      -> 0400000000000000 7465616d
#   "deadbeef" -> u64 len 8  + utf8      -> 0800000000000000 6465616462656566
REQ_PREFIX = "0400000000000000" "7465616d" "0800000000000000" "6465616462656566"

GOLDEN_REQS = {
    # Open — a fieldless variant still costs a full u32 discriminant.
    "open": REQ_PREFIX + "00000000",
    # Stat { path: "/a/b" }
    "stat": REQ_PREFIX + "01000000" + "0400000000000000" + "2f612f62",
    # List { path: "/a", cursor: None, limit: 10 }
    "list": REQ_PREFIX + "02000000" + "0200000000000000" + "2f61" + "00" + "0a000000",
    # List { path: "/a", cursor: Some("x"), limit: 0 }
    "list_cursor": (REQ_PREFIX + "02000000" + "0200000000000000" + "2f61"
                    + "01" + "0100000000000000" + "78" + "00000000"),
    # Read { path: "/f", offset: 0, len: None }
    "read": (REQ_PREFIX + "03000000" + "0200000000000000" + "2f66"
             + "0000000000000000" + "00"),
    # Write { path: "/f", object_cid: "cid", size: 5, base_etag: Some("e") }
    "write": (REQ_PREFIX + "04000000" + "0200000000000000" + "2f66"
              + "0300000000000000" + "636964" + "0500000000000000"
              + "01" + "0100000000000000" + "65"),
    # Mkdir { path: "/d" }
    "mkdir": REQ_PREFIX + "05000000" + "0200000000000000" + "2f64",
    # Move { from: "/a", to: "/b" }
    "move": (REQ_PREFIX + "06000000" + "0200000000000000" + "2f61"
             + "0200000000000000" + "2f62"),
    # Delete { path: "/f", recursive: true }
    "delete": REQ_PREFIX + "08000000" + "0200000000000000" + "2f66" + "01",
    # Poll { cursor: Some(7), limit: 500 }
    "poll": (REQ_PREFIX + "0a000000" + "01" + "0700000000000000" + "f4010000"),
    # Watch
    "watch": REQ_PREFIX + "0b000000",
    # Meta { path: "/a" }
    "meta": REQ_PREFIX + "0c000000" + "0200000000000000" + "2f61",
    # Tag { path: "/a", tag: "x", remove: true }
    "tag": (REQ_PREFIX + "0e000000" + "0200000000000000" + "2f61"
            + "0100000000000000" + "78" + "01"),
    # Share { path: "/p", audience: "aud", abilities: ["read"],
    #         caveats: { not_after: 1, max_bytes_read: None, max_bytes_write: Some(2) } }
    "share": (REQ_PREFIX + "09000000"
              + "0200000000000000" + "2f70"
              + "0300000000000000" + "617564"
              + "0100000000000000" + "0400000000000000" + "72656164"
              + "0100000000000000" + "00" + "01" + "0200000000000000"),
}

# DriveReply { result: Result<DriveOk, DriveErr> } — Result itself is an enum.
GOLDEN_REPLIES = {
    "deleted": "00000000" + "06000000",                       # Ok(Deleted)
    "not_found": "01000000" + "04000000",                     # Err(NotFound)
    "unauthorized": "01000000" + "00000000",                  # Err(Unauthorized)
    "out_of_scope": "01000000" + "03000000",                  # Err(OutOfScope)
    # Err(Conflict { current_etag: "e" })
    "conflict": "01000000" + "05000000" + "0100000000000000" + "65",
    # Err(Internal("boom"))
    "internal": "01000000" + "09000000" + "0400000000000000" + "626f6f6d",
    # Ok(Made { node_id: "n1" })
    "made": "00000000" + "05000000" + "0200000000000000" + "6e31",
    # Ok(Written { etag: "e", node_id: "n", version_seq: 3 })
    "written": ("00000000" + "04000000" + "0100000000000000" + "65"
                + "0100000000000000" + "6e" + "0300000000000000"),
    # Ok(Watching { topic: "t", cursor: 9 })
    "watching": ("00000000" + "09000000" + "0100000000000000" + "74"
                 + "0900000000000000"),
}

DRIVE, CAP = "team", "deadbeef"


def enc(op_index, write_fields=None):
    return cedrive._enc_req(DRIVE, CAP, op_index, write_fields).hex()


class TestBincodeCodec(unittest.TestCase):
    """The primitives, pinned independently of any wire type."""

    def test_integers_are_little_endian_fixed_width(self):
        self.assertEqual(_Enc().u8(1).bytes().hex(), "01")
        self.assertEqual(_Enc().u32(1).bytes().hex(), "01000000")
        self.assertEqual(_Enc().u64(1).bytes().hex(), "0100000000000000")
        self.assertEqual(_Enc().u32(500).bytes().hex(), "f4010000")

    def test_u64_survives_above_2_53(self):
        """Sizes and cursors exceed JSON's safe integer range — bincode carries
        them exactly, and that is half the reason this wire is not JSON."""
        big = 2**64 - 1
        self.assertEqual(_Dec(_Enc().u64(big).bytes()).u64(), big)
        mid = 2**53 + 12345
        self.assertEqual(_Dec(_Enc().u64(mid).bytes()).u64(), mid)

    def test_string_is_u64_length_then_utf8(self):
        self.assertEqual(_Enc().str("team").bytes().hex(),
                         "0400000000000000" + "7465616d")
        self.assertEqual(_Enc().str("").bytes().hex(), "0000000000000000")

    def test_non_ascii_string_length_counts_bytes_not_chars(self):
        # "é" is two UTF-8 bytes; a char count here would desync the whole stream.
        self.assertEqual(_Enc().str("é").bytes().hex(), "0200000000000000" + "c3a9")
        self.assertEqual(_Dec(_Enc().str("skärgård").bytes()).str(), "skärgård")

    def test_option_is_a_leading_tag_byte(self):
        self.assertEqual(_Enc().opt_str(None).bytes().hex(), "00")
        self.assertEqual(_Enc().opt_str("x").bytes().hex(),
                         "01" + "0100000000000000" + "78")
        self.assertEqual(_Enc().opt_u64(None).bytes().hex(), "00")
        self.assertEqual(_Enc().opt_u64(7).bytes().hex(), "01" + "0700000000000000")

    def test_bool_and_seq(self):
        self.assertEqual(_Enc().bool(True).bytes().hex(), "01")
        self.assertEqual(_Enc().bool(False).bytes().hex(), "00")
        self.assertEqual(_Enc().seq_str([]).bytes().hex(), "0000000000000000")
        self.assertEqual(_Enc().seq_str(["a"]).bytes().hex(),
                         "0100000000000000" + "0100000000000000" + "61")

    def test_decoder_refuses_a_truncated_buffer(self):
        with self.assertRaises(DriveError):
            _Dec(b"\x01\x02").u64()

    def test_decoder_tolerates_trailing_bytes(self):
        """The host encodes with allow_trailing_bytes; a stricter client would
        reject replies a newer host legitimately sends."""
        d = _Dec(_Enc().u32(4).bytes() + b"\xde\xad\xbe\xef")
        self.assertEqual(d.u32(), 4)


class TestGoldenRequests(unittest.TestCase):
    """Every DriveOp variant against a hand-computed vector."""

    def test_open(self):
        self.assertEqual(enc(cedrive.OP_OPEN), GOLDEN_REQS["open"])

    def test_stat(self):
        self.assertEqual(enc(cedrive.OP_STAT, lambda e: e.str("/a/b")),
                         GOLDEN_REQS["stat"])

    def test_list(self):
        self.assertEqual(
            enc(cedrive.OP_LIST, lambda e: e.str("/a").opt_str(None).u32(10)),
            GOLDEN_REQS["list"])
        self.assertEqual(
            enc(cedrive.OP_LIST, lambda e: e.str("/a").opt_str("x").u32(0)),
            GOLDEN_REQS["list_cursor"])

    def test_read(self):
        self.assertEqual(
            enc(cedrive.OP_READ, lambda e: e.str("/f").u64(0).opt_u64(None)),
            GOLDEN_REQS["read"])

    def test_write(self):
        self.assertEqual(
            enc(cedrive.OP_WRITE,
                lambda e: e.str("/f").str("cid").u64(5).opt_str("e")),
            GOLDEN_REQS["write"])

    def test_mkdir_move_delete(self):
        self.assertEqual(enc(cedrive.OP_MKDIR, lambda e: e.str("/d")),
                         GOLDEN_REQS["mkdir"])
        self.assertEqual(enc(cedrive.OP_MOVE, lambda e: e.str("/a").str("/b")),
                         GOLDEN_REQS["move"])
        self.assertEqual(
            enc(cedrive.OP_DELETE, lambda e: e.str("/f").bool(True)),
            GOLDEN_REQS["delete"])

    def test_poll_and_watch(self):
        self.assertEqual(
            enc(cedrive.OP_POLL, lambda e: e.opt_u64(7).u32(500)),
            GOLDEN_REQS["poll"])
        self.assertEqual(enc(cedrive.OP_WATCH), GOLDEN_REQS["watch"])

    def test_share_caveats_field_order(self):
        def w(e):
            (e.str("/p").str("aud").seq_str(["read"])
             .u64(1).opt_u64(None).opt_u64(2))
        self.assertEqual(enc(cedrive.OP_SHARE, w), GOLDEN_REQS["share"])

    def test_metadata_ops(self):
        self.assertEqual(enc(cedrive.OP_META, lambda e: e.str("/a")), GOLDEN_REQS["meta"])
        self.assertEqual(
            enc(cedrive.OP_TAG, lambda e: e.str("/a").str("x").bool(True)),
            GOLDEN_REQS["tag"])

    def test_metadata_variants_were_APPENDED_not_inserted(self):
        """Inserting a variant anywhere but the end silently repoints every later op for every
        deployed client. Metadata had to land after Watch for exactly that reason."""
        self.assertEqual(cedrive.OP_WATCH, 11, "Watch must stay the last pre-metadata op")
        self.assertEqual(
            [cedrive.OP_META, cedrive.OP_SETPROP, cedrive.OP_TAG,
             cedrive.OP_LINK, cedrive.OP_BACKLINKS, cedrive.OP_VERSIONS],
            [12, 13, 14, 15, 16, 17])

    def test_variant_indices_match_declaration_order(self):
        """The discriminant IS the declaration order in wire.rs. Inserting a
        variant anywhere but the end silently repoints every later op."""
        self.assertEqual(
            [cedrive.OP_OPEN, cedrive.OP_STAT, cedrive.OP_LIST, cedrive.OP_READ,
             cedrive.OP_WRITE, cedrive.OP_MKDIR, cedrive.OP_MOVE, cedrive.OP_COPY,
             cedrive.OP_DELETE, cedrive.OP_SHARE, cedrive.OP_POLL, cedrive.OP_WATCH],
            list(range(12)))


class TestGoldenReplies(unittest.TestCase):

    def dec(self, name):
        return cedrive._dec_reply(bytes.fromhex(GOLDEN_REPLIES[name]))

    def test_ok_deleted(self):
        self.assertIs(self.dec("deleted"), True)

    def test_ok_made_and_written(self):
        self.assertEqual(self.dec("made"), {"node_id": "n1"})
        self.assertEqual(self.dec("written"),
                         {"etag": "e", "node_id": "n", "version_seq": 3})
        self.assertEqual(self.dec("watching"), {"topic": "t", "cursor": 9})

    def test_errors_carry_the_hosts_stable_code(self):
        for name, code in (("not_found", 404), ("unauthorized", 401),
                           ("out_of_scope", 403), ("internal", 500)):
            with self.assertRaises(DriveError) as cm:
                self.dec(name)
            self.assertEqual(cm.exception.code, code, name)

    def test_conflict_surfaces_the_current_etag(self):
        """A 409 is actionable only if the caller can re-read and retry, which
        needs the etag the host actually holds."""
        with self.assertRaises(DriveError) as cm:
            self.dec("conflict")
        self.assertEqual(cm.exception.code, 409)
        self.assertEqual(cm.exception.current_etag, "e")

    def test_internal_keeps_the_hosts_message(self):
        with self.assertRaises(DriveError) as cm:
            self.dec("internal")
        self.assertIn("boom", str(cm.exception))

    def test_empty_reply_is_a_clear_error(self):
        """No provider / dropped request must not look like a successful empty
        result — the caller would write it into a document."""
        with self.assertRaises(DriveError) as cm:
            cedrive._dec_reply(b"")
        self.assertIn("empty reply", str(cm.exception))

    def test_unknown_ok_variant_names_the_cause(self):
        with self.assertRaises(DriveError) as cm:
            cedrive._dec_reply(bytes.fromhex("00000000" + "63000000"))
        self.assertIn("newer than this SDK", str(cm.exception))


def _entry_bytes(path, is_dir=False, size=0, etag="e", node_id="n",
                 object_cid=None, doc_id=None):
    e = (_Enc().str(path).variant(1 if is_dir else 0).u64(size).u64(0)
         .str(etag).str(node_id).opt_str(object_cid).opt_str(doc_id))
    return e.bytes()


class TestEntryAndChangeDecoding(unittest.TestCase):

    def test_entry_field_order(self):
        payload = (_Enc().variant(0).variant(cedrive.OK_ENTRY).bytes()
                   + _entry_bytes("/a/b.md", size=12, node_id="n7",
                                  object_cid="abc"))
        e = cedrive._dec_reply(payload)
        self.assertEqual((e.path, e.kind, e.size, e.node_id, e.object_cid),
                         ("/a/b.md", cedrive.FILE, 12, "n7", "abc"))
        self.assertEqual(e.name, "b.md")
        self.assertFalse(e.is_dir)

    def test_dir_entry(self):
        payload = (_Enc().variant(0).variant(cedrive.OK_ENTRY).bytes()
                   + _entry_bytes("/notes", is_dir=True))
        self.assertTrue(cedrive._dec_reply(payload).is_dir)

    def test_listing_with_cursor(self):
        payload = (_Enc().variant(0).variant(cedrive.OK_LISTING).u64(2).bytes()
                   + _entry_bytes("/a") + _entry_bytes("/b", is_dir=True)
                   + _Enc().opt_str("next").bytes())
        entries, cursor = cedrive._dec_reply(payload)
        self.assertEqual([e.path for e in entries], ["/a", "/b"])
        self.assertEqual(cursor, "next")

    def test_change_moved_carries_its_from_path(self):
        payload = (_Enc().variant(0).variant(cedrive.OK_CHANGES).u64(1)
                   .u64(4).str("/new").str("n1").variant(3).str("/old")
                   .str("e").u64(9).bytes())
        changes, cursor = cedrive._dec_reply(payload)
        self.assertEqual(cursor, 9)
        self.assertEqual((changes[0].kind, changes[0].moved_from, changes[0].seq),
                         ("moved", "/old", 4))

    def test_change_kinds(self):
        for v, name in enumerate(("created", "modified", "deleted")):
            payload = (_Enc().variant(0).variant(cedrive.OK_CHANGES).u64(1)
                       .u64(1).str("/p").str("n").variant(v).str("e").u64(1).bytes())
            changes, _ = cedrive._dec_reply(payload)
            self.assertEqual(changes[0].kind, name)

    def test_opened_reports_granted_abilities(self):
        payload = (_Enc().variant(0).variant(cedrive.OK_OPENED)
                   .str("rootcid").u64(42).seq_str(["read", "write"])
                   .str("0").str("0").u64(1024).bool(False).bytes())
        o = cedrive._dec_reply(payload)
        self.assertEqual(o.granted_abilities, ["read", "write"])
        self.assertEqual(o.server_seq, 42)
        self.assertEqual(o.quota.free_tier_bytes, 1024)


class FakeDrive(cedrive.Drive):
    """A Drive with the node HTTP layer replaced: no node, no mesh."""

    def __init__(self, replies=None, **kw):
        super().__init__(drive=DRIVE, cap=CAP, token="t", **kw)
        self.provider = "host"
        self.replies = list(replies or [])
        self.sent = []
        self.blobs = {}

    def _json(self, method, path, body=None, timeout=35.0):
        if path == "/mesh/request":
            self.sent.append(body)
            return {"payload_hex": self.replies.pop(0).hex()}
        raise AssertionError(f"unexpected json call {method} {path}")

    def _http(self, method, path, body=None, raw=None, timeout=35.0):
        if method == "POST" and path == "/blobs":
            h = hashlib.sha256(raw).hexdigest()
            self.blobs[h] = raw
            return json.dumps({"hash": h}).encode()
        if method == "GET" and path.startswith("/blobs/"):
            return self.blobs[path.split("/")[-1]]
        raise AssertionError(f"unexpected http call {method} {path}")


class TestTransport(unittest.TestCase):

    def test_request_targets_the_drive_topic_with_hex_payload(self):
        d = FakeDrive([bytes.fromhex(GOLDEN_REPLIES["deleted"])])
        self.assertIs(d.rm("/f"), True)
        sent = d.sent[0]
        self.assertEqual(sent["to"], "host")
        self.assertEqual(sent["topic"], "ce-drive/v1")
        self.assertEqual(sent["payload_hex"], GOLDEN_REQS["delete"][:-2] + "00")

    def test_ls_pages_until_the_cursor_runs_out(self):
        """A single List reply is one PAGE. A client that stops at the first
        page silently reports a partial directory."""
        page1 = (_Enc().variant(0).variant(cedrive.OK_LISTING).u64(1).bytes()
                 + _entry_bytes("/a") + _Enc().opt_str("c1").bytes())
        page2 = (_Enc().variant(0).variant(cedrive.OK_LISTING).u64(1).bytes()
                 + _entry_bytes("/b") + _Enc().opt_str(None).bytes())
        d = FakeDrive([page1, page2])
        self.assertEqual([e.path for e in d.ls("/")], ["/a", "/b"])
        self.assertEqual(len(d.sent), 2)

    def test_exists_maps_404_to_false_but_reraises_403(self):
        d = FakeDrive([bytes.fromhex(GOLDEN_REPLIES["not_found"])])
        self.assertFalse(d.exists("/nope"))
        d = FakeDrive([bytes.fromhex(GOLDEN_REPLIES["out_of_scope"])])
        with self.assertRaises(DriveError):
            d.exists("/secret")

    def test_write_uploads_the_object_then_commits_the_cid(self):
        d = FakeDrive([bytes.fromhex(GOLDEN_REPLIES["written"])])
        out = d.write_text("/f.md", "hello")
        self.assertEqual(out["etag"], "e")
        # The manifest and its chunk are both in the blob store.
        stored = [json.loads(v) for v in d.blobs.values()
                  if v.startswith(b'{"kind":"ce-object-v1"')]
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["total_size"], 5)
        self.assertEqual(stored[0]["chunk_size"], 1 << 20)

    def test_object_manifest_is_byte_stable_across_sdks(self):
        """The manifest bytes ARE the object CID. Field order or spacing drift
        makes the same file hash differently in Python than in Rust/Go/TS."""
        d = FakeDrive([])
        d._put_object(b"hello")
        manifest = next(v for v in d.blobs.values()
                        if v.startswith(b'{"kind":"ce-object-v1"'))
        chunk_hash = hashlib.sha256(b"hello").hexdigest()
        self.assertEqual(
            manifest,
            b'{"kind":"ce-object-v1","chunk_size":1048576,"total_size":5,'
            b'"chunks":["' + chunk_hash.encode() + b'"]}')

    def test_read_verifies_every_chunk_against_its_cid(self):
        """Content addressing IS the integrity proof — a chunk whose bytes do
        not hash to the CID the host named must never reach the caller."""
        d = FakeDrive([])
        good = hashlib.sha256(b"abcdefgh").hexdigest()
        d.blobs[good] = b"CORRUPTED"          # same key, wrong bytes
        plan = (_Enc().variant(0).variant(cedrive.OK_READPLAN)
                .str("obj").u64(8).u64(1 << 20).u64(1)
                .str(good).u64(0).u64(8)
                .bool(False).opt_str(None).bytes())
        d.replies = [plan]
        with self.assertRaises(DriveError) as cm:
            d.read("/f")
        self.assertIn("cid mismatch", str(cm.exception))

    def test_read_trims_to_the_requested_range(self):
        """Chunks start at chunk boundaries, so a ranged read gets back MORE
        than it asked for and must trim — off-by-one here corrupts every
        partial read."""
        d = FakeDrive([])
        body = b"0123456789"
        h = hashlib.sha256(body).hexdigest()
        d.blobs[h] = body
        plan = (_Enc().variant(0).variant(cedrive.OK_READPLAN)
                .str("obj").u64(10).u64(1 << 20).u64(1)
                .str(h).u64(0).u64(10)
                .bool(False).opt_str(None).bytes())
        d.replies = [plan]
        self.assertEqual(d.read("/f", offset=3, length=4), b"3456")

    def test_read_of_an_empty_file_is_empty_not_an_error(self):
        d = FakeDrive([(_Enc().variant(0).variant(cedrive.OK_READPLAN)
                        .str("obj").u64(0).u64(1 << 20).u64(0)
                        .bool(False).opt_str(None).bytes())])
        self.assertEqual(d.read("/empty"), b"")

    def test_round_trip_through_the_fake_blob_store(self):
        d = FakeDrive([bytes.fromhex(GOLDEN_REPLIES["written"])])
        text = "# hello\nsome ✓ unicode\n"
        d.write_text("/n.md", text)
        cid_ = next(k for k, v in d.blobs.items()
                    if v.startswith(b'{"kind":"ce-object-v1"'))
        m = json.loads(d.blobs[cid_])
        plan = (_Enc().variant(0).variant(cedrive.OK_READPLAN)
                .str(cid_).u64(m["total_size"]).u64(m["chunk_size"])
                .u64(len(m["chunks"])))
        off = 0
        for h in m["chunks"]:
            plan.str(h).u64(off).u64(len(d.blobs[h]))
            off += len(d.blobs[h])
        d.replies = [plan.bool(False).opt_str(None).bytes()]
        self.assertEqual(d.read_text("/n.md"), text)

    def test_a_transport_failure_clears_the_cached_provider(self):
        """A dead host must not be retried forever — the next call re-discovers."""
        class Broken(FakeDrive):
            def _json(self, method, path, body=None, timeout=35.0):
                raise DriveError("connection refused")

        d = Broken([])
        with self.assertRaises(DriveError):
            d.stat("/a")
        self.assertIsNone(d.provider)


class TestTopics(unittest.TestCase):

    def test_changes_topic_is_per_drive_and_stable(self):
        self.assertEqual(cedrive.changes_topic("team"), "ce-drive/team/changes")
        self.assertNotEqual(cedrive.changes_topic("a"), cedrive.changes_topic("b"))

    def test_drive_topic_is_the_pinned_string(self):
        self.assertEqual(cedrive.DRIVE_TOPIC, "ce-drive/v1")

    def test_cid_is_lowercase_hex_sha256(self):
        self.assertEqual(cedrive.cid(b"hello"), hashlib.sha256(b"hello").hexdigest())


if __name__ == "__main__":
    unittest.main()
