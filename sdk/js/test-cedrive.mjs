/**
 * Golden-vector tests for the JS SDK.
 *
 * The SAME hand-computed hex asserted by sdk/py/test_cedrive.py and tests/wire_golden_py.rs. Three
 * implementations of one wire, pinned to constants none of them generated, so no side can ratify its
 * own drift.
 *
 *     node --test sdk/js/
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeReq, decodeReply, DriveError, OP, OK, DRIVE_TOPIC } from './cedrive.js';

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (s) => Uint8Array.from(s.match(/../g).map((h) => parseInt(h, 16)));

// drive "team", cap "deadbeef"
const P = '04000000000000007465616d08000000000000006465616462656566';
const enc = (op, w) => hex(encodeReq('team', 'deadbeef', op, w));

test('a fieldless variant still costs a full u32 discriminant', () => {
  assert.equal(enc(OP.OPEN), P + '00000000');
});

test('stat', () => {
  assert.equal(enc(OP.STAT, (e) => e.str('/a/b')), P + '01000000' + '0400000000000000' + '2f612f62');
});

test('list, with and without a cursor', () => {
  assert.equal(enc(OP.LIST, (e) => e.str('/a').optStr(null).u32(10)),
    P + '02000000' + '0200000000000000' + '2f61' + '00' + '0a000000');
  assert.equal(enc(OP.LIST, (e) => e.str('/a').optStr('x').u32(0)),
    P + '02000000' + '0200000000000000' + '2f61' + '01' + '0100000000000000' + '78' + '00000000');
});

test('read and write', () => {
  assert.equal(enc(OP.READ, (e) => e.str('/f').u64(0).optU64(null)),
    P + '03000000' + '0200000000000000' + '2f66' + '0000000000000000' + '00');
  assert.equal(enc(OP.WRITE, (e) => e.str('/f').str('cid').u64(5).optStr('e')),
    P + '04000000' + '0200000000000000' + '2f66' + '0300000000000000' + '636964'
      + '0500000000000000' + '01' + '0100000000000000' + '65');
});

test('delete carries its bool', () => {
  assert.equal(enc(OP.DELETE, (e) => e.str('/f').bool(true)),
    P + '08000000' + '0200000000000000' + '2f66' + '01');
});

test('metadata ops were APPENDED after Watch, not inserted', () => {
  // An inserted variant silently repoints every later op for every deployed client, and no
  // round-trip test can catch it because each side stays self-consistent.
  assert.equal(OP.WATCH, 11);
  assert.deepEqual([OP.META, OP.SETPROP, OP.TAG, OP.LINK, OP.BACKLINKS, OP.VERSIONS],
    [12, 13, 14, 15, 16, 17]);
  assert.equal(enc(OP.META, (e) => e.str('/a')), P + '0c000000' + '0200000000000000' + '2f61');
  assert.equal(enc(OP.TAG, (e) => e.str('/a').str('x').bool(true)),
    P + '0e000000' + '0200000000000000' + '2f61' + '0100000000000000' + '78' + '01');
});

test('a string length counts BYTES, not characters', () => {
  // A char count here would desync the entire stream after the first non-ASCII name.
  assert.equal(enc(OP.STAT, (e) => e.str('é')), P + '01000000' + '0200000000000000' + 'c3a9');
});

test('u64 survives above 2^53 — the trap this language has', () => {
  // JS numbers are doubles. Reading a u64 as a Number silently corrupts it, which is exactly the bug
  // that bit ce-ts once with a reply_token.
  const big = 2n ** 64n - 1n;
  const bytes = encodeReq('', '', OP.READ, (e) => e.str('').u64(big).optU64(null));
  // Ok(Written) carries a u64 version_seq; round-trip a big one through the decoder.
  const reply = unhex('00000000' + '04000000' + '0000000000000000' + '0000000000000000'
    + 'ffffffffffffffff');
  assert.equal(decodeReply(reply).versionSeq, big);
  assert.ok(bytes.length > 0);
});

test('errors carry the hosts stable code', () => {
  for (const [hexs, code] of [['0100000004000000', 404], ['0100000000000000', 401],
                              ['0100000003000000', 403]]) {
    assert.throws(() => decodeReply(unhex(hexs)), (e) => e instanceof DriveError && e.code === code);
  }
});

test('a conflict surfaces the current etag so a caller can retry', () => {
  assert.throws(
    () => decodeReply(unhex('01000000' + '05000000' + '0100000000000000' + '65')),
    (e) => e.code === 409 && e.currentEtag === 'e');
});

test('an empty reply is a clear error, not a successful empty result', () => {
  // Otherwise "no provider" would be written into a document as empty content.
  assert.throws(() => decodeReply(new Uint8Array(0)), /empty reply/);
});

test('a newer host is named as such rather than misparsed', () => {
  assert.throws(() => decodeReply(unhex('00000000' + '63000000')), /newer than this SDK/);
});

test('ok replies decode', () => {
  assert.equal(decodeReply(unhex('0000000006000000')), true);
  assert.deepEqual(decodeReply(unhex('00000000' + '05000000' + '0200000000000000' + '6e31')),
    { nodeId: 'n1' });
});

test('the topic is the pinned string', () => {
  assert.equal(DRIVE_TOPIC, 'ce-drive/v1');
  assert.equal(OK.DELETED, 6);
});
