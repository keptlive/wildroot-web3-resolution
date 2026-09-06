/*
 * How an Arweave identifier is REACHED — the two routes into this namespace
 * that are not a typed URL. SPEC.md §5.2 (an `ar=` TXT record on a Handshake
 * name) and §5.3 (an `arweave-ns` EIP-1577 contenthash on the `_op` or ENS
 * routes).
 *
 * Neither parser lives here. Both are at the repository ROOT, because the root
 * SPEC §10 specifies them and the IPFS, BitTorrent and Hyper namespaces share
 * them. This file imports them from there rather than copying, so a fix in one
 * is provably the same fix here — which is the same reason the root package
 * keeps its source byte-identical to the browser's.
 *
 * What these tests pin is the ARWEAVE-specific half: the identifier rule is
 * the same one `src/ar.js` enforces — `isCanonicalTxid`, imported by both — the
 * precedence rule puts `ar=` last, a malformed or non-canonical identifier is
 * not a half-trusted pointer, and the on-chain route is canonical by
 * construction.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import {
  parsePointer, pointerFrom, pointerRecord, txtStringsFrom,
  isCanonicalTxid, ARTX_RE, POINTER_PRECEDENCE, POINTER_TAG
} from '../../../src/pointers.js'
import { decodeContenthash, readVarint, toBytes, CODEC } from '../../../src/contenthash.js'

const TX = 'W-9rj7LCX-1kRs8Edf4UmJvzCHYBCnZN_13dh0Y7xq8'
const CID = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi'

// --- §5.2: `ar=<txid>` on a Handshake name ---------------------------------

test('`ar=<txid>` parses to an arweave pointer', () => {
  assert.deepEqual(parsePointer(`ar=${TX}`), { kind: 'arweave', txid: TX })
  assert.equal(POINTER_TAG.arweave, 'ar')
})

test('the pointer grammar uses the SAME identifier rule as the ar:// handler', () => {
  // SPEC §3.2. One function, imported by both `src/ar.js` and the `ar=`
  // parser. Two copies allowed to drift would mean a name could publish an id
  // the handler refuses, or the reverse.
  assert.equal(ARTX_RE.source, /^[A-Za-z0-9_-]{43}$/.source, 'the shape')
  assert.equal(isCanonicalTxid(TX), true)
  assert.equal(isCanonicalTxid(TX.slice(0, 42) + '9'), false, 'and the spelling')
  assert.equal(isCanonicalTxid(TX.slice(0, 42)), false)
  assert.equal(isCanonicalTxid(''), false)
  assert.equal(isCanonicalTxid(null), false)
})

test('a malformed identifier is NOT a pointer — never a half-trusted record', () => {
  for (const bad of ['ar=', 'ar=too-short', `ar=${'A'.repeat(44)}`, `ar=${'A'.repeat(42)}+`]) {
    assert.equal(parsePointer(bad), null, bad)
  }
  // Nor is a NON-CANONICAL spelling of a real id (SPEC §3.3). A record that
  // did not round-trip to one spelling would be sixteen records for one
  // transaction, and the handler would refuse what the parser accepted.
  assert.equal(parsePointer(`ar=${TX.slice(0, 42)}9`), null)
  // And a name carrying ONLY a malformed ar= resolves as though it carried
  // no pointer at all, rather than as a broken Arweave name.
  assert.equal(pointerFrom(['ar=nonsense']), null)
})

test('`ar=` is LAST in precedence, whatever order DNS returns the records in', () => {
  assert.equal(POINTER_PRECEDENCE[POINTER_PRECEDENCE.length - 1], 'arweave')
  // The paid permanent archive is the backstop behind the free live pointers.
  assert.equal(pointerFrom([`ar=${TX}`, `ipfs=${CID}`]).kind, 'ipfs')
  assert.equal(pointerFrom([`ipfs=${CID}`, `ar=${TX}`]).kind, 'ipfs')
  // ...and it IS chosen when it is the only one.
  assert.deepEqual(pointerFrom([`ar=${TX}`]), { kind: 'arweave', txid: TX })
})

test('a record whose strings are split is ONE value (RFC 1035 §3.3.14)', () => {
  // A pointer longer than 255 bytes arrives split across character-strings.
  // Spreading instead of joining reads it as nothing; this is the rule that
  // made the SPV and DoH paths disagree about `ar=` before they shared a
  // parser. Root SPEC §10.
  const split = txtStringsFrom([{ type: 16, txt: ['ar=' + TX.slice(0, 20), TX.slice(20)] }])
  assert.deepEqual(split, [`ar=${TX}`])
  assert.deepEqual(parsePointer(split[0]), { kind: 'arweave', txid: TX })
})

test('an ar= record round-trips byte-for-byte through a re-publish', () => {
  // Written in the exact form the parser reads back, so a republish is never a
  // spurious zone diff. Note there is no case normalization here and there
  // must not be: SPEC §3.4.
  assert.equal(pointerRecord('arweave', TX), `ar=${TX}`)
  assert.equal(pointerRecord('arweave', ` ${TX} `), `ar=${TX}`)
  // An uppercased id is a DIFFERENT valid id, and is written back as itself.
  // Contrast `hyper=` and `bt=`, whose hex keys ARE lowercased on the way out.
  assert.equal(pointerRecord('arweave', TX.toUpperCase()), `ar=${TX.toUpperCase()}`)
})

// --- §5.3: `arweave-ns` contenthash on the _op / ENS routes -----------------

test('arweave-ns is multicodec 0xb29910, four bytes of unsigned varint', () => {
  assert.equal(CODEC.ARWEAVE, 0xb29910)
  const { value, length } = readVarint(toBytes('90b2ca05'), 0)
  assert.equal(value, 0xb29910)
  assert.equal(length, 4)
})

test('an arweave-ns contenthash decodes to ar://<43-char base64url>', () => {
  // A real captured value: the 4-byte varint code then the raw 32-byte id.
  const hex = '90b2ca0570a189aae8a5d118311f080010d15d9db5e57cb0f602850cff93ed9f68fd9b5a'
  const r = decodeContenthash(hex)
  assert.equal(r.protocol, 'arweave')
  assert.equal(r.supported, true)
  assert.equal(r.code, CODEC.ARWEAVE)
  assert.equal(r.id, 'cKGJquil0RgxHwgAENFdnbXlfLD2AoUM_5Ptn2j9m1o')
  assert.equal(r.id.length, 43)
  assert.equal(r.url, `ar://${r.id}`)
  // The URL it hands on must satisfy the handler that will receive it.
  assert.ok(ARTX_RE.test(r.id))
})

test('the on-chain route is canonical by construction', () => {
  // The contenthash value is 32 raw bytes, so base64url encoding it emits the
  // canonical 43 characters with nothing to check. A non-canonical spelling
  // can only arrive as a STRING — from a TXT record or a typed URL — which is
  // where `isCanonicalTxid` refuses it.
  const hex = '90b2ca05' + '00'.repeat(31) + 'ff'
  const r = decodeContenthash(hex)
  assert.equal(r.id.length, 43)
  assert.equal(isCanonicalTxid(r.id), true)
  assert.equal(Buffer.from(r.id, 'base64url').toString('base64url'), r.id)
})

test('a recognised codec we cannot fetch is refused BY NAME, never mis-routed', () => {
  // SPEC §5.3. Falling through would hand the name to the seller's
  // nameservers, which is the box the _op route exists to avoid trusting.
  const swarm = decodeContenthash('e40101fa01122044eb92b46360c22af3395633b6e3014a30afa97b02305b385c51d3feebceda9c')
  assert.equal(swarm.protocol, 'swarm')
  assert.equal(swarm.supported, false)
  assert.equal(swarm.url, undefined, 'no pointer is handed to any handler')

  // An unknown codec is reported as unknown rather than guessed at as Arweave.
  const unknown = decodeContenthash('ff01' + '00'.repeat(32))
  assert.equal(unknown.protocol, 'unknown')
  assert.equal(unknown.supported, false)

  // And an EMPTY record is "no contenthash", which is a different answer again.
  assert.equal(decodeContenthash('0x'), null)
})
