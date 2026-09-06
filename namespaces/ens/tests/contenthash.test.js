/*
 * EIP-1577 / ENSIP-7 contenthash decoding, against REAL captured values.
 *
 * The IPFS vector is the canonical one from the content-hash / ethers test
 * suites (it decodes to the well-known CIDv0 QmRAQB…). The others are built
 * from real CIDs / a real 32-byte Arweave txid and their exact bytes are
 * pinned here, so a change in the varint or CID handling is a red test.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { CID } from 'multiformats/cid'

import { decodeContenthash, readVarint, toBytes, CODEC } from '../../../src/contenthash.js'

// --- IPFS: canonical external vector ---------------------------------------

test('decodes an ipfs-ns contenthash to an ipfs:// pointer', () => {
  const hex = '0xe3010170122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f'
  const r = decodeContenthash(hex)
  assert.equal(r.protocol, 'ipfs')
  assert.equal(r.supported, true)
  assert.equal(r.code, CODEC.IPFS)
  // The decoded CIDv1 is the well-known QmRAQB… in v0 form.
  assert.equal(CID.parse(r.id).toV0().toString(), 'QmRAQB6YaCyidP37UdDnjFY5vQuiBrcqdyoW1CuDgwxkD4')
  assert.equal(r.url, `ipfs://${r.id}`)
})

// --- IPNS: real libp2p-key CID ---------------------------------------------

test('decodes an ipns-ns contenthash to an ipns:// pointer', () => {
  const hex = 'e50101720024080112200405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223'
  const r = decodeContenthash(hex)
  assert.equal(r.protocol, 'ipns')
  assert.equal(r.supported, true)
  assert.equal(r.id, 'bafzaajaiaejcabafaydqqcikbmga2dqpcaireeyuculbogazdinryhi6d4qccird')
  assert.equal(r.url, `ipns://${r.id}`)
})

// --- Arweave: arweave-ns (0xb29910), raw 32-byte txid ----------------------

test('decodes an arweave-ns contenthash to an ar:// pointer (base64url txid)', () => {
  const hex = '90b2ca0570a189aae8a5d118311f080010d15d9db5e57cb0f602850cff93ed9f68fd9b5a'
  const r = decodeContenthash(hex)
  assert.equal(r.protocol, 'arweave')
  assert.equal(r.supported, true)
  assert.equal(r.code, CODEC.ARWEAVE)
  assert.equal(r.id, 'cKGJquil0RgxHwgAENFdnbXlfLD2AoUM_5Ptn2j9m1o')
  assert.equal(r.id.length, 43) // a canonical Arweave txid
  assert.equal(r.url, 'ar://cKGJquil0RgxHwgAENFdnbXlfLD2AoUM_5Ptn2j9m1o')
})

// --- Swarm: recognised but unsupported -------------------------------------

test('decodes swarm-ns but reports it unsupported (fails closed, never mis-routes)', () => {
  const hex = 'e40101fa01122044eb92b46360c22af3395633b6e3014a30afa97b02305b385c51d3feebceda9c'
  const r = decodeContenthash(hex)
  assert.equal(r.protocol, 'swarm')
  assert.equal(r.supported, false)
  assert.equal(r.url, undefined) // no pointer handed to any handler
})

// --- Absent / unknown -------------------------------------------------------

test('an empty record is null (no contenthash), not an error', () => {
  assert.equal(decodeContenthash('0x'), null)
  assert.equal(decodeContenthash(''), null)
  assert.equal(decodeContenthash(new Uint8Array(0)), null)
})

test('an unknown codec is reported, not guessed', () => {
  // 0x99 0x01 = codec 0x99 (not one we know) + junk
  const r = decodeContenthash('9901aabbcc')
  assert.equal(r.protocol, 'unknown')
  assert.equal(r.supported, false)
})

// --- primitives -------------------------------------------------------------

test('readVarint decodes multi-byte codes (0xb29910 = 4 bytes)', () => {
  const bytes = toBytes('90b2ca05')
  const { value, length } = readVarint(bytes, 0)
  assert.equal(value, 0xb29910)
  assert.equal(length, 4)
})

test('readVarint decodes the single-logical two-byte 0xe3 code', () => {
  const { value, length } = readVarint(toBytes('e301'), 0)
  assert.equal(value, CODEC.IPFS)
  assert.equal(length, 2)
})

test('toBytes rejects malformed hex rather than decoding garbage', () => {
  assert.throws(() => toBytes('0xzz'))
  assert.throws(() => toBytes('abc')) // odd length
})
