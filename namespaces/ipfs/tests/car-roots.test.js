// `carRoots` — what an archive says its roots are, and what that claim is worth.
//
// The header fixtures below are REAL bytes: they were produced by
// `@ipld/dag-cbor`'s encoder (the one the Wildroot browser decodes with) over
// `{ version: 1, roots: [CID…] }` and frozen here, so the minimal decoder in
// `src/car-roots.js` is checked against the encoder it replaces rather than
// against itself. See ../../DEVIATIONS.md IP-7.

import test from 'node:test'
import assert from 'node:assert/strict'
import os from 'node:os'
import path from 'node:path'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'

import { carRoots, decodeHeaderCbor } from '../src/car-roots.js'

const V1 = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi'
const RAW = 'bafkreigph5cub32tn4ph2au3izioyxnr37lvthzdug4xlmhlbnxj7h3mqu'
const V0 = 'QmWfVY9y3xjsixTgbd9AorQxH7VtMpzfx2HaWtsoUYecaX'

/** `{version: 1, roots: [V1]}`, dag-cbor. */
const ONE = Buffer.from('a265726f6f747381d82a58250001701220c3c4733ec8affd06cf9e9ff50ffc6bcd2ec85a6170004bb709669c31de94391a6776657273696f6e01', 'hex')
/** `{version: 1, roots: [V1, RAW]}`. */
const TWO = Buffer.from('a265726f6f747382d82a58250001701220c3c4733ec8affd06cf9e9ff50ffc6bcd2ec85a6170004bb709669c31de94391ad82a58250001551220cf3f4540ef536f1e7d029b4650ec5db1dfd7599f23a1b975b0eb0b6e9f9f6c856776657273696f6e01', 'hex')
/** `{version: 1, roots: [V0]}` — a CIDv0 root, which is how kubo writes a dag-pb archive exported at v0. */
const ZERO = Buffer.from('a265726f6f747381d82a58230012207bb129136cd5c391f6a2401e5cb7317575dcf79352249536bea3a937aef9bd9c6776657273696f6e01', 'hex')

/** The CAR framing: an unsigned-varint header length, then the header. */
function framed (header) {
  const len = []
  let n = header.length
  while (n >= 0x80) { len.push((n & 0x7f) | 0x80); n >>= 7 }
  len.push(n)
  return Buffer.concat([Buffer.from(len), Buffer.from(header)])
}

async function withDir (fn) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'car-roots-'))
  try { return await fn(dir) } finally { await rm(dir, { recursive: true, force: true }) }
}

async function car (dir, bytes, name = 'x.car') {
  const file = path.join(dir, name)
  await writeFile(file, bytes)
  return file
}

test('a CARv1 header names its roots — one, several, and a CIDv0', async () => {
  await withDir(async (dir) => {
    assert.deepEqual(await carRoots(await car(dir, framed(ONE))), [V1])
    assert.deepEqual(await carRoots(await car(dir, framed(TWO), 'two.car')), [V1, RAW])
    // A CIDv0 round-trips to its base58btc form, which is case-SENSITIVE.
    assert.deepEqual(await carRoots(await car(dir, framed(ZERO), 'zero.car')), [V0])
  })
})

test('only the first 64 KiB are read: the header, never the blocks', async () => {
  await withDir(async (dir) => {
    const file = await car(dir, Buffer.concat([framed(ONE), Buffer.alloc(4 * 1024 * 1024, 7)]))
    assert.deepEqual(await carRoots(file), [V1])
  })
})

test('anything that is not a CAR header is refused, never guessed at', async () => {
  await withDir(async (dir) => {
    await assert.rejects(carRoots(await car(dir, Buffer.from('not a car at all'))), /not a CAR/)
    await assert.rejects(carRoots(await car(dir, Buffer.alloc(0), 'empty.car')), /not a CAR file \(no header length\)/)
    // A length varint with the continuation bit set and nothing after it.
    await assert.rejects(carRoots(await car(dir, Buffer.from([0x80]), 'trunc.car')), /no header length/)
    // A length that runs past the bytes on disk.
    await assert.rejects(carRoots(await car(dir, Buffer.from([0x40, 0x01]), 'short.car')), /header out of range/)
    // A zero-length header.
    await assert.rejects(carRoots(await car(dir, Buffer.from([0x00]), 'zerolen.car')), /header out of range/)
  })
})

test('a CARv2 header, or one without roots, is not a CARv1 header', async () => {
  await withDir(async (dir) => {
    // {version: 2, roots: [V1]} — the same bytes with the version byte changed.
    const v2 = Buffer.from(ONE)
    v2[v2.length - 1] = 0x02
    await assert.rejects(carRoots(await car(dir, framed(v2), 'v2.car')), /not a CARv1 header/)
    // {version: 1} with no roots key at all: `a1 67 version 01`.
    const noRoots = Buffer.from('a16776657273696f6e01', 'hex')
    await assert.rejects(carRoots(await car(dir, framed(noRoots), 'noroots.car')), /not a CARv1 header/)
  })
})

test('the header decoder reads the dag-cbor subset a CAR header uses, and refuses the rest', () => {
  assert.deepEqual(decodeHeaderCbor(ONE).version, 1)
  assert.equal(decodeHeaderCbor(ONE).roots[0].toString(), V1)
  assert.equal(decodeHeaderCbor(TWO).roots.length, 2)
  // Indefinite-length map (0xbf): legal CBOR, forbidden by dag-cbor, refused here.
  assert.throws(() => decodeHeaderCbor(Buffer.from([0xbf, 0xff])), /additional information 31/)
  // A tag that is not 42 is not a link, and this header holds nothing else.
  assert.throws(() => decodeHeaderCbor(Buffer.from([0xc0, 0x01])), /unexpected CBOR tag 0/)
  // A CID tag over something that is not a byte string.
  assert.throws(() => decodeHeaderCbor(Buffer.from([0xd8, 0x2a, 0x01])), /non-byte-string/)
  // A byte string that is not identity-multibase-prefixed is not a dag-cbor link.
  assert.throws(() => decodeHeaderCbor(Buffer.from([0xd8, 0x2a, 0x42, 0x01, 0x02])), /multibase prefix/)
  // Floats, booleans, null: major type 7, which cannot appear here.
  assert.throws(() => decodeHeaderCbor(Buffer.from([0xf6])), /major type 7/)
  // Trailing bytes after a complete item mean the length varint lied.
  assert.throws(() => decodeHeaderCbor(Buffer.concat([ONE, Buffer.from([0x01])])), /trailing bytes/)
})

test('the roots are the archive\'s CLAIM about itself — the check that matters is elsewhere', async () => {
  // SPEC §11.2. A header can name any root at all; here is one naming a CID
  // whose blocks are not in the file. `carRoots` reports the claim faithfully,
  // and the caller (origin-warm.js) compares it to the CID it asked for. That
  // comparison catches a confused or misconfigured origin. It does not catch a
  // HOSTILE one — for that, every block is hash-checked on import by the node,
  // and a block that is not the CID asked for simply is not there afterwards.
  await withDir(async (dir) => {
    assert.deepEqual(await carRoots(await car(dir, framed(ONE))), [V1],
      'the header said V1; nothing here proves a single V1 block exists')
  })
})
