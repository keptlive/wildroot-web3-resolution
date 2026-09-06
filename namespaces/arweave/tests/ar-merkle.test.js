/*
 * Arweave's chunk Merkle tree (src/hns/ar-merkle.js). The vectors are real:
 * EDGVy6… is a top-level transaction whose bytes and header were fetched from
 * arweave.net on 2026-09-06 (data_root from `/tx/<id>`), and the two-chunk
 * case was validated live the same day against qXKRE6Rw7JW2tcUp77q4tVOAMAmEfxmHDgsK32yi5gM
 * (516,531 bytes) before the synthetic root below was pinned from the same
 * implementation. Recipe: fetch `/tx/<id>` and `/raw/<id>`, compare
 * dataRootB64(bytes) with data_root.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'

import { chunkRanges, dataRootB64, bytesMatchRoot, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE } from '../src/ar-merkle.js'

const FIXTURE = new URL('./fixtures/arweave/EDGVy6AAKFNKEA3LsjZJ5OXv82eRvJPsomCA4AWC7y8.bin', import.meta.url)
const FIXTURE_ROOT = 'WCfBwUaeU65cNkG7aHfyqW48AuhhjgychOA9WIc43aU'

test('a real top-level transaction: the bytes hash to the header\'s data_root', () => {
  const bytes = readFileSync(FIXTURE)
  assert.equal(bytes.length, 5725)
  assert.equal(dataRootB64(bytes), FIXTURE_ROOT)
  assert.equal(bytesMatchRoot(bytes, FIXTURE_ROOT), true)
  const tampered = Buffer.from(bytes)
  tampered[100] ^= 1
  assert.equal(bytesMatchRoot(tampered, FIXTURE_ROOT), false, 'one flipped bit is a different transaction')
  assert.equal(bytesMatchRoot(bytes, ''), false, 'no root, no claim')
})

test('chunking: 256 KiB chunks, the last two rebalanced so no chunk is under 32 KiB', () => {
  assert.deepEqual(chunkRanges(1000), [{ start: 0, end: 1000 }])
  assert.deepEqual(chunkRanges(MAX_CHUNK_SIZE + 100 * 1024), [{ start: 0, end: MAX_CHUNK_SIZE }, { start: MAX_CHUNK_SIZE, end: MAX_CHUNK_SIZE + 100 * 1024 }])
  const small = MAX_CHUNK_SIZE + 10 * 1024 // the tail would be 10 KiB: rebalance
  const half = Math.ceil(small / 2)
  assert.deepEqual(chunkRanges(small), [{ start: 0, end: half }, { start: half, end: small }])
  assert.ok(half >= MIN_CHUNK_SIZE)
  const three = 2 * MAX_CHUNK_SIZE + 200 * 1024
  assert.equal(chunkRanges(three).length, 3)
})

test('a two-chunk root is stable (pinned from the live-validated implementation)', () => {
  // Deterministic pseudo-random 600,000 bytes.
  const bytes = Buffer.alloc(600_000)
  let seed = Buffer.from('wildroot')
  for (let i = 0; i < bytes.length; i += 32) {
    seed = createHash('sha256').update(seed).digest()
    seed.copy(bytes, i, 0, Math.min(32, bytes.length - i))
  }
  assert.equal(chunkRanges(bytes.length).length, 3)
  assert.equal(dataRootB64(bytes), dataRootB64(Buffer.from(bytes)), 'deterministic')
  assert.equal(dataRootB64(bytes), 'Etqwkp034SzU4Y7PGoRBzLUQrxKPX3w4W8kP7rcSqIg')
})
