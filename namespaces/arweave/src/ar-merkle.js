/*
 * Arweave's data root — the chunk Merkle tree a transaction commits to.
 *
 * A transaction header carries `data_root`; the bytes a gateway serves are
 * the transaction's only if they hash to it. This is the check src/hns/ar.js
 * could not make before (`X-Arweave-Verified: header` was the most it could
 * say): with it, the bytes themselves are verified against the id, and the
 * gateway is a courier.
 *
 * The construction, as arweave-js `lib/merkle.ts` and the Arweave node do:
 *   - data is cut into chunks of at most 256 KiB; when the remainder after
 *     a full chunk would be under 32 KiB, the last two are rebalanced to
 *     halves so no chunk is tiny;
 *   - leaf id  = H( H(H(chunk)) ‖ H(note) ), note = the chunk's END offset
 *     as a 32-byte big-endian integer (the chunk hash is itself hashed
 *     again before the note — the one detail that is easy to miss);
 *   - branch id = H( H(left.id) ‖ H(right.id) ‖ H(note) ), note = the left
 *     child's end offset; an odd node passes up unchanged;
 *   - H is SHA-256; data_root is the root id, base64url.
 * Verified against live top-level transactions on arweave.net (see
 * tests/hns/ar-merkle.test.js for the pinned vectors and the recipe).
 */

import { createHash } from 'node:crypto'

export const MAX_CHUNK_SIZE = 256 * 1024
export const MIN_CHUNK_SIZE = 32 * 1024
const NOTE_SIZE = 32

const sha256 = (...parts) => {
  const h = createHash('sha256')
  for (const p of parts) h.update(p)
  return h.digest()
}

/** A 32-byte big-endian integer. */
function note (n) {
  const out = Buffer.alloc(NOTE_SIZE)
  let v = BigInt(n)
  for (let i = NOTE_SIZE - 1; i >= 0 && v > 0n; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

/**
 * The chunk boundaries of `data`: [{ start, end }], end exclusive.
 * @param {number} length
 */
export function chunkRanges (length) {
  const ranges = []
  let cursor = 0
  let rest = length
  while (rest >= MAX_CHUNK_SIZE) {
    let size = MAX_CHUNK_SIZE
    const after = rest - MAX_CHUNK_SIZE
    if (after > 0 && after < MIN_CHUNK_SIZE) size = Math.ceil(rest / 2)
    ranges.push({ start: cursor, end: cursor + size })
    cursor += size
    rest -= size
  }
  ranges.push({ start: cursor, end: cursor + rest })
  return ranges
}

/**
 * The data root of `data`, as raw bytes.
 * @param {Uint8Array} data
 * @returns {Buffer}
 */
export function dataRoot (data) {
  const bytes = Buffer.isBuffer(data) ? data : Buffer.from(data)
  let nodes = chunkRanges(bytes.length).map(({ start, end }) => ({
    id: sha256(sha256(sha256(bytes.subarray(start, end))), sha256(note(end))),
    max: end
  }))
  while (nodes.length > 1) {
    const next = []
    for (let i = 0; i < nodes.length; i += 2) {
      const left = nodes[i]
      const right = nodes[i + 1]
      if (!right) { next.push(left); continue }
      next.push({ id: sha256(sha256(left.id), sha256(right.id), sha256(note(left.max))), max: right.max })
    }
    nodes = next
  }
  return nodes[0].id
}

/** The data root as Arweave writes it: base64url, no padding. */
export function dataRootB64 (data) {
  return dataRoot(data).toString('base64url')
}

/**
 * Do these bytes belong to a transaction whose header says `data_root`?
 * @param {Uint8Array} data
 * @param {string} expected base64url data_root from the header
 */
export function bytesMatchRoot (data, expected) {
  const want = String(expected || '').replace(/=+$/, '')
  if (!want) return false
  return dataRootB64(data) === want
}
