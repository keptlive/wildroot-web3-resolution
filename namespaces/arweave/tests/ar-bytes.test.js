/*
 * ar://: the bytes are checked against the proven header's data root
 * (src/hns/ar-merkle.js). Header from one gateway, bytes from another, and
 * the body either hashes to the root or is refused.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'

import createArHandler, { MAX_VERIFY_BYTES } from '../src/ar.js'
import { dataRootB64 } from '../src/ar-merkle.js'
import { signedTransaction } from './signed-tx.js'

/**
 * A transaction whose header really is its id's, over `bytes`: genuinely
 * signed, because the header check verifies the signature over these very
 * fields before the root is used (src/ar-tx.js, tests/ar-tx.test.js).
 */
function transaction (bytes, { root = null, size = null } = {}) {
  return signedTransaction({ data_root: root || dataRootB64(bytes), data_size: String(size ?? bytes.length) })
}

/** Two gateways: `a` serves bytes, `b` serves the header. */
function gateways (id, header, served) {
  const asked = []
  const fetchImpl = async (url, init) => {
    asked.push(url)
    const u = new URL(url)
    if (u.pathname === `/tx/${id}`) return new Response(JSON.stringify(header), { status: 200, headers: { 'content-type': 'application/json' } })
    if (u.pathname === `/${id}`) return new Response(served, { status: 200, headers: { 'content-type': 'application/octet-stream' } })
    return new Response('nope', { status: 404 })
  }
  return { asked, fetchImpl }
}

const opts = (fetchImpl) => ({ gateways: ['https://a.example', 'https://b.example'], fetchImpl, verifyHeader: true })

test('bytes that hash to the proven header\'s data root are served as `bytes`-verified', async () => {
  const bytes = randomBytes(70_000)
  const { id, header } = transaction(bytes)
  const { handler } = createArHandler(opts(gateways(id, header, bytes).fetchImpl))
  const res = await handler(new Request(`ar://${id}`))
  assert.equal(res.status, 200)
  assert.equal(res.headers.get('X-Arweave-Verified'), 'bytes')
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), bytes)
})

test('a body that does not hash to the root is REFUSED, not served', async () => {
  const bytes = randomBytes(70_000)
  const { id, header } = transaction(bytes)
  const tampered = Buffer.from(bytes); tampered[7] ^= 0x10
  const { handler } = createArHandler(opts(gateways(id, header, tampered).fetchImpl))
  const res = await handler(new Request(`ar://${id}`))
  assert.equal(res.status, 502)
  assert.match(await res.text(), /do not hash to the transaction's data root/)
})

test('a Range request, or a transaction over the in-memory limit, keeps the header check alone', async () => {
  const bytes = randomBytes(70_000)
  const { id, header } = transaction(bytes)
  const { handler } = createArHandler(opts(gateways(id, header, bytes).fetchImpl))
  const ranged = await handler(new Request(`ar://${id}`, { headers: { range: 'bytes=0-9' } }))
  assert.equal(ranged.headers.get('X-Arweave-Verified'), 'header', 'a partial body cannot be checked')
  const big = transaction(bytes, { size: MAX_VERIFY_BYTES + 1 })
  const { handler: bigHandler } = createArHandler(opts(gateways(big.id, big.header, bytes).fetchImpl))
  const res = await bigHandler(new Request(`ar://${big.id}`))
  assert.equal(res.headers.get('X-Arweave-Verified'), 'header', 'declared too large to hold: header only, and the response says so')
})

test('a gateway that RENDERS a transaction (a bundle, a manifest) serves a different length: header only, not a refusal', async () => {
  const bytes = randomBytes(10_386)
  const { id, header } = transaction(bytes)
  const rendered = Buffer.from('<!DOCTYPE html><html><body>an index page the gateway made</body></html>')
  const { handler } = createArHandler(opts(gateways(id, header, rendered).fetchImpl))
  const res = await handler(new Request(`ar://${id}`))
  assert.equal(res.status, 200, 'the page is served')
  assert.equal(res.headers.get('X-Arweave-Verified'), 'header', 'not the transaction\'s own bytes, so only the header is claimed')
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), rendered)
})
