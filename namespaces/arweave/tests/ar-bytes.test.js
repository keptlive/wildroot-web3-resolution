/*
 * ar://: the bytes are checked against the proven header's data root
 * (src/hns/ar-merkle.js). Header from one gateway, bytes from another, and
 * the body either hashes to the root or is refused.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'

import createArHandler, { MAX_HEADER_BYTES, MAX_VERIFY_BYTES } from '../src/ar.js'
import { tag, transaction } from './ar-transaction-fixture.js'

/** Two gateways: `a` serves bytes, `b` serves the header. */
function gateways (id, header, served) {
  const asked = []
  const fetchImpl = async (url, init) => {
    asked.push(url)
    const u = new URL(url)
    if (u.pathname === `/tx/${id}`) return new Response(JSON.stringify(header), { status: 200, headers: { 'content-type': 'application/json' } })
    if (u.pathname === `/${id}`) return served instanceof Response ? served : new Response(served, { status: 200, headers: { 'content-type': 'application/octet-stream' } })
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
  const large = Buffer.alloc(MAX_VERIFY_BYTES + 1, 42)
  const big = transaction(large)
  const { handler: bigHandler } = createArHandler(opts(gateways(big.id, big.header, large).fetchImpl))
  const res = await bigHandler(new Request(`ar://${big.id}`))
  assert.equal(res.headers.get('X-Arweave-Verified'), 'header', 'declared too large to hold: header only, and the response says so')
  assert.equal((await res.arrayBuffer()).byteLength, large.length)
})

test('only an authenticated rendering type selects the gateway-rendered contract', async () => {
  const bytes = randomBytes(10_386)
  const rendered = Buffer.from('<!DOCTYPE html><html><body>an index page the gateway made</body></html>')
  for (const tags of [[tag('Content-Type', 'application/x.arweave-manifest+json')], [tag('Bundle-Format', 'binary'), tag('Bundle-Version', '2.0.0')]]) {
    const { id, header } = transaction(bytes, { tags })
    const { handler } = createArHandler(opts(gateways(id, header, rendered).fetchImpl))
    const res = await handler(new Request(`ar://${id}`))
    assert.equal(res.status, 200)
    assert.equal(res.headers.get('X-Arweave-Representation'), 'gateway-rendered')
    assert.equal(res.headers.get('X-Arweave-Verified'), 'header', 'only the signed header, never the rendered page')
    assert.deepEqual(Buffer.from(await res.arrayBuffer()), rendered)
  }
  const { id, header } = transaction(bytes)
  const { handler } = createArHandler(opts(gateways(id, header, rendered).fetchImpl))
  assert.equal((await handler(new Request(`ar://${id}`))).status, 502, 'different length is not evidence of rendering')
})

function streamed (chunkSizes, responseHeaders = {}, failAt = -1) {
  let pulled = 0
  let cancelled = false
  const response = new Response(new ReadableStream({
    pull (controller) {
      if (pulled === failAt) return controller.error(new Error('interrupted body'))
      if (pulled >= chunkSizes.length) return controller.close()
      controller.enqueue(new Uint8Array(chunkSizes[pulled++]))
    },
    cancel () { cancelled = true }
  }, { highWaterMark: 0 }), { headers: responseHeaders })
  response.arrayBuffer = () => { throw new Error('unbounded arrayBuffer must not be called') }
  return { response, get pulled () { return pulled }, get cancelled () { return cancelled } }
}

test('actual received bytes, not missing or false Content-Length, bound the raw read', async () => {
  const { id, header } = transaction(Buffer.alloc(13))
  for (const responseHeaders of [{}, { 'content-length': '13' }, { 'content-length': '999999999999' }]) {
    const source = streamed([13, 1, MAX_VERIFY_BYTES, MAX_VERIFY_BYTES], responseHeaders)
    const { handler } = createArHandler(opts(gateways(id, header, source.response).fetchImpl))
    const res = await handler(new Request(`ar://${id}`))
    assert.equal(res.status, 502)
    assert.match(await res.text(), /size exceeds signed data_size/)
    assert.equal(source.cancelled, true)
    assert.equal(source.pulled, 2, 'stops before any later large chunks')
  }
})

test('verification threshold plus one cancels without buffering the excess chunk', async () => {
  const { id, header } = transaction(Buffer.alloc(MAX_VERIFY_BYTES))
  const source = streamed([MAX_VERIFY_BYTES, 1, MAX_VERIFY_BYTES])
  const { handler } = createArHandler(opts(gateways(id, header, source.response).fetchImpl))
  const res = await handler(new Request(`ar://${id}`))
  assert.equal(res.status, 502)
  assert.match(await res.text(), /verification byte limit/)
  assert.equal(source.cancelled, true)
  assert.equal(source.pulled, 2)
})

test('short, interrupted, or missing raw bodies never downgrade to header-only success', async () => {
  const { id, header } = transaction(Buffer.alloc(13))
  for (const response of [streamed([12]).response, streamed([1], {}, 1).response, new Response(null)]) {
    const { handler } = createArHandler(opts(gateways(id, header, response).fetchImpl))
    const res = await handler(new Request(`ar://${id}`))
    assert.equal(res.status, 502)
    assert.equal(res.headers.get('X-Arweave-Verified'), 'none')
  }
})

test('large raw bodies stay streamed but must finish at the signed size', async () => {
  const { id, header } = transaction(Buffer.alloc(13), { data_size: String(MAX_VERIFY_BYTES + 1) })
  const source = streamed([1, 2])
  const { handler } = createArHandler(opts(gateways(id, header, source.response).fetchImpl))
  const res = await handler(new Request(`ar://${id}`))
  assert.equal(res.status, 200)
  assert.equal(res.headers.get('X-Arweave-Verified'), 'header')
  await assert.rejects(res.arrayBuffer(), /size does not match signed data_size/)
})

test('authenticated empty data and HEAD have distinct body contracts', async () => {
  const empty = transaction(Buffer.alloc(0))
  const { handler } = createArHandler(opts(gateways(empty.id, empty.header, new Response(null)).fetchImpl))
  const res = await handler(new Request(`ar://${empty.id}`))
  assert.equal(res.headers.get('X-Arweave-Verified'), 'bytes')
  assert.equal(await res.text(), '')
  const bytes = transaction(Buffer.alloc(13))
  const head = createArHandler(opts(gateways(bytes.id, bytes.header, new Response(null, { headers: { 'content-length': '13' } })).fetchImpl))
  const headRes = await head.handler(new Request(`ar://${bytes.id}`, { method: 'HEAD' }))
  assert.equal(headRes.status, 200)
  assert.equal(headRes.headers.get('X-Arweave-Verified'), 'header')
  assert.equal(headRes.headers.get('content-length'), '13')
})

test('verified raw MIME and length come from signed tags and measured bytes', async () => {
  const bytes = Buffer.from('<p>example</p>')
  const { id, header } = transaction(bytes, { tags: [tag('Content-Type', 'text/plain')] })
  const source = new Response(bytes, { headers: { 'content-type': 'text/html', 'content-length': '1' } })
  const { handler } = createArHandler(opts(gateways(id, header, source).fetchImpl))
  const res = await handler(new Request(`ar://${id}`))
  assert.equal(res.headers.get('content-type'), 'text/plain')
  assert.equal(res.headers.get('content-length'), String(bytes.length))
  assert.equal(res.headers.get('X-Arweave-Representation'), 'raw')
})

test('malformed and oversized header responses refuse and cancel the data stream', async () => {
  const { id } = transaction(Buffer.alloc(13))
  for (const headerResponse of [new Response('{'), streamed([MAX_HEADER_BYTES + 1, 1]).response]) {
    const source = streamed([13])
    const { handler } = createArHandler(opts(async (url) => url.includes('/tx/') ? headerResponse : source.response))
    const res = await handler(new Request(`ar://${id}`))
    assert.equal(res.status, 502)
    assert.equal(source.cancelled, true)
    assert.equal(source.pulled, 0, 'no data consumed before header authentication')
  }
})

test('disabled checking and unavailable header remain explicitly unchecked streams', async () => {
  const { id } = transaction(Buffer.alloc(13))
  for (const verifyHeader of [false, true]) {
    const source = streamed([20, 30])
    let headersAsked = 0
    const fetchImpl = async (url) => {
      if (url.includes('/tx/')) { headersAsked++; throw new Error('offline') }
      return source.response
    }
    const { handler } = createArHandler({ ...opts(fetchImpl), verifyHeader })
    const res = await handler(new Request(`ar://${id}`))
    assert.equal(headersAsked, verifyHeader ? 1 : 0)
    assert.equal(res.headers.get('X-Arweave-Verified'), 'none')
    assert.equal((await res.arrayBuffer()).byteLength, 50)
  }
})

test('abort during the bounded raw read cancels upstream and refuses', async () => {
  const { id, header } = transaction(Buffer.alloc(13))
  const abort = new AbortController()
  let cancelled = false
  const source = new Response(new ReadableStream({
    pull () { abort.abort() },
    cancel () { cancelled = true }
  }, { highWaterMark: 0 }))
  const { handler } = createArHandler(opts(gateways(id, header, source).fetchImpl))
  const res = await handler(new Request(`ar://${id}`, { signal: abort.signal }))
  assert.equal(res.status, 502)
  assert.equal(cancelled, true)
  assert.match(await res.text(), /aborted/)
})
