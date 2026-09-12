/*
 * The transaction header check, at the handler: the header is fetched from a
 * SECOND gateway, its signature must hash to the id AND verify over the
 * fields served with it (src/ar-tx.js, proven against real transactions in
 * tests/ar-tx.test.js), and only then does the id's `data_root` mean
 * anything. A header that is not this id's transaction is a refusal; a header
 * this implementation cannot check is a shrug that claims nothing.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import createArHandler, { headerMatchesId, headerVerdict } from '../src/ar.js'
import { signedTransaction } from './signed-tx.js'

const { id: ID, header: HEADER } = signedTransaction()

const answers = (header) => async (url) => {
  if (/\/tx\//.test(url)) return new Response(JSON.stringify(header), { status: 200, headers: { 'content-type': 'application/json' } })
  return new Response('bytes', { status: 200, headers: { 'content-type': 'text/plain' } })
}

const two = (header) => createArHandler({
  gateways: ['https://a.example', 'https://b.example'], fetchImpl: answers(header), verifyHeader: true
})

test('headerMatchesId is the protocol\'s definition of a transaction id AND the signature over the fields', () => {
  assert.equal(headerMatchesId(HEADER, ID), true)
  assert.equal(headerMatchesId({ ...HEADER, data_root: 'WCfBwUaeU65cNkG7aHfyqW48AuhhjgychOA9WIc43aU' }, ID), false,
    'a swapped data root no longer passes on the strength of the signature\'s hash')
  assert.equal(headerMatchesId({ signature: HEADER.signature }, ID), false, 'the hash alone proves nothing about the fields')
  assert.equal(headerMatchesId({}, ID), false)
  assert.equal(headerMatchesId(null, ID), false)
})

test('with the check on, the header comes from the OTHER gateway and must match; a mismatch is refused', async () => {
  const ok = await two(HEADER).handler(new Request(`ar://${ID}/`))
  assert.equal(ok.status, 200)
  assert.equal(ok.headers.get('X-Arweave-Verified'), 'header')

  const asked = []
  const lying = createArHandler({
    gateways: ['https://a.example', 'https://b.example'],
    fetchImpl: async (url, init) => { asked.push(url); return answers(signedTransaction({ reward: '7' }).header)(url, init) },
    verifyHeader: true
  })
  const bad = await lying.handler(new Request(`ar://${ID}/`))
  assert.equal(bad.status, 502)
  assert.match(await bad.text(), /does not hash to the id/)
  assert.ok(asked.some((u) => u.startsWith('https://b.example/tx/')), 'the header was asked of the second gateway')
})

test('a header with the right signature but doctored fields is REFUSED, not served as checked', async () => {
  // The attack the hash alone could not see: the signature is the id's, and
  // the data root beside it is another transaction's.
  const doctored = { ...HEADER, data_root: 'WCfBwUaeU65cNkG7aHfyqW48AuhhjgychOA9WIc43aU', data_size: '5725' }
  assert.equal(headerVerdict(doctored, ID), 'mismatch')
  const res = await two(doctored).handler(new Request(`ar://${ID}/`))
  assert.equal(res.status, 502)
  assert.match(await res.text(), /does not sign the fields served with it/)
})

test('a header that cannot be checked claims nothing: `none`, and the bytes are not measured against it', async () => {
  // A real transaction of a format this implementation does not construct a
  // payload for. Its signature really does hash to the id.
  const future = { ...HEADER, format: 3 }
  assert.equal(headerVerdict(future, ID), 'unsupported')
  const res = await two(future).handler(new Request(`ar://${ID}/`))
  assert.equal(res.status, 200, 'not a refusal: nothing was caught, only unproven')
  assert.equal(res.headers.get('X-Arweave-Verified'), 'none')
})

test('the real thing, end to end: a fetched header proves the root the served bytes are then hashed against', async () => {
  const header = JSON.parse(readFileSync(new URL('./fixtures/arweave/EDGVy6AAKFNKEA3LsjZJ5OXv82eRvJPsomCA4AWC7y8.tx.json', import.meta.url), 'utf8'))
  const bytes = readFileSync(new URL('./fixtures/arweave/EDGVy6AAKFNKEA3LsjZJ5OXv82eRvJPsomCA4AWC7y8.bin', import.meta.url))
  const fetchImpl = async (url) => (/\/tx\//.test(url)
    ? new Response(JSON.stringify(header), { status: 200, headers: { 'content-type': 'application/json' } })
    : new Response(bytes, { status: 200, headers: { 'content-type': 'application/octet-stream' } }))
  const { handler } = createArHandler({ gateways: ['https://a.example', 'https://b.example'], fetchImpl, verifyHeader: true })
  const res = await handler(new Request(`ar://${header.id}`))
  assert.equal(res.status, 200)
  assert.equal(res.headers.get('X-Arweave-Verified'), 'bytes')
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), bytes)
})

test('what is not checked is said: a manifest path, a single gateway, the check switched off', async () => {
  const good = two(HEADER)
  assert.equal((await good.handler(new Request(`ar://${ID}/index.html`))).headers.get('X-Arweave-Verified'), 'none')
  const single = createArHandler({ gateway: 'https://a.example', fetchImpl: answers(HEADER), verifyHeader: true })
  assert.equal((await single.handler(new Request(`ar://${ID}/`))).headers.get('X-Arweave-Verified'), 'none')
  const off = createArHandler({ gateways: ['https://a.example', 'https://b.example'], fetchImpl: answers(HEADER) })
  assert.equal((await off.handler(new Request(`ar://${ID}/`))).headers.get('X-Arweave-Verified'), 'none')
})
