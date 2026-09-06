/*
 * The transaction header check: an Arweave transaction id is the SHA-256 of
 * the transaction's signature, so a header fetched from a SECOND gateway is
 * proven to be the id's transaction with one hash and no trust in either
 * gateway. It does not prove the bytes (the data_root and its Merkle tree are
 * not computed here); it closes the cheapest lie.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import createArHandler, { headerMatchesId } from '../src/ar.js'

const sig = Buffer.alloc(512, 7)
const ID = createHash('sha256').update(sig).digest().toString('base64url')

const answers = (header) => async (url) => {
  if (/\/tx\//.test(url)) return new Response(JSON.stringify(header), { status: 200, headers: { 'content-type': 'application/json' } })
  return new Response('bytes', { status: 200, headers: { 'content-type': 'text/plain' } })
}

test('headerMatchesId is the protocol\'s own definition of a transaction id', () => {
  assert.equal(headerMatchesId({ signature: sig.toString('base64url') }, ID), true)
  assert.equal(headerMatchesId({ signature: Buffer.alloc(512, 8).toString('base64url') }, ID), false)
  assert.equal(headerMatchesId({}, ID), false)
  assert.equal(headerMatchesId(null, ID), false)
})

test('with the check on, the header comes from the OTHER gateway and must match; a mismatch is refused', async () => {
  const good = createArHandler({ gateways: ['https://a.example', 'https://b.example'], fetchImpl: answers({ signature: sig.toString('base64url') }), verifyHeader: true })
  const ok = await good.handler(new Request(`ar://${ID}/`))
  assert.equal(ok.status, 200)
  assert.equal(ok.headers.get('X-Arweave-Verified'), 'header')

  const asked = []
  const lying = createArHandler({
    gateways: ['https://a.example', 'https://b.example'],
    fetchImpl: async (url, init) => { asked.push(url); return answers({ signature: Buffer.alloc(512, 9).toString('base64url') })(url, init) },
    verifyHeader: true
  })
  const bad = await lying.handler(new Request(`ar://${ID}/`))
  assert.equal(bad.status, 502)
  assert.match(await bad.text(), /does not hash to the id/)
  assert.ok(asked.some((u) => u.startsWith('https://b.example/tx/')), 'the header was asked of the second gateway')
})

test('what is not checked is said: a manifest path, a single gateway, the check switched off', async () => {
  const good = createArHandler({ gateways: ['https://a.example', 'https://b.example'], fetchImpl: answers({ signature: sig.toString('base64url') }), verifyHeader: true })
  assert.equal((await good.handler(new Request(`ar://${ID}/index.html`))).headers.get('X-Arweave-Verified'), 'none')
  const single = createArHandler({ gateway: 'https://a.example', fetchImpl: answers({}), verifyHeader: true })
  assert.equal((await single.handler(new Request(`ar://${ID}/`))).headers.get('X-Arweave-Verified'), 'none')
  const off = createArHandler({ gateways: ['https://a.example', 'https://b.example'], fetchImpl: answers({}) })
  assert.equal((await off.handler(new Request(`ar://${ID}/`))).headers.get('X-Arweave-Verified'), 'none')
})
