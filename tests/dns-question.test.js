// A DNS reply is a reply to the question that was asked.
//
// The message id is 16 bits, and over DoH it is fixed at zero (RFC 8484
// §4.1), so the question section is the only thing that binds an answer to a
// query. A resolver, or anyone on the path, that returns a valid-looking
// answer for a DIFFERENT name or type must be caught rather than believed.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { buildQuery, parseAnswers, assertAnswersTo, TYPES } from '../src/dns-query.js'
import { DoHResolver } from '../src/doh.js'
import { stubWireFetch } from './doh-wire.js'

/** A reply frame built from a query: the QR bit set, the question kept. */
function replyFor (name, type) {
  const q = buildQuery(name, type, 0)
  q.writeUInt16BE(q.readUInt16BE(2) | 0x8000, 2)
  return q
}

test('the question section is parsed, and a reply to another question is refused', () => {
  const parsed = parseAnswers(replyFor('Proof.W3.', TYPES.TXT))
  assert.deepEqual(parsed.questions, [{ name: 'proof.w3', type: TYPES.TXT, klass: 1 }])
  assert.equal(assertAnswersTo(parsed, 'proof.w3', TYPES.TXT), parsed)
  assert.equal(assertAnswersTo(parsed, 'PROOF.w3.', TYPES.TXT), parsed, 'owner names compare case-insensitively')
  assert.throws(() => assertAnswersTo(parsed, 'other.w3', TYPES.TXT), /different question/)
  assert.throws(() => assertAnswersTo(parsed, 'proof.w3', TYPES.A), /different question/)
  assert.throws(() => assertAnswersTo({ questions: [] }, 'proof.w3', TYPES.A), /no question section/)
})

test('a DoH answer for a different name is not used — the endpoint is treated as failed', async () => {
  // The stub answers every query with a reply whose question names another host.
  const honest = stubWireFetch({ 'site.14898:A': [{ type: TYPES.A, data: '203.0.113.10' }] })
  const lying = async (url, opts) => {
    const res = await honest(url, opts)
    const body = Buffer.from(await res.arrayBuffer())
    // Rewrite the question's owner name (whatever the type asked): a
    // same-length name with a different label.
    const swapped = Buffer.from(body)
    const wireName = Buffer.concat([Buffer.from([4]), Buffer.from('site'), Buffer.from([5]), Buffer.from('14898'), Buffer.from([0])])
    const at = swapped.indexOf(wireName)
    if (at >= 0) swapped.write('sote', at + 1, 'latin1')
    return { ok: true, status: 200, arrayBuffer: async () => swapped }
  }
  const r = new DoHResolver({ endpoints: ['https://liar.example/dns-query'], fetchImpl: lying })
  const out = await r.resolve('site.14898')
  assert.equal(out.kind, 'unreachable', 'a reply to another question is no reply')
  const ok = new DoHResolver({ endpoints: ['https://honest.example/dns-query'], fetchImpl: honest })
  assert.equal((await ok.resolve('site.14898')).kind, 'site')
})
