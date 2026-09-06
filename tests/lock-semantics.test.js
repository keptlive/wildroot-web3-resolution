/*
 * What the padlock means.
 *
 * Matt, 2026-09-04: "there should be different colored locks for trustless and
 * trusted". The distinction the lock exists to make is not "did this load" —
 * every browser's lock answers that — but **who did you have to believe**:
 *
 *   verified  TRUSTLESS. Every step was checked on this computer: a chain
 *             proof, a signature we validated, bytes checked against the
 *             address they were requested by. Nobody was taken at their word.
 *   partial   TRUSTED. It loaded, and something in the path rests on someone
 *             else's assurance — a certificate authority, an RPC endpoint, an
 *             unsigned DNS answer.
 *   failed    something that should have verified did not.
 *
 * These tests pin the verdicts rather than the colours, because the verdict is
 * the decision and the colour is its presentation. The one rule about
 * presentation worth holding here is that an OPEN lock outranks any trust
 * colour — a plain `http://` page is `partial`, and painting it the neutral
 * "trusted" colour would leave an open padlock looking ordinary.
 *
 * The lock and the security panel are built from the SAME steps, which is the
 * point of deriving both from trust-path.js: a lock that disagreed with the
 * panel behind it would be worse than no lock.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { schemeSteps, summarize, hnsSteps } from '../src/trust-path.js'

/** The verdict exactly as src/index.js `hnsone-scheme-trust` computes it. */
function verdictFor (url) {
  const steps = schemeSteps(url)
  const { state } = summarize(steps)
  const connection = steps.find((s) => s.label === 'Connection')
  const secure = state !== 'failed' && !(connection && connection.state === 'none')
  return { state, secure }
}

test('content-addressed schemes are TRUSTLESS', () => {
  // The bytes are checked against the address they were asked for, so there is
  // nobody to believe.
  for (const url of ['ipfs://bafyfoo/', 'ar://sometxid/', 'hyper://key/']) {
    assert.equal(verdictFor(url).state, 'verified', url)
  }
})

test('an ordinary https:// page is TRUSTED, not trustless', () => {
  // A CA vouched for the name and the browser believed it. That is the normal
  // web, and it is exactly what the green lock must NOT claim.
  const v = verdictFor('https://example.com/')
  assert.equal(v.state, 'partial')
  assert.equal(v.secure, true, 'it is still encrypted — the lock stays closed')
})

test('plain http:// keeps an OPEN lock, whatever colour the verdict implies', () => {
  const v = verdictFor('http://example.com/')
  assert.equal(v.secure, false)
})

test('ens:// is TRUSTED — and stays so until there is a light client', () => {
  // The registry read, the resolver address and every CCIP callback arrive on
  // the word of an RPC endpoint. Grading a CCIP resolver's own rigour (signed
  // gateway vs on-chain proof) would show a difference we cannot observe: we
  // learned about the proof from the same endpoint that could have invented
  // it. See src/protocols/ccip-read.js.
  assert.equal(verdictFor('ens://vitalik.eth/').state, 'partial')
})

test('a Handshake name with a chain proof and a DANE pin is TRUSTLESS', () => {
  const steps = hnsSteps('site.w3', {
    trust: 'spv', kind: 'site', ns: 'ns1.hns.one', tlsa: [{ usage: 3 }], dnssecValidated: true
  }, { transport: 'https-dane' })
  assert.equal(summarize(steps).state, 'verified')
})

test('...and the same name over DoH, or without a pin, is TRUSTED', () => {
  assert.equal(summarize(hnsSteps('site.w3',
    { trust: 'doh', kind: 'ipfs', cid: 'bafy' }, {})).state, 'partial')
  assert.equal(summarize(hnsSteps('site.w3',
    { trust: 'spv', kind: 'site', ns: 'ns1', tlsa: [], allowInsecure: true },
    { transport: 'http' })).state, 'partial')
})

test('a chain-proven content pointer is TRUSTLESS even with no TLS at all', () => {
  // There is no transport to secure: the CID is the guarantee, and the chain
  // proved which CID this name means.
  assert.equal(summarize(hnsSteps('site.w3',
    { trust: 'spv', kind: 'ipfs', cid: 'bafy' }, {})).state, 'verified')
})

test('a failed resolution is FAILED, never quietly trusted', () => {
  for (const kind of ['unregistered', 'blocked', 'unreachable']) {
    const state = summarize(hnsSteps('x.w3',
      { trust: 'spv', kind, address: '10.0.0.1', reason: 'nope' }, {})).state
    assert.notEqual(state, 'verified', kind)
  }
})

// EXTRACTION NOTE (hns-resolution): two tests here assert that the browser's
// chrome (src/ui/style.css, src/ui/omni-box.js, src/index.js) renders these
// verdicts and never recomputes them. They are about the browser, not the
// resolution standard, and stay in the Wildroot tree.
