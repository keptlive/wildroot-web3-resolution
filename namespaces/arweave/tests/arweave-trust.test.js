/*
 * What the browser is allowed to SAY about bytes fetched from an Arweave
 * gateway. SPEC.md §9.
 *
 * This is the assertion the whole chapter turns on: the bytes are not checked
 * against the transaction, so no step may borrow the content-addressed
 * sentence that `ipfs=`, `bt=` and `hyper=` earn, and no aggregate verdict may
 * come out `verified`. The panel is at the repository root
 * (`../../../src/trust-path.js`) because every namespace renders through it;
 * what is Arweave-specific is pinned here.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { hnsSteps, schemeSteps, summarize } from '../../../src/trust-path.js'

const TX = 'W-9rj7LCX-1kRs8Edf4UmJvzCHYBCnZN_13dh0Y7xq8'

const byLabel = (steps, label) => steps.find((s) => s.label === label)

test('a bare ar:// URL reports its content as UNVERIFIED and names the gateway', () => {
  const steps = schemeSteps(`ar://${TX}/index.html`)
  const content = byLabel(steps, 'Content')
  assert.equal(content.state, 'unverified')
  assert.match(content.source, /gateway/i)
  assert.match(content.source, /HTTPS/)
  assert.ok(content.source.includes(TX), 'the transaction id is named')
  assert.match(content.detail, /not checked against the transaction/)
  assert.equal(summarize(steps).state, 'partial')
})

test('no Arweave step ever claims the bytes were checked against the address', () => {
  // The claim `ipfs://`, `bittorrent://` and `hyper://` are entitled to, and
  // this namespace is not. A regression here is a false security claim, which
  // is worse than an unhelpful one.
  const paths = [
    schemeSteps(`ar://${TX}`),
    hnsSteps('ark.w3', { trust: 'spv', kind: 'arweave', txid: TX }),
    hnsSteps('ark.w3', { trust: 'doh', kind: 'arweave', txid: TX })
  ]
  for (const steps of paths) {
    for (const s of steps) {
      assert.doesNotMatch(s.detail || '', /checked against the address/)
      assert.doesNotMatch(s.detail || '', /Content-addressed/)
      if (s.label === 'Content') assert.notEqual(s.state, 'verified')
    }
    assert.equal(summarize(steps).state, 'partial',
      'a gateway hop nobody checked can never aggregate to verified')
  }
})

test('the chain proof of the POINTER survives beside the unverified content', () => {
  // SPEC §9.4. The two claims are independent and both are made: which
  // immutable object the name names is proven; the bytes are not.
  const steps = hnsSteps('ark.w3', { trust: 'spv', kind: 'arweave', txid: TX })
  assert.equal(byLabel(steps, 'Handshake name').state, 'verified')
  assert.equal(byLabel(steps, 'Content').state, 'unverified')
  assert.equal(byLabel(steps, 'Pointer'), undefined,
    'the chain path adds no separate pointer caveat')

  // Over DoH even the binding is taken on a resolver's word, and that is a
  // step of its own rather than a silent downgrade of the same one.
  const doh = hnsSteps('ark.w3', { trust: 'doh', kind: 'arweave', txid: TX })
  assert.equal(byLabel(doh, 'Pointer').state, 'unverified')
  assert.match(byLabel(doh, 'Pointer').detail, /not\s+chain-verified/)
})
