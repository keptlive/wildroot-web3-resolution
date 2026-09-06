import { test } from 'node:test'
import assert from 'node:assert/strict'

import { DoHResolver } from '../src/doh.js'
import { stubWireFetch, wireResponse } from './doh-wire.js'
import { TYPES } from '../src/dns-query.js'

test('DoH resolves an ipfs= TXT pointer, marked untrusted', async () => {
  const cid = 'bafkreigph5cub32tn4ph2au3izioyxnr37lvthzdug4xlmhlbnxj7h3mqu'
  const r = new DoHResolver({
    fetchImpl: stubWireFetch({
      'hello.14898:TXT': [{ type: TYPES.TXT, data: `ipfs=${cid}` }]
    })
  })
  const out = await r.resolve('hello.14898')
  // `endpoint` names WHO answered. The security panel shows it as the source
  // of an unverified step, so a DoH answer can never be presented as if the
  // chain had vouched for it.
  assert.deepEqual(out, {
    kind: 'ipfs',
    cid,
    trust: 'doh',
    oblivious: false,
    via: null,
    endpoint: 'query.hns.one'
  })
})

test('a DoH answer always names the resolver that gave it', async () => {
  const r = new DoHResolver({
    endpoints: ['https://resolver.example/dns-query'],
    fetchImpl: stubWireFetch({ 'site.14898:A': [{ type: TYPES.A, data: '203.0.113.10' }] })
  })
  assert.equal(r.endpointLabel, 'resolver.example')
  assert.equal((await r.resolve('site.14898')).endpoint, 'resolver.example')
})

test('DoH resolves an A record as an insecure site', async () => {
  const r = new DoHResolver({
    fetchImpl: stubWireFetch({
      'site.14898:A': [{ type: TYPES.A, data: '203.0.113.10' }]
    })
  })
  const out = await r.resolve('site.14898')
  assert.equal(out.kind, 'site')
  assert.equal(out.address, '203.0.113.10')
  assert.equal(out.trust, 'doh')
  assert.equal(out.allowInsecure, true)
})

test('DoH returns unregistered when nothing answers', async () => {
  const r = new DoHResolver({ fetchImpl: stubWireFetch({}) })
  assert.equal((await r.resolve('nope.14898')).kind, 'unregistered')
})

test('DoH tries the next endpoint on failure', async () => {
  let calls = 0
  const good = stubWireFetch({ 'x.14898:A': [{ type: TYPES.A, data: '203.0.113.7' }] })
  const fetchImpl = async (url, opts) => {
    calls++
    if (calls === 1) throw new Error('first endpoint down')
    return good(url, opts)
  }
  const r = new DoHResolver({ endpoints: ['https://a/dns', 'https://b/dns'], fetchImpl })
  const out = await r.resolve('x.14898')
  assert.equal(out.kind, 'site')
  assert.ok(calls >= 2)
})

test('DoH retries the next endpoint on SERVFAIL, accepts NXDOMAIN', async () => {
  let calls = 0
  const fetchImpl = async (url) => {
    calls++
    const u = new URL(url)
    const q = Buffer.from(u.searchParams.get('dns').replace(/-/g, '+').replace(/_/g, '/'), 'base64')
    // first endpoint SERVFAILs everything; second returns NXDOMAIN
    const rcode = calls <= 2 ? 2 : 3
    const body = wireResponse(q, [], rcode)
    return {
      ok: true,
      arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength)
    }
  }
  const r = new DoHResolver({ endpoints: ['https://flaky/dns', 'https://ok/dns'], fetchImpl })
  const out = await r.resolve('gone.14898')
  assert.equal(out.kind, 'unregistered')
  assert.ok(calls >= 3, `expected fallback retries, got ${calls}`)
})

// ---------------------------------------------------------------------------
// 2026-09-05: the pin rides DoH too, and an outage is not an absence
// ---------------------------------------------------------------------------

test('a TLSA the resolver returns PINS the connection, on the resolver\'s word', async () => {
  const pin = 'f0'.repeat(32)
  const r = new DoHResolver({
    fetchImpl: stubWireFetch({
      'site.14898:A': [{ type: TYPES.A, data: '203.0.113.10' }],
      '_443._tcp.site.14898:TLSA': [{ type: TYPES.TLSA, data: `3 1 1 ${pin}` }]
    })
  })
  const out = await r.resolve('site.14898')
  assert.equal(out.kind, 'site')
  assert.equal(out.tlsa.length, 1, 'the pin was dropped on the DoH path')
  assert.equal(out.tlsa[0].certificate, pin)
  assert.equal(out.allowInsecure, false, 'a pinned site must never be offered in the clear')
  assert.equal(out.trust, 'doh', 'still the resolver\'s word, never chain-proven')
})

test('an EMPTY TLSA answer still allows plaintext — the resolver said there is no pin', async () => {
  const r = new DoHResolver({
    fetchImpl: stubWireFetch({ 'site.14898:A': [{ type: TYPES.A, data: '203.0.113.10' }] })
  })
  const out = await r.resolve('site.14898')
  assert.equal(out.allowInsecure, true)
  assert.equal(out.tlsaKnown, true)
})

test('a TLSA lookup that FAILS refuses to downgrade — unknown is not permission', async () => {
  const inner = stubWireFetch({ 'site.14898:A': [{ type: TYPES.A, data: '203.0.113.10' }] })
  const fetchImpl = async (url, opts) => {
    const q = Buffer.from(new URL(url).searchParams.get('dns').replace(/-/g, '+').replace(/_/g, '/'), 'base64')
    let i = 12
    while (q[i] !== 0) i += q[i] + 1
    if (q.readUInt16BE(i + 1) === TYPES.TLSA) throw new Error('TLSA lookup lost')
    return inner(url, opts)
  }
  const r = new DoHResolver({ endpoints: ['https://one.example/dns-query'], fetchImpl })
  const out = await r.resolve('site.14898')
  assert.equal(out.kind, 'site')
  assert.equal(out.allowInsecure, false)
  assert.equal(out.tlsaKnown, false)
})

test('every endpoint failing is UNREACHABLE, not "unregistered"', async () => {
  const r = new DoHResolver({
    endpoints: ['https://one.example/dns-query', 'https://two.example/dns-query'],
    fetchImpl: async () => { throw new Error('network is down') }
  })
  const out = await r.resolve('friend.14898')
  assert.equal(out.kind, 'unreachable', JSON.stringify(out))
  assert.match(out.reason, /down/)
})

// ---------------------------------------------------------------- Private mode
// Row 3 of the divergence inventory: in Private mode a Handshake name is
// looked up obliviously or not at all. The plain-DoH fallback below the
// oblivious transport is the ONE place a relay outage used to cost privacy
// instead of availability; `strictOblivious` makes it cost availability and
// say so.

/** A fake oblivious transport that answers from the same wire fixture a plain endpoint would. */
function fakeOdoh (map, { fail = null } = {}) {
  const inner = stubWireFetch(map)
  const asked = []
  return {
    label: 'odoh.test',
    asked,
    async query (wire) {
      asked.push(wire)
      if (fail) throw new Error(fail)
      const param = Buffer.from(wire).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
      const res = await inner(`https://odoh.test/dns-query?dns=${param}`)
      return { answer: Buffer.from(await res.arrayBuffer()), via: 'relay.test' }
    }
  }
}

test('strict: an oblivious answer is used exactly as before, and no plain endpoint is asked', async () => {
  const plain = []
  const r = new DoHResolver({
    endpoints: ['https://plain.example/dns-query'],
    fetchImpl: async (url) => { plain.push(url); throw new Error('must not be asked') },
    odoh: fakeOdoh({ 'name.14898:TXT': [{ type: TYPES.TXT, data: 'ipfs=bafkreigph5cub32tn4ph2au3izioyxnr37lvthzdug4xlmhlbnxj7h3mqu' }] }),
    strictOblivious: true
  })
  const out = await r.resolve('name.14898')
  assert.equal(out.kind, 'ipfs')
  assert.equal(out.oblivious, true)
  assert.deepEqual(plain, [], 'Private mode never falls back to plain DoH')
})

test('strict: when the oblivious transport fails, the name is UNREACHABLE and no plain query left the machine', async () => {
  const plain = []
  const r = new DoHResolver({
    endpoints: ['https://plain.example/dns-query'],
    fetchImpl: async (url) => { plain.push(url); return stubWireFetch({ 'name.14898:TXT': [{ type: TYPES.TXT, data: 'ipfs=bafkreigph5cub32tn4ph2au3izioyxnr37lvthzdug4xlmhlbnxj7h3mqu' }] })(url) },
    odoh: fakeOdoh({}, { fail: 'relay unreachable' }),
    strictOblivious: () => true // the live predicate form the browser passes
  })
  const out = await r.resolve('name.14898')
  assert.equal(out.kind, 'unreachable', JSON.stringify(out))
  assert.match(out.reason, /private lookup failed/)
  assert.match(out.reason, /relay unreachable/)
  assert.match(out.reason, /no unprotected lookup was made/)
  assert.deepEqual(plain, [], 'the plain endpoint that WOULD have answered was never asked')
})

test('strict with no oblivious transport configured refuses rather than resolving in the clear', async () => {
  const plain = []
  const r = new DoHResolver({ fetchImpl: async (url) => { plain.push(url); throw new Error('nope') }, strictOblivious: true })
  const out = await r.resolve('name.14898')
  assert.equal(out.kind, 'unreachable')
  assert.match(out.reason, /no oblivious resolver is configured/)
  assert.deepEqual(plain, [])
})

test('not strict (Fast): the same relay failure falls back to plain DoH, as it always did', async () => {
  const r = new DoHResolver({
    endpoints: ['https://plain.example/dns-query'],
    fetchImpl: stubWireFetch({ 'name.14898:TXT': [{ type: TYPES.TXT, data: 'ipfs=bafkreigph5cub32tn4ph2au3izioyxnr37lvthzdug4xlmhlbnxj7h3mqu' }] }),
    odoh: fakeOdoh({}, { fail: 'relay unreachable' }),
    strictOblivious: () => false
  })
  const out = await r.resolve('name.14898')
  assert.equal(out.kind, 'ipfs')
  assert.notEqual(out.oblivious, true)
})

test('a TXT that answered followed by an A lookup that could not be asked is UNREACHABLE, never unregistered', async () => {
  // The one-transport case Private mode makes common: the relay carried the
  // TXT question and then dropped; the name has not been shown to be absent.
  let asked = 0
  const inner = stubWireFetch({})
  const fetchImpl = async (url, opts) => {
    asked++
    if (asked > 1) throw new Error('relay dropped')
    return inner(url, opts)
  }
  const r = new DoHResolver({ endpoints: ['https://one.example/dns-query'], fetchImpl })
  const out = await r.resolve('friend.14898')
  assert.equal(out.kind, 'unreachable', JSON.stringify(out))
  assert.match(out.reason, /relay dropped/)
})
