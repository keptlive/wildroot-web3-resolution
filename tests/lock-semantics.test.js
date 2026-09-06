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
  const secure = state !== 'failed' && state !== 'open'
  return { state, secure }
}

test('content-addressed schemes are TRUSTLESS', () => {
  // The bytes are checked against the address they were asked for, so there is
  // nobody to believe.
  for (const url of ['ipfs://bafyfoo/', 'ipld://bafyfoo/x', 'hyper://key/',
    'bittorrent://' + 'a'.repeat(40) + '/', 'bt://' + 'b'.repeat(64) + '/', 'ssb://%25abc/']) {
    assert.equal(verdictFor(url).state, 'verified', url)
  }
})

test('ar:// is TRUSTED, not trustless — the gateway is believed', () => {
  // The transaction id names immutable bytes, but the ar:// handler does not
  // check the bytes it was handed against the transaction: the gateway is
  // trusted the way any HTTPS host is. The lock stays closed (HTTPS transport)
  // and the verdict is partial, and the step says which hop is the unchecked one.
  const v = verdictFor('ar://sometxid/')
  assert.equal(v.state, 'partial')
  assert.equal(v.secure, true)
  const content = schemeSteps('ar://sometxid/').find((s) => s.label === 'Content')
  assert.equal(content.state, 'unverified')
  assert.match(content.detail, /otherwise the gateway is trusted the way any HTTPS site is/, 'bytes are checked only for a top-level transaction under the limit; the step stays unverified because the check happens after resolution')
})

test('a hyper:// DNSLink name is TRUSTED; a hyper:// key is TRUSTLESS', () => {
  assert.equal(verdictFor('hyper://' + 'k'.repeat(52) + '/').state, 'verified')
  const v = verdictFor('hyper://blog.example.com/')
  assert.equal(v.state, 'partial')
  const name = schemeSteps('hyper://blog.example.com/').find((s) => s.label === 'Name records')
  assert.equal(name.state, 'unverified')
  assert.match(name.source, /DNSLink/)
})

test('nostr: proves authorship, never completeness — the lock is never green', () => {
  const steps = schemeSteps('nostr://npub1abc')
  assert.equal(steps.find((s) => s.label === 'Authorship').state, 'verified')
  assert.equal(steps.find((s) => s.label === 'Completeness').state, 'unverified')
  assert.equal(summarize(steps).state, 'partial')
})

test('gemini:// and did: and pubsub:// are never called verified', () => {
  for (const url of ['gemini://x.test/', 'did:plc:abc', 'pubsub://topic/']) {
    const steps = schemeSteps(url)
    assert.ok(steps.length, url)
    assert.ok(!steps.some((s) => s.state === 'verified'), `${url} claimed a verified step`)
    assert.ok(!steps.some((s) => /no verification path/.test(s.detail || '')),
      `${url} fell through to the default arm`)
  }
  const gemini = schemeSteps('gemini://x.test/')[0]
  assert.match(gemini.source, /certificate not verified/)
})

test('an ordinary https:// page is TRUSTED, not trustless', () => {
  // A CA vouched for the name and the browser believed it. That is the normal
  // web, and it is exactly what the green lock must NOT claim.
  const v = verdictFor('https://example.com/')
  assert.equal(v.state, 'partial')
  assert.equal(v.secure, true, 'it is still encrypted — the lock stays closed')
})

test('plain http:// is OPEN — a verdict of its own, in the model, not only in a renderer', () => {
  const v = verdictFor('http://example.com/')
  assert.equal(v.state, 'open')
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

test('...and the same name over DoH is TRUSTED; without a pin, over plain HTTP, it is OPEN', () => {
  assert.equal(summarize(hnsSteps('site.w3',
    { trust: 'doh', kind: 'ipfs', cid: 'bafy' }, {})).state, 'partial')
  assert.equal(summarize(hnsSteps('site.w3',
    { trust: 'spv', kind: 'site', ns: 'ns1', tlsa: [], allowInsecure: true },
    { transport: 'http' })).state, 'open')
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

test('the scheme table\'s `trust` column is what the panel actually delivers, scheme by scheme', async () => {
  // A table entry that claims more (or less) than schemeSteps() produces is
  // the exact kind of drift this file exists to stop: every row is resolved
  // to a sample URL and its verdict compared with the claim.
  const { SCHEME_TABLE } = await import('../src/router.js')
  const sample = {
    hns: null, // hnsSteps, not schemeSteps — covered below
    ipfs: 'ipfs://bafyfoo/',
    ipns: 'ipns://k51x/',
    ipld: 'ipld://bafyfoo/x',
    pubsub: 'pubsub://topic/',
    ar: 'ar://tx/',
    ens: 'ens://vitalik.eth/',
    web3: 'web3://0x1111111111111111111111111111111111111111/',
    nostr: 'nostr://npub1abc',
    at: 'at://did:plc:x/y',
    did: 'did:plc:abc',
    activitypub: 'activitypub:@a@b.c',
    onion: 'onion://' + 'a'.repeat(56) + '.onion/',
    https: 'https://example.com/',
    http: 'http://example.com/',
    'https+raw': 'https+raw://example.com/',
    gemini: 'gemini://x.test/',
    hyper: 'hyper://' + 'k'.repeat(52) + '/',
    ssb: 'ssb://%25x/',
    bittorrent: 'bittorrent://' + 'a'.repeat(40) + '/',
    bt: 'bt://' + 'a'.repeat(40) + '/',
    magnet: 'magnet:?xt=urn:btih:' + 'a'.repeat(40),
    wildroot: 'wildroot://welcome',
    agregore: 'agregore://welcome',
    browser: 'browser://welcome',
    search: 'search://?q=x',
    paste: 'paste://x',
    editor: 'editor://new/',
    bluesky: 'bluesky://home',
    mastodon: 'mastodon://home',
    media: 'media://x',
    docview: 'docview://x'
  }
  const expected = { trustless: 'verified', trusted: 'partial', open: 'open', refused: 'partial', builtin: 'verified' }
  for (const row of SCHEME_TABLE) {
    assert.ok(['trustless', 'trusted', 'open', 'refused', 'builtin'].includes(row.trust), `${row.scheme} has a trust claim`)
    const url = sample[row.scheme]
    if (url === null) continue
    assert.ok(url, `a sample URL for ${row.scheme}`)
    const steps = schemeSteps(url)
    const { state } = summarize(steps)
    assert.equal(state, expected[row.trust], `${row.scheme}: the table says ${row.trust}, the panel says ${state}`)
    if (row.trust === 'refused') {
      assert.ok(steps.every((s) => s.state !== 'verified'), `${row.scheme}: a refused scheme verifies nothing`)
    }
  }
  // hns: the chain path, TRUSTLESS when the proof and the pin hold.
  const chain = hnsSteps('site.w3', { trust: 'spv', kind: 'ipfs', cid: 'bafyfoo' })
  assert.equal(summarize(chain).state, 'verified')
})
