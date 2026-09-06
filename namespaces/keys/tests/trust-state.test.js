// The trust state each key-addressed scheme exposes.
//
// `src/trust-path.js` at the root of this package is byte-identical to
// `src/hns/trust-path.js` in the Wildroot tree. `schemeSteps()` is what the
// browser's security panel and padlock render for anything that is not an
// `hns://` page, so it — not the router's `verify` string — is what a USER is
// actually told about a hyper/ssb/bittorrent/gemini address.
//
// Every scheme in this chapter has its own case: there is no key-addressed
// address that falls through to the default sentence, and the two claims a
// key address is NOT entitled to make — freshness, and the name->key hop of a
// DNSLink host — are said out loud in the step text. These assertions pin that
// wording, because the wording is the security claim.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { schemeSteps, summarize } from '../../../src/trust-path.js'

const INFOHASH = 'c0ffee0123456789abcdef0123456789abcdef01'
const HYPER_KEY = 'a'.repeat(64)
const PUBKEY = 'd'.repeat(64)

const only = (url) => {
  const steps = schemeSteps(url)
  assert.equal(steps.length, 1, url)
  return steps[0]
}

test('hyper and ssb are reported VERIFIED — key-addressed by construction', () => {
  // Each says what a KEY proves and what it does not: who wrote it, never that
  // this is the newest version (hyper) or the whole feed (ssb). A step that
  // said only "verified" would let a reader take freshness for granted.
  for (const [url, promise] of [
    [`hyper://${HYPER_KEY}/`, /Key-addressed: every block .* not that you were shown the newest version/s],
    ['ssb://feed/ed25519/abc', /Key-addressed: every message .* not that the feed is complete/s]
  ]) {
    const step = only(url)
    assert.equal(step.state, 'verified', url)
    assert.equal(step.label, 'Content')
    assert.match(step.detail, promise, url)
  }
  assert.equal(summarize(schemeSteps(`hyper://${HYPER_KEY}/`)).state, 'verified')
})

test('a hyper DNSLink address is TWO steps: the mapping unverified, the content verified', () => {
  // `hyper://blog.example.com/` resolves its key from a `_dnslink` TXT record
  // fetched over the DoH JSON API, with no DNSSEC and no proof, so the
  // name->key binding is that resolver's word. That is the `ens://` shape and
  // it gets the `ens://` treatment: the pointer is unverified, the content it
  // names verifies, and the lock does not close. KY-4.
  const [name, content] = schemeSteps('hyper://blog.example.com/')
  assert.equal(name.label, 'Name records')
  assert.equal(name.state, 'unverified')
  assert.match(name.source, /DNSLink name blog\.example\.com/)
  assert.match(name.detail, /no DNSSEC, no chain proof/)
  assert.equal(content.label, 'Content')
  assert.equal(content.state, 'verified')
  assert.equal(summarize(schemeSteps('hyper://blog.example.com/')).state, 'partial',
    'a resolver-trusted hop must not read as a verified address')
})

test('`bt://` and `bittorrent://` are described identically, and the two key shapes are not', () => {
  // One namespace, two spellings: `bittorrent://` is the canonical form every
  // magnet redirects to and every `bt=` pointer builds, so it must not be the
  // one address the panel cannot describe.
  for (const url of [`bt://${INFOHASH}/`, `bittorrent://${INFOHASH}/`]) {
    const step = only(url)
    assert.equal(step.state, 'verified', url)
    assert.equal(step.label, 'Content')
    assert.match(step.detail, /Content-addressed: every piece is checked against the infohash/, url)
    assert.equal(summarize([step]).state, 'verified', url)
  }

  // A 40-hex infohash is a HASH; a 64-hex host is a BEP-46 public KEY. Both
  // verify, but only the hash fixes the bytes forever — the key says who
  // published, not that this is the newest thing they published.
  const mutable = only(`bittorrent://${PUBKEY}/`)
  assert.equal(mutable.state, 'verified')
  assert.match(mutable.source, /signed by public key/)
  assert.match(mutable.detail, /BEP 46.*not that this is the newest version/s)
})

test('gemini says the connection is encrypted and the certificate is not verified', () => {
  // Gemini has its own case, so "nothing is established about who answered" is
  // a statement about Gemini rather than the sentence the panel prints for a
  // scheme nobody thought about. Encrypted, unauthenticated, verdict
  // `partial`: there is no certificate store, so nothing is pinned and nothing
  // is compared (KY-1).
  const step = only('gemini://geminiprotocol.net/')
  assert.equal(step.label, 'Connection')
  assert.equal(step.state, 'unverified')
  assert.match(step.source, /certificate not verified/)
  assert.match(step.detail, /neither checked against an authority nor remembered/)
  assert.equal(summarize([step]).state, 'partial')
})

test('no address in this chapter falls through to the default sentence', () => {
  // The default is "we have not thought about this scheme". While gemini or
  // bittorrent reached it, a real verdict and an unwired scheme printed the
  // same words and a reader could not tell them apart.
  for (const url of [
    `hyper://${HYPER_KEY}/`, 'hyper://blog.example.com/', 'ssb://feed/ed25519/abc',
    `bt://${INFOHASH}/`, `bittorrent://${INFOHASH}/`, `bittorrent://${PUBKEY}/`,
    'gemini://geminiprotocol.net/', `magnet:?xt=urn:btih:${INFOHASH}`
  ]) {
    for (const step of schemeSteps(url)) {
      assert.doesNotMatch(step.detail, /no verification path for this scheme/, url)
    }
  }
  // …and the default is still there, for a scheme that really has no case.
  assert.match(schemeSteps('gopher://example.com/').at(0).detail,
    /no verification path for this scheme/)
})

test('magnet: says a magnet is a pointer and that nothing loads until it is added', () => {
  // A magnet is always a 308, so this is rarely rendered — but it is written
  // rather than left to the default, so the default keeps its one meaning.
  const step = only('magnet:?xt=urn:btih:' + INFOHASH)
  assert.equal(step.label, 'Address')
  assert.equal(step.state, 'none')
  assert.match(step.detail, /nothing loads until it is added/)
})

test('an unparseable address fails rather than defaulting to trusted', () => {
  const steps = schemeSteps('not a url')
  assert.equal(steps[0].state, 'failed')
  assert.equal(summarize(steps).state, 'failed')
})
