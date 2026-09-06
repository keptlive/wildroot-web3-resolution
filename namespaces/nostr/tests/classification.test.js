// Where the Nostr namespace begins and ends, per the router.
//
// This file imports the TOP-LEVEL `src/router.js` — the same module the
// Handshake chapter of this specification uses, which is byte-identical to the
// browser's `src/protocols/router.js`. Nothing is forked: the classifier that
// decides "is this Handshake?" is the same one that decides "is this Nostr?",
// and a divergent copy of a security-relevant classifier is a worse problem
// than an over-broad dependency.
//
// The rule under test is L2 from `docs/RESOLUTION-ROUTER.md`: a failure in one
// namespace never becomes a lookup in another. For Nostr specifically, an
// identifier that does not resolve must not fall through to DNS.

import test from 'node:test'
import assert from 'node:assert/strict'

import {
  classify, classifyHost, namespaceForScheme, schemeInfo, NAMESPACES
} from '../../../src/router.js'

const NPUB = 'npub1sn0wdenkukak0d9dfczzeacvhkrgz92ak56egt7vdgzn8pv2wfqqhrjdv9'

test('the `nostr` scheme has its own namespace and an honest verification story', () => {
  assert.equal(namespaceForScheme('nostr'), NAMESPACES.NOSTR)
  const row = schemeInfo('nostr')
  // 'partial', not 'live': the object is verified, the ANSWER is not.
  assert.equal(row.status, 'partial')
  assert.match(row.verify, /schnorr signature/)
  assert.match(row.verify, /completeness NOT proven/)
})

test('an explicit nostr: URI is routed to nostr and is never re-sniffed', () => {
  for (const input of [`nostr:${NPUB}`, `nostr://${NPUB}`, 'nostr:note1garbage']) {
    const out = classify(input)
    assert.equal(out.namespace, NAMESPACES.NOSTR, input)
    assert.equal(out.explicit, true)
    assert.equal(out.url, input, 'an explicit scheme is passed through untouched')
    assert.equal(out.reason, 'explicit-scheme')
  }
})

test('L2: a nostr identifier that cannot resolve does not become a DNS lookup', () => {
  // The classifier has exactly one outcome per input. There is no second
  // guess, and no code path that turns a `nostr:` failure into an `hns://` or
  // `https://` attempt — the handler's own 404/502 is the whole answer.
  const out = classify(`nostr:${NPUB}`)
  assert.equal(out.scheme, 'nostr')
  assert.notEqual(out.namespace, NAMESPACES.HNS)
  assert.notEqual(out.namespace, NAMESPACES.ICANN)
})

test('DOCUMENTED GAP (NO-1): a BARE NIP-19 identifier is not classified as Nostr', () => {
  // `nip19.js` accepts a bare `npub1…` (`parseNostrURI` strips an optional
  // `nostr:`), and every other self-describing address form in this browser
  // is recognised bare: a `.eth` name goes to ENS, a 56-character v3 address
  // goes to Tor, a `/ipfs/<cid>` path goes to IPFS. A pasted npub does not.
  //
  // It is a single label with no dot, so `classifyHost` returns null and the
  // bare-label rule sends it to Handshake as the name `npub1sn0w…`, which is
  // a chain lookup for a name nobody owns. See DEVIATIONS.md NO-1 and NO-D2.
  //
  // This test asserts what the code does today. The day the classifier row
  // lands it fails, which is the point: a gap nobody's test would notice is a
  // gap that gets quietly reintroduced.
  assert.equal(classifyHost(NPUB), null, 'one label, so the caller decides')
  const out = classify(NPUB)
  assert.equal(out.namespace, NAMESPACES.HNS,
    'TODAY: a pasted npub is looked up on the Handshake chain')
  assert.equal(out.reason, 'hns-bare-label')
})

test('DOCUMENTED GAP (NO-1): a NIP-05 address is not classified as Nostr either', () => {
  // `alice@example.com` is genuinely ambiguous — it is the Mastodon shape AND
  // the NIP-05 shape — and the browser's own `social-model.js` says so
  // (`kind: 'fediverse-or-nip05'`). The omnibox classifier has no row for it
  // at all, so it is neither.
  const out = classify('alice@example.com')
  assert.notEqual(out.namespace, NAMESPACES.NOSTR)
})

test('a bare `.hns.one` NIP-05 host stays an ICANN name, which is what serves it', () => {
  // `_@alice.w3.hns.one` is deliberately an ICANN-resolvable address: the
  // whole point is that a Damus user with no Handshake client can verify it.
  assert.equal(classifyHost('alice.w3.hns.one'), NAMESPACES.ICANN)
})
