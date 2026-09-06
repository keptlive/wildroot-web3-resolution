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

test('a BARE NIP-19 identifier is a Nostr address — decoded before it is claimed, an nsec included', () => {
  // A pasted npub is self-describing: the human-readable part is the type and
  // the checksum makes a false positive a one-in-a-billion event, so the
  // classifier decodes it before claiming it. An nsec is routed too, on
  // purpose: the handler answers with the PRIVATE KEY page, where the
  // bare-label rule would have sent the secret to a resolver as a name.
  assert.equal(classifyHost(NPUB), null, 'one label: the host classifier defers to classify()')
  const out = classify(NPUB)
  assert.equal(out.namespace, NAMESPACES.NOSTR)
  assert.equal(out.reason, 'nip19-identifier')
  assert.equal(out.url, `nostr:${NPUB}`)
  // A Handshake name that merely starts with npub is still a name.
  assert.equal(classify('npub1shop').namespace, NAMESPACES.HNS)
  assert.equal(classify('npub1' + 'q'.repeat(58)).namespace, NAMESPACES.HNS)
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
