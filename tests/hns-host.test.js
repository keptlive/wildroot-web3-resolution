import { test } from 'node:test'
import assert from 'node:assert/strict'

import { isHnsHost, rewriteToHns, reservedNamespaceScheme, isReservedHost } from '../src/hns-host.js'

// A small TLD set so the tests do not depend on the bundled IANA snapshot.
const TLDS = new Set(['com', 'org', 'one', 'io', 'blog', 'xn--p1ai'])

test('isHnsHost: handshake hosts, single labels and numeric TLDs included', () => {
  assert.equal(isHnsHost('nathan.woodburn', TLDS), true)
  assert.equal(isHnsHost('hnshosting', TLDS), true) // single label
  assert.equal(isHnsHost('proofofconcept', TLDS), true)
  assert.equal(isHnsHost('hello.14898', TLDS), true) // numeric TLD
  assert.equal(isHnsHost('d.yup.', TLDS), true) // trailing dot form
})

test('isHnsHost: ICANN domains, IPs and localhost refused', () => {
  assert.equal(isHnsHost('example.com', TLDS), false)
  assert.equal(isHnsHost('hns.one', TLDS), false)
  assert.equal(isHnsHost('shop.blog', TLDS), false)
  assert.equal(isHnsHost('localhost', TLDS), false)
  assert.equal(isHnsHost('192.168.1.1', TLDS), false)
  assert.equal(isHnsHost('[::1]', TLDS), false)
  assert.equal(isHnsHost('', TLDS), false)
  assert.equal(isHnsHost(null, TLDS), false)
})

test('isHnsHost: IDN hosts are punycoded before the TLD lookup', () => {
  // президент.рф — real Russian ccTLD (xn--p1ai) must NOT be hijacked
  assert.equal(isHnsHost('президент.рф', TLDS), false)
  // unicode TLD that is not in the ICANN set -> handshake
  assert.equal(isHnsHost('site.🤝', TLDS), true)
})

test('rewriteToHns: http(s) on handshake hosts maps, everything else null', () => {
  assert.equal(rewriteToHns('http://nathan.woodburn/', TLDS), 'hns://nathan.woodburn/')
  assert.equal(
    rewriteToHns('https://setup.skyinclude/guide?x=1#top', TLDS),
    'hns://setup.skyinclude/guide?x=1#top')
  assert.equal(rewriteToHns('http://hnshosting:8080/a', TLDS), 'hns://hnshosting:8080/a')
  assert.equal(rewriteToHns('https://example.com/', TLDS), null)
  assert.equal(rewriteToHns('https://hns.one/downloads/', TLDS), null)
  assert.equal(rewriteToHns('hns://already/', TLDS), null)
  assert.equal(rewriteToHns('wildroot://settings', TLDS), null)
  assert.equal(rewriteToHns('not a url', TLDS), null)
  assert.equal(rewriteToHns('http://192.168.1.1/admin', TLDS), null)
  assert.equal(rewriteToHns('http://localhost:8010/', TLDS), null)
})

test('rewriteToHns: uses the real bundled ICANN list by default', () => {
  assert.equal(rewriteToHns('http://nathan.woodburn/'), 'hns://nathan.woodburn/')
  assert.equal(rewriteToHns('https://github.com/x'), null)
})

// ---- namespace-reserved TLDs (LAW L2) --------------------------------------
// .eth and .onion are not in the ICANN root, so before the guard a literal
// http:// link on either was rewritten to hns:// — an ENS hijack and a Tor
// deanonymising DNS leak respectively. They must route into their OWN schemes,
// whose handlers fail closed without touching the network.

test('isHnsHost: .eth and .onion are never Handshake hosts', () => {
  assert.equal(isHnsHost('vitalik.eth', TLDS), false)
  assert.equal(isHnsHost('sub.vitalik.eth', TLDS), false)
  assert.equal(isHnsHost('VITALIK.ETH', TLDS), false)
  assert.equal(isHnsHost('vitalik.eth.', TLDS), false) // trailing dot form
  const v3 = 'a'.repeat(56)
  assert.equal(isHnsHost(`${v3}.onion`, TLDS), false)
  assert.equal(isHnsHost('malformed.onion', TLDS), false) // malformed too
})

test('reservedNamespaceScheme: classifies eth/onion, null otherwise', () => {
  assert.equal(reservedNamespaceScheme('vitalik.eth'), 'ens')
  assert.equal(reservedNamespaceScheme('x.onion'), 'onion')
  assert.equal(reservedNamespaceScheme('nathan.woodburn'), null)
  assert.equal(reservedNamespaceScheme('example.com'), null)
  assert.equal(reservedNamespaceScheme(''), null)
  assert.equal(reservedNamespaceScheme(null), null)
})

test('rewriteToHns: .eth and .onion rewrite into their own fail-closed schemes', () => {
  assert.equal(
    rewriteToHns('http://vitalik.eth/', TLDS),
    'ens://vitalik.eth/')
  assert.equal(
    rewriteToHns('https://vitalik.eth/page?x=1#top', TLDS),
    'ens://vitalik.eth/page?x=1#top')
  const v3 = 'a'.repeat(56)
  assert.equal(
    rewriteToHns(`http://${v3}.onion/`, TLDS),
    `onion://${v3}.onion/`)
  // A malformed onion host must stay in the tor namespace: a typo'd onion in
  // a DNS query leaks exactly as effectively as a valid one.
  assert.equal(
    rewriteToHns('http://typod.onion/x', TLDS),
    'onion://typod.onion/x')
  // Ports are preserved like the hns:// path preserves them.
  assert.equal(
    rewriteToHns('http://vitalik.eth:8080/a', TLDS),
    'ens://vitalik.eth:8080/a')
})

// ─────────────────── names the network reserves are never Handshake names
//
// THE BUG THESE PIN (found 2026-08-31). The classifier calls any final label
// absent from the bundled ICANN snapshot a Handshake name, and only the exact
// string `localhost` was exempt. So `nas.local`, `printer.lan`,
// `gitlab.internal` and `app.localhost` were all rewritten to hns://.
//
// Two harms, and the second is the serious one: the user cannot reach their
// own NAS, printer or dev server — and the private hostname is sent to a
// Handshake resolver, so whoever registers the TLD `local` receives queries
// for the user's internal machines and can serve content at what looks like
// their own device's address.

test('a home network device is not a Handshake name', () => {
  for (const host of ['nas.local', 'homeassistant.local', 'printer.lan', 'router.home',
    'gitlab.internal', 'app.localhost', 'localhost', 'files.corp', 'db.private']) {
    assert.equal(isHnsHost(host), false, `${host} is local, not Handshake`)
    assert.equal(isReservedHost(host), true)
  }
})

test('reserved-by-RFC names are not Handshake names either', () => {
  for (const host of ['anything.invalid', 'a.test', 'b.example', 'x.onion', 'home.arpa']) {
    assert.equal(isHnsHost(host), false, `${host} is reserved`)
  }
})

test('a local address is left alone instead of being rewritten', () => {
  for (const url of ['http://nas.local:5000/', 'http://homeassistant.local:8123/lovelace',
    'https://gitlab.internal/dashboard', 'http://app.localhost:3000/']) {
    assert.equal(rewriteToHns(url), null, `${url} keeps its own scheme`)
  }
})

test('real Handshake names still route', () => {
  // The fix must not cost the feature it guards.
  assert.equal(rewriteToHns('https://matt.w3/'), 'hns://matt.w3/')
  assert.equal(rewriteToHns('https://someone.pxls/x?y=1'), 'hns://someone.pxls/x?y=1')
  assert.equal(isHnsHost('matt.w3'), true)
  assert.equal(rewriteToHns('https://example.com/'), null, 'and ICANN names are untouched')
})
