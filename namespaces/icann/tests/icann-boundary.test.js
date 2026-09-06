/*
 * The ICANN/Handshake boundary: which names leave this machine as ordinary DNS
 * lookups, and which never may.
 *
 * Every assertion here is about SPEC §2 (ICANN first), §3 (the collision
 * policy) and §4 (special-use names). The failures they guard against are not
 * cosmetic:
 *
 *   - an ICANN name classified as Handshake is a working site that reports
 *     itself as not existing;
 *   - a Handshake name classified as ICANN is a lookup disclosed to an ICANN
 *     resolver that can never answer it;
 *   - a special-use name (`nas.local`, `printer.lan`) classified as Handshake
 *     is the name of a machine on the user's own network, handed to whoever
 *     registers the Handshake top-level name `local`, who may then answer for
 *     it;
 *   - an IP literal classified as a name is a Handshake resolution started
 *     for an address the user typed in full.
 *
 * The classification order those last two depend on is asserted directly:
 * the reserved-name test and the IP-literal test both run BEFORE the label
 * count, and one list serves every path that classifies a host.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'

import { classify, classifyHost, NAMESPACES, isReservedHost as routerReserved } from '../../../src/router.js'
import { isHnsHost, isReservedHost, rewriteToHns } from '../../../src/hns-host.js'

const require = createRequire(import.meta.url)
const ICANN_TLDS = require('../../../src/icann-tlds.cjs')

// --- SPEC §2: ICANN first ---------------------------------------------------

test('a delegated ICANN TLD is an ICANN name, and gets https://', () => {
  for (const name of ['example.com', 'bbc.co.uk', 'shop.blog', 'a.link', 'x.museum']) {
    assert.equal(classifyHost(name), NAMESPACES.ICANN, name)
    const c = classify(name)
    assert.equal(c.namespace, NAMESPACES.ICANN, name)
    assert.equal(c.scheme, 'https', name)
    assert.equal(c.reason, 'icann-tld', name)
  }
})

test('the comparison is case-insensitive and ignores the DNS root dot', () => {
  // RFC 4343: owner names compare case-insensitively. A trailing dot is the
  // root form of the same name, and must not change which namespace it is in.
  for (const name of ['EXAMPLE.COM', 'Example.Com', 'example.com.', 'EXAMPLE.COM.']) {
    assert.equal(classifyHost(name), NAMESPACES.ICANN, name)
  }
})

test('an internationalized host is compared as A-labels, not as Unicode', () => {
  // The set holds IANA's published punycode. `пример.рф` must match `xn--p1ai`
  // and be ICANN's; an emoji label matches nothing and is Handshake's.
  assert.equal(classifyHost('пример.рф'), NAMESPACES.ICANN)
  assert.ok(ICANN_TLDS.has('xn--p1ai'))
  assert.equal(classifyHost('hello.🤝'), NAMESPACES.HNS)
})

test('a bare ICANN TLD is a search, not a name', () => {
  // `com`, `org`, `app` are words somebody is part-way through typing. The
  // same list decides this as decides the dotted case.
  for (const word of ['com', 'org', 'app', 'blog']) {
    assert.equal(classify(word).namespace, NAMESPACES.SEARCH, word)
  }
  // …and a bare label that is NOT an ICANN TLD is a Handshake name.
  assert.equal(classify('hnshosting').namespace, NAMESPACES.HNS)
})

// --- SPEC §3: the collision policy ------------------------------------------

test('a label that is both an ICANN TLD and a Handshake TLD goes to ICANN', () => {
  // This is the whole collision policy, and it is decided by data, not by
  // code: membership of the snapshot wins. Handshake's own model reserves
  // ICANN labels and lets their holders claim them; a claimed one would make
  // the chain authoritative. We route to ICANN anyway: ../../DEVIATIONS.md
  // IC-2 here, D-16 in the top-level DEVIATIONS.md.
  //
  // Driven with an override so the test states the rule rather than depending
  // on which strings happen to be registered on either root today. The
  // override label is one no RFC reserves, because the reserved list is
  // consulted BEFORE the snapshot and would otherwise decide the case.
  const tlds = new Set(['delegated'])
  assert.equal(classifyHost('collision.delegated', tlds), NAMESPACES.ICANN)
  assert.equal(classifyHost('collision.notdelegated', tlds), NAMESPACES.HNS)
  // isHnsHost consumes the same override, and agrees.
  assert.equal(isHnsHost('collision.delegated', tlds), false)
  assert.equal(isHnsHost('collision.notdelegated', tlds), true)
})

test('a reserved label outranks BOTH roots, whatever the snapshot says', () => {
  // The ordering is the point: a name the network reserves is the user's own
  // device, so it is never a Handshake lookup and never an ICANN one either,
  // even if the label were delegated. RFC 6761 reserves `example` and `test`,
  // so an override claiming them changes nothing.
  const tlds = new Set(['local', 'example'])
  assert.equal(classifyHost('nas.local', tlds), NAMESPACES.WEB)
  assert.equal(classifyHost('x.example', tlds), NAMESPACES.WEB)
})

test('every other alt-root is Handshake, not its own registry', () => {
  // `.crypto`, `.sol`, `.bnb` are not delegated by IANA, so by the rule above
  // they belong to whoever holds the Handshake top-level name of that string.
  for (const name of ['brad.crypto', 'x.sol', 'y.bnb', 'z.nft']) {
    assert.equal(classifyHost(name), NAMESPACES.HNS, name)
  }
  // The two exceptions are namespaces with their own root of trust, matched
  // BEFORE the ICANN test so a failure can never fall through to DNS.
  assert.equal(classifyHost('vitalik.eth'), NAMESPACES.ENS)
  assert.equal(classifyHost('a'.repeat(56) + '.onion'), NAMESPACES.TOR)
})

test('ICANN has no all-numeric TLD, so a numeric final label is Handshake', () => {
  assert.equal(classifyHost('hello.14898'), NAMESPACES.HNS)
  assert.equal([...ICANN_TLDS].filter((t) => /^\d+$/.test(t)).length, 0)
})

// --- SPEC §4: special-use names are never ICANN and never Handshake ---------

test('special-use names are refused by the Handshake host test', () => {
  // RFC 6761 / 6762 / 7686 / 8375. Without this, every NAS, printer and
  // internal service name on the user's network is disclosed to whoever
  // registers the Handshake top-level name `local`.
  for (const name of [
    'nas.local', 'printer.lan', 'gitlab.internal', 'app.localhost',
    'x.home', 'x.corp', 'x.intranet', 'x.private', 'x.invalid', 'x.test',
    'x.example', 'x.arpa', 'localhost'
  ]) {
    assert.equal(isReservedHost(name), true, name)
    assert.equal(isHnsHost(name), false, name)
    assert.equal(rewriteToHns('http://' + name + '/'), null, name)
  }
})

test('there is ONE reserved-name list, and every path reads it', () => {
  // A list kept in two places is a list that disagrees with itself, and the
  // disagreement is a LAN disclosure. `../../../src/reserved-names.cjs` is the
  // file; the router's classifier reads it and `hns-host.js` re-exports the
  // router's own binding rather than keeping a copy.
  const reserved = require('../../../src/reserved-names.cjs')
  assert.equal(routerReserved, reserved.isReservedHost)
  assert.equal(isReservedHost, reserved.isReservedHost)
  for (const label of ['localhost', 'local', 'internal', 'home', 'lan', 'intranet',
    'corp', 'private', 'invalid', 'test', 'example', 'onion', 'arpa']) {
    assert.ok(reserved.NEVER_HNS_TLDS.has(label), label)
  }
})

test('the typed-input classifier consults the same list, and reaches the device', () => {
  // ONE list, every path. `classifyHost` reads `../../src/reserved-names.cjs`,
  // which is the file `isHnsHost` reads, so typed input, the http->hns
  // rewrite, the subresource guard and the certificate hook all agree that
  // `nas.local` is not a name we resolve.
  //
  // `web` and not `null`: the user meant their NAS, so the classifier produces
  // `http://nas.local` and lets the platform resolve it — the same treatment
  // bare `localhost` gets. Plain http, because a device on the LAN has no
  // public certificate.
  for (const name of ['nas.local', 'printer.lan', 'gitlab.internal', 'app.localhost']) {
    assert.equal(classifyHost(name), NAMESPACES.WEB, name)
    const c = classify(name)
    assert.equal(c.namespace, NAMESPACES.WEB, name)
    assert.equal(c.url, `http://${name}`, name)
    assert.equal(c.scheme, 'http', name)
    assert.equal(c.reason, 'reserved-host', name)
    assert.equal(isHnsHost(name), false, name)
  }
  // A bare reserved label is the same decision, and never a search.
  assert.equal(classify('localhost').url, 'http://localhost')
  assert.equal(classifyHost('invalid'), NAMESPACES.WEB)
})

// --- Address literals -------------------------------------------------------

test('an IPv4 literal is the web namespace, never a name', () => {
  for (const ip of ['1.2.3.4', '127.0.0.1', '192.168.1.1']) {
    assert.equal(classifyHost(ip), NAMESPACES.WEB, ip)
    assert.equal(classify(ip).scheme, 'https', ip)
    assert.equal(isHnsHost(ip), false, ip)
  }
})

test('an IPv6 literal is the web namespace too, bracketed or not', () => {
  // An IPv6 literal has no dots, so the IP-literal test has to run BEFORE the
  // label count or `[::1]` falls to the bare-label rule and starts a Handshake
  // resolution for an address the user typed in full.
  for (const ip of ['[::1]', '::1', '[2001:db8::1]', '2001:db8::1']) {
    assert.equal(classifyHost(ip), NAMESPACES.WEB, ip)
    assert.equal(classify(ip).namespace, NAMESPACES.WEB, ip)
    assert.equal(classify(ip).reason, 'ip-literal', ip)
    assert.equal(isHnsHost(ip), false, ip)
  }
  // A bracketed literal keeps its brackets and loses only its port, so the
  // host survives as something a URL can carry.
  assert.equal(classifyHost('[2001:db8::1]:8443'), NAMESPACES.WEB)
  assert.equal(rewriteToHns('http://[::1]/'), null)
})

// --- What ICANN names never touch -------------------------------------------

test('no ICANN name is ever rewritten into the Handshake pipeline', () => {
  // The testable form of "ICANN names get no DANE pin and no SSRF guard":
  // neither mechanism exists outside the hns:// handler, and an ICANN host
  // never enters it. `rewriteToHns` is the only door — used by the navigation
  // entry points AND by the subresource guard — and it returns null here.
  for (const url of [
    'http://example.com/', 'https://example.com/a?b=c#d',
    'https://sub.bbc.co.uk:8443/x', 'http://xn--p1ai.xn--p1ai/'
  ]) {
    assert.equal(rewriteToHns(url), null, url)
  }
  // A Handshake host, by contrast, is rewritten scheme and all.
  assert.equal(rewriteToHns('http://nathan.woodburn/p?q=1'), 'hns://nathan.woodburn/p?q=1')
})

test('a URL the host parser refuses is not rewritten at all', () => {
  // The numeric-TLD problem (the spine's D-4) reaches this path too:
  // `new URL('http://hello.14898/')` throws, because the WHATWG "ends in a
  // number" rule sends the host to the IPv4 parser. `rewriteToHns` catches
  // and returns null, so a literal http:// link to a numeric Handshake TLD is
  // left alone rather than rewritten. The typed-input path handles the same
  // name (via the `_` convention) — the two disagree on paper about an input
  // the engine cannot construct either. ../../DEVIATIONS.md IC-14.
  assert.equal(isHnsHost('hello.14898'), true)
  assert.equal(rewriteToHns('http://hello.14898/'), null)
  assert.equal(classify('hello.14898').url, 'hns://hello._14898/')
})
