// The router's rows for the key-addressed namespaces, and the two laws that
// decide what happens to an address before any engine sees it.
//
// `src/router.js` at the root of this package is the browser's classifier and
// registry, byte-identical to `src/protocols/router.js` in the Wildroot tree.
// It is the source of the `verify` claims this section's SPEC quotes, so those
// claims are asserted here rather than paraphrased.
//
// Adapted from tests/hns/router.test.js and tests/hns/nav-scheme-coverage.test.js.
// The assertions that read src/window.js off disk were dropped with the rest of
// the browser wiring.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  ProtocolRouter, SCHEME_TABLE, NAMESPACES, namespaceForScheme, schemeInfo,
  classify, hasExplicitScheme, schemeOf
} from '../../../src/router.js'

const KEY_SCHEMES = ['gemini', 'hyper', 'ssb', 'bittorrent', 'bt', 'magnet']

test('every key-addressed scheme has a row, a namespace and a verification story', () => {
  for (const scheme of KEY_SCHEMES) {
    const row = schemeInfo(scheme)
    assert.ok(row, `no SCHEME_TABLE row for "${scheme}"`)
    assert.ok(row.verify, `"${scheme}" has no verify string`)
    assert.equal(row.status, 'live')
    assert.notEqual(row.navigable, false, `"${scheme}" must be a link target`)
  }
})

test('the verify strings are exactly what SPEC quotes', () => {
  // Quoted verbatim so that a change to the router is a red test here, not a
  // silently stale specification. Each names the layer that authenticates the
  // object and NOTHING ELSE: gemini names none, and hyper names the one hop
  // inside it that a resolver is trusted for.
  assert.equal(schemeInfo('gemini').verify,
    'none — TLS with no certificate verification (not TOFU: nothing is pinned)')
  assert.equal(schemeInfo('hyper').verify,
    'hypercore key (a DNSLink name→key binding is resolver-trusted)')
  assert.equal(schemeInfo('ssb').verify, 'feed signature')
  assert.equal(schemeInfo('bittorrent').verify, 'infohash')
  assert.equal(schemeInfo('bt').verify, 'infohash')
  assert.equal(schemeInfo('magnet').verify, 'infohash')
})

test('no verify string CLAIMS a verification the code does not perform', () => {
  // The half of trust-on-first-use that matters is REMEMBERING the key. No
  // certificate is stored and none is compared, so `gemini` may not be sold as
  // TOFU: its row leads with `none` and mentions TOFU only to deny it (KY-1).
  assert.ok(schemeInfo('gemini').verify.startsWith('none'))
  assert.match(schemeInfo('gemini').verify, /not TOFU/)
  // Every other row names a layer that really authenticates the object, and
  // none of the rest mentions certificates at all.
  for (const scheme of KEY_SCHEMES.filter((s) => s !== 'gemini')) {
    assert.doesNotMatch(schemeInfo(scheme).verify, /TOFU|certificate/i, scheme)
  }
})

test('bittorrent and bt are ONE namespace; magnet is its own', () => {
  assert.equal(namespaceForScheme('bittorrent'), NAMESPACES.BITTORRENT)
  assert.equal(namespaceForScheme('bt'), NAMESPACES.BITTORRENT)
  // magnet: is a separate namespace even though it only ever 308s into
  // bittorrent://. That is deliberate — the redirect is an answer, not a
  // fallback — but it does mean a magnet failure is tagged `magnet`, not
  // `bittorrent`. DEVIATIONS.md KY-5.
  assert.equal(namespaceForScheme('magnet'), NAMESPACES.MAGNET)
  assert.notEqual(NAMESPACES.MAGNET, NAMESPACES.BITTORRENT)
})

test('no `web+…` scheme is registered, and one cannot be registered by accident', () => {
  // The prompt for this section asks about `web+…` and other registered
  // schemes. There are none: the table has no `web+` row, and register()
  // refuses a scheme without one.
  assert.deepEqual(SCHEME_TABLE.filter((r) => r.scheme.startsWith('web+')), [])
  assert.equal(namespaceForScheme('web+torrent'), null)
  assert.throws(
    () => new ProtocolRouter().register('web+torrent', () => new Response('')),
    /no SCHEME_TABLE row/)
})

// --- L1: an explicit scheme is authoritative --------------------------------

test('an explicit key-addressed scheme is routed to itself, never reclassified', () => {
  for (const [input, scheme, namespace] of [
    [`bittorrent://${'a'.repeat(40)}/`, 'bittorrent', NAMESPACES.BITTORRENT],
    [`bt://${'a'.repeat(40)}/`, 'bt', NAMESPACES.BITTORRENT],
    ['magnet:?xt=urn:btih:' + 'a'.repeat(40), 'magnet', NAMESPACES.MAGNET],
    ['hyper://blog.mauve.moe/', 'hyper', NAMESPACES.HYPER],
    ['ssb://feed/ed25519/abc', 'ssb', NAMESPACES.SSB],
    ['gemini://geminiprotocol.net/', 'gemini', NAMESPACES.GEMINI]
  ]) {
    const decision = classify(input)
    assert.equal(decision.explicit, true, input)
    assert.equal(decision.reason, 'explicit-scheme', input)
    assert.equal(decision.scheme, scheme, input)
    assert.equal(decision.namespace, namespace, input)
    assert.equal(decision.url, input, 'the URL is passed through unaltered')
  }
})

test('`magnet:?…` is recognised as a scheme, not as a host:port', () => {
  assert.equal(hasExplicitScheme('magnet:?xt=urn:btih:abc'), true)
  assert.equal(schemeOf('MAGNET:?xt=urn:btih:abc'), 'magnet')
  // The host:port guard only fires for a token this table does not know, so
  // `bt:8080` is the bt scheme, not the host "bt" on port 8080.
  assert.equal(schemeOf('bt:8080'), 'bt')
  assert.equal(hasExplicitScheme('example.com:8080/x'), false)
})

test('a bare key is NOT classified into any key-addressed namespace', () => {
  // Nothing about a 40-hex or 52-character string says "torrent" or
  // "hypercore" — the classifier has no rule for either, so a bare one is a
  // single label and goes to Handshake, exactly as `pinner` does. A key must
  // be typed with its scheme, arrive as a magnet link, or be named by a
  // Handshake `bt=`/`hyper=` pointer. Consequence, not a bug: SPEC §K.7.
  for (const bare of ['a'.repeat(40), 'd'.repeat(64), 'y'.repeat(52)]) {
    const decision = classify(bare)
    assert.equal(decision.explicit, false)
    assert.equal(decision.namespace, NAMESPACES.HNS)
  }
})

// --- L2: a failure never crosses a namespace boundary -----------------------

test('an unregistered key scheme fails closed IN its own namespace', async () => {
  const router = new ProtocolRouter()
  for (const scheme of KEY_SCHEMES) {
    const url = scheme === 'magnet'
      ? 'magnet:?xt=urn:btih:' + 'a'.repeat(40)
      : `${scheme}://${'a'.repeat(40)}/`
    const res = await router.dispatch(new Request(url))
    assert.equal(res.status, 501, url)
    assert.equal(res.headers.get('X-Resolution-Namespace'), namespaceForScheme(scheme), url)
    assert.match(await res.text(), /will not guess a different protocol/)
  }
})

test('a handler that throws is a 502 tagged with THAT namespace', async () => {
  const router = new ProtocolRouter()
  router.register(['bittorrent', 'bt'], () => { throw new Error('the torrent engine is not running') })
  const res = await router.dispatch(new Request(`bittorrent://${'a'.repeat(40)}/`))
  assert.equal(res.status, 502)
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'bittorrent')
  assert.match(await res.text(), /torrent engine is not running/)
})
