/*
 * The scheme registry and the dispatcher (Part II §4, §5).
 *
 * The top-level tests/router.test.js proves the L1/L2 dispatch invariants. This
 * file proves the registry's own rules — the ones that make the table an
 * anti-drift device rather than documentation:
 *
 *   - a scheme cannot be wired in without a namespace and a verification story;
 *   - a double registration is a wiring bug and throws;
 *   - every one of the four dispatch outcomes stays inside its own namespace;
 *   - the alias and non-navigable markers mean what SPEC §4 says they mean.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import {
  ProtocolRouter,
  SCHEME_TABLE,
  NAMESPACES,
  namespaceForScheme,
  schemeInfo,
  classify
} from '../../../src/router.js'

const noop = () => new Response('ok')

// --- the table --------------------------------------------------------------

test('every row carries a declared namespace, an honest status and a verification story', () => {
  const declared = new Set(Object.values(NAMESPACES))
  for (const row of SCHEME_TABLE) {
    assert.ok(declared.has(row.namespace), `${row.scheme}: namespace is declared`)
    assert.ok(['live', 'partial', 'planned'].includes(row.status), `${row.scheme}: status`)
    assert.equal(typeof row.verify, 'string', `${row.scheme}: names its verification layer`)
    assert.ok(row.verify.length > 0, `${row.scheme}: the verification story is not empty`)
    assert.equal(namespaceForScheme(row.scheme), row.namespace, row.scheme)
    assert.equal(schemeInfo(row.scheme), row, row.scheme)
  }
})

test('the verification story names what is actually checked, and no more', () => {
  // The row is the anti-drift device (§4.1): it is what the trust model is held
  // to in namespace-trust.test.js, so an over-claim here becomes an over-claim
  // in the padlock. These are the rows where the honest answer is the
  // surprising one.
  assert.match(schemeInfo('ar').verify, /shape only.*gateway-trusted/,
    'ar: the bytes are never checked against the transaction')
  assert.equal(schemeInfo('ar').status, 'partial')
  assert.match(schemeInfo('ens').verify, /RPC-trusted, not chain-proven.*never green/,
    'ens: TRUSTED, and never the trustless lock')
  assert.match(schemeInfo('gemini').verify, /^none — TLS with no certificate verification/,
    'gemini: not TOFU — nothing is pinned or remembered')
  assert.match(schemeInfo('gemini').verify, /not TOFU/)
  assert.match(schemeInfo('pubsub').verify, /libp2p publisher signature/,
    'pubsub: a topic is not a content address')
  assert.match(schemeInfo('did').verify, /id checked; not proven/,
    'did: fetched, not proven')
  assert.match(schemeInfo('hyper').verify, /DNSLink name.*resolver-trusted/,
    'hyper: the key verifies itself, a DNSLink name does not')
  assert.match(schemeInfo('nostr').verify, /relay completeness NOT proven/)
  assert.match(schemeInfo('onion').verify, /NEVER DNS/)
})

test('scheme lookup is case-insensitive and total', () => {
  assert.equal(namespaceForScheme('HNS'), NAMESPACES.HNS)
  assert.equal(namespaceForScheme('Ipfs'), NAMESPACES.IPFS)
  assert.equal(namespaceForScheme('nope'), null)
  assert.equal(namespaceForScheme(''), null)
  assert.equal(namespaceForScheme(null), null)
  assert.equal(schemeInfo(undefined), null)
})

test('no scheme is registered twice, and every namespace with a scheme is reachable', () => {
  const seen = new Set()
  for (const row of SCHEME_TABLE) {
    assert.equal(seen.has(row.scheme), false, `${row.scheme} appears once`)
    seen.add(row.scheme)
  }
  // Several schemes may share a namespace (ipfs/ipns/ipld/pubsub), which is the
  // point: L2 is enforced at namespace boundaries, not scheme boundaries.
  const perNamespace = new Map()
  for (const row of SCHEME_TABLE) {
    perNamespace.set(row.namespace, (perNamespace.get(row.namespace) || 0) + 1)
  }
  assert.equal(perNamespace.get(NAMESPACES.IPFS), 4)
  assert.equal(perNamespace.get(NAMESPACES.BITTORRENT), 2)
  assert.equal(perNamespace.get(NAMESPACES.WEB), 3)
})

test('RT-5: the icann namespace is declared, used by the classifier, and has no scheme', () => {
  // Recorded as an open deviation, not a guarantee: a classification and a
  // dispatch answer with two different vocabularies for the same page. The
  // marker speaks the SCHEME TABLE's vocabulary — an ICANN navigation is an
  // `https://` URL and so carries `web` — and §4.3 says so in as many words.
  const withRows = new Set(SCHEME_TABLE.map((row) => row.namespace))
  const declared = new Set(Object.values(NAMESPACES))
  const orphans = [...declared].filter((ns) => !withRows.has(ns))
  assert.deepEqual(orphans, [NAMESPACES.ICANN])
  assert.equal(classify('example.com').namespace, NAMESPACES.ICANN)
  assert.equal(namespaceForScheme(classify('example.com').scheme), NAMESPACES.WEB)
})

test('aliases name their canonical scheme and share its namespace', () => {
  const aliases = SCHEME_TABLE.filter((row) => row.aliasOf)
  assert.deepEqual(aliases.map((row) => row.scheme), ['agregore', 'browser'])
  for (const row of aliases) {
    assert.equal(row.aliasOf, 'wildroot')
    assert.equal(row.namespace, namespaceForScheme(row.aliasOf))
  }
})

test('a scheme marked not navigable is an origin, never a link target', () => {
  const notLinks = SCHEME_TABLE.filter((row) => row.navigable === false).map((row) => row.scheme)
  assert.deepEqual(notLinks, ['media', 'docview'])
  // Everything else is navigable by omission — the marker is opt-out, so a new
  // scheme is a link target unless somebody says otherwise.
  for (const row of SCHEME_TABLE) {
    assert.ok(row.navigable === undefined || row.navigable === false, row.scheme)
  }
})

test('web3:// and the .w3 Handshake TLD are not conflated', () => {
  assert.equal(namespaceForScheme('web3'), NAMESPACES.WEB3)
  assert.equal(namespaceForScheme('w3'), null, 'RT-9: the w3:// short form is not offered')
  assert.equal(classify('proof.w3').namespace, NAMESPACES.HNS)
  assert.equal(classify('web3://0xabc/').namespace, NAMESPACES.WEB3)
})

// --- registration -----------------------------------------------------------

test('register() refuses a scheme with no table row', () => {
  const router = new ProtocolRouter()
  assert.throws(() => router.register('mystery', noop), /no SCHEME_TABLE row/)
  // ...unless the caller supplies BOTH a namespace and a status explicitly,
  // which is the escape hatch a test needs and a handler must not use.
  router.register('mystery', noop, { namespace: 'test-ns', status: 'planned' })
  assert.equal(router.has('mystery'), true)
})

test('register() refuses a double registration unless overridden', () => {
  const router = new ProtocolRouter()
  router.register('hns', noop)
  assert.throws(() => router.register('hns', noop), /already registered/)
  router.register('hns', () => new Response('v2'), { override: true })
  assert.equal(router.has('hns'), true)
})

test('register() refuses a handler that is not a function', () => {
  const router = new ProtocolRouter()
  assert.throws(() => router.register('hns', null), /handler must be a function/)
  assert.throws(() => router.register('hns', 'nope'), /handler must be a function/)
})

test('register() takes a list, lowercases, and reports what it holds', () => {
  const router = new ProtocolRouter()
  router.register(['ipfs', 'IPNS', 'ipld'], noop)
  assert.deepEqual(router.registeredSchemes(), ['ipfs', 'ipld', 'ipns'])
  assert.equal(router.has('IPFS'), true)
  assert.equal(typeof router.handlerFor('ipns'), 'function')
  assert.equal(router.handlerFor('nope'), null)
})

// --- dispatch ---------------------------------------------------------------

test('dispatch has exactly four outcomes, and none crosses a namespace', async () => {
  const hit = []
  const router = new ProtocolRouter()
  router.register('hns', (req) => { hit.push('hns'); return new Response('page') })
  router.register('ipfs', () => { hit.push('ipfs'); return new Response('gone', { status: 404 }) })
  router.register('ens', () => { hit.push('ens'); throw new Error('RPC down') })
  // Registered so that a fallback, if one existed, would have somewhere to go.
  router.register('https', () => { hit.push('https'); return new Response('leaked!') })

  // 1. the handler answers
  const ok = await router.dispatch(new Request('hns://pinner/'))
  assert.equal(ok.status, 200)
  assert.equal(await ok.text(), 'page')

  // 2. the handler answers with a failure — returned VERBATIM, not retried
  const missing = await router.dispatch(new Request('ipfs://bafygone/'))
  assert.equal(missing.status, 404)
  assert.equal(await missing.text(), 'gone')

  // 3. the handler throws — 502 tagged with THIS scheme's namespace
  const threw = await router.dispatch(new Request('ens://vitalik.eth/'))
  assert.equal(threw.status, 502)
  assert.equal(threw.headers.get('X-Resolution-Namespace'), NAMESPACES.ENS)
  assert.match(await threw.text(), /ens: RPC down/)

  // 4. no handler — 501 as ITSELF
  const none = await router.dispatch(new Request('nostr://npub1xyz'))
  assert.equal(none.status, 501)
  assert.equal(none.headers.get('X-Resolution-Namespace'), NAMESPACES.NOSTR)
  assert.match(await none.text(), /will not guess a different protocol/)

  assert.deepEqual(hit, ['hns', 'ipfs', 'ens'], 'the https handler was never consulted')
})

test('an unregistered scheme with no table row is tagged with the scheme itself', async () => {
  const res = await new ProtocolRouter().dispatch(new Request('foobar://x'))
  assert.equal(res.status, 501)
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'foobar')
})

test('the scheme is read from the URL and nothing else', async () => {
  const hit = []
  const router = new ProtocolRouter()
  router.register('ipfs', () => { hit.push('ipfs'); return new Response('') })
  router.register('ens', () => { hit.push('ens'); return new Response('') })
  router.register('hns', () => { hit.push('hns'); return new Response('') })
  // Hosts that look like another namespace must not move the request.
  await router.dispatch(new Request('ipfs://vitalik.eth/'))
  await router.dispatch(new Request('HNS://EXAMPLE.COM/'))
  assert.deepEqual(hit, ['ipfs', 'hns'])
})

test('RT-12: an unparseable URL that names no scheme is a 400 with NO namespace marker', async () => {
  // Reachable only from a caller that is not a WHATWG Request — the runtime
  // and this test. Correct that it carries no marker: no scheme was
  // established, so there is no namespace to claim it stayed in.
  const res = await new ProtocolRouter().dispatch({ url: 'not a url' })
  assert.equal(res.status, 400)
  assert.equal(res.headers.get('X-Resolution-Namespace'), null)
  assert.match(await res.text(), /not a valid URL/)
  assert.throws(() => new Request('not a url'), /Invalid URL|Failed to parse/)
})

test('an unparseable URL that DOES name a scheme keeps its namespace', async () => {
  // The scheme is read by prefix when the WHATWG parse fails, so a named
  // protocol's failure is reported as that protocol's — the reporting half of
  // L2. Without it the commonest AT-URI spelling has no namespace at all.
  const hit = []
  const router = new ProtocolRouter()
  router.register('at', () => { hit.push('at'); return new Response('handled', { status: 501 }) })
  const routed = await router.dispatch({ url: 'at://did:plc:abc/app.bsky.feed.post/1' })
  assert.equal(routed.status, 501)
  assert.deepEqual(hit, ['at'])
  // ...and with no handler registered it is still tagged, not orphaned.
  const unregistered = await new ProtocolRouter().dispatch({ url: 'at://did:plc:abc/x' })
  assert.equal(unregistered.status, 501)
  assert.equal(unregistered.headers.get('X-Resolution-Namespace'), NAMESPACES.ATPROTO)
  // A handler that throws on such a URL is a 502 in its own namespace too.
  const angry = new ProtocolRouter()
  angry.register('at', () => { throw new Error('unsupported AT-URI') })
  const threw = await angry.dispatch({ url: 'at://did:plc:abc/x' })
  assert.equal(threw.status, 502)
  assert.equal(threw.headers.get('X-Resolution-Namespace'), NAMESPACES.ATPROTO)
})

test('every routed failure is plain text the user can read', async () => {
  const router = new ProtocolRouter()
  router.register('hns', () => { throw new Error('SERVFAIL') })
  for (const url of ['hns://dead.14898/', 'gemini://nowhere/']) {
    const res = await router.dispatch(new Request(url))
    assert.match(res.headers.get('content-type'), /^text\/plain/)
  }
})
