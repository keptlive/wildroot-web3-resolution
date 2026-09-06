/*
 * Resolution router & scheme registry (BR-1). Pure logic — no Electron, no
 * network — so it runs under plain `node --test`.
 *
 * Proves the two LAW invariants at the dispatch layer:
 *   L1  explicit scheme always routes to its own handler (never sniffed)
 *   L2  no input ever falls back across a namespace boundary
 * plus the input classifier for .onion, .eth, and bare-HNS.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  ProtocolRouter,
  classify,
  classifyHost,
  hasExplicitScheme,
  schemeOf,
  namespaceForScheme,
  isValidV3Onion,
  NAMESPACES,
  SCHEME_TABLE
} from '../src/router.js'

const VALID_ONION = 'p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion'

function ok (status = 200, tag = 'ok') {
  return () => new Response(tag, { status })
}

// --- L1: explicit scheme always wins ---------------------------------------

test('L1: dispatch routes strictly by the explicit scheme', async () => {
  const seen = []
  const router = new ProtocolRouter()
  router.register('ipfs', (req) => { seen.push('ipfs'); return new Response('ipfs') })
  router.register('hns', (req) => { seen.push('hns'); return new Response('hns') })
  router.register('web3', (req) => { seen.push('web3'); return new Response('web3') })

  for (const [url, expect] of [
    ['ipfs://bafyfoo/', 'ipfs'],
    ['hns://hello.14898/', 'hns'],
    ['web3://0xabc/', 'web3']
  ]) {
    seen.length = 0
    const res = await router.dispatch(new Request(url))
    assert.equal(res.status, 200)
    assert.equal(await res.text(), expect)
    assert.deepEqual(seen, [expect], `${url} hit exactly its own handler`)
  }
})

test('L1: an explicit scheme is NOT re-sniffed from a misleading host', async () => {
  // ipfs://vitalik.eth must go to IPFS, never ENS. at://foo.14898 must go to
  // atproto, never HNS. The host looking like another namespace is irrelevant.
  const hit = []
  const router = new ProtocolRouter()
  router.register('ipfs', () => { hit.push('ipfs'); return new Response('') })
  router.register('ens', () => { hit.push('ens'); return new Response('') })
  router.register('at', () => { hit.push('at'); return new Response('') })
  router.register('hns', () => { hit.push('hns'); return new Response('') })

  await router.dispatch(new Request('ipfs://vitalik.eth/'))
  await router.dispatch(new Request('at://foo.14898/'))
  assert.deepEqual(hit, ['ipfs', 'at'])
})

test('L1: classify() defers entirely to an explicit scheme', () => {
  // The classifier must not "improve" a scheme the user typed.
  const c1 = classify('ipfs://vitalik.eth/')
  assert.equal(c1.explicit, true)
  assert.equal(c1.scheme, 'ipfs')
  assert.equal(c1.namespace, NAMESPACES.IPFS)
  assert.equal(c1.url, 'ipfs://vitalik.eth/')

  // Even an onion under an explicit non-tor scheme stays on that scheme.
  const c2 = classify(`https://${VALID_ONION}/`)
  assert.equal(c2.scheme, 'https')
  assert.equal(c2.explicit, true)

  // An unknown scheme is preserved as itself (dispatch will fail closed).
  const c3 = classify('foobar://whatever')
  assert.equal(c3.explicit, true)
  assert.equal(c3.scheme, 'foobar')
  assert.equal(c3.namespace, null)
})

test('hasExplicitScheme / schemeOf distinguish scheme from host:port', () => {
  assert.equal(hasExplicitScheme('ipfs://x'), true)
  assert.equal(hasExplicitScheme('did:plc:abc'), true)
  assert.equal(hasExplicitScheme('magnet:?xt=urn:btih:abc'), true)
  assert.equal(schemeOf('web3://0xabc'), 'web3')
  // host:port is NOT an explicit scheme
  assert.equal(hasExplicitScheme('example.com:8080'), false)
  assert.equal(hasExplicitScheme('localhost:3000'), false)
  assert.equal(schemeOf('example.com:8080/path'), null)
})

// --- L2: no cross-namespace fallback ---------------------------------------

test('L2: a handler failure surfaces in-namespace and never re-dispatches', async () => {
  const hit = []
  const router = new ProtocolRouter()
  // hns handler "fails" the way a SERVFAIL would; ICANN handler must NEVER run.
  router.register('hns', () => { hit.push('hns'); throw new Error('SERVFAIL') })
  router.register('https', () => { hit.push('https'); return new Response('leaked!') })

  const res = await router.dispatch(new Request('hns://dead.14898/'))
  assert.equal(res.status, 502)
  assert.deepEqual(hit, ['hns'], 'only the hns handler ran — no ICANN fallback')
  // The failure is tagged with the HNS namespace, proving it stayed put.
  assert.equal(res.headers.get('X-Resolution-Namespace'), NAMESPACES.HNS)
  assert.match(await res.text(), /hns: SERVFAIL/)
})

test('L2: an unregistered scheme fails closed, never reinterpreted', async () => {
  const hit = []
  const router = new ProtocolRouter()
  // Only https is registered. A nostr:// with no handler must 501 as nostr —
  // it must NOT be re-read as a bare host / ICANN name / search.
  router.register('https', () => { hit.push('https'); return new Response('') })

  const res = await router.dispatch(new Request('nostr://npub1xyz'))
  assert.equal(res.status, 501)
  assert.deepEqual(hit, [], 'no other handler was consulted')
  assert.equal(res.headers.get('X-Resolution-Namespace'), NAMESPACES.NOSTR)
})

test('L2: a handler returning 404 is returned as-is, not retried elsewhere', async () => {
  const hit = []
  const router = new ProtocolRouter()
  router.register('hns', () => { hit.push('hns'); return new Response('nope', { status: 404 }) })
  router.register('https', () => { hit.push('https'); return new Response('') })

  const res = await router.dispatch(new Request('hns://gone.14898/'))
  assert.equal(res.status, 404)
  assert.deepEqual(hit, ['hns'])
})

// --- Classifier: .onion -----------------------------------------------------

test('.onion classifies to Tor and NEVER to DNS/ICANN', () => {
  assert.equal(classifyHost(VALID_ONION), NAMESPACES.TOR)
  const c = classify(VALID_ONION)
  assert.equal(c.namespace, NAMESPACES.TOR)
  assert.equal(c.scheme, 'onion')
  assert.equal(c.validV3, true)
  assert.equal(c.reason, 'onion-host')
})

test('a malformed .onion still stays in the Tor namespace (fails as Tor, not DNS)', () => {
  const bad = 'tooshort.onion'
  assert.equal(classifyHost(bad), NAMESPACES.TOR)
  const c = classify(bad)
  assert.equal(c.namespace, NAMESPACES.TOR)
  assert.equal(c.validV3, false)
})

// --- Classifier: .eth -------------------------------------------------------

test('.eth classifies to ENS, with no HNS/ICANN fallback', () => {
  assert.equal(classifyHost('vitalik.eth'), NAMESPACES.ENS)
  const c = classify('vitalik.eth')
  assert.equal(c.namespace, NAMESPACES.ENS)
  assert.equal(c.scheme, 'ens')
  assert.equal(c.url, 'ens://vitalik.eth')
  // subdomains too
  assert.equal(classifyHost('app.uniswap.eth'), NAMESPACES.ENS)
})

// --- Classifier: bare HNS vs ICANN vs search --------------------------------

test('bare HNS names classify to the HNS namespace', () => {
  // numeric TLD (14898), a non-ICANN word TLD, and the .w3 / .exist HNS TLDs.
  for (const name of ['hello.14898', 'nathan.woodburn', 'me.exist', 'proof.w3']) {
    assert.equal(classifyHost(name), NAMESPACES.HNS, name)
    assert.equal(classify(name).namespace, NAMESPACES.HNS, name)
  }
  // A numeric final label is an IPv4 address to the URL parser, so
  // `hns://hello.14898/` is not a URL Chromium will open at all. The name is
  // carried with the `_` marker no Handshake name can contain
  // (src/hns/hns-url.cjs); the handler strips it, the address bar hides it.
  assert.equal(classify('hello.14898').url, 'hns://hello._14898/')
  assert.equal(classify('14898/').url, 'hns://_14898/')
  // a word-TLD HNS name keeps the normalized trailing slash
  assert.equal(classify('nathan.woodburn').url, 'hns://nathan.woodburn/')
})

test('an emoji / non-ASCII single label is HNS, not search', () => {
  const c = classify('🤝')
  assert.equal(c.namespace, NAMESPACES.HNS)
  assert.match(c.url, /^hns:\/\//)
})

test('a bare word IS a Handshake name', () => {
  // Changed deliberately on 2026-09-04. A bare word used to be a search unless
  // it carried a trailing slash or dot; most Handshake sites ARE bare TLDs, and
  // a browser about names should not answer `pinner` by asking a search engine.
  for (const word of ['hnshosting', 'hnshosting/', 'pinner', 'bananas', '14898']) {
    const c = classify(word)
    assert.equal(c.namespace, NAMESPACES.HNS, word)
    assert.match(c.url, /^hns:\/\//, word)
  }
})

test('a bare ICANN TLD is still a search — it is a word somebody is mid-way through typing', () => {
  for (const word of ['com', 'org', 'app', 'blog', 'link']) {
    const c = classify(word)
    assert.equal(c.namespace, NAMESPACES.SEARCH, word)
    assert.equal(c.reason, 'search', word)
  }
})

test('anything with whitespace is a search, never a name', () => {
  for (const q of ['how to publish a site', 'pinner hns', '  ']) {
    assert.equal(classify(q).namespace, NAMESPACES.SEARCH, q)
  }
})

test('ICANN names classify to ICANN and get https://', () => {
  for (const name of ['example.com', 'shop.blog', 'foo.link', 'bbc.co.uk']) {
    assert.equal(classifyHost(name), NAMESPACES.ICANN, name)
  }
  const c = classify('example.com')
  assert.equal(c.namespace, NAMESPACES.ICANN)
  assert.equal(c.url, 'https://example.com')
})

test('IPFS/IPNS gateway paths and localhost classify without touching DNS', () => {
  assert.equal(classify('/ipfs/bafyfoo').url, 'ipfs://bafyfoo')
  assert.equal(classify('/ipns/foo.key').url, 'ipns://foo.key')
  assert.equal(classify('/ipfs/bafyfoo').namespace, NAMESPACES.IPFS)
  const l = classify('localhost:3000')
  assert.equal(l.namespace, NAMESPACES.WEB)
  assert.equal(l.url, 'http://localhost:3000')
})

// --- Table integrity --------------------------------------------------------

test('the scheme table is internally consistent', () => {
  // every namespace referenced by the table is a declared NAMESPACES value
  const known = new Set(Object.values(NAMESPACES))
  for (const row of SCHEME_TABLE) {
    assert.ok(known.has(row.namespace), `${row.scheme} -> known namespace`)
    assert.equal(namespaceForScheme(row.scheme), row.namespace)
    assert.ok(['live', 'partial', 'planned'].includes(row.status), `${row.scheme} status`)
  }
  // the target protocol set is all present
  for (const scheme of ['hns', 'ipfs', 'ipns', 'ar', 'ens', 'web3', 'nostr', 'at', 'activitypub', 'onion', 'https']) {
    assert.ok(namespaceForScheme(scheme), `table covers ${scheme}`)
  }
  // web3:// (a scheme) and .w3 (an HNS TLD) are NOT conflated. The w3://
  // short form is deliberately absent so nothing shadows the .w3 TLD.
  assert.equal(namespaceForScheme('web3'), NAMESPACES.WEB3)
  assert.equal(namespaceForScheme('w3'), null)
  assert.equal(classify('proof.w3').namespace, NAMESPACES.HNS)
})

test('register() rejects a double-registration wiring bug', () => {
  const router = new ProtocolRouter()
  router.register('hns', ok())
  assert.throws(() => router.register('hns', ok()), /already registered/)
  // override is allowed explicitly
  router.register('hns', ok(200, 'v2'), { override: true })
  assert.ok(router.has('hns'))
})

test('isValidV3Onion enforces the 56-char v3 shape', () => {
  assert.equal(isValidV3Onion(VALID_ONION), true)
  assert.equal(isValidV3Onion('short.onion'), false)
  assert.equal(isValidV3Onion('example.com'), false)
})
