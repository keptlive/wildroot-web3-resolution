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
import { createRequire } from 'node:module'

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
const { setNumericNames } = createRequire(import.meta.url)('../src/classify-host.cjs')

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
  // a non-ICANN word TLD, and the .w3 / .exist HNS TLDs.
  for (const name of ['nathan.woodburn', 'me.exist', 'proof.w3']) {
    assert.equal(classifyHost(name), NAMESPACES.HNS, name)
    assert.equal(classify(name).namespace, NAMESPACES.HNS, name)
  }
  // a word-TLD HNS name keeps the normalized trailing slash
  assert.equal(classify('nathan.woodburn').url, 'hns://nathan.woodburn/')
})

test('names that are only numbers are OFF by default, and a switch turns the resolution on', () => {
  // Decided 2026-09-06: excluded for simplicity; the method stays in the code.
  assert.equal(classifyHost('hello.14898'), NAMESPACES.WEB, 'off: what the URL parser makes of it')
  assert.equal(classify('hello.14898').namespace, NAMESPACES.WEB)
  assert.equal(classify('14898').namespace, 'search', 'off: a bare number is a search')
  setNumericNames(true)
  try {
    for (const name of ['hello.14898', 'blog.10103']) {
      assert.equal(classifyHost(name), NAMESPACES.HNS, name)
      assert.equal(classify(name).namespace, NAMESPACES.HNS, name)
    }
    // A numeric final label is an IPv4 address to the URL parser, so
    // `hns://hello.14898/` is not a URL Chromium will open at all. The name is
    // carried with the `_` marker no Handshake name can contain
    // (src/hns/hns-url.cjs); the handler strips it, the address bar hides it.
    assert.equal(classify('hello.14898').url, 'hns://hello._14898/')
    assert.equal(classify('14898/').url, 'hns://_14898/')
    assert.equal(classify('14898').namespace, NAMESPACES.HNS, 'on: a bare number is a name')
  } finally {
    setNumericNames(false)
  }
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
  for (const word of ['hnshosting', 'hnshosting/', 'pinner', 'bananas']) {
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
    assert.ok(['trustless', 'trusted', 'open', 'refused', 'builtin'].includes(row.trust), `${row.scheme} trust`)
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

// --- Reserved names, IP literals, self-describing inputs ---------------------

test('a reserved name (nas.local, app.localhost) is the user\'s own device, never a Handshake lookup', () => {
  for (const host of ['nas.local', 'homeassistant.local', 'printer.lan', 'router.home', 'gitlab.internal',
    'app.localhost', 'files.corp', 'db.private', 'a.test', 'b.example', 'home.arpa']) {
    assert.equal(classifyHost(host), NAMESPACES.WEB, host)
    const c = classify(host)
    assert.equal(c.namespace, NAMESPACES.WEB, host)
    assert.equal(c.reason, 'reserved-host', host)
    assert.equal(c.url, `http://${host}`, host)
  }
  assert.equal(classify('nas.local:5000/admin').url, 'http://nas.local:5000/admin')
  // `.onion` is in the reserved list too, and must still reach Tor first.
  assert.equal(classifyHost('x.onion'), NAMESPACES.TOR)
  // A Handshake name whose LABEL is one of the reserved words is unaffected.
  setNumericNames(true)
  try { assert.equal(classifyHost('local.14898'), NAMESPACES.HNS) } finally { setNumericNames(false) }
  assert.equal(classifyHost('test.w3'), NAMESPACES.HNS)
})

test('an IPv6 literal, bracketed or not, is an address and never a Handshake name', () => {
  for (const ip of ['::1', '[::1]', '[::1]:8080', '2001:db8::1', '[2001:db8::1]', '::ffff:127.0.0.1', '127.0.0.1', '10.0.0.5:3000']) {
    assert.equal(classifyHost(ip), NAMESPACES.WEB, ip)
    const c = classify(ip)
    assert.equal(c.namespace, NAMESPACES.WEB, ip)
    assert.equal(c.reason, 'ip-literal', ip)
    assert.doesNotMatch(c.url, /^hns:/, ip)
  }
  // The port strip does not mangle an address: `::1` is not "host with port 1",
  // and the URL built for it is bracketed, or it would not be a URL at all.
  assert.equal(classify('::1').url, 'https://[::1]')
  assert.equal(classify('fe80::1/x').url, 'https://[fe80::1]/x')
  assert.ok(new URL(classify('2001:db8::1').url))
  assert.equal(classify('[::1]:8080').url, 'https://[::1]:8080')
  assert.equal(hasExplicitScheme('fe80::1'), false, 'the first group of an IPv6 literal is not a scheme')
})

test('a pasted CID opens as ipfs://, never as a Handshake name', () => {
  const v1 = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi'
  const c1 = classify(v1)
  assert.equal(c1.namespace, NAMESPACES.IPFS)
  assert.equal(c1.url, `ipfs://${v1}/`)
  assert.equal(c1.reason, 'bare-cid')
  // A CIDv0 is case-sensitive and cannot survive as a URL host, so it is
  // written as the CIDv1 that names the same bytes.
  const v0 = 'QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG'
  const c0 = classify(v0)
  assert.equal(c0.namespace, NAMESPACES.IPFS)
  assert.match(c0.url, /^ipfs:\/\/bafy[a-z2-7]+\/$/)
  // A malformed one (bad multibase content) is not stolen from the bare-label rule.
  assert.equal(classify('b' + 'a'.repeat(58)).namespace, NAMESPACES.HNS)
  // An IPNS key is deliberately NOT sniffed: k51… is a bare label like any other.
  assert.equal(classify('k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8').namespace, NAMESPACES.HNS)
})

test('@user@host is a Fediverse address, routed to activitypub, never to https', () => {
  const c = classify('@alice@example.social')
  assert.equal(c.namespace, NAMESPACES.ACTIVITYPUB)
  assert.equal(c.url, 'activitypub:@alice@example.social')
  assert.equal(c.reason, 'fedi-handle')
  // A bare atproto handle IS a website and stays ICANN.
  assert.equal(classify('alice.bsky.social').namespace, NAMESPACES.ICANN)
  // Any other `@` is not a name: the URL constructor would drop what precedes
  // it as userinfo, so `@alice@localhostish` must not become `hns://localhostish/`.
  for (const odd of ['@alice@localhostish', 'alice@example', 'user@host.w3/path']) {
    const c = classify(odd)
    assert.equal(c.namespace, NAMESPACES.SEARCH, odd)
  }
})

test('an explicit scheme reports whether the table knows it', () => {
  assert.equal(classify('hns://proof.w3/').known, true)
  assert.equal(classify('javascript:alert(1)').known, false)
  assert.equal(classify('javascript:alert(1)').namespace, null)
})

test('a named scheme whose URL will not parse still fails INSIDE its namespace', async () => {
  // `at://did:plc:abc/…` is the canonical AT-URI and not a WHATWG URL (a host
  // may not carry a colon that is not a port). The scheme was named, so the
  // failure is the at handler's, tagged with its namespace — not a bare 400.
  const router = new ProtocolRouter()
  const seen = []
  router.register('at', (req) => { seen.push(req.url); return new Response('refused', { status: 501 }) })
  const res = await router.dispatch({ url: 'at://did:plc:abc/app.bsky.feed.post/3k' })
  assert.equal(res.status, 501)
  assert.deepEqual(seen, ['at://did:plc:abc/app.bsky.feed.post/3k'])
  // A named scheme with NO handler: 501 tagged with the scheme, as always.
  const none = await router.dispatch({ url: 'did://web:host%3A/x y' })
  assert.equal(none.status, 501)
  assert.equal(none.headers.get('X-Resolution-Namespace'), 'did')
  // No scheme at all stays a bare 400.
  const bare = await router.dispatch({ url: 'not a url' })
  assert.equal(bare.status, 400)
  assert.equal(bare.headers.get('X-Resolution-Namespace'), null)
})

test('isValidV3Onion checks the version byte and the SHA3 checksum, not just the shape', () => {
  // Two published v3 addresses (The New York Times, DuckDuckGo).
  const NYT = 'p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion'
  const DDG = 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion'
  assert.equal(isValidV3Onion(NYT), true)
  assert.equal(isValidV3Onion(DDG.toUpperCase()), true)
  // 56 letters is the right SHAPE and cannot be an address: version 0, checksum 0.
  assert.equal(isValidV3Onion('a'.repeat(56) + '.onion'), false)
  // One flipped character breaks the checksum.
  assert.equal(isValidV3Onion('q' + NYT.slice(1)), false)
  // Routing is unaffected: an invalid onion is STILL Tor's, never a resolver's.
  assert.equal(classifyHost('a'.repeat(56) + '.onion'), NAMESPACES.TOR)
  assert.equal(classify('a'.repeat(56) + '.onion').validV3, false)
  assert.equal(classify(NYT).validV3, true)
})

test('a bare NIP-19 identifier is a Nostr address — and a pasted nsec reaches the refusal page, never a resolver', () => {
  const NPUB = 'npub1sn0wdenkukak0d9dfczzeacvhkrgz92ak56egt7vdgzn8pv2wfqqhrjdv9'
  // The NIP-19 specification's own published example vector, not anyone's key.
  const NSEC = 'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5'
  for (const id of [NPUB, NPUB.toUpperCase(), NSEC]) {
    const c = classify(id)
    assert.equal(c.namespace, NAMESPACES.NOSTR, id)
    assert.equal(c.reason, 'nip19-identifier', id)
    assert.equal(c.url, `nostr:${id.toLowerCase()}`, id)
  }
  // The address bar appends a slash; it is not part of the identifier, and an
  // nsec with one must still reach the refusal page rather than a lookup.
  assert.equal(classify(`${NPUB}/`).url, `nostr:${NPUB}`)
  assert.equal(classify(`${NSEC}/`).namespace, NAMESPACES.NOSTR)
  // A Handshake name that merely starts with npub is still a name: the
  // checksum decides, not the prefix.
  assert.equal(classify('npub1shop').namespace, NAMESPACES.HNS)
  assert.equal(classify('npub1' + 'q'.repeat(58)).namespace, NAMESPACES.HNS)
  assert.equal(classify('note').namespace, NAMESPACES.HNS)
})
