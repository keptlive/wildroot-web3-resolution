// Which namespace a DID-family address belongs to, and what happens when its
// namespace cannot answer. Runs against the SHARED classifier at
// ../../../src/router.js — the same file the Handshake section uses, and the
// same file byte-for-byte as the browser's src/protocols/router.js.
//
// The rule under test is LAW L2: a failure never crosses a namespace boundary.
// `at://` and `activitypub:` exist as namespaces precisely so that they can
// fail inside themselves instead of being guessed at as Handshake names.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  classify, classifyHost, hasExplicitScheme, schemeOf, namespaceForScheme,
  schemeInfo, NAMESPACES, SCHEME_TABLE, ProtocolRouter
} from '../../../src/router.js'

// ------------------------------------------------------- the three namespaces

test('did, atproto and activitypub are namespaces of their own', () => {
  assert.equal(NAMESPACES.DID, 'did')
  assert.equal(NAMESPACES.ATPROTO, 'atproto')
  assert.equal(NAMESPACES.ACTIVITYPUB, 'activitypub')
  assert.equal(namespaceForScheme('did'), 'did')
  assert.equal(namespaceForScheme('at'), 'atproto')
  assert.equal(namespaceForScheme('activitypub'), 'activitypub')
})

test('the scheme table states each one\'s maturity and verification story', () => {
  assert.deepEqual(schemeInfo('did'), {
    scheme: 'did',
    namespace: 'did',
    status: 'partial',
    trust: 'trusted',
    verify: 'DID document fetched from plc.directory / the did:web host ' +
      '(id checked; not proven — lock TRUSTED)'
  })
  assert.deepEqual(schemeInfo('at'), {
    scheme: 'at', namespace: 'atproto', status: 'planned', trust: 'refused', verify: 'DID document (BR-7)'
  })
  assert.deepEqual(schemeInfo('activitypub'), {
    scheme: 'activitypub',
    namespace: 'activitypub',
    status: 'planned',
    trust: 'refused',
    verify: 'WebFinger/actor signature (BR-7)'
  })
  // Every row in the table names a namespace the table itself declares.
  const known = new Set(Object.values(NAMESPACES))
  for (const row of SCHEME_TABLE) assert.ok(known.has(row.namespace), row.scheme)
})

// ------------------------------------------------- a colon-only DID is a scheme

test('a slashless did: is recognised as an explicit scheme, not a host:port', () => {
  assert.equal(hasExplicitScheme('did:plc:ewvi7nxzyoun6zhxrhs64oiz'), true)
  assert.equal(schemeOf('did:plc:ewvi7nxzyoun6zhxrhs64oiz'), 'did')
  assert.equal(hasExplicitScheme('did://plc:abc'), true)
  // The host:port guard only fires for an UNKNOWN token followed by digits.
  assert.equal(hasExplicitScheme('example.com:8080'), false)
})

test('classify defers to the scheme and never re-reads the identifier', () => {
  const did = classify('did:web:alice.hns.one')
  assert.deepEqual(did, {
    url: 'did:web:alice.hns.one',
    scheme: 'did',
    namespace: 'did',
    explicit: true,
    reason: 'explicit-scheme',
    // The table knows this scheme. `javascript:`, `data:` and `file:` come
    // back explicit too, with `known: false` and a null namespace, so a
    // caller that navigates can tell a link target from a decision.
    known: true
  })
  // `alice.hns.one` is an ICANN host and `at://foo.14898` looks Handshake:
  // neither is looked at, because a scheme was named (L1).
  assert.equal(classify('at://foo.14898/x').namespace, NAMESPACES.ATPROTO)
  assert.equal(classify('activitypub:@alice@example.social').namespace,
    NAMESPACES.ACTIVITYPUB)
})

test('a bare `@user@host` is a Fediverse address and classifies to activitypub', () => {
  // `@alice@example.social` is the canonical Fediverse address form and is
  // NOT a host: the URL parser reads the second `@` as a userinfo separator
  // and would navigate to the instance with a stray credential. It reaches
  // the activitypub namespace, and therefore the fail-closed refusal written
  // for it (SPEC §7, §8).
  const fedi = classify('@alice@example.social')
  assert.deepEqual(fedi, {
    url: 'activitypub:@alice@example.social',
    scheme: 'activitypub',
    namespace: NAMESPACES.ACTIVITYPUB,
    explicit: false,
    reason: 'fedi-handle'
  })
  assert.equal(classify('@matt@hns.one').namespace, NAMESPACES.ACTIVITYPUB)
  // A single `@` is not the form, and neither is a hostless second part.
  assert.notEqual(classify('@alice').namespace, NAMESPACES.ACTIVITYPUB)
  assert.notEqual(classify('alice@example.social').namespace, NAMESPACES.ACTIVITYPUB)
})

test('a BARE social name is a Handshake name, not an atproto address', () => {
  // The deliberate non-conflation: `alice.wildroot` is an HNS name whose zone
  // publishes `_hns`/`_atproto`; the at:// and did: schemes address the native
  // objects. HNS authenticates the mapping, the native layer the object (L3).
  assert.equal(classifyHost('alice.wildroot'), NAMESPACES.HNS)
  assert.equal(classify('alice.wildroot').namespace, NAMESPACES.HNS)
  assert.equal(classify('alice.hns.one').namespace, NAMESPACES.ICANN)
})

// ------------------------------------------------------------ L2 at the router

test('an unregistered did: fails as did:, tagged, and is never re-read as a host', async () => {
  const router = new ProtocolRouter()
  router.register('hns', () => new Response('hns'))
  const res = await router.dispatch(new Request('did:web:alice.hns.one'))
  assert.equal(res.status, 501)
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'did')
  assert.match(await res.text(), /No handler is registered for "did:\/\/"/)
})

test('a did handler that throws surfaces as a did failure, not another lookup', async () => {
  const hit = []
  const router = new ProtocolRouter()
  router.register('did', () => { hit.push('did'); throw new Error('plc.directory unreachable') })
  router.register('hns', () => { hit.push('hns'); return new Response('hns') })
  router.register('https', () => { hit.push('https'); return new Response('web') })

  const res = await router.dispatch(new Request('did:web:alice.hns.one'))
  assert.equal(res.status, 502)
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'did')
  assert.match(await res.text(), /plc\.directory unreachable/)
  assert.deepEqual(hit, ['did'], 'exactly one handler ran')
})

test('at:// reaches the atproto handler even when the authority looks Handshake', async () => {
  const hit = []
  const router = new ProtocolRouter()
  router.register('at', () => { hit.push('at'); return new Response('', { status: 501 }) })
  router.register('hns', () => { hit.push('hns'); return new Response('') })
  await router.dispatch(new Request('at://foo.14898/app.bsky.feed.post/3k'))
  assert.deepEqual(hit, ['at'])
})

test('the canonical at://did:plc:… AT-URI reaches the at handler inside its namespace', async () => {
  // `at://did:plc:abc/app.bsky.feed.post/3k` is the AT-URI form the protocol
  // itself uses, and the WHATWG parser refuses it — a host may not carry a
  // colon that is not a port. dispatch reads the scheme by PREFIX when the
  // URL will not parse, so a named scheme's failure is still that scheme's
  // and never falls out into another namespace (L2).
  const AT_URI = 'at://did:plc:abc/app.bsky.feed.post/3k'
  assert.throws(() => new URL(AT_URI))
  // Node's own Request constructor refuses it for the same reason, so the
  // request reaching dispatch is the engine's `{ url }`-shaped object.
  assert.throws(() => new Request(AT_URI))

  const hit = []
  const router = new ProtocolRouter()
  const { createUnimplementedHandler, UNIMPLEMENTED } =
    await import('../src/unimplemented-protocol.js')
  const atSpec = UNIMPLEMENTED.find((s) => s.scheme === 'at')
  router.register('at', (req) => { hit.push('at'); return createUnimplementedHandler(atSpec)(req) })
  router.register('hns', () => { hit.push('hns'); return new Response('') })

  const res = await router.dispatch({ url: AT_URI })
  assert.deepEqual(hit, ['at'])
  assert.equal(res.status, 501)
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'atproto')
})

test('an address that names no scheme at all is a bare 400, tagged with nothing', async () => {
  // The prefix read is a fallback for a NAMED scheme, not a licence to guess:
  // with no scheme there is no namespace to fail inside, so there is no tag.
  const router = new ProtocolRouter()
  router.register('did', () => new Response('did'))
  const res = await router.dispatch({ url: 'not a url at all' })
  assert.equal(res.status, 400)
  assert.equal(res.headers.get('X-Resolution-Namespace'), null)
})

test('a handler-returned 501 is passed through verbatim — including its namespace tag', async () => {
  // This is how the fail-closed stubs reach the trust UI: dispatch does not
  // rewrite a response the handler produced, so the stub's own
  // X-Resolution-Namespace is the one that arrives.
  const router = new ProtocolRouter()
  router.register('activitypub', () => new Response('stub', {
    status: 501, headers: { 'X-Resolution-Namespace': 'activitypub' }
  }))
  const res = await router.dispatch(new Request('activitypub:@a@b.example'))
  assert.equal(res.status, 501)
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'activitypub')
  assert.equal(await res.text(), 'stub')
})

test('every did: response carries its namespace tag, the handler\'s own included', async () => {
  // The router tags the failures it generates (501 unregistered, 502 handler
  // threw) and passes a handler's response through verbatim, so a handler
  // that answers for itself sets the header for itself. That is the whole
  // L2 evidence chain: every `did:` outcome is provably still in `did`.
  const { default: createHandler } = await import('../src/did-protocol.js')
  const router = new ProtocolRouter()
  router.register('did', await createHandler({
    fetchImpl: async () => new Response('{}', { status: 404 })
  }))

  const refused = await router.dispatch(new Request('did:key:z6Mk'))
  assert.equal(refused.status, 400)
  assert.equal(refused.headers.get('X-Resolution-Namespace'), 'did')

  const upstream = await router.dispatch(new Request('did:plc:missing'))
  assert.equal(upstream.status, 404)
  assert.equal(upstream.headers.get('X-Resolution-Namespace'), 'did')
})
