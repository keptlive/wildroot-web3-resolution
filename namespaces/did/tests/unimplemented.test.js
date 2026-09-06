// The fail-closed contract for `at://` and `activitypub:` (BR-7).
//
// The whole security value of these handlers is NEGATIVE: they must make no
// network request of any kind, and they must answer inside their own
// namespace. These are the tests that pin it.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createUnimplementedHandler, UNIMPLEMENTED } from '../src/unimplemented-protocol.js'
import { createNonProxiedGate } from '../src/gate.js'

const specFor = (scheme) => UNIMPLEMENTED.find((s) => s.scheme === scheme)

test('the build recognises exactly two unresolved namespaces: atproto and activitypub', () => {
  assert.deepEqual(UNIMPLEMENTED.map((s) => s.scheme), ['at', 'activitypub'])
  assert.deepEqual(UNIMPLEMENTED.map((s) => s.namespace), ['atproto', 'activitypub'])
  for (const spec of UNIMPLEMENTED) {
    assert.equal(typeof spec.title, 'string')
    assert.ok(spec.detail.length > 20, 'the refusal says what resolving it would need')
  }
})

test('at:// answers 501 tagged with its own namespace', async () => {
  const handler = createUnimplementedHandler(specFor('at'))
  const res = await handler({ url: 'at://did:plc:abc/app.bsky.feed.post/3kabc' })
  assert.equal(res.status, 501)
  assert.equal(res.headers.get('x-resolution-namespace'), 'atproto')
  assert.equal(res.headers.get('access-control-allow-origin'), 'null')
  assert.match(res.headers.get('content-type'), /^text\/html/)
  const body = await res.text()
  assert.match(body, /atproto is not supported yet/)
  assert.match(body, /DID document for the repository/)
})

test('activitypub: answers 501 tagged with its own namespace', async () => {
  const handler = createUnimplementedHandler(specFor('activitypub'))
  const res = await handler({ url: 'activitypub:@alice@example.social' })
  assert.equal(res.status, 501)
  assert.equal(res.headers.get('x-resolution-namespace'), 'activitypub')
  assert.match(await res.text(), /WebFinger lookup and an actor signature/)
})

test('THE contract: no network request of any kind, for either scheme', async () => {
  const real = globalThis.fetch
  let called = 0
  globalThis.fetch = async () => { called++; throw new Error('must not fetch') }
  try {
    for (const spec of UNIMPLEMENTED) {
      const handler = createUnimplementedHandler(spec)
      await handler({ url: `${spec.scheme}://anything.invalid/x` })
    }
    assert.equal(called, 0, 'a recognised-but-unresolved namespace never leaves the machine')
  } finally { globalThis.fetch = real }
})

test('the echoed address is HTML-escaped, so the refusal page cannot be scripted', async () => {
  const handler = createUnimplementedHandler(specFor('at'))
  const res = await handler({ url: 'at://x/<script>alert(1)</script>"\'&' })
  const body = await res.text()
  assert.ok(!body.includes('<script>alert(1)</script>'))
  assert.match(body, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/)
  assert.match(body, /&quot;&#39;&amp;/)
})

test('a request whose url cannot even be read still answers 501, never throws', async () => {
  const handler = createUnimplementedHandler(specFor('at'))
  const hostile = { get url () { throw new Error('nope') } }
  const res = await handler(hostile)
  assert.equal(res.status, 501)
  const res2 = await handler(undefined)
  assert.equal(res2.status, 501)
})

// ------------------------------------------------------ the IP-Protection gate

test('a handler that opens its own transport is refused in Private mode', async () => {
  // The gate covers handlers that do NOT ride the proxied Electron session —
  // p2p overlays that dial peers directly, and main-process handlers holding
  // a raw socket. `did:` is NOT one of them: it takes the proxied session
  // fetch as `fetchImpl` (SPEC §5.4, §10.4), so it resolves with IP
  // Protection on rather than refusing. The gate is specified here because
  // the rule it encodes is normative for anything that cannot be proxied.
  let on = false
  const gate = createNonProxiedGate(() => on)
  let ran = 0
  const gated = gate(async () => { ran++; return new Response('page') }, 'Hyper')

  assert.equal((await gated({ url: 'hyper://x' })).status, 200)
  assert.equal(ran, 1)

  on = true
  const res = await gated({ url: 'hyper://x' })
  // 503, not a status the engine does not know: a protocol handler's status
  // goes straight into Chromium's reason-phrase lookup.
  assert.equal(res.status, 503)
  assert.equal(ran, 1, 'the handler never ran')
  assert.match(await res.text(), /Hyper is refused in Private mode/)
})

test('the did: handler resolves under anonymization, on the transport it was given', async () => {
  // The proof that `did:` needs no gate: the only transport it uses is the
  // injected one, so whatever proxying that transport carries, it carries.
  const { default: createDidHandler } = await import('../src/did-protocol.js')
  const seen = []
  const handler = await createDidHandler({
    fetchImpl: async (url) => {
      seen.push(String(url))
      return new Response(JSON.stringify({ id: 'did:plc:abc' }),
        { headers: { 'content-type': 'application/json' } })
    }
  })
  const res = await handler({ url: 'did:plc:abc' })
  assert.equal(res.status, 200)
  assert.deepEqual(seen, ['https://plc.directory/did:plc:abc'])
})
