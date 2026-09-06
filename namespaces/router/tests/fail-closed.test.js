/*
 * The fail-closed handler (Part II §4.5).
 *
 * A namespace an implementation can NAME but cannot RESOLVE must fail inside
 * itself. The alternative is what this rule was written after: before `.eth`
 * and `.onion` had handlers, a TLD outside the ICANN root was assumed to be
 * Handshake, so `vitalik.eth` was resolved on-chain — traffic meant for ENS
 * handed to whoever holds the Handshake name `eth` — and an onion address left
 * the machine in a DNS query, which for a Tor user is a deanonymising leak
 * rather than a failed page.
 *
 * The handler's security value is entirely in what it does NOT do: no network
 * request of any kind. These tests hold it to that, and to the namespace
 * marker that proves the failure stayed put.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { createUnimplementedHandler, UNIMPLEMENTED } from '../src/unimplemented-protocol.js'
import { namespaceForScheme, ProtocolRouter } from '../../../src/router.js'

test('every unimplemented namespace answers 501, in its own namespace', async () => {
  for (const spec of UNIMPLEMENTED) {
    const res = await createUnimplementedHandler(spec)({ url: `${spec.scheme}://example-input` })
    assert.equal(res.status, 501, spec.scheme)
    assert.equal(res.headers.get('X-Resolution-Namespace'), spec.namespace, spec.scheme)
    const body = await res.text()
    assert.match(body, /not supported yet/i, spec.scheme)
    assert.match(body, /example-input/, 'it shows the user what it understood')
    assert.match(body, new RegExp(spec.namespace), 'and which namespace it decided on')
  }
})

test('the marker each stub sets agrees with the router registry', () => {
  // Two sources for one fact is how they drift. The stub's namespace and the
  // table's namespace for the same scheme must be the same string.
  for (const spec of UNIMPLEMENTED) {
    assert.equal(namespaceForScheme(spec.scheme), spec.namespace,
      `${spec.scheme}: the stub and SCHEME_TABLE must agree`)
  }
})

test('the stubs cover exactly the schemes the table calls planned', () => {
  const stubbed = new Set(UNIMPLEMENTED.map((spec) => spec.scheme))
  assert.deepEqual([...stubbed].sort(), ['activitypub', 'at'])
})

test('the page escapes the address instead of rendering it', async () => {
  const handler = createUnimplementedHandler({
    scheme: 'at', namespace: 'atproto', title: 'T', detail: 'D'
  })
  const res = await handler({ url: 'at://<img src=x onerror=alert(1)>' })
  const body = await res.text()
  assert.equal(body.includes('<img src=x'), false, 'raw markup must not survive')
  assert.match(body, /&lt;img/)
  // The title, namespace and detail are attacker-adjacent too.
  const evil = createUnimplementedHandler({
    scheme: 'x', namespace: '<b>ns</b>', title: '<b>t</b>', detail: '<b>d</b>', leak: '<b>l</b>'
  })
  const out = await (await evil({ url: 'x://y' })).text()
  assert.equal(out.includes('<b>'), false)
})

test('a request whose url cannot even be read does not throw', async () => {
  const handler = createUnimplementedHandler(UNIMPLEMENTED[0])
  const hostile = { get url () { throw new Error('nope') } }
  const res = await handler(hostile)
  assert.equal(res.status, 501)
})

test('the handler makes no network request — it has nothing to make one with', async () => {
  // Structural, not behavioural: the module imports nothing at all, so there is
  // no fetch, no socket and no resolver in its scope. Asserted on the source
  // because "it did not call the network" is otherwise untestable offline.
  const { readFileSync } = await import('node:fs')
  const src = readFileSync(new URL('../src/unimplemented-protocol.js', import.meta.url), 'utf8')
  assert.doesNotMatch(src, /\bimport\s|\brequire\(/, 'the module imports nothing')
  assert.doesNotMatch(src, /\bfetch\(|https?\.request|net\.|dns\./, 'and reaches nothing')
})

test('a stub registered into the router answers in-namespace and consults nobody else', async () => {
  const hit = []
  const router = new ProtocolRouter()
  router.register('hns', () => { hit.push('hns'); return new Response('leaked!') })
  for (const spec of UNIMPLEMENTED) {
    router.register(spec.scheme, createUnimplementedHandler(spec))
  }
  const res = await router.dispatch(new Request('at://alice.example/app.bsky.feed.post/1'))
  assert.equal(res.status, 501)
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'atproto')
  assert.deepEqual(hit, [], 'no other namespace was consulted')
})

test('the canonical AT-URI reaches its own handler, inside its own namespace', async () => {
  // `at://did:plc:…/…` is the spelling the AT Protocol actually uses, and it is
  // not a WHATWG URL: a host may not carry a colon that is not a port. The
  // dispatcher reads the scheme by PREFIX when the parse fails, so the request
  // still reaches — and fails inside — the namespace the user named. Any
  // namespace whose addresses are not WHATWG hosts depends on this.
  const hit = []
  const router = new ProtocolRouter()
  for (const spec of UNIMPLEMENTED) {
    router.register(spec.scheme, (req) => { hit.push(spec.scheme); return createUnimplementedHandler(spec)(req) })
  }
  assert.throws(() => new URL('at://did:plc:abc/app.bsky.feed.post/1'), /Invalid URL/)
  const res = await router.dispatch({ url: 'at://did:plc:abc/app.bsky.feed.post/1' })
  assert.equal(res.status, 501)
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'atproto')
  assert.match(await res.text(), /did:plc:abc/, 'and it echoes what it understood')
  assert.deepEqual(hit, ['at'], 'the atproto handler ran, and nobody else did')
  // The host-authority spelling behaves identically, which is the point.
  const ok = await router.dispatch({ url: 'at://alice.example/x' })
  assert.equal(ok.status, 501)
  assert.equal(ok.headers.get('X-Resolution-Namespace'), 'atproto')
  // An unparseable address that names NO scheme is still a bare 400, with no
  // namespace to claim it stayed in (RT-12).
  const bare = await router.dispatch({ url: 'not a url' })
  assert.equal(bare.status, 400)
  assert.equal(bare.headers.get('X-Resolution-Namespace'), null)
})
