// What happens to an address before — and instead of — an engine.
//
// `hyper://`, `ssb://`, `gemini://` and the mutable `bittorrent://` branch each
// call `fetchToHandler()` with a closure that constructs their engine
// (hyper-sdk, ssb-fetch, @derhuerst/gemini's client, bt-fetch). Those engines
// are not extractable — hypercore's storage layer is a prebuilt native addon,
// and all of them open real sockets — so this package carries the wrapper they
// all share and STUBS the engines, which is enough to pin the two
// resolution-visible behaviours the wrapper owns:
//
//   1. the engine is constructed LAZILY, once, on the first address, and a
//      concurrent second address waits for the same construction; and
//   2. an engine that will not start is that scheme's own failure — a 500 with
//      the engine's message — never a retry anywhere else.
//
// The gate in front of them (`src/gate.js`, byte-identical) is the IP
// Protection refusal: every one of these namespaces dials peers or opens a raw
// TLS socket from the main process, where the session proxy does not reach.
//
// Adapted from tests/hns/torrent-gate.test.js; the assertions in that file
// that read src/protocols/index.js and src/main.cjs off disk are browser
// wiring and were dropped.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import fetchToHandler, { CORS_HEADERS } from '../src/fetch-to-handler.js'
import { createNonProxiedGate } from '../src/gate.js'

const INFOHASH = 'c0ffee0123456789abcdef0123456789abcdef01'

/** A stand-in for hyper-sdk / ssb-fetch / bt-fetch / a Gemini client. */
function stubEngine ({ fail = null } = {}) {
  const state = { constructed: 0, urls: [] }
  state.make = async () => {
    state.constructed++
    if (fail) throw new Error(fail)
    const fetch = async (request) => {
      state.urls.push(request.url)
      return new Response('engine answered', { status: 200 })
    }
    fetch.close = async () => { state.closed = true }
    return fetch
  }
  return state
}

test('the engine is built once, lazily, and shared by concurrent addresses', async () => {
  const engine = stubEngine()
  const { handler, close } = fetchToHandler(engine.make)
  assert.equal(engine.constructed, 0, 'constructing the handler must not start an engine')

  const [a, b] = await Promise.all([
    handler(new Request('hyper://' + 'a'.repeat(64) + '/')),
    handler(new Request('hyper://' + 'b'.repeat(64) + '/'))
  ])
  assert.equal(engine.constructed, 1, 'two concurrent addresses, one construction')
  assert.equal(await a.text(), 'engine answered')
  assert.equal(await b.text(), 'engine answered')

  await handler(new Request('hyper://' + 'c'.repeat(64) + '/'))
  assert.equal(engine.constructed, 1)
  await close()
  assert.equal(engine.closed, true)
})

test('an engine that will not start is THIS scheme failing, with its own message', async () => {
  // The real message this exists for: hypercore's rocksdb-native addon links
  // libatomic.so.1, and when that library is missing the loader reports
  // "Cannot find addon '.'" — which names the wrong problem. The browser
  // rewrites it before it gets here; what is pinned here is that whatever the
  // sentence says, it is returned AS this scheme's answer.
  const engine = stubEngine({ fail: 'Shared folders and hyper:// cannot start. libatomic.so.1 is missing.' })
  const { handler } = fetchToHandler(engine.make)

  const res = await handler(new Request('hyper://' + 'a'.repeat(64) + '/'))
  assert.equal(res.status, 500)
  assert.match(await res.text(), /libatomic\.so\.1 is missing/)

  // And it is retried, not cached as dead: a later request tries again.
  await handler(new Request('hyper://' + 'a'.repeat(64) + '/'))
  assert.equal(engine.constructed, 2)
})

test('every answer carries the CORS headers, whether or not they were mutable', async () => {
  const engine = stubEngine()
  const { handler } = fetchToHandler(engine.make)
  const res = await handler(new Request('ssb://feed/ed25519/abc'))
  for (const header of CORS_HEADERS) assert.equal(res.headers.get(header), '*')
})

test('IP Protection refuses the whole namespace with a 503 — nothing underneath runs', async () => {
  // BitTorrent dials peers directly and hyperswarm dials peers directly:
  // neither rides session.setProxy, so while anonymization is on they are
  // refused rather than leaked. (Gemini is one TCP connection to one host, so
  // it is routed through the Tor SOCKS port instead — gemini-protocol.test.js.)
  // 503, never a made-up status: an unknown code reaches Chromium's
  // NOTREACHED in the protocol loader.
  let anonymized = true
  const engine = stubEngine()
  const { handler } = fetchToHandler(engine.make)
  const gated = createNonProxiedGate(() => anonymized)(handler, 'BitTorrent')

  for (const url of [`bittorrent://${INFOHASH}/`, `bittorrent://${'d'.repeat(64)}/`]) {
    const res = await gated(new Request(url))
    assert.equal(res.status, 503)
    assert.match(await res.text(), /disabled while anonymization is on/)
  }
  assert.equal(engine.constructed, 0, 'the gate answers before the engine is even considered')

  // The gate reads the LIVE state per request: off again means through again.
  anonymized = false
  const res = await gated(new Request(`bittorrent://${INFOHASH}/`))
  assert.equal(await res.text(), 'engine answered')
  assert.equal(engine.constructed, 1)
})
