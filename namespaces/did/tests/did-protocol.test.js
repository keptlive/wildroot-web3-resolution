// The `did:` handler: identifier -> DID document (SPEC §5).
//
// Every case runs through the REAL handler with the transport INJECTED
// (`fetchImpl`), which is the seam the module offers and the seam the browser
// uses to hand it the proxied session fetch. No global is patched and no
// socket is opened.
//
// Two things carry the section: the document served is ABOUT the identifier
// that was asked for, and a did:web host — a stranger's choice — is held to
// the same rules as any other stranger-directed request (public host, no
// redirect, a deadline). The did:web URL builder is held to the method
// specification's own published examples.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import createHandler, { didWebUrl, isSafeDidWebHost } from '../src/did-protocol.js'

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json' }
})

const PLC_DID = 'did:plc:ewvi7nxzyoun6zhxrhs64oiz'
const PLC_DOC = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: PLC_DID,
  alsoKnownAs: ['at://atproto.com'],
  service: [{
    id: '#atproto_pds',
    type: 'AtprotoPersonalDataServer',
    serviceEndpoint: 'https://enoki.us-east.host.bsky.network'
  }]
}

/** A fetch that records its calls and answers from `impl`. */
function recording (impl) {
  const calls = []
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init: init || {} })
    return impl(String(url), init)
  }
  fetchImpl.calls = calls
  return fetchImpl
}

// ------------------------------------------------- the did:web read algorithm

test('didWebUrl follows the method specification\'s own examples', () => {
  // did:web §3.2, in its order: ':' -> '/' BEFORE percent-decoding, then the
  // port's %3A, then `.well-known` only when there is no path, then did.json.
  assert.equal(didWebUrl('w3c-ccg.github.io'),
    'https://w3c-ccg.github.io/.well-known/did.json')
  assert.equal(didWebUrl('w3c-ccg.github.io:user:alice'),
    'https://w3c-ccg.github.io/user/alice/did.json')
  assert.equal(didWebUrl('example.com%3A3000'),
    'https://example.com:3000/.well-known/did.json')
  assert.equal(didWebUrl('example.com%3A3000:user:alice'),
    'https://example.com:3000/user/alice/did.json')
  // RFC 3986 §2.1 makes percent-encoding case-insensitive.
  assert.equal(didWebUrl('example.com%3a3000'),
    'https://example.com:3000/.well-known/did.json')
})

test('isSafeDidWebHost admits a public host or address and nothing else', () => {
  assert.equal(isSafeDidWebHost('example.com'), true)
  assert.equal(isSafeDidWebHost('example.com:3000'), true)
  assert.equal(isSafeDidWebHost('8.8.8.8'), true)
  for (const bad of ['', 'localhost', '127.0.0.1', '10.0.0.1', '169.254.169.254',
    'nas.local', 'gitlab.internal', '[::1]', '::1']) {
    assert.equal(isSafeDidWebHost(bad), false, bad)
  }
})

// --------------------------------------------------------------- did:plc

test('did:plc resolves through the PLC directory, with no redirect and a deadline', async () => {
  const fetchImpl = recording(() => json(PLC_DOC))
  const handler = await createHandler({ fetchImpl })
  const res = await handler({ url: PLC_DID })

  assert.equal(res.status, 200)
  assert.equal(fetchImpl.calls.length, 1)
  assert.equal(fetchImpl.calls[0].url, `https://plc.directory/${PLC_DID}`)
  // A redirect is a second, unchecked choice of host made by the first one.
  assert.equal(fetchImpl.calls[0].init.redirect, 'error')
  assert.ok(fetchImpl.calls[0].init.signal instanceof AbortSignal,
    'the request is bounded in time')
  assert.deepEqual(await res.json(), PLC_DOC)
  assert.equal(res.headers.get('content-type'), 'application/json; charset=utf-8')
  assert.equal(res.headers.get('x-resolution-namespace'), 'did')
})

test('the PLC directory is configurable, and did:// is normalised to did:', async () => {
  const fetchImpl = recording(() => json(PLC_DOC))
  const handler = await createHandler({ plcDirectory: 'https://plc.example', fetchImpl })
  const res = await handler({ url: 'did://plc:ewvi7nxzyoun6zhxrhs64oiz' })
  assert.equal(res.status, 200)
  assert.equal(fetchImpl.calls[0].url, `https://plc.example/${PLC_DID}`)
})

test('the transport is the injected one; the global fetch is never reached', async () => {
  const real = globalThis.fetch
  globalThis.fetch = async () => { throw new Error('the global transport was used') }
  try {
    const fetchImpl = recording(() => json(PLC_DOC))
    const handler = await createHandler({ fetchImpl })
    assert.equal((await handler({ url: PLC_DID })).status, 200)
    assert.equal(fetchImpl.calls.length, 1)
  } finally { globalThis.fetch = real }
})

// --------------------------------------------------------------- did:web

test('did:web fetches the document from the host and path the identifier names', async () => {
  const fetchImpl = recording(() => json({ id: 'did:web:example.com:user:alice' }))
  const handler = await createHandler({ fetchImpl })
  const res = await handler({ url: 'did:web:example.com:user:alice' })
  assert.equal(res.status, 200)
  assert.equal(fetchImpl.calls[0].url, 'https://example.com/user/alice/did.json')
  assert.equal(fetchImpl.calls[0].init.redirect, 'error')
})

test('a did:web on a private, loopback or reserved host is refused before any fetch', async () => {
  const fetchImpl = recording(() => json({}))
  const handler = await createHandler({ fetchImpl })
  for (const id of [
    'did:web:localhost', 'did:web:127.0.0.1', 'did:web:10.0.0.1%3A8080',
    'did:web:nas.local', 'did:web:169.254.169.254',
    'did:web:gitlab.internal:user:x', 'did:web:%5B%3A%3A1%5D'
  ]) {
    const res = await handler({ url: id })
    assert.equal(res.status, 400, id)
    assert.match(await res.text(), /not a public web host/, id)
  }
  assert.equal(fetchImpl.calls.length, 0, 'nothing left the machine')
})

// -------------------------------------------------------------- refusals

test('an unsupported method or a malformed DID is refused without a network request', async () => {
  const fetchImpl = recording(() => { throw new Error('must not fetch') })
  const handler = await createHandler({ fetchImpl })

  const unsupported = await handler({ url: 'did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w' })
  assert.equal(unsupported.status, 400)
  assert.match(await unsupported.text(), /Unsupported DID method: ion/)

  for (const id of ['did:plc', 'did:', 'did::x', 'notadid', 'did:web:']) {
    const res = await handler({ url: id })
    assert.equal(res.status, 400, id)
  }
  assert.equal(fetchImpl.calls.length, 0)
})

// ------------------------------------------------- the one check that is made

test('a document about a DIFFERENT identifier is a 502, never served as the one asked for', async () => {
  // DID Core §7.1.3: a resolver answers with the document FOR the input DID.
  // A directory or host answering with somebody else's document is a wrong
  // answer, not a resolution.
  const fetchImpl = recording(() => json({ ...PLC_DOC, id: 'did:plc:somebodyelse' }))
  const handler = await createHandler({ fetchImpl })
  const res = await handler({ url: PLC_DID })
  assert.equal(res.status, 502)
  const body = await res.text()
  assert.match(body, /mismatch/)
  assert.match(body, /did:plc:somebodyelse/)
  assert.equal(res.headers.get('x-resolution-namespace'), 'did')
})

test('a body that is not an object, or carries no id, is a mismatch too', async () => {
  for (const body of [null, 'a string', 42, [], { service: [] }]) {
    const handler = await createHandler({ fetchImpl: recording(() => json(body)) })
    const res = await handler({ url: PLC_DID })
    assert.equal(res.status, 502, JSON.stringify(body))
  }
})

// ------------------------------------------------------------- failures

test('an upstream failure carries a status Chromium knows', async () => {
  const notFound = await (await createHandler({
    fetchImpl: recording(() => json({}, 404))
  }))({ url: 'did:plc:missing' })
  assert.equal(notFound.status, 404)
  assert.equal(notFound.headers.get('content-type'), 'text/plain; charset=utf-8')
  assert.equal(notFound.headers.get('x-resolution-namespace'), 'did')
  assert.match(await notFound.text(), /Failed to resolve DID: did:plc:missing/)

  // A status Chromium does not know is NOTREACHED in the URL loader, so
  // safe-status.js clamps it (Cloudflare's 523 among them).
  const cloudflare = await (await createHandler({
    fetchImpl: recording(() => json({}, 523))
  }))({ url: PLC_DID })
  assert.equal(cloudflare.status, 502)
})

test('a transport error is a 502 carrying the message and no stack', async () => {
  const handler = await createHandler({
    fetchImpl: recording(() => { throw new Error('ECONNREFUSED') })
  })
  const res = await handler({ url: PLC_DID })
  assert.equal(res.status, 502)
  assert.equal(res.headers.get('x-resolution-namespace'), 'did')
  const body = await res.text()
  assert.match(body, /ECONNREFUSED/)
  // A stack carries this installation's paths, to whoever caused the
  // navigation.
  assert.doesNotMatch(body, /\n\s+at /, 'no stack trace in the body')
})

// ------------------------------------------------------------- the response

test('DI-1: a resolved document still carries wildcard CORS headers', async () => {
  // The consolidated DEVIATIONS.md, DI-1. Inert while `did:` is a non-standard scheme with no
  // fetch support, and pinned here so that making `did:` standard cannot turn
  // an inert header into a live one unnoticed.
  const handler = await createHandler({ fetchImpl: recording(() => json(PLC_DOC)) })
  const res = await handler({ url: PLC_DID })
  assert.equal(res.headers.get('access-control-allow-origin'), '*')
  assert.equal(res.headers.get('allow-csp-from'), '*')
})

test('DI-3: the body is the bare document, not a DID resolution result', async () => {
  // The consolidated DEVIATIONS.md, DI-3. DID Core §7.1 defines the result as `didDocument`
  // alongside `didResolutionMetadata` and `didDocumentMetadata`.
  const handler = await createHandler({ fetchImpl: recording(() => json(PLC_DOC)) })
  const res = await handler({ url: PLC_DID })
  const body = await res.json()
  assert.deepEqual(body, PLC_DOC)
  assert.equal(body.didDocument, undefined)
  assert.equal(body.didResolutionMetadata, undefined)
  assert.equal(res.headers.get('content-type'), 'application/json; charset=utf-8')
})
