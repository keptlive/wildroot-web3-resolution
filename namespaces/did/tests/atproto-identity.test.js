// AT Protocol identity resolution as this implementation performs it:
//   handle -> DID  (com.atproto.identity.resolveHandle, at the public AppView)
//   DID    -> PDS  (did:plc via plc.directory; did:web via /.well-known/did.json)
//
// The adapter in src/bsky.js also carries the whole Bluesky read/write surface.
// Only the two functions above are in this namespace's scope; the rest is kept
// so the file stays byte-identical to the Wildroot tree (see SPEC §1.1).
//
// Everything runs against an injected fetch. Cases marked DI-n pin a
// documented deviation, not an aspiration.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { makeBsky, DEFAULT_PDS } from '../src/bsky.js'

function response ({ status = 200, json = {}, headers = {} } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => headers[String(k).toLowerCase()] ?? null },
    json: async () => json,
    text: async () => JSON.stringify(json)
  }
}

/** Routes: [substring, responder|shape]. Records every call. */
function fakeFetch (routes) {
  const calls = []
  const fn = async (url, init = {}) => {
    calls.push({ url: String(url), init })
    for (const [match, responder] of routes) {
      if (String(url).includes(match)) {
        return response(typeof responder === 'function'
          ? responder({ url: String(url), init })
          : responder)
      }
    }
    throw new Error('unrouted: ' + url)
  }
  fn.calls = calls
  return fn
}

const PLC_DOC = {
  id: 'did:plc:self',
  service: [
    { id: '#other', type: 'Whatever', serviceEndpoint: 'https://nope.example' },
    {
      id: '#atproto_pds',
      type: 'AtprotoPersonalDataServer',
      serviceEndpoint: 'https://pds.selfhost.example'
    }
  ]
}

// ------------------------------------------------------- handle -> DID

test('DI-5: a handle is resolved by ASKING THE APPVIEW, not by DNS or a well-known', async () => {
  // The AT Protocol handle-resolution spec gives two authoritative methods:
  //   _atproto.<handle> TXT "did=..."   and   GET https://<handle>/.well-known/atproto-did
  // Neither is implemented anywhere in this tree. `resolveHandle` calls
  // com.atproto.identity.resolveHandle on Bluesky's PUBLIC AppView, so the
  // AppView is a trusted third party for handle -> DID.
  const fetchFn = fakeFetch([
    ['com.atproto.identity.resolveHandle', { json: { did: 'did:plc:z72i' } }]
  ])
  const bsky = makeBsky({ fetchFn })
  assert.equal(await bsky.resolveHandle('bsky.app'), 'did:plc:z72i')
  assert.match(fetchFn.calls[0].url,
    /^https:\/\/public\.api\.bsky\.app\/xrpc\/com\.atproto\.identity\.resolveHandle\?handle=bsky\.app$/)
})

// ---------------------------------------------------------- DID -> PDS

test('did:plc: the PDS comes out of the DID document\'s #atproto_pds service', async () => {
  const fetchFn = fakeFetch([
    ['com.atproto.identity.resolveHandle', { json: { did: 'did:plc:self' } }],
    ['plc.directory/did:plc:self', { json: PLC_DOC }]
  ])
  const bsky = makeBsky({ fetchFn })
  assert.deepEqual(await bsky.resolvePds('self.example'),
    { did: 'did:plc:self', pds: 'https://pds.selfhost.example' })
  assert.equal(fetchFn.calls[1].url, 'https://plc.directory/did:plc:self')
})

test('a DID may be passed directly; no handle lookup happens', async () => {
  const fetchFn = fakeFetch([['plc.directory/did:plc:self', { json: PLC_DOC }]])
  const bsky = makeBsky({ fetchFn })
  assert.deepEqual(await bsky.resolvePds('did:plc:self'),
    { did: 'did:plc:self', pds: 'https://pds.selfhost.example' })
  assert.equal(fetchFn.calls.length, 1)
})

test('the DID-document fetch refuses redirects and carries a timeout', async () => {
  // The did:web branch fetches an attacker-influenceable host; a 302 must not
  // carry it into internal space. src/did-protocol.js sets the same two, and
  // this reader shares its host guard (isSafeDidWebHost) before connecting.
  const fetchFn = fakeFetch([['plc.directory', { json: PLC_DOC }]])
  await makeBsky({ fetchFn }).resolvePds('did:plc:self')
  assert.equal(fetchFn.calls[0].init.redirect, 'error')
  assert.ok(fetchFn.calls[0].init.signal, 'an AbortSignal is passed')
})

test('did:web resolves at https://<method-specific-id>/.well-known/did.json', async () => {
  const fetchFn = fakeFetch([
    ['alice.hns.one/.well-known/did.json', {
      json: {
        id: 'did:web:alice.hns.one',
        service: [{
          id: '#atproto_pds',
          type: 'AtprotoPersonalDataServer',
          serviceEndpoint: 'https://pds.hns.one'
        }]
      }
    }]
  ])
  const bsky = makeBsky({ fetchFn })
  assert.deepEqual(await bsky.resolvePds('did:web:alice.hns.one'),
    { did: 'did:web:alice.hns.one', pds: 'https://pds.hns.one' })
  assert.equal(fetchFn.calls[0].url, 'https://alice.hns.one/.well-known/did.json')
})

test('ONE did:web reader: resolvePds builds the URL the method specification describes, host-guarded', async () => {
  const fetchFn = fakeFetch([['https://', { json: {} }]])
  const bsky = makeBsky({ fetchFn })
  await bsky.resolvePds('did:web:example.com%3A3000')
  assert.equal(fetchFn.calls[0].url, 'https://example.com:3000/.well-known/did.json')
  await bsky.resolvePds('did:web:example.com:user:alice')
  assert.equal(fetchFn.calls[1].url, 'https://example.com/user/alice/did.json')
  // A private host is never fetched; the fallback says why.
  const local = await bsky.resolvePds('did:web:localhost')
  assert.equal(local.assumed, true)
  assert.match(local.reason, /not a public web host/)
  assert.equal(fetchFn.calls.length, 2)
})

// -------------------------------------------------- what is checked

test('the service TYPE is checked as well as the id', async () => {
  // The AT Protocol DID-document requirements name BOTH: id `#atproto_pds`
  // and type `AtprotoPersonalDataServer`. A service with another type is not
  // the PDS, and the fallback is marked as such.
  const fetchFn = fakeFetch([['plc.directory', {
    json: { id: 'did:plc:self', service: [{ id: 'https://x#atproto_pds', type: 'NotAPds', serviceEndpoint: 'https://anything.example' }] }
  }]])
  const out = await makeBsky({ fetchFn }).resolvePds('did:plc:self')
  assert.equal(out.pds, DEFAULT_PDS)
  assert.equal(out.assumed, true)
})

test('the document must be about the DID asked for — somebody else\'s document is not a resolution', async () => {
  const fetchFn = fakeFetch([['plc.directory/did:plc:self', {
    json: { id: 'did:plc:somebodyelse', service: PLC_DOC.service }
  }]])
  const out = await makeBsky({ fetchFn }).resolvePds('did:plc:self')
  assert.equal(out.did, 'did:plc:self')
  assert.equal(out.pds, DEFAULT_PDS)
  assert.equal(out.assumed, true)
  assert.match(out.reason, /not about this DID/)
})

test('a non-https serviceEndpoint is refused — and the fallback is legible', async () => {
  const fetchFn = fakeFetch([['plc.directory', {
    json: { id: 'did:plc:self', service: [{ id: '#atproto_pds', type: 'AtprotoPersonalDataServer', serviceEndpoint: 'http://plaintext.example' }] }
  }]])
  const out = await makeBsky({ fetchFn }).resolvePds('did:plc:self')
  assert.equal(out.pds, DEFAULT_PDS)
  assert.equal(out.assumed, true)
  assert.match(out.reason, /no https PDS/)
})

test('an unresolvable DID document falls back to bsky.social AND SAYS SO', async () => {
  // The AT Protocol DID-resolution spec makes an unresolvable DID a failure.
  // The fallback is kept for the login path (right for almost everyone) but a
  // caller answering "where does this account live" can see it is a guess.
  const offline = makeBsky({ fetchFn: fakeFetch([]) })
  const out = await offline.resolvePds('anyone.example')
  assert.equal(out.pds, DEFAULT_PDS)
  assert.equal(out.assumed, true)
  assert.ok(out.reason)

  const unknownMethod = await makeBsky({ fetchFn: fakeFetch([]) }).resolvePds('did:key:z6Mk')
  assert.equal(unknownMethod.did, 'did:key:z6Mk')
  assert.equal(unknownMethod.assumed, true)
  assert.match(unknownMethod.reason, /unsupported DID method/)
})
