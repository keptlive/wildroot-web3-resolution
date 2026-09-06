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
  // additionally refuses a private or reserved host before connecting — a
  // guard this reader does not have (DI-6).
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

test('DI-6: this did:web reader diverges from src/did-protocol.js on ports and paths', async () => {
  // Two did:web resolvers in one tree. src/did-protocol.js implements the
  // method specification's read algorithm and is checked against its
  // published examples; this one splices the method-specific id into the URL
  // verbatim: %3A is never decoded (so a port form requests a host literally
  // named "example.com%3A3000") and a path form's ':' separators are never
  // turned into '/'. The DIVERGENCE is the defect — one shared builder, not
  // two patches.
  const fetchFn = fakeFetch([['https://', { json: {} }]])
  const bsky = makeBsky({ fetchFn })
  await bsky.resolvePds('did:web:example.com%3A3000')
  assert.equal(fetchFn.calls[0].url, 'https://example.com%3A3000/.well-known/did.json')
  await bsky.resolvePds('did:web:example.com:user:alice')
  assert.equal(fetchFn.calls[1].url, 'https://example.com:user:alice/.well-known/did.json')
})

// -------------------------------------------------- what is not checked

test('DI-7: the service TYPE is not checked, only that the id ends in #atproto_pds', async () => {
  // The AT Protocol DID-document requirements name BOTH: id `#atproto_pds`
  // and type `AtprotoPersonalDataServer`.
  const fetchFn = fakeFetch([['plc.directory', {
    json: { id: 'did:plc:self', service: [{ id: 'https://x#atproto_pds', type: 'NotAPds', serviceEndpoint: 'https://anything.example' }] }
  }]])
  const bsky = makeBsky({ fetchFn })
  assert.deepEqual(await bsky.resolvePds('did:plc:self'),
    { did: 'did:plc:self', pds: 'https://anything.example' })
})

test('DI-8: this reader does not check the document\'s id against the DID asked for', async () => {
  // src/did-protocol.js refuses a mismatch with a 502; resolvePds does not
  // make the comparison at all, so a directory answering with somebody
  // else's document hands back that document's PDS under the asked-for DID.
  const fetchFn = fakeFetch([['plc.directory/did:plc:self', {
    json: { id: 'did:plc:somebodyelse', service: PLC_DOC.service }
  }]])
  const bsky = makeBsky({ fetchFn })
  const out = await bsky.resolvePds('did:plc:self')
  assert.equal(out.did, 'did:plc:self')
  assert.equal(out.pds, 'https://pds.selfhost.example')
})

test('a non-https serviceEndpoint is refused — and falls back rather than failing', async () => {
  const fetchFn = fakeFetch([['plc.directory', {
    json: { id: 'did:plc:self', service: [{ id: '#atproto_pds', serviceEndpoint: 'http://plaintext.example' }] }
  }]])
  assert.deepEqual(await makeBsky({ fetchFn }).resolvePds('did:plc:self'),
    { did: 'did:plc:self', pds: DEFAULT_PDS })
})

test('DI-9: an unresolvable DID document silently substitutes bsky.social', async () => {
  // The AT Protocol DID-resolution spec makes an unresolvable DID a FAILURE.
  // Here it becomes "assume the default PDS", which is right for almost
  // everyone and wrong for exactly the self-hosters this browser is for.
  const offline = makeBsky({ fetchFn: fakeFetch([]) })
  assert.deepEqual(await offline.resolvePds('anyone.example'),
    { did: null, pds: DEFAULT_PDS })

  const unknownMethod = makeBsky({ fetchFn: fakeFetch([]) })
  assert.deepEqual(await unknownMethod.resolvePds('did:key:z6Mk'),
    { did: 'did:key:z6Mk', pds: DEFAULT_PDS })
})
