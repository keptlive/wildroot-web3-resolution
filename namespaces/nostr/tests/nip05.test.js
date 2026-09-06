// NIP-05: `<local>@<domain>` -> a pubkey, over HTTPS, on the domain's word.
//
// The SSRF block below is ADAPTED from the Wildroot tree —
// `tests/hns/social-adversarial.test.js`, "FINDING: a claimed name is not
// constrained to being a hostname". Those are reproductions of a real
// adversarial review: each vector is a string an attacker can put in the `hns`
// field of their own kind:0, which this browser then turns into a URL and
// fetches. They are kept verbatim in spirit because they are the reason
// `verificationHost` validates the SHAPE of a claim before appending anything
// to it.
//
// The rest is new: `lookupNip05` did not exist as a function in the Wildroot
// tree (it is a branch of an IPC switch — see the header of ../src/nip05.js),
// so nothing tested it. No test here touches the network; `fetch` is injected.

import test from 'node:test'
import assert from 'node:assert/strict'

import {
  nip05For, displayName, verificationHost, parseNip05, lookupNip05,
  verifyHandshakeClaim
} from '../src/nip05.js'

const KEY = '84dee6e676e5bb67b4ad4e042cf70cbd8681155db535942fcc6a0533858a7240'
const OTHER = '11'.repeat(32)

// ------------------------------------------------------------ the address

test('a Handshake identity is `_@<name>.hns.one`, which clients display bare', () => {
  assert.equal(nip05For('alice.wildroot'), '_@alice.wildroot.hns.one')
  // NIP-05: a `_` local part is rendered as the bare domain, so this is
  // exactly the string the user typed to claim the name.
  assert.equal(displayName(nip05For('alice.wildroot')), 'alice.wildroot.hns.one')
})

test('an identifier splits into local and domain, and a bare domain means `_`', () => {
  assert.deepEqual(parseNip05('alice@example.com'), { local: 'alice', domain: 'example.com' })
  assert.deepEqual(parseNip05('example.com'), { local: '_', domain: 'example.com' })
  assert.deepEqual(parseNip05('_@alice.w3.hns.one'),
    { local: '_', domain: 'alice.w3.hns.one' })
})

test('anything outside the NIP-05 grammar is refused, not escaped', () => {
  for (const bad of ['', null, 'alice@', '@example.com', 'ali ce@example.com',
    'alice@exam ple.com', 'alice@localhost', 'alice+tag@example.com',
    'alice@192.168.1.1:8080', 'alice@example.com/x']) {
    assert.equal(parseNip05(bad), null, `should refuse: ${JSON.stringify(bad)}`)
  }
})

// ---------------------------------------------------------------- the SSRF

test('a claimed name is constrained to being a hostname (SSRF)', () => {
  // Each of these is a string an attacker can put in `"hns"` in their profile.
  // Appending `.hns.one` does not save you: every one already contains the
  // character that ENDS the host, so the fetch would go somewhere else.
  for (const claim of [
    '127.0.0.1:8080/x?y=',
    '169.254.169.254/latest/meta-data/?x=',
    'evil.example/#',
    'evil.example\\.hns.one',
    'evil.example?x=.hns.one',
    'user:pass@evil.example',
    'evil.example:443'
  ]) {
    assert.equal(verificationHost(claim), null, `must refuse: ${claim}`)
  }
})

test('an ordinary claim is suffixed once, and an already-suffixed one is left alone', () => {
  assert.equal(verificationHost('alice.w3'), 'alice.w3.hns.one')
  assert.equal(verificationHost('alice.w3.hns.one'), 'alice.w3.hns.one')
  assert.equal(verificationHost('ALICE.W3.'), 'alice.w3.hns.one')
})

// -------------------------------------------------------------- the lookup

/** A fetch that answers one URL with one document, and records what it was asked. */
function stubFetch (doc, { status = 200, asked = [], json = true } = {}) {
  return async (url, init) => {
    asked.push({ url, init })
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => {
        if (!json) throw new Error('not JSON')
        return doc
      }
    }
  }
}

test('the well-known URL is built from the identifier and redirects are refused', async () => {
  const asked = []
  await lookupNip05('alice@example.com',
    { fetchImpl: stubFetch({ names: { alice: KEY } }, { asked }) })
  assert.equal(asked[0].url, 'https://example.com/.well-known/nostr.json?name=alice')
  assert.equal(asked[0].init.redirect, 'error',
    'NIP-05 forbids following a redirect here — a redirect moves the answer ' +
    'to a host other than the one being asserted about')
})

test('a matching key resolves, with any wss relay hints the domain offers', async () => {
  const out = await lookupNip05('alice@example.com', {
    fetchImpl: stubFetch({
      names: { alice: KEY },
      relays: { [KEY]: ['wss://relay.example', 'ws://plaintext.example', 'http://nope'] }
    })
  })
  assert.equal(out.ok, true)
  assert.equal(out.pubkey, KEY)
  assert.deepEqual(out.relays, ['wss://relay.example'],
    'a relay hint is about to become a socket somebody else chose: wss only')
})

test('every failure is a reason, never a silent empty answer', async () => {
  const cases = [
    [stubFetch({}, { status: 404 }), /returned 404/],
    [stubFetch({ names: {} }), /no 32-byte key/],
    [stubFetch({ names: { alice: 'not-hex' } }), /no 32-byte key/],
    [stubFetch({}, { json: false }), /not JSON/],
    [async () => { throw new Error('unexpected redirect') }, /redirect/]
  ]
  for (const [fetchImpl, pattern] of cases) {
    const out = await lookupNip05('alice@example.com', { fetchImpl })
    assert.equal(out.ok, false)
    assert.match(out.reason, pattern)
  }
})

test('a lookup is never attempted for a non-identifier', async () => {
  const asked = []
  const out = await lookupNip05('127.0.0.1:8080/x',
    { fetchImpl: stubFetch({}, { asked }) })
  assert.equal(out.ok, false)
  assert.deepEqual(asked, [], 'nothing may be fetched before the address parses')
})

// -------------------------------------------- the Handshake-claim direction

test('a Handshake claim is verified against that name\'s OWN zone, and only that', async () => {
  const asked = []
  const ok = await verifyHandshakeClaim('alice.w3', KEY,
    { fetchImpl: stubFetch({ names: { _: KEY } }, { asked }) })
  assert.equal(ok.verified, true)
  assert.equal(asked[0].url, 'https://alice.w3.hns.one/.well-known/nostr.json?name=_')
})

test('a claim whose zone names a DIFFERENT key is not verified', async () => {
  const out = await verifyHandshakeClaim('alice.w3', KEY,
    { fetchImpl: stubFetch({ names: { _: OTHER } }) })
  assert.equal(out.verified, false)
  assert.equal(out.found, OTHER, 'and the page can say what the zone actually said')
})

test('a claim that is not a hostname is refused before any fetch', async () => {
  const asked = []
  const out = await verifyHandshakeClaim('169.254.169.254/latest/meta-data/?x=', KEY,
    { fetchImpl: stubFetch({}, { asked }) })
  assert.equal(out.verified, false)
  assert.equal(out.reason, 'not a resolvable name')
  assert.deepEqual(asked, [])
})
