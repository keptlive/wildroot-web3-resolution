// The `nostr:` handler, end to end, against relays that misbehave.
//
// The handler composes the NIP-19 parser and the relay client and decides the
// HTTP status, the escaping, the CSP and the trust header. Every relay here is
// a scripted WebSocket handed in through the `WebSocketImpl` option, so no
// test touches the network and no test mutates a global.
//
// The ones that matter most are the ones where a relay answers a DIFFERENT
// question than the one asked, and the ones where a link carries relay hints
// that must not be dialled: authorship is proven per event (`event.js`) and
// says nothing at all about whether the event is an ANSWER.

import test from 'node:test'
import assert from 'node:assert/strict'
import { schnorr } from '@noble/curves/secp256k1'

import createHandler, { MAX_RELAY_HINTS } from '../src/nostr-protocol.js'
import { eventId } from '../src/event.js'

// --------------------------------------------------------------- helpers
// A minimal bech32 ENCODER, test-only, so the decoder under test is fed
// independently constructed input rather than its own output.

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
function polymod (values) {
  let chk = 1
  for (const v of values) {
    const top = chk >> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i]
  }
  return chk
}
function hrpExpand (hrp) {
  const out = []
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5)
  out.push(0)
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31)
  return out
}
function bech32Encode (hrp, bytes) {
  const data = []
  let acc = 0
  let bits = 0
  for (const b of bytes) {
    acc = (acc << 8) | b
    bits += 8
    while (bits >= 5) { bits -= 5; data.push((acc >> bits) & 31) }
  }
  if (bits > 0) data.push((acc << (5 - bits)) & 31)
  const mod = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 1
  const checksum = []
  for (let i = 0; i < 6; i++) checksum.push((mod >> (5 * (5 - i))) & 31)
  return hrp + '1' + [...data, ...checksum].map((v) => CHARSET[v]).join('')
}
function tlv (entries) {
  const out = []
  for (const [type, bytes] of entries) out.push(type, bytes.length, ...bytes)
  return Uint8Array.from(out)
}
const be32 = (n) => Uint8Array.from([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255])

function neventFor (idHex, { author, kind } = {}) {
  return bech32Encode('nevent', tlv([
    [0, Buffer.from(idHex, 'hex')],
    ...(author ? [[2, Buffer.from(author, 'hex')]] : []),
    ...(Number.isInteger(kind) ? [[3, be32(kind)]] : [])
  ]))
}
function noteFor (idHex) {
  return bech32Encode('note', Buffer.from(idHex, 'hex'))
}
function nprofileFor (pubkeyHex, relays) {
  return bech32Encode('nprofile', tlv([
    [0, Buffer.from(pubkeyHex, 'hex')],
    ...relays.map((r) => [1, Buffer.from(r, 'utf8')])
  ]))
}

// The page's own key: a fresh keypair, so the profile tests can sign notes AS
// the key the page is about. An answer is only an answer when the author
// matches the query, so a test that wants an event RENDERED has to sign it
// with this key and a test that wants one DISCARDED must not.
const PAGE_SK = schnorr.utils.randomPrivateKey()
const PAGE_HEX = Buffer.from(schnorr.getPublicKey(PAGE_SK)).toString('hex')
const NPUB = bech32Encode('npub', Buffer.from(PAGE_HEX, 'hex'))
// The NIP-19 specification's own published example key. It is a document
// vector, not anyone's key, and it is here so the refusal path can be driven.
const NSEC = 'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5'

function signedEvent (overrides = {}, sk = schnorr.utils.randomPrivateKey()) {
  const pubkey = Buffer.from(schnorr.getPublicKey(sk)).toString('hex')
  const base = {
    pubkey, created_at: 1700000000, kind: 1, tags: [], content: 'hello', ...overrides
  }
  const id = eventId(base)
  return { ...base, id, sig: Buffer.from(schnorr.sign(id, sk)).toString('hex') }
}

/** An event signed by the key the profile pages below are about. */
const mine = (overrides = {}) => signedEvent(overrides, PAGE_SK)

/**
 * A relay that answers every REQ with the same scripted frames, and records
 * every URL it was asked to connect to.
 */
function scriptRelay (events, dialled = [], { dead = false } = {}) {
  return class {
    constructor (url) {
      dialled.push(url)
      this.url = url
      setTimeout(() => {
        if (dead) { this.onerror && this.onerror(new Error('refused')); return }
        this.onopen && this.onopen()
      }, 0)
    }

    send (raw) {
      const [type, subId] = JSON.parse(raw)
      if (type !== 'REQ') return
      setTimeout(() => {
        for (const ev of events) {
          this.onmessage && this.onmessage({ data: JSON.stringify(['EVENT', subId, ev]) })
        }
        this.onmessage && this.onmessage({ data: JSON.stringify(['EOSE', subId]) })
      }, 0)
    }

    close () {}
  }
}

/** Run one request with a scripted WebSocket injected through the seam. */
async function withRelay (WebSocketImpl, url, options = {}) {
  const handler = await createHandler({ timeout: 200, WebSocketImpl, ...options })
  return handler({ url })
}

// ------------------------------------------------------------------ shape

test('an nsec is refused at the door, as a SECRET', async () => {
  const dialled = []
  const res = await withRelay(scriptRelay([], dialled), `nostr:${NSEC}`)
  assert.equal(res.status, 400)
  assert.match(await res.text(), /PRIVATE KEY/)
  assert.deepEqual(dialled, [], 'a secret key is never carried onto a socket')
})

test('an unparseable identifier is a 400, not a relay query', async () => {
  const dialled = []
  const res = await withRelay(scriptRelay([], dialled), 'nostr:not-an-identifier')
  assert.equal(res.status, 400)
  assert.deepEqual(dialled, [], 'nothing may be asked before the address parses')
})

test('every response carries the honest trust header and a no-network CSP', async () => {
  const ev = mine({ kind: 0, content: '{"name":"alice"}' })
  const res = await withRelay(scriptRelay([ev]), `nostr:${NPUB}`)
  assert.equal(res.status, 200)
  assert.equal(res.headers.get('X-Nostr-Trust'),
    'signature-verified; completeness-unverified')
  assert.equal(res.headers.get('X-Nostr-Pubkey'), PAGE_HEX)
  const csp = res.headers.get('Content-Security-Policy')
  assert.match(csp, /default-src 'none'/)
  assert.doesNotMatch(csp, /script-src/, 'no script source is granted at all')
})

test('content from a stranger is HTML-escaped before it is shown', async () => {
  const ev = mine({ content: '<img src=x onerror="alert(1)"> & "quoted"' })
  const res = await withRelay(scriptRelay([ev]), `nostr:${NPUB}`)
  const html = await res.text()
  assert.doesNotMatch(html, /<img src=x/, 'raw markup from a note must never reach the page')
  assert.match(html, /&lt;img src=x/)
})

test('an event that fails verification is DISCARDED and the discard is reported', async () => {
  const ev = mine({ content: 'the original' })
  const tampered = { ...ev, content: 'the relay rewrote this' }
  const res = await withRelay(scriptRelay([tampered]), `nostr:${NPUB}`)
  const html = await res.text()
  assert.doesNotMatch(html, /the relay rewrote this/)
  assert.match(html, /DISCARDED as unverifiable/)
})

// --------------------------------------------- reachability is not absence

test('a profile with nothing behind it is a 404 — only because a relay ANSWERED', async () => {
  const res = await withRelay(scriptRelay([]), `nostr:${NPUB}`)
  assert.equal(res.status, 404)
  assert.match(await res.text(), /Where this came from/, 'the relay report is always rendered')
})

test('no relay reachable is 502 "unknown", never 404 "not found"', async () => {
  const res = await withRelay(scriptRelay([], [], { dead: true }), `nostr:${NPUB}`)
  assert.equal(res.status, 502)
  assert.match(await res.text(), /not found to be absent/)
})

test('a note nobody could be asked about is 502, not "no such note"', async () => {
  const wanted = signedEvent({ content: 'somewhere out there' })
  const res = await withRelay(scriptRelay([], [], { dead: true }), `nostr:${noteFor(wanted.id)}`)
  assert.equal(res.status, 502)
  assert.match(await res.text(), /No relay could be reached|not found to be absent/)
})

// ------------------------------------------- the answer is bound to the query

test('a note query answered with a DIFFERENT (validly signed) event is discarded and reported', async () => {
  // The request names one event id. The relay returns a completely different
  // event — validly signed, by somebody else, saying something else. The
  // signature check says only that this event was authored by the key that
  // signed it; `matchesFilter` is what says it is not an ANSWER.
  const asked = signedEvent({ content: 'the note that was linked' })
  const other = signedEvent({ content: 'a different note by somebody else' })
  const res = await withRelay(scriptRelay([other]), `nostr:${noteFor(asked.id)}`)
  assert.equal(res.status, 404, 'the relay answered, and had no such note')
  const html = await res.text()
  assert.doesNotMatch(html, /a different note by somebody else/)
  assert.match(html, /does not match the filter/)
  assert.match(html, new RegExp(asked.id), 'the id actually requested is named on the page')
})

test("a profile query answered with another author's notes lists none of them", async () => {
  const stranger = signedEvent({ content: 'words put in another mouth' })
  const res = await withRelay(scriptRelay([stranger]), `nostr:${NPUB}`)
  const html = await res.text()
  assert.doesNotMatch(html, /words put in another mouth/)
  assert.match(html, /0 verified notes/)
  assert.match(html, /does not match the filter/, 'the substitution is reported, not merely dropped')
})

test("an nevent's author TLV becomes part of the question", async () => {
  // Same event id asked for, but the link says who wrote it. A relay holding
  // an event with that id signed by anybody else is answering a different
  // question, and the page says so rather than rendering it.
  const ev = signedEvent({ content: 'signed by somebody' })
  const someoneElse = Buffer.from(schnorr.getPublicKey(schnorr.utils.randomPrivateKey())).toString('hex')
  const res = await withRelay(scriptRelay([ev]), `nostr:${neventFor(ev.id, { author: someoneElse })}`)
  assert.equal(res.status, 404)
  assert.match(await res.text(), /does not match the filter/)
})

test("an nevent's kind TLV becomes part of the question", async () => {
  const ev = mine({ kind: 1, content: 'an ordinary note' })
  const res = await withRelay(scriptRelay([ev]), `nostr:${neventFor(ev.id, { kind: 30023 })}`)
  assert.equal(res.status, 404, 'a kind:1 event does not answer a kind:30023 question')
  const ok = await withRelay(scriptRelay([ev]), `nostr:${neventFor(ev.id, { kind: 1 })}`)
  assert.equal(ok.status, 200, 'and the matching kind resolves')
})

test('every note card names its author, and flags one that is not the page key', async () => {
  const ev = mine({ content: 'mine' })
  const res = await withRelay(scriptRelay([ev]), `nostr:${NPUB}`)
  const html = await res.text()
  assert.match(html, new RegExp(`by <code title="${PAGE_HEX}">${PAGE_HEX.slice(0, 16)}…</code>`))
  assert.doesNotMatch(html, /NOT the key this page is about/,
    'the page key does not flag itself')
})

test('a naddr answered by the wrong author is not rendered', async () => {
  const article = mine({ kind: 30023, tags: [['d', 'my-article']], content: 'the article' })
  const naddr = bech32Encode('naddr', tlv([
    [0, Buffer.from('my-article', 'utf8')],
    [2, Buffer.from(PAGE_HEX, 'hex')],
    [3, be32(30023)]
  ]))
  const ok = await withRelay(scriptRelay([article]), `nostr:${naddr}`)
  assert.equal(ok.status, 200)
  assert.match(await ok.text(), /the article/)

  const impostor = signedEvent({ kind: 30023, tags: [['d', 'my-article']], content: 'not the article' })
  const bad = await withRelay(scriptRelay([impostor]), `nostr:${naddr}`)
  assert.equal(bad.status, 404)
  assert.doesNotMatch(await bad.text(), /not the article/)
})

// ----------------------------------------------------- relay hints are checked

test('relay hints inside an identifier are refused unless public wss://, and the refusal is reported', async () => {
  // The hints are attacker-chosen: whatever bytes were bech32-encoded into
  // the link somebody clicked. A plaintext `ws://`, a loopback, a private
  // range and a reserved name must never become a socket from this process.
  const dialled = []
  const hostile = nprofileFor(PAGE_HEX, [
    'ws://127.0.0.1:9999', 'wss://192.168.1.1:8080', 'wss://nas.local',
    'wss://hidden.onion', 'wss://good.example/'
  ])
  const res = await withRelay(scriptRelay([], dialled), `nostr:${hostile}`, { relays: [] })
  // A profile page asks two questions (kind 0, kind 1), so each relay is
  // dialled twice; the SET of relays is what the hints decide.
  assert.deepEqual([...new Set(dialled)], ['wss://good.example'],
    'only the public wss:// hint is dialled, canonicalised')
  const html = await res.text()
  assert.match(html, /ws:\/\/127\.0\.0\.1:9999 — refused/)
  assert.match(html, /wss:\/\/192\.168\.1\.1:8080 — refused/)
  assert.match(html, /wss:\/\/nas\.local — refused/)
  assert.match(html, /wss:\/\/hidden\.onion — refused/)
})

test('relay hints are bounded, and duplicate spellings collapse', async () => {
  const dialled = []
  const many = Array.from({ length: MAX_RELAY_HINTS + 3 }, (_, i) => `wss://r${i}.example`)
  const hostile = nprofileFor(PAGE_HEX, [...many, 'wss://r0.example/'])
  const res = await withRelay(scriptRelay([], dialled), `nostr:${hostile}`,
    { relays: ['wss://base.example/'] })
  assert.equal(new Set(dialled).size, MAX_RELAY_HINTS + 1,
    `at most ${MAX_RELAY_HINTS} hints, plus the configured relay`)
  assert.ok(dialled.includes('wss://base.example'), 'and the configured relay is canonicalised too')
  assert.match(await res.text(), new RegExp(`refused: more than ${MAX_RELAY_HINTS} relay hints`))
})

// ----------------------------------------------------------- the nip05 claim

test('a nip05 field is shown as an unverified CLAIM, never as a fact', async () => {
  const ev = mine({ kind: 0, content: JSON.stringify({ name: 'A', nip05: 'satoshi@bitcoin.org' }) })
  const res = await withRelay(scriptRelay([ev]), `nostr:${NPUB}`)
  const html = await res.text()
  assert.match(html, /claims <code>satoshi@bitcoin\.org<\/code>/)
  assert.match(html, /not verified — the handle was not looked up/)
})

test('a malformed kind:0 is an absent profile, not an error', async () => {
  const ev = mine({ kind: 0, content: 'this is not JSON at all' })
  const res = await withRelay(scriptRelay([ev]), `nostr:${NPUB}`)
  assert.equal(res.status, 200)
  assert.match(await res.text(), /Unnamed profile/)
})

// ---------------------------------------------------------------- Private mode
// Row 15 of the divergence inventory: with protection on, the relays are
// dialled through the device-local Tor (the WebSocketImpl seam takes the
// SOCKS-capable class); with protection on and NO Tor port, the request is
// refused in words rather than dialled directly.

test('Private mode with a Tor port: the Tor-dialling class is built for that port and used for the relays', async () => {
  const built = []
  const dialled = []
  const res = await withRelay(undefined, `nostr:${NPUB}`, {
    isAnonymized: () => true,
    torSocks: () => 'socks5://127.0.0.1:41000',
    torWebSocket: (socks) => { built.push(socks); return scriptRelay([], dialled) }
  })
  assert.equal(res.status, 404, 'the scripted relay answered with nothing, so: not found')
  assert.deepEqual(built, ['socks5://127.0.0.1:41000'], 'one class, for the anonymizer\'s port')
  assert.ok(dialled.length > 0, 'the relays were dialled through it')
})

test('Private mode with NO Tor port: refused before any relay is dialled, and the page says which switch', async () => {
  const dialled = []
  const res = await withRelay(scriptRelay([], dialled), `nostr:${NPUB}`, {
    isAnonymized: () => true,
    torSocks: () => null
  })
  assert.equal(res.status, 503)
  const body = await res.text()
  assert.match(body, /Relays are not asked in Private mode/)
  assert.match(body, /Nothing was asked/)
  assert.match(body, /Settings › Content delivery/)
  assert.deepEqual(dialled, [], 'no relay saw the question')
})

test('Fast mode: the injected WebSocketImpl is used and the Tor builder is never called', async () => {
  const built = []
  const res = await withRelay(scriptRelay([]), `nostr:${NPUB}`, {
    isAnonymized: () => false,
    torSocks: () => 'socks5://127.0.0.1:41000',
    torWebSocket: (socks) => { built.push(socks); return scriptRelay([]) }
  })
  assert.equal(res.status, 404)
  assert.deepEqual(built, [])
})
