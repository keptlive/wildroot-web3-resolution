import test from 'node:test'
import assert from 'node:assert/strict'
import { decodeNip19, parseNostrURI, bech32Decode } from '../src/nip19.js'
import { eventId, verifyEvent } from '../src/event.js'
import { schnorr } from '@noble/curves/secp256k1'

// Vectors from the NIP-19 specification itself.
const NPUB = 'npub1sn0wdenkukak0d9dfczzeacvhkrgz92ak56egt7vdgzn8pv2wfqqhrjdv9'
const NPUB_HEX = '84dee6e676e5bb67b4ad4e042cf70cbd8681155db535942fcc6a0533858a7240' // cross-checked against bcrypto's independent bech32
const NSEC = 'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5'

test('npub decodes to the spec vector', () => {
  assert.deepEqual(decodeNip19(NPUB), { type: 'npub', pubkey: NPUB_HEX })
})

test('an nsec is refused as a SECRET, not as unsupported', () => {
  const out = decodeNip19(NSEC)
  assert.ok(out.error, 'must not decode a private key into a resolvable target')
  assert.match(out.error, /PRIVATE KEY/)
  // The wording matters: someone who pasted their key needs to know it is a
  // secret, not that we lack a handler for it.
  assert.match(out.error, /not sent anywhere/i)
})

test('a corrupted checksum is rejected, not silently accepted', () => {
  const bad = NPUB.slice(0, -1) + (NPUB.endsWith('9') ? 'q' : '9')
  assert.ok(decodeNip19(bad).error)
})

test('mixed case is rejected per BIP-173', () => {
  assert.match(bech32Decode('npub1SN0Wdenkukak0d9dfczzeacvhkrgz92ak56egt7vdgzn8pv2wfqqhrjdv9').error, /mixed case/)
})

test('the 90-char BIP-173 limit is NOT applied — nostr routinely exceeds it', () => {
  // An nevent carrying an id, an author and two relay hints is >90 chars and
  // is perfectly valid. A limit-enforcing decoder would reject it.
  const long = buildNevent(NPUB_HEX, NPUB_HEX, ['wss://relay.example.com', 'wss://another.example.org'])
  assert.ok(long.length > 90, `test vector should exceed 90 chars, got ${long.length}`)
  const out = decodeNip19(long)
  assert.equal(out.error, undefined, out.error)
  assert.equal(out.type, 'nevent')
  assert.equal(out.id, NPUB_HEX)
  assert.equal(out.author, NPUB_HEX)
  assert.deepEqual(out.relays, ['wss://relay.example.com', 'wss://another.example.org'])
})

test("an nevent's kind TLV is read, so it can become part of the question", () => {
  const withKind = bech32Encode('nevent', Uint8Array.from([
    0, 32, ...Buffer.from(NPUB_HEX, 'hex'),
    2, 32, ...Buffer.from(NPUB_HEX, 'hex'),
    3, 4, 0x00, 0x00, 0x75, 0x53 // 30035, big-endian uint32 per NIP-19
  ]))
  const out = decodeNip19(withKind)
  assert.equal(out.error, undefined, out.error)
  assert.equal(out.type, 'nevent')
  assert.equal(out.id, NPUB_HEX)
  assert.equal(out.author, NPUB_HEX)
  assert.equal(out.kind, 30035)
})

test('a trailing byte that cannot begin a TLV is refused, not dropped', () => {
  // Two distinct byte strings must not decode to one target. Both would carry
  // a valid checksum, so this is strictness rather than a hole — and a decoder
  // that silently discards bytes is one that disagrees with another decoder.
  const stray = bech32Encode('nprofile', Uint8Array.from([
    0, 32, ...Buffer.from(NPUB_HEX, 'hex'), 0x01
  ]))
  const out = decodeNip19(stray)
  assert.match(out.error, /trailing bytes in TLV/)
})

test('a TLV whose declared length runs past the buffer is refused', () => {
  const truncated = bech32Encode('nprofile', Uint8Array.from([0, 32, 0xde, 0xad, 0xbe, 0xef]))
  assert.match(decodeNip19(truncated).error, /truncated TLV/)
})

test('an naddr with an empty `d` tag is legal and decodes', () => {
  const naddr = bech32Encode('naddr', Uint8Array.from([
    0, 0,
    2, 32, ...Buffer.from(NPUB_HEX, 'hex'),
    3, 4, 0x00, 0x00, 0x75, 0x53
  ]))
  const out = decodeNip19(naddr)
  assert.equal(out.error, undefined, out.error)
  assert.equal(out.type, 'naddr')
  assert.equal(out.identifier, '')
  assert.equal(out.pubkey, NPUB_HEX)
  assert.equal(out.kind, 30035)
})

test('nostr: and nostr:// and bare identifiers all parse', () => {
  for (const form of [`nostr:${NPUB}`, `nostr://${NPUB}`, NPUB, `NOSTR:${NPUB}`]) {
    assert.equal(parseNostrURI(form).pubkey, NPUB_HEX, `failed on ${form}`)
  }
})

test('a trailing path from Chromium does not break parsing', () => {
  assert.equal(parseNostrURI(`nostr://${NPUB}/`).pubkey, NPUB_HEX)
})

test('unknown prefixes fail closed', () => {
  assert.ok(decodeNip19('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4').error)
  assert.ok(decodeNip19('').error)
  assert.ok(decodeNip19(null).error)
})

// ---------------------------------------------------------------- events

/** A real signed event, built here so the test owns its own key material. */
function signedEvent (overrides = {}) {
  const sk = schnorr.utils.randomPrivateKey()
  const pubkey = Buffer.from(schnorr.getPublicKey(sk)).toString('hex')
  const base = {
    pubkey,
    created_at: 1700000000,
    kind: 1,
    tags: [],
    content: 'hello from a test',
    ...overrides
  }
  const id = eventId(base)
  const sig = Buffer.from(schnorr.sign(id, sk)).toString('hex')
  return { ...base, id, sig }
}

test('a correctly signed event verifies', () => {
  assert.deepEqual(verifyEvent(signedEvent()).ok, true)
})

test('a relay that alters content is caught by the id, before the signature', () => {
  const ev = signedEvent()
  const tampered = { ...ev, content: 'hello from a LIAR' }
  const out = verifyEvent(tampered)
  assert.equal(out.ok, false)
  assert.match(out.reason, /id does not match/)
})

test('a forged signature does not verify', () => {
  const ev = signedEvent()
  const other = signedEvent()
  const out = verifyEvent({ ...ev, sig: other.sig })
  assert.equal(out.ok, false)
  assert.match(out.reason, /does not verify/)
})

test('an event claiming someone else authored it does not verify', () => {
  const ev = signedEvent()
  const victim = signedEvent()
  // Swap the pubkey and recompute the id so the id check passes: the ONLY
  // thing standing between a relay and impersonation is the signature.
  const impersonation = { ...ev, pubkey: victim.pubkey }
  impersonation.id = eventId(impersonation)
  const out = verifyEvent(impersonation)
  assert.equal(out.ok, false)
  assert.match(out.reason, /does not verify/)
})

test('malformed events are rejected without throwing', () => {
  for (const bad of [null, {}, { pubkey: 'zz' }, { ...signedEvent(), tags: 'nope' },
    { ...signedEvent(), created_at: 'yesterday' }]) {
    const out = verifyEvent(bad)
    assert.equal(out.ok, false)
  }
})

// --------------------------------------------------------------- helpers

/** Minimal bech32 ENCODER, test-only, so the decoder is tested against
 *  independently constructed input rather than against itself. */
function buildNevent (idHex, authorHex, relays) {
  const tlv = []
  const push = (type, bytes) => { tlv.push(type, bytes.length, ...bytes) }
  push(0, Buffer.from(idHex, 'hex'))
  for (const r of relays) push(1, Buffer.from(r, 'utf8'))
  push(2, Buffer.from(authorHex, 'hex'))
  return bech32Encode('nevent', Uint8Array.from(tlv))
}

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
  const values = [...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]
  const mod = polymod(values) ^ 1
  const checksum = []
  for (let i = 0; i < 6; i++) checksum.push((mod >> (5 * (5 - i))) & 31)
  return hrp + '1' + [...data, ...checksum].map((v) => CHARSET[v]).join('')
}
