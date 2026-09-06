/*
 * The onion ADDRESS: what the implementation checks, and where that check is
 * allowed to matter.
 *
 * `isValidV3Onion` (../../../src/router.js) implements rend-spec-v3 §6 in
 * full: the 56 base32 characters decode to 35 bytes that are
 * PUBKEY(32) ‖ CHECKSUM(2) ‖ VERSION(1), the version byte is 0x03, and the
 * checksum is SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)[:2].
 *
 * This file pins both halves:
 *   1. every .onion host — well-formed or not — is classified into the Tor
 *      namespace and never into DNS, because validity MUST NOT gate routing;
 *   2. the validator agrees, address for address, with a test-local reference
 *      decoder written independently from rend-spec-v3. That decoder is an
 *      ORACLE FOR THIS TEST ONLY — it is deliberately not in src/, so the
 *      implementation is checked against the specification rather than
 *      against itself.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import { classify, classifyHost, isOnionHost, isValidV3Onion, NAMESPACES } from '../../../src/router.js'
import { isHnsHost, isReservedHost, reservedNamespaceScheme, rewriteToHns } from '../../../src/hns-host.js'

// Two real, published v3 onion services. Used as vectors, never contacted.
const NYT = 'p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion'
const DDG = 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion'
// 56 legal base32 characters that are NOT a v3 address: version byte 0x00,
// checksum 0x0000 against a required 0x6bf7. It is the shape of an address
// without being one, which is exactly the case the checksum exists to catch.
const SHAPED_BUT_INVALID = 'a'.repeat(56) + '.onion'

// --- a reference decoder, per rend-spec-v3 §6 (ORACLE — not the implementation)

const B32 = 'abcdefghijklmnopqrstuvwxyz234567' // RFC 4648 §6, lower-cased

function base32Decode (s) {
  let bits = ''
  for (const c of s.toLowerCase()) {
    const i = B32.indexOf(c)
    if (i < 0) return null
    bits += i.toString(2).padStart(5, '0')
  }
  const out = []
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2))
  return Buffer.from(out)
}

/** Full rend-spec-v3 §6 validation: length, decode, version, checksum. */
function decodeV3Onion (host) {
  const label = String(host || '').toLowerCase().replace(/\.onion$/, '')
  if (label.length !== 56) return { ok: false, reason: 'length' }
  const raw = base32Decode(label)
  if (!raw || raw.length !== 35) return { ok: false, reason: 'base32' }
  const pubkey = raw.subarray(0, 32)
  const checksum = raw.subarray(32, 34)
  const version = raw[34]
  const want = createHash('sha3-256')
    .update(Buffer.concat([Buffer.from('.onion checksum'), pubkey, Buffer.from([version])]))
    .digest().subarray(0, 2)
  if (version !== 3) return { ok: false, reason: 'version', version }
  if (!checksum.equals(want)) return { ok: false, reason: 'checksum', got: checksum.toString('hex'), want: want.toString('hex') }
  return { ok: true, version, pubkey }
}

// --- 1. what the implementation does check ---------------------------------

test('a v3 address is length, alphabet, version byte and checksum', () => {
  assert.equal(isValidV3Onion(NYT), true)
  assert.equal(isValidV3Onion(DDG), true)
  assert.equal(isValidV3Onion('short.onion'), false)
  assert.equal(isValidV3Onion('example.com'), false)
  // v2 (16 characters) is dead and is NOT accepted as valid.
  assert.equal(isValidV3Onion('expyuzz4wqqyqhjn.onion'), false)
  // Case is folded: an address typed in capitals is still the same address.
  assert.equal(isValidV3Onion(NYT.toUpperCase()), true)
  // A character outside the RFC 4648 §6 alphabet (base32 has no 0/1/8/9).
  assert.equal(isValidV3Onion('0'.repeat(56) + '.onion'), false)
})

test('isOnionHost matches the suffix only — a malformed onion is still an onion', () => {
  assert.equal(isOnionHost(NYT), true)
  assert.equal(isOnionHost('typod.onion'), true)
  assert.equal(isOnionHost('onion.example.com'), false)
  assert.equal(isOnionHost(''), false)
  assert.equal(isOnionHost(null), false)
})

// --- 2. RFC 7686: .onion is never a DNS name, never a Handshake name -------

test('every .onion host classifies to the Tor namespace, valid or not', () => {
  for (const host of [NYT, DDG, SHAPED_BUT_INVALID, 'short.onion', 'typod.onion', 'a.b.onion', 'ONION.ONION']) {
    assert.equal(classifyHost(host), NAMESPACES.TOR, host)
  }
})

test('a bare onion address becomes onion://, never a resolver query', () => {
  const c = classify(NYT)
  assert.equal(c.namespace, NAMESPACES.TOR)
  assert.equal(c.scheme, 'onion')
  assert.equal(c.url, `onion://${NYT}`)
  assert.equal(c.reason, 'onion-host')
  assert.equal(c.validV3, true)
})

test('a MALFORMED onion stays in Tor too — a typo leaks as well as a real address', () => {
  const c = classify('obviously-not-a-real-onion.onion')
  assert.equal(c.namespace, NAMESPACES.TOR)
  assert.equal(c.scheme, 'onion')
  assert.equal(c.url.startsWith('onion://'), true)
  assert.equal(c.validV3, false)
})

test('RFC 7686: onion is a reserved name and is never a Handshake host', () => {
  assert.equal(isReservedHost(NYT), true)
  assert.equal(isReservedHost('typod.onion'), true)
  assert.equal(isReservedHost('onion'), true)
  assert.equal(isHnsHost(NYT), false)
  assert.equal(isHnsHost('typod.onion'), false)
  assert.equal(reservedNamespaceScheme(NYT), 'onion')
})

test('an http(s) URL on an onion host is rewritten into onion://, not hns://', () => {
  assert.equal(rewriteToHns(`http://${NYT}/`), `onion://${NYT}/`)
  assert.equal(rewriteToHns(`https://${NYT}/a?b=1#c`), `onion://${NYT}/a?b=1#c`)
  assert.equal(rewriteToHns('http://typod.onion/x'), 'onion://typod.onion/x')
})

test('a Handshake name whose LABEL is "onion" is still Handshake', () => {
  // Only the FINAL label is reserved. `onion.w3` is a Handshake name (and so
  // is `onion.14898` with numeric names on — off by default since 2026-09-06).
  assert.equal(classifyHost('onion.w3'), NAMESPACES.HNS)
  assert.equal(isReservedHost('onion.14898'), false)
})

// --- 3. the validator against the specification ----------------------------

test('the reference decoder accepts two real v3 addresses (the oracle is sound)', () => {
  for (const host of [NYT, DDG]) {
    const d = decodeV3Onion(host)
    assert.equal(d.ok, true, `${host}: ${d.reason}`)
    assert.equal(d.version, 3)
    assert.equal(d.pubkey.length, 32)
  }
})

test('the version byte and the checksum are verified (rend-spec-v3 §6)', () => {
  // 56 legal base32 characters, so the shape half passes...
  assert.equal(/^[a-z2-7]{56}\.onion$/.test(SHAPED_BUT_INVALID), true)
  // ...and the address is still refused, because it is not a v3 address at
  // all: the reference decoder puts the failure at the version byte.
  assert.equal(isValidV3Onion(SHAPED_BUT_INVALID), false)
  const d = decodeV3Onion(SHAPED_BUT_INVALID)
  assert.equal(d.ok, false)
  assert.equal(d.reason, 'version')
  assert.equal(d.version, 0)
  // With the version byte fixed the checksum still does not match, so the
  // second check is doing work of its own rather than shadowing the first.
  const raw = base32Decode('a'.repeat(56))
  raw[34] = 3
  const want = createHash('sha3-256')
    .update(Buffer.concat([Buffer.from('.onion checksum'), raw.subarray(0, 32), Buffer.from([3])]))
    .digest().subarray(0, 2)
  assert.notEqual(raw.subarray(32, 34).toString('hex'), want.toString('hex'))
})

test('one flipped character in a real address is caught by the checksum', () => {
  // A single-character typo is exactly what the checksum exists to catch, and
  // it is the case a shape test cannot see.
  const typo = NYT.replace(/^p/, 'q')
  assert.equal(/^[a-z2-7]{56}\.onion$/.test(typo), true, 'the shape is intact')
  assert.equal(isValidV3Onion(typo), false, 'the checksum is not')
  assert.equal(decodeV3Onion(typo).reason, 'checksum')
})

test('the validator and the reference decoder agree on every generated label', () => {
  // Stated as a property: 56 legal base32 characters are not an onion address,
  // and the implementation reaches the same verdict as the specification on
  // each one, locally, without spending a circuit to find out.
  let accepted = 0
  let real = 0
  for (let i = 0; i < 32; i++) {
    const label = Array.from({ length: 56 }, (_, j) => B32[(i * 7 + j * 13) % 32]).join('')
    const host = `${label}.onion`
    assert.equal(isValidV3Onion(host), decodeV3Onion(host).ok, host)
    if (isValidV3Onion(host)) accepted++
    if (decodeV3Onion(host).ok) real++
  }
  assert.equal(real, 0, 'not one of them is a v3 onion address')
  assert.equal(accepted, 0, 'and not one of them is accepted')
})

test('validity is computed for the caller but never decides the namespace', () => {
  // R3: an invalid address is still a Tor address. The flag rides along on the
  // classification so the handler can refuse locally; it does not route.
  const bad = classify(SHAPED_BUT_INVALID)
  assert.equal(bad.namespace, NAMESPACES.TOR)
  assert.equal(bad.validV3, false)
  assert.equal(classify(NYT).validV3, true)
})
