// DANE certificate validation.
//
// Fixtures are checked in (fixtures/certs.js) rather than generated with the
// openssl CLI, because that CLI is absent on Windows — which silently removed
// every one of these tests from the platform we ship. See that file's header.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { X509Certificate } from 'node:crypto'

import { verifyDane } from '../src/dane.js'
import { MATCHING, OTHER, EXPIRED } from './fixtures/certs.js'

const tlsa = (hash, over = {}) => ({
  usage: 3, selector: 1, matchingType: 1, certificate: hash, ...over
})

test('verified for a matching 3 1 1 SPKI hash', () => {
  assert.equal(verifyDane(MATCHING.pem, [tlsa(MATCHING.spki)]).state, 'verified')
})

test('mismatch for a wrong hash', () => {
  const r = verifyDane(MATCHING.pem, [tlsa(OTHER.spki)])
  assert.equal(r.state, 'tlsa_mismatch')
  assert.match(r.detail, /matches none/)
})

test('no_tlsa when the zone publishes nothing', () => {
  assert.equal(verifyDane(MATCHING.pem, []).state, 'no_tlsa')
  assert.equal(verifyDane(MATCHING.pem, null).state, 'no_tlsa')
})

test('unsupported TLSA profile fails closed, not open', () => {
  // Usage 1 (PKIX-EE) is a profile we do not implement. Reading that as "no
  // pinning" would let a zone's stated policy be ignored by an implementation
  // gap — the exact shape of a downgrade.
  for (const over of [{ usage: 1 }, { usage: 2 }, { selector: 0 }, { matchingType: 2 }]) {
    const r = verifyDane(MATCHING.pem, [tlsa(MATCHING.spki, over)])
    assert.equal(r.state, 'tlsa_mismatch', `profile ${JSON.stringify(over)} must fail closed`)
  }
})

test('a supported record is used even when unsupported ones sit beside it', () => {
  const records = [tlsa(MATCHING.spki, { usage: 1 }), tlsa(MATCHING.spki)]
  assert.equal(verifyDane(MATCHING.pem, records).state, 'verified')
})

test('matching is case-insensitive on the hex hash', () => {
  assert.equal(verifyDane(MATCHING.pem, [tlsa(MATCHING.spki.toUpperCase())]).state, 'verified')
})

test('garbage certificate is cert_invalid', () => {
  const r = verifyDane(Buffer.from('not a cert'), [tlsa(MATCHING.spki)])
  assert.equal(r.state, 'cert_invalid')
})

test('DANE-EE ignores PKIX expiry (RFC 7671 §5.1): a lapsed pinned cert verifies', () => {
  // This fixture is REALLY expired — notAfter 2020-01-02 — and shares its key
  // with MATCHING, so the pin still matches and the only difference is the
  // date. The old version of this test could not build an expired certificate
  // and settled for asserting that a valid one verified, which proved nothing.
  const cert = new X509Certificate(EXPIRED.pem)
  assert.ok(Date.parse(cert.validTo) < Date.now(), 'fixture must be expired')
  assert.equal(verifyDane(EXPIRED.pem, [tlsa(EXPIRED.spki)]).state, 'verified')
})

test('an expired cert with the WRONG pin still fails — expiry is ignored, the pin is not', () => {
  assert.equal(verifyDane(EXPIRED.pem, [tlsa(OTHER.spki)]).state, 'tlsa_mismatch')
})
