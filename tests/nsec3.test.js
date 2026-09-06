/*
 * Hashed denial (NSEC3, RFC 5155) — the proofs, and the ways they must fail.
 *
 * The reason this exists at all: since a signed zone's denial must be PROVEN
 * before the browser will downgrade to plaintext, a zone whose denials it
 * cannot read is a zone it must refuse. NSEC3 is not exotic — Namebase's
 * `hns`, the registry TLD every `pinner.hns`-shaped name hangs off, signs with
 * it — so "we only read NSEC" meant refusing a whole branch of the namespace
 * in order to protect it.
 *
 * The captured fixture below is REAL third-party material: `hns`'s own signer,
 * its own NSEC3 parameters, its own hashes. Nothing here was invented to make
 * an implementation look right, and the hash function was checked against that
 * zone before a line of proof logic was written — H("hns") is exactly the apex
 * NSEC3's owner label.
 *
 * As with nsec.js, permissiveness is the only real hazard, so most of what
 * follows is negative.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import {
  base32hexEncode, wireNameLower, nsec3Hash, ownerHashOf, nsec3Matches,
  nsec3Covers, nsec3ProvesNoData, nsec3ProvesNxdomain, nsec3ProvesDenial,
  closestEncloserProof, MAX_ITERATIONS
} from '../src/nsec3.js'
import { provesDenial } from '../src/denial.js'

const A = 1
const NS = 2
const SOA = 6
const TLSA = 52
const CNAME = 5
const PARAMS = { hashAlgorithm: 1, salt: Buffer.alloc(0), iterations: 0 }

/** base32hex label -> the raw bytes an NSEC3 next-hash field carries. */
function unb32 (label) {
  return ownerHashOf({ name: `${label}.hns` })
}

/**
 * The three NSEC3 records `hns` really returned for a nonexistent name on
 * 2026-09-04, in the shape src/hns/dns-query.js produces.
 */
const HNS_DENIAL = [
  { name: '293AQUAU56MEG6I3IGGJKKNLG21VI55F.hns', ...PARAMS, optOut: false, nextHashed: unb32('2COEBCPG36KASAF0VEJ4AFFBCOREULQ4'), types: new Set([NS, SOA, 46, 48, 51]) },
  { name: 'LH4GF6CU0PUS9AEKJKJ612IGO2D7R3T6.hns', ...PARAMS, optOut: false, nextHashed: unb32('LUJ5RATKLO2HO9MSRFTFRL7TGK4LF3O9'), types: new Set([NS, 43, 46]) },
  { name: 'TDA0R6K9C29BOIMM7M1MJ65IG1OCCGRQ.hns', ...PARAMS, optOut: false, nextHashed: unb32('TQU79VUVMH4UQSF4CBLQ1CKNOUFDUQ9G'), types: new Set([NS, 43, 46]) }
]

// ---------------------------------------------------------------------------
// the hash, checked against a zone that exists
// ---------------------------------------------------------------------------

test('the hash reproduces hns\'s own NSEC3 owner names', () => {
  // If this is wrong, every proof below is meaningless — so it is checked
  // against real published hashes rather than against itself.
  assert.equal(base32hexEncode(nsec3Hash('hns', PARAMS)),
    '293AQUAU56MEG6I3IGGJKKNLG21VI55F', 'the apex')
  assert.equal(base32hexEncode(nsec3Hash('pinner.hns', PARAMS)),
    'RUI42C03DHGMDURPVGVBF1A2INJTG89M', 'a delegation that exists')
})

test('hashing is case- and trailing-dot-insensitive', () => {
  const a = nsec3Hash('Pinner.HNS.', PARAMS)
  const b = nsec3Hash('pinner.hns', PARAMS)
  assert.equal(Buffer.compare(a, b), 0)
})

test('the wire form is length-prefixed labels and a root byte', () => {
  assert.deepEqual([...wireNameLower('hns')], [3, 0x68, 0x6e, 0x73, 0])
})

test('an unsupported hash algorithm computes nothing', () => {
  assert.equal(nsec3Hash('hns', { ...PARAMS, hashAlgorithm: 2 }), null)
})

test('an absurd iteration count is REFUSED, not computed', () => {
  // RFC 9276 §3.1: the work is the validator's to do, so an uncapped count is
  // a cost a hostile zone gets to impose on us.
  assert.equal(nsec3Hash('hns', { ...PARAMS, iterations: MAX_ITERATIONS + 1 }), null)
  assert.ok(nsec3Hash('hns', { ...PARAMS, iterations: MAX_ITERATIONS }))
  assert.equal(nsec3Hash('hns', { ...PARAMS, iterations: -1 }), null)
})

test('a non-base32hex owner label decodes to nothing', () => {
  assert.equal(ownerHashOf({ name: 'not-base32!.hns' }), null)
  assert.equal(ownerHashOf({}), null)
})

// ---------------------------------------------------------------------------
// matches / covers, in hashed space
// ---------------------------------------------------------------------------

test('an NSEC3 matches the name whose hash it is named after', () => {
  assert.equal(nsec3Matches(HNS_DENIAL[0], 'hns', PARAMS), true)
  assert.equal(nsec3Matches(HNS_DENIAL[0], 'pinner.hns', PARAMS), false)
})

test('an NSEC3 never proves the absence of the name it names', () => {
  assert.equal(nsec3Covers(HNS_DENIAL[0], 'hns', PARAMS), false)
})

test('a malformed NSEC3 covers nothing', () => {
  assert.equal(nsec3Covers({ name: 'X.hns', ...PARAMS }, 'a.hns', PARAMS), false)
  assert.equal(nsec3Covers(null, 'a.hns', PARAMS), false)
})

// ---------------------------------------------------------------------------
// the real denial
// ---------------------------------------------------------------------------

test('hns\'s real NSEC3 set proves a nonexistent name absent', () => {
  assert.equal(nsec3ProvesDenial(HNS_DENIAL, 'nosuchname9x.hns', A, 'hns'), true)
  assert.equal(nsec3ProvesNxdomain(HNS_DENIAL, 'nosuchname9x.hns', 'hns', PARAMS), true)
})

test('...and does NOT prove a name that exists absent', () => {
  // `pinner.hns` is a real delegation in that zone. A proof set that "proved"
  // it missing would be proving anything at all.
  assert.equal(nsec3ProvesDenial(HNS_DENIAL, 'pinner.hns', A, 'hns'), false)
})

test('the closest encloser proof finds the apex and the next closer name', () => {
  const proof = closestEncloserProof(HNS_DENIAL, 'nosuchname9x.hns', 'hns', PARAMS)
  assert.ok(proof)
  assert.equal(proof.encloser, 'hns')
  assert.equal(proof.nextCloser, 'nosuchname9x.hns')
})

// ---------------------------------------------------------------------------
// the opt-out trap
// ---------------------------------------------------------------------------

test('an OPT-OUT gap proves nothing — the classic NSEC3 mistake', () => {
  // RFC 5155 §6: an opt-out gap proves only that no SIGNED DELEGATION exists
  // in it. Unsigned delegations may be present and unproven, so reading it as
  // a denial of existence is exactly the hole an attacker wants when the thing
  // being denied is a TLSA record.
  const optOut = HNS_DENIAL.map((rr, i) => (i === 0 ? rr : { ...rr, optOut: true }))
  assert.equal(nsec3ProvesDenial(optOut, 'nosuchname9x.hns', A, 'hns'), false,
    'an opt-out gap was accepted as proof of non-existence')
})

// ---------------------------------------------------------------------------
// NODATA
// ---------------------------------------------------------------------------

test('NODATA: the name exists and its bitmap lacks the type', () => {
  const set = [{ ...HNS_DENIAL[0], types: new Set([A, SOA]) }]
  assert.equal(nsec3ProvesNoData(set, 'hns', TLSA, PARAMS), true)
})

test('NODATA is REFUSED when the bitmap contains the type', () => {
  const set = [{ ...HNS_DENIAL[0], types: new Set([A, TLSA, SOA]) }]
  assert.equal(nsec3ProvesNoData(set, 'hns', TLSA, PARAMS), false)
})

test('NODATA is REFUSED at a CNAME and at a delegation', () => {
  assert.equal(nsec3ProvesNoData(
    [{ ...HNS_DENIAL[0], types: new Set([CNAME]) }], 'hns', TLSA, PARAMS), false)
  assert.equal(nsec3ProvesNoData(
    [{ ...HNS_DENIAL[0], types: new Set([NS]) }], 'hns', TLSA, PARAMS), false)
})

// ---------------------------------------------------------------------------
// the shared gate
// ---------------------------------------------------------------------------

test('provesDenial routes an NSEC3 set to the hashed proofs', () => {
  assert.equal(provesDenial(HNS_DENIAL, 'nosuchname9x.hns', A, 'hns'), true)
  assert.equal(provesDenial(HNS_DENIAL, 'pinner.hns', A, 'hns'), false)
})

test('a MIXED set proves nothing — it is not one coherent proof', () => {
  // Records of both schemes in one answer is a broken signer or someone
  // splicing. Reading it as either would leave the other kind sitting there
  // unexamined, so the whole set is refused (src/hns/denial.js).
  const mixed = [
    ...HNS_DENIAL,
    { name: 'a.hns', nextName: 'z.hns', types: new Set([A]) }
  ]
  assert.equal(provesDenial(HNS_DENIAL, 'nosuchname9x.hns', A, 'hns'), true,
    'the NSEC3 set alone still proves')
  assert.equal(provesDenial(mixed, 'nosuchname9x.hns', A, 'hns'), false,
    'and adding one NSEC record to it must void the proof')
})

test('NSEC3 records with disagreeing parameters prove nothing', () => {
  const mixed = [HNS_DENIAL[0], { ...HNS_DENIAL[1], iterations: 5 }]
  assert.equal(nsec3ProvesDenial(mixed, 'nosuchname9x.hns', A, 'hns'), false)
})

test('an empty set proves nothing', () => {
  assert.equal(nsec3ProvesDenial([], 'a.hns', A, 'hns'), false)
  assert.equal(nsec3ProvesDenial(null, 'a.hns', A, 'hns'), false)
})

test('an NSEC3 with a Flags bit other than Opt-Out set is ignored (RFC 5155 §8.2), so it can prove nothing', async () => {
  const { usableNsec3 } = await import('../src/nsec3.js')
  assert.equal(usableNsec3(HNS_DENIAL[0]), true, 'flags absent = 0')
  assert.equal(usableNsec3({ ...HNS_DENIAL[0], flags: 1 }), true, 'opt-out alone is fine')
  assert.equal(usableNsec3({ ...HNS_DENIAL[0], flags: 2 }), false)
  assert.equal(usableNsec3({ ...HNS_DENIAL[0], flags: 3 }), false)
  const flagged = HNS_DENIAL.map((rr) => ({ ...rr, flags: 2 }))
  assert.equal(nsec3ProvesDenial(flagged, 'nosuchname9x.hns', A, 'hns'), false, 'a set of unusable records proves nothing')
})
