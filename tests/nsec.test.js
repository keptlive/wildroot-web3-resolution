/*
 * Authenticated denial of existence — the proofs, and the ways they must fail.
 *
 * This is the piece the codebase deliberately deferred ("rather than half-build
 * security-critical crypto, this is left as the next step"), and it is what two
 * documented limitations were both waiting on:
 *
 *   - a forged NXDOMAIN at `_443._tcp.<host>` stripped a real TLSA and forced
 *     plaintext, because the denial was trusted without proof;
 *   - a wildcard-expanded answer could not be authenticated at all, because
 *     RFC 4035 §5.3.4 requires exactly these steps.
 *
 * It is ordering logic, not cryptography — the RRSIGs over these NSEC records
 * are checked by dnssec.js like any other RRset. The only real hazard is being
 * permissive, so most of what follows is negative: proofs that look plausible
 * and must be refused.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

import {
  canonicalCompareNames, nsecCovers, nsecMatches, provesNoData, provesNxdomain,
  closestEncloser, isUnder, parentOf
} from '../src/nsec.js'
import { provesDenial } from '../src/denial.js'
import { HNSResolver } from '../src/resolver.js'
import { dsDigest, dnskeyRdata } from '../src/dnssec.js'
import { TYPES } from '../src/dns-query.js'
import { freeUdpPort } from './free-port.js'
import { FIXTURE, withNsd as runNsd } from './nsd.js'

const PORT = await freeUdpPort()
const A = TYPES.A
const TXT = TYPES.TXT
const TLSA = TYPES.TLSA
const CNAME = TYPES.CNAME
const NS = TYPES.NS
const SOA = TYPES.SOA

/** An NSEC record in the shape src/hns/dns-query.js produces. */
const nsec = (name, nextName, types = [A, TXT]) => ({
  name, type: TYPES.NSEC, nextName, types: new Set(types), rdataRaw: Buffer.alloc(4)
})

// ---------------------------------------------------------------------------
// RFC 4034 §6.1 — canonical name order
// ---------------------------------------------------------------------------

test('names sort by their RIGHTMOST label first', () => {
  // The whole ordering rests on this. Comparing left-to-right would put
  // `z.a.example` after `a.b.example`, and every "covers" test would be wrong.
  assert.ok(canonicalCompareNames('z.a.example', 'a.b.example') < 0)
  assert.ok(canonicalCompareNames('a.b.example', 'z.a.example') > 0)
})

test('a shorter name sorts before a longer one that extends it', () => {
  assert.ok(canonicalCompareNames('a.example', 'b.a.example') < 0)
  assert.ok(canonicalCompareNames('example', 'a.example') < 0)
})

test('comparison ignores case and the trailing root dot', () => {
  assert.equal(canonicalCompareNames('A.Example', 'a.example'), 0)
  assert.equal(canonicalCompareNames('a.example.', 'a.example'), 0)
})

test('`*` sorts before any letter, which is why wildcards need their own proof', () => {
  assert.ok(canonicalCompareNames('*.example', 'a.example') < 0)
})

test('isUnder and parentOf agree about the tree', () => {
  assert.equal(isUnder('a.b.example', 'b.example'), true)
  assert.equal(isUnder('b.example', 'b.example'), true)
  assert.equal(isUnder('b.example', 'a.b.example'), false)
  assert.equal(isUnder('notexample', 'example'), false)
  assert.equal(parentOf('a.b.example'), 'b.example')
  assert.equal(parentOf('example'), '')
})

// ---------------------------------------------------------------------------
// covers / matches
// ---------------------------------------------------------------------------

test('an NSEC covers the gap strictly between its owner and its next name', () => {
  const n = nsec('a.example', 'd.example')
  assert.equal(nsecCovers(n, 'b.example'), true)
  assert.equal(nsecCovers(n, 'd.example'), false, 'the next name EXISTS')
  assert.equal(nsecCovers(n, 'e.example'), false)
})

test('an NSEC NEVER proves the absence of the name it is named after', () => {
  // It asserts that name exists — the opposite claim. Getting this backwards
  // would let any NSEC "prove" its own owner missing.
  const n = nsec('a.example', 'd.example')
  assert.equal(nsecCovers(n, 'a.example'), false)
  assert.equal(nsecMatches(n, 'a.example'), true)
})

test('the last NSEC of a zone wraps, and covers everything after its owner', () => {
  const last = nsec('z.example', 'example')
  assert.equal(nsecCovers(last, 'zz.example'), true)
  assert.equal(nsecCovers(last, 'b.example'), false, 'b sorts before z, not after')
})

test('a malformed NSEC covers nothing', () => {
  assert.equal(nsecCovers(null, 'a.example'), false)
  assert.equal(nsecCovers({ name: 'a.example' }, 'b.example'), false)
})

// ---------------------------------------------------------------------------
// NODATA
// ---------------------------------------------------------------------------

test('NODATA: the name exists and its bitmap lacks the type', () => {
  const set = [nsec('host.example', 'next.example', [A, TXT])]
  assert.equal(provesNoData(set, 'host.example', TLSA), true)
})

test('NODATA is REFUSED when the bitmap contains the type', () => {
  // The zone says the record is there. An empty answer for it is a lie, and
  // accepting this would be the TLSA-stripping downgrade all over again.
  const set = [nsec('host.example', 'next.example', [A, TLSA])]
  assert.equal(provesNoData(set, 'host.example', TLSA), false)
})

test('NODATA is REFUSED when a CNAME sits at the name', () => {
  // A CNAME means the answer should have been a redirect, not an empty set.
  const set = [nsec('host.example', 'next.example', [CNAME])]
  assert.equal(provesNoData(set, 'host.example', TLSA), false)
})

test('NODATA is REFUSED at a DELEGATION — that name is not this zone to answer for', () => {
  const set = [nsec('sub.example', 'next.example', [NS])]
  assert.equal(provesNoData(set, 'sub.example', TLSA), false)
  // ...but an NS *with* SOA is the apex, which is the zone itself.
  const apex = [nsec('example', 'a.example', [NS, SOA, A])]
  assert.equal(provesNoData(apex, 'example', TLSA), true)
})

test('NODATA is REFUSED when no NSEC names the queried name at all', () => {
  const set = [nsec('other.example', 'next.example', [A])]
  assert.equal(provesNoData(set, 'host.example', TLSA), false)
})

// ---------------------------------------------------------------------------
// NXDOMAIN — both halves, always
// ---------------------------------------------------------------------------

test('NXDOMAIN needs the name covered AND the wildcard covered', () => {
  // One NSEC often does both, which is the common real case: our own zone's
  // denial for `_443._tcp.hello.14898` is a single record covering the name
  // and `*.hello.14898` together.
  const set = [nsec('hello.example', 'hnsone.example')]
  assert.equal(provesNxdomain(set, '_443._tcp.hello.example', 'example'), true)
})

test('NXDOMAIN is REFUSED when only the NAME is covered and a wildcard could still have answered', () => {
  // The half-proof an attacker can produce by withholding the second NSEC.
  // The zone may well hold `*.example`; "this exact name is absent" says
  // nothing about that.
  const set = [nsec('m.example', 'z.example')]
  assert.equal(nsecCovers(set[0], 'n.example'), true, 'the name IS covered')
  assert.equal(provesNxdomain(set, 'n.example', 'example'), false,
    'and that alone must not be enough')
})

test('NXDOMAIN is REFUSED when the wildcard demonstrably EXISTS', () => {
  // If `*.example` exists, the server should have synthesised an answer from
  // it. An NXDOMAIN was the wrong reply, so the proof fails rather than passes.
  const set = [
    nsec('m.example', 'z.example'),
    nsec('*.example', 'a.example', [A])
  ]
  assert.equal(provesNxdomain(set, 'n.example', 'example'), false)
})

test('NXDOMAIN is REFUSED when nothing covers the name', () => {
  const set = [nsec('a.example', 'b.example')]
  assert.equal(provesNxdomain(set, 'zzz.example', 'example'), false)
})

test('the closest encloser comes from a name the NSEC shows to exist', () => {
  const n = nsec('hello.example', 'hnsone.example')
  assert.equal(closestEncloser(n, '_443._tcp.hello.example'), 'hello.example')
})

// ---------------------------------------------------------------------------
// the combined gate
// ---------------------------------------------------------------------------

test('no NSEC records at all proves nothing', () => {
  assert.equal(provesDenial([], 'a.example', TLSA, 'example'), false)
  assert.equal(provesDenial(null, 'a.example', TLSA, 'example'), false)
})

test('a DNAME in the set makes the whole thing unreasonable-about, so it is refused', () => {
  const set = [{ ...nsec('a.example', 'z.example'), types: new Set([39]) }]
  assert.equal(provesDenial(set, 'b.example', TLSA, 'example'), false)
})

// ---------------------------------------------------------------------------
// end to end, against the frozen SIGNED fixture
// ---------------------------------------------------------------------------

const withNsd = (fn) => runNsd({ port: PORT }, fn)

function anchorFor () {
  const signed = JSON.parse(fs.readFileSync(FIXTURE.signed, 'utf8'))
  const raw = Buffer.from(signed.dnskey, 'base64').subarray(4)
  return {
    type: 'DS',
    keyTag: signed.key_tag,
    algorithm: 13,
    digestType: 2,
    digest: dsDigest(signed.zone, dnskeyRdata(raw, 257))
  }
}

const resolverWith = (records) => new HNSResolver({
  spv: { getResource: async () => ({ records }), isSynced: async () => true },
  authoritative: { server: '127.0.0.1', port: PORT },
  timeout: 5000
})

test('a SIGNED zone that proves it has no pin may still be loaded in clear', () =>
  withNsd(async () => {
    // This is the behaviour that must NOT regress: our own nameserver sends a
    // proper signed NSEC, so the denial is real and plaintext stays allowed.
    const out = await resolverWith([{ type: 'NS', ns: 'ns1.hns.one.' }, anchorFor()])
      .resolve(FIXTURE.noTlsaHost)
    assert.equal(out.kind, 'site')
    assert.equal(out.allowInsecure, true, 'a PROVEN denial was refused')
    assert.equal(out.dnssecAnchored, true)
  }))

test('an UNSIGNED zone is unaffected — there is no guarantee to downgrade from', () =>
  withNsd(async () => {
    const out = await resolverWith([{ type: 'NS', ns: 'ns1.hns.one.' }])
      .resolve(FIXTURE.noTlsaHost)
    assert.equal(out.kind, 'site')
    assert.equal(out.allowInsecure, true)
  }))

test('an NSEC with no signature over it is not usable as proof', () =>
  withNsd(async () => {
    // The security property in one line: an unverified NSEC is an assertion by
    // whoever answered, which is the party a forged denial comes from.
    const r = resolverWith([{ type: 'NS', ns: 'ns1.hns.one.' }, anchorFor()])
    const usable = await r._validatedNsecs(
      [nsec('host.wrfixture', 'next.wrfixture')],
      { dsRecords: [anchorFor()], fetchDnskeys: async () => ({ dnskeys: [], dnskeyRRSIG: null }) })
    assert.deepEqual(usable, [], 'an unsigned NSEC was accepted as proof')
    assert.equal(provesDenial(usable, '_443._tcp.host.wrfixture', TLSA, 'wrfixture'), false)
  }))
