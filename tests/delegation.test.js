/*
 * Names sold UNDER a Handshake TLD: the delegation walk.
 *
 * A registry TLD does not hold the names it sells. `hns` answers a query for
 * `pinner.hns` with a REFERRAL to `ns1.lumeweb` — a nameserver whose name only
 * exists on Handshake — and the records live in that delegated zone. Before
 * 2026-09-04 the browser did exactly one authoritative hop, read the empty
 * answer section, and called every such name `unregistered`; `dns.lookup`
 * could not have found `ns1.lumeweb` even if it had followed.
 *
 * Two things have to hold for that to be safe rather than merely working:
 *
 *   1. A REFERRAL must be told apart from a NODATA. The SOA is the tell
 *      (RFC 1034 §4.3.2) — a zone that owns the name and has no record of
 *      that type returns its own SOA; a zone that delegated it returns the
 *      child's NS and no SOA. Reading a NODATA as a referral would send the
 *      browser off to re-ask a zone that already answered honestly.
 *
 *   2. The child must be ANCHORED, not merely reached. The parent publishes a
 *      DS for it, signed under the parent's own keys, which are anchored to
 *      the on-chain DS. Following a referral without checking that link hands
 *      every name under a registry TLD to whichever box the referral names,
 *      on nobody's authority.
 *
 * The DS fixture is VENDORED (tests/fixtures/hns-delegation.json) and is real
 * third-party material: Namebase's signer, `hns`'s own keys, the DS `hns`
 * publishes for `pinner.hns`. Its RRSIGs carry a fixed window, so the clock is
 * pinned inside it exactly as dnssec.test.js does — otherwise this file turns
 * red on an expiry date for a reason that is not a defect. Refresh it by
 * re-capturing DNSKEY at `hns` and DS at `pinner.hns` from ns1.namebase.io.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { validateDsAt } from '../src/dnssec.js'
import { referralIn, HNSResolver } from '../src/resolver.js'
import { TYPES } from '../src/dns-query.js'

const fixturePath = path.join(
  path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'hns-delegation.json')

/** Buffers survive the fixture as {b64}; put them back. */
function revive (value) {
  if (Array.isArray(value)) return value.map(revive)
  if (value && typeof value === 'object') {
    if (typeof value.b64 === 'string') return Buffer.from(value.b64, 'base64')
    const out = {}
    for (const [k, v] of Object.entries(value)) out[k] = revive(v)
    return out
  }
  return value
}

function load () {
  const raw = revive(JSON.parse(fs.readFileSync(fixturePath, 'utf8')))
  const dnskeys = raw.dnskeyAnswers.filter((r) => r.type === TYPES.DNSKEY)
  const dnskeyRRSIG = raw.dnskeyAnswers.find(
    (r) => r.type === TYPES.RRSIG && r.typeCovered === TYPES.DNSKEY)
  const childDs = raw.dsAnswers.filter((r) => r.type === TYPES.DS)
  const childDsRRSIG = raw.dsAnswers.find(
    (r) => r.type === TYPES.RRSIG && r.typeCovered === TYPES.DS)
  return { raw, dnskeys, dnskeyRRSIG, childDs, childDsRRSIG }
}

/** A clock inside the fixture's own RRSIG window. Production never picks one. */
function insideWindow (rrsig) {
  const at = Math.floor((rrsig.inception + rrsig.expiration) / 2)
  assert.ok(at > rrsig.inception && at < rrsig.expiration)
  return at
}

const ns = (name, target) => ({ name, type: TYPES.NS, target })
const soa = (name) => ({ name, type: TYPES.SOA, rdata: '00' })

// ---------------------------------------------------------------------------
// 1. referral vs NODATA
// ---------------------------------------------------------------------------

test('a referral below the zone, toward the host, is followed', () => {
  const found = referralIn({
    answers: [],
    authority: [ns('pinner.hns', 'ns1.lumeweb'), ns('pinner.hns', 'ns2.lumeweb')]
  }, 'hns', 'pinner.hns')
  assert.deepEqual(found, { child: 'pinner.hns', targets: ['ns1.lumeweb', 'ns2.lumeweb'] })
})

test('a referral is still a referral for a name deeper than the delegation', () => {
  const found = referralIn({
    answers: [],
    authority: [ns('pinner.hns', 'ns1.lumeweb')]
  }, 'hns', 'www.pinner.hns')
  assert.deepEqual(found, { child: 'pinner.hns', targets: ['ns1.lumeweb'] })
})

test('NODATA is NOT a referral — the SOA says this zone owns the name', () => {
  assert.equal(referralIn({
    answers: [],
    authority: [soa('14898'), ns('14898', 'ns1.hns.one')]
  }, '14898', 'hello.14898'), null)
})

test('an answer present is never a referral', () => {
  assert.equal(referralIn({
    answers: [{ name: 'hello.14898', type: TYPES.TXT, txt: ['ipfs=x'] }],
    authority: [ns('sub.14898', 'ns1.elsewhere')]
  }, '14898', 'hello.14898'), null)
})

test('a sideways delegation is refused — a zone cannot delegate what it does not hold', () => {
  // The zone answering is `hns`, the name asked about is `pinner.hns`, and the
  // authority section names a zone that is neither. Following it would be a
  // redirect to somewhere the browser never asked about.
  assert.equal(referralIn({
    answers: [],
    authority: [ns('evil.example', 'ns1.attacker')]
  }, 'hns', 'pinner.hns'), null)
})

test('a delegation NOT under the answering zone is refused', () => {
  assert.equal(referralIn({
    answers: [],
    authority: [ns('other.tld', 'ns1.attacker')]
  }, 'hns', 'pinner.hns'), null)
})

test('a delegation that is not an ancestor of the host is refused', () => {
  assert.equal(referralIn({
    answers: [],
    authority: [ns('sibling.hns', 'ns1.attacker')]
  }, 'hns', 'pinner.hns'), null)
})

test('the zone re-delegating to ITSELF is not a referral (no infinite descent)', () => {
  assert.equal(referralIn({
    answers: [],
    authority: [ns('hns', 'ns1.namebase.io')]
  }, 'hns', 'pinner.hns'), null)
})

// ---------------------------------------------------------------------------
// 2. the DS link that anchors the child
// ---------------------------------------------------------------------------

test('the real DS hns publishes for pinner.hns verifies under the on-chain anchor', () => {
  const { raw, dnskeys, dnskeyRRSIG, childDs, childDsRRSIG } = load()
  const result = validateDsAt(insideWindow(childDsRRSIG), {
    dsRecords: raw.chainDs,
    dnskeys,
    dnskeyRRSIG,
    parentZone: raw.parentZone,
    childOwner: raw.childOwner,
    childDs,
    childDsRRSIG
  })
  assert.equal(result.ok, true, result.reason)
})

test('a DS whose digest was tampered with does NOT verify', () => {
  const { raw, dnskeys, dnskeyRRSIG, childDs, childDsRRSIG } = load()
  const forged = childDs.map((d) => {
    const rdataRaw = Buffer.from(d.rdataRaw)
    rdataRaw[rdataRaw.length - 1] ^= 0xff
    return { ...d, rdataRaw }
  })
  const result = validateDsAt(insideWindow(childDsRRSIG), {
    dsRecords: raw.chainDs,
    dnskeys,
    dnskeyRRSIG,
    parentZone: raw.parentZone,
    childOwner: raw.childOwner,
    childDs: forged,
    childDsRRSIG
  })
  assert.equal(result.ok, false)
})

test('an UNSIGNED DS RRset is refused — a delegation nobody vouched for', () => {
  const { raw, dnskeys, dnskeyRRSIG, childDs, childDsRRSIG } = load()
  const result = validateDsAt(insideWindow(childDsRRSIG), {
    dsRecords: raw.chainDs,
    dnskeys,
    dnskeyRRSIG,
    parentZone: raw.parentZone,
    childOwner: raw.childOwner,
    childDs,
    childDsRRSIG: null
  })
  assert.equal(result.ok, false)
})

test('a DS signed for a DIFFERENT child does not verify for this one', () => {
  const { raw, dnskeys, dnskeyRRSIG, childDs, childDsRRSIG } = load()
  const result = validateDsAt(insideWindow(childDsRRSIG), {
    dsRecords: raw.chainDs,
    dnskeys,
    dnskeyRRSIG,
    parentZone: raw.parentZone,
    childOwner: 'attacker.hns',
    childDs,
    childDsRRSIG
  })
  assert.equal(result.ok, false)
})

test('the parent DNSKEY must itself match the on-chain DS', () => {
  const { raw, dnskeys, dnskeyRRSIG, childDs, childDsRRSIG } = load()
  const wrongAnchor = raw.chainDs.map((d) => ({ ...d, digest: 'ab'.repeat(32) }))
  const result = validateDsAt(insideWindow(childDsRRSIG), {
    dsRecords: wrongAnchor,
    dnskeys,
    dnskeyRRSIG,
    parentZone: raw.parentZone,
    childOwner: raw.childOwner,
    childDs,
    childDsRRSIG
  })
  assert.equal(result.ok, false)
  assert.match(result.reason, /DNSKEY/)
})

test('an RRSIG outside its validity window does not verify', () => {
  const { raw, dnskeys, dnskeyRRSIG, childDs, childDsRRSIG } = load()
  const args = {
    dsRecords: raw.chainDs,
    dnskeys,
    dnskeyRRSIG,
    parentZone: raw.parentZone,
    childOwner: raw.childOwner,
    childDs,
    childDsRRSIG
  }
  assert.equal(validateDsAt(childDsRRSIG.expiration + 1, args).ok, false)
  assert.equal(validateDsAt(childDsRRSIG.inception - 1, args).ok, false)
})

// ---------------------------------------------------------------------------
// 3. a nameserver that is itself a Handshake name
// ---------------------------------------------------------------------------

/** An SPV stub that answers getResource from a fixed table. */
function stubSpv (table) {
  return {
    async getResource (tld) {
      return Object.prototype.hasOwnProperty.call(table, tld) ? table[tld] : null
    },
    async isSynced () { return true }
  }
}

test('glue handed to us wins over every lookup', async () => {
  const r = new HNSResolver({ spv: stubSpv({}) })
  const address = await r._addressForNsHost('ns1.lumeweb', [
    { type: 'GLUE4', ns: 'ns1.lumeweb.', address: '203.0.113.7' }
  ])
  assert.equal(address, '203.0.113.7')
})

test('a nameserver under a Handshake TLD resolves from that TLD chain glue', async () => {
  // ns1.lumeweb has no address in ICANN DNS at all. Its address is published
  // as GLUE4 on the `lumeweb` chain resource, which is the only place to look
  // and the reason this path exists.
  const r = new HNSResolver({
    spv: stubSpv({
      lumeweb: {
        records: [
          { type: 'NS', ns: 'ns1.lumeweb.' },
          { type: 'GLUE4', ns: 'ns1.lumeweb.', address: '198.51.100.9' }
        ]
      }
    })
  })
  assert.equal(await r._addressForNsHost('ns1.lumeweb', []), '198.51.100.9')
})

test('a SYNTH4 apex is an address for the nameserver named by it', async () => {
  const r = new HNSResolver({
    spv: stubSpv({ solo: { records: [{ type: 'SYNTH4', address: '198.51.100.22' }] } })
  })
  assert.equal(await r._chainAddress('solo'), '198.51.100.22')
})

test('an unregistered TLD yields nothing from the chain — ICANN owns the question', async () => {
  // `one`, `io`, `com`: real ICANN TLDs, no chain records. The chain must say
  // "not mine" rather than answer, or a Handshake browser would shadow ICANN.
  const r = new HNSResolver({ spv: stubSpv({}) })
  assert.equal(await r._chainAddress('ns1.hns.one'), null)
})

test('a chain resource with no glue and no usable NS yields nothing', async () => {
  const r = new HNSResolver({
    spv: stubSpv({ empty: { records: [{ type: 'NS', ns: 'ns1.empty.' }] } })
  })
  // The only nameserver IS the host we are trying to address; resolving it
  // through itself is the loop this guards against.
  assert.equal(await r._chainAddress('ns1.empty'), null)
})
