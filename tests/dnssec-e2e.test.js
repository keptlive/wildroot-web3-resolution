/*
 * End-to-end DNSSEC through the resolver, against a FROZEN signed zone.
 *
 * A stub SPV node supplies a chain resource carrying the on-chain DS, a live
 * nsd.py serves the real signed zone, and the resolver must validate the TLSA
 * pin up to that DS over actual DNS-over-TCP with the DO bit — and must FAIL
 * CLOSED when the DS does not match.
 *
 * WHY THIS FILE IS NOT CALLED *-live.test.js ANY MORE
 *   It was, and that was a labelling bug with teeth. `test:live` is documented
 *   as "tests against third-party ODoH relays; informative only, never a gate",
 *   and `test:hns` — the release gate — excludes `*-live.test.js` BY
 *   CONSTRUCTION. But nothing here touches the network: it spawns our own
 *   nsd.py against our own zone with a stubbed SPV. So the one deterministic
 *   self-check of the DNSSEC chain sat in the bucket nobody gates on, and when
 *   it went red it stayed red — 2/2 failing, reproducibly, while the gate
 *   reported 591/591 green.
 *
 * WHY THE SUBJECTS ARE NAMED AGAIN, AFTER BEING DISCOVERED
 *   The first version hard-coded `dir` and went stale when the real zone
 *   changed under it. The fix was to DISCOVER a suitable host by searching
 *   ~/hns/zones.json — which cured the staleness and caused something worse:
 *   the whole file skipped on any machine without ~/hns, i.e. on the Windows
 *   box that builds our installers. Ten tests, including fail-closed
 *   validation, unaudited on the platform we ship from.
 *
 *   Both problems come from the same root: the tests were reading LIVE
 *   OPERATOR DATA. The zone is now frozen in tests/fixtures/resolver/ and
 *   owned by this suite, so naming its hosts is safe again — a change to the
 *   fixture is a change to the test, reviewed together. See that directory's
 *   README.md.
 *
 * WHAT IS STILL NOT DETERMINISTIC HERE
 *   Nothing. There is no skip in this file. If it cannot run, it fails.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

import { HNSResolver } from '../src/resolver.js'
import { dsDigest, dnskeyRdata } from '../src/dnssec.js'
import { freeUdpPort } from './free-port.js'
import { FIXTURE, TENANT_ZONES, ZONES, withNsd as runNsd } from './nsd.js'

// Not a fixed port: see free-port.js — two concurrent runs used to
// collide and fail in a pattern that looked like a resolver regression.
const PORT = await freeUdpPort()

const withNsd = (fn) => runNsd({ port: PORT }, fn)

/** DS for the signed zone, as the chain would carry it. */
function dsFor ({ tamper = false } = {}) {
  const signed = JSON.parse(fs.readFileSync(FIXTURE.signed, 'utf8'))
  const raw = Buffer.from(signed.dnskey, 'base64').subarray(4)
  const digest = dsDigest(signed.zone, dnskeyRdata(raw, 257))
  return {
    type: 'DS',
    keyTag: signed.key_tag,
    algorithm: 13,
    digestType: 2,
    // One byte different: a DS that anchors a key this zone does not hold.
    digest: tamper
      ? digest.slice(0, -2) + (digest.endsWith('aa') ? 'bb' : 'aa')
      : digest
  }
}

function resolverFor (dsRecords) {
  return new HNSResolver({
    spv: { getResource: async () => ({ records: [{ type: 'NS', ns: 'ns1.hns.one.' }, ...dsRecords] }) },
    authoritative: { server: '127.0.0.1', port: PORT }
  })
}

// ---------------------------------------------------------------------------
// The fixture's own invariants. Every test below assumes a shape; if the
// fixture ever stops having it, that must be a LOUD failure here rather than
// a quiet green over an untested code path — which is exactly how the earlier
// version of this file came to be 2/2 red and unseen.

test('the frozen zone still has a host that exercises DNSSEC → TLSA', () => {
  const zones = JSON.parse(fs.readFileSync(ZONES, 'utf8'))
  const records = zones[FIXTURE.zone].records
  const label = FIXTURE.siteHost.slice(0, -FIXTURE.zone.length - 1)
  assert.ok(records.some((r) => r.type === 'A' && r.name === label),
    `${FIXTURE.siteHost} must have an A record`)
  assert.ok(records.some((r) => r.type === 'TLSA' && r.name === `_443._tcp.${label}`),
    `${FIXTURE.siteHost} must publish a TLSA`)
  // A TXT pointer is answered BEFORE the A/TLSA path is reached, so a host
  // carrying one proves nothing about DNSSEC validation.
  assert.ok(!records.some((r) => r.name === label && r.type === 'TXT' &&
      /^\s*(ipfs|ipns|ar)=/.test(String(r.value || ''))),
    `${FIXTURE.siteHost} must NOT carry a TXT pointer`)
})

test('the frozen zone still has a signed host with an ipfs= pointer', () => {
  const signed = JSON.parse(fs.readFileSync(FIXTURE.signed, 'utf8'))
  assert.ok(signed.rrsets[FIXTURE.pointerHost]?.TXT,
    `${FIXTURE.pointerHost} must be a signed TXT RRset`)
})

test('the frozen RRSIGs have years of head room, not days', () => {
  // These tests drive the resolver through validateChain, which takes NO clock
  // argument and always reads the real one (dnssec-clock-guard.test.js pins
  // that). So the validity window is the only lever there is, and the fixture
  // carries 20 years of it. The failure this guards is a REFRESH that used the
  // signer's production default of 30 days: without this check the suite would
  // go green today and red a month from now, for a reason that is not a defect.
  const signed = JSON.parse(fs.readFileSync(FIXTURE.signed, 'utf8'))
  const yearsLeft = (signed.expiration - Date.now() / 1000) / (365.25 * 86400)
  assert.ok(yearsLeft > 3,
    `the frozen fixture expires in ${yearsLeft.toFixed(2)} years. Re-sign it ` +
    'with the long validity window — see tests/fixtures/resolver/README.md. ' +
    'A plain `cp` from ~/hns brings a 30-day window with it.')
})

// ---------------------------------------------------------------------------
// The A + TLSA path.

test('DNSSEC-signed zone: TLSA validates up to the on-chain DS', () =>
  withNsd(async () => {
    const out = await resolverFor([dsFor()]).resolve(FIXTURE.siteHost)
    assert.equal(out.kind, 'site', JSON.stringify(out))
    assert.equal(out.dnssecValidated, true,
      `${FIXTURE.siteHost}: the TLSA did not validate up to the on-chain DS`)
    assert.ok(out.tlsa.length >= 1, 'no TLSA returned')
  }))

test('no DS on-chain: the same zone resolves without requiring DNSSEC', () =>
  withNsd(async () => {
    const out = await resolverFor([]).resolve(FIXTURE.siteHost)
    assert.equal(out.kind, 'site', JSON.stringify(out))
    assert.equal(out.dnssecValidated, false)
  }))

// The header of the file this replaces claimed "Tampering must fail closed"
// and then never tested it. Fail-closed is the ONLY property that makes the
// chain worth validating: a resolver that validates when it can and shrugs
// when it cannot is a resolver an attacker simply makes unable to validate.
test('a DS that does not match the zone key FAILS CLOSED', () =>
  withNsd(async () => {
    const out = await resolverFor([dsFor({ tamper: true })])
      .resolve(FIXTURE.siteHost)
    assert.equal(out.kind, 'dnssec-fail',
      `${FIXTURE.siteHost}: a DS that anchors a key this zone does not hold ` +
      `was ACCEPTED — DNSSEC validation is not failing closed: ${JSON.stringify(out)}`)
    assert.match(String(out.reason), /DNSKEY|DS|RRSIG/)
  }))

// ---------------------------------------------------------------------------
// The ipfs= POINTER path. Until 2026-08-24 this path sent DO=0 and trusted
// the TXT unvalidated — the browser "worked" on signed zones by accident of
// a default while validators got signed NXDOMAINs (the DO-bit entry in
// OPEN-ISSUES). These tests pin the fix from both sides: a signed pointer
// must validate up to the on-chain DS, and a tampered anchor must fail
// closed on the POINTER path too, not only on TLSA.

test('signed zone: the ipfs= pointer validates up to the on-chain DS', () =>
  withNsd(async () => {
    const out = await resolverFor([dsFor()]).resolve(FIXTURE.pointerHost)
    assert.equal(out.kind, 'ipfs', JSON.stringify(out))
    assert.equal(out.dnssecValidated, true,
      `${FIXTURE.pointerHost}: pointer accepted without validating up to the DS`)
  }))

test('a DS that does not match FAILS CLOSED on the pointer path too', () =>
  withNsd(async () => {
    const out = await resolverFor([dsFor({ tamper: true })])
      .resolve(FIXTURE.pointerHost)
    assert.equal(out.kind, 'dnssec-fail',
      `${FIXTURE.pointerHost}: pointer under a tampered DS was ACCEPTED: ${JSON.stringify(out)}`)
  }))

test('no DS on-chain: an unsigned zone\'s pointer still resolves, unvalidated', () =>
  withNsd(async () => {
    const out = await resolverFor([]).resolve(FIXTURE.pointerHost)
    assert.equal(out.kind, 'ipfs', JSON.stringify(out))
    assert.ok(!out.dnssecValidated)
  }))

// ---------------------------------------------------------------------------
// The DO-bit regression pin proper.

test('tenant-published labels are IN the signed zone (the DO-bit pin)', () => {
  // The label lives only in zones-tenant.json. If the signer ever goes back to
  // signing the operator file alone it vanishes from the signed file, and
  // every validating resolver is told the name does not exist.
  const tenant = JSON.parse(fs.readFileSync(TENANT_ZONES, 'utf8'))
  const operator = JSON.parse(fs.readFileSync(ZONES, 'utf8'))
  const label = FIXTURE.tenantHost.slice(0, -FIXTURE.zone.length - 1)
  assert.ok(tenant[FIXTURE.zone].records.some((r) => r.name === label),
    `${FIXTURE.tenantHost} must be published by the TENANT file`)
  assert.ok(!operator[FIXTURE.zone].records.some((r) => r.name === label),
    `${FIXTURE.tenantHost} must NOT be in the operator file, or it proves nothing`)
  const signed = JSON.parse(fs.readFileSync(FIXTURE.signed, 'utf8'))
  assert.ok(signed.rrsets[FIXTURE.tenantHost]?.TXT,
    `${FIXTURE.tenantHost} is published but NOT signed — the signer has ` +
    'stopped signing the merged view')
})

test('a tenant-published label resolves VALIDATED end-to-end', () =>
  withNsd(async () => {
    // The label is absent from the operator zones.json that nsd serves
    // unsigned — only the signed file knows it. Resolving it validated
    // proves the whole chain the DO-bit bug broke: tenant publish -> merged
    // signing -> DO=1 answer -> DS-anchored proof.
    const out = await resolverFor([dsFor()]).resolve(FIXTURE.tenantHost)
    assert.equal(out.kind, 'ipfs', JSON.stringify(out))
    assert.equal(out.dnssecValidated, true,
      `${FIXTURE.tenantHost}: tenant label did not validate up to the on-chain DS`)
  }))
