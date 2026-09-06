/*
 * nsd.py must answer NODATA, not NXDOMAIN, for a missing TLSA (or other
 * _service._proto owner) that hangs beneath a host it really serves.
 *
 * WHY IT MATTERS. A DANE client asks _443._tcp.<host> TLSA to decide HTTPS-
 * with-a-pin vs plain HTTP. NXDOMAIN there reads as "this host is unknown",
 * indistinguishable on the wire from "no pin published", so a strict client
 * fails closed and an A-record-only Handshake site (most of them) will not
 * load at all. NODATA is the truthful "we are authoritative for this host and
 * there is no record of this type" — and it must NOT weaken a real NXDOMAIN
 * for a name that genuinely does not exist.
 *
 * Runs the vendored nsd.py against the FROZEN zone in tests/fixtures/resolver
 * (a stubbed chain is not even needed — this is pure authoritative DNS). It
 * used to run against ~/hns/zones.json and skip when that was absent, so all
 * four of these were silently unrun on the Windows packaging box, and on the
 * machine that had them they asserted against whatever host live operator data
 * happened to be shaped like today. No skips remain: if it cannot run, it
 * fails.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

import { query, TYPES } from '../src/dns-query.js'
import { freeUdpPort } from './free-port.js'
import { FIXTURE, ZONES, withNsd as runNsd } from './nsd.js'

const PORT = await freeUdpPort()
const withNsd = (fn) => runNsd({ port: PORT }, fn)

test('the frozen zone still has an A-record host with no TLSA', () => {
  // The whole file asserts about this one host. If the fixture ever gives it a
  // TLSA, these tests would pass while testing nothing, so say so loudly here.
  const zones = JSON.parse(fs.readFileSync(ZONES, 'utf8'))
  const records = zones[FIXTURE.zone].records
  const label = FIXTURE.noTlsaHost.slice(0, -FIXTURE.zone.length - 1)
  assert.ok(records.some((r) => r.type === 'A' && r.name === label),
    `${FIXTURE.noTlsaHost} must have an A record`)
  assert.ok(!records.some((r) => r.type === 'TLSA' && r.name === `_443._tcp.${label}`),
    `${FIXTURE.noTlsaHost} must NOT publish a TLSA — it is the NODATA subject`)
})

test('a host with an A record but no TLSA answers NODATA (NOERROR, empty)',
  () => withNsd(async () => {
    const r = await query('127.0.0.1', PORT, FIXTURE.noTlsaOwner, TYPES.TLSA,
      { timeout: 1000 })
    assert.equal(r.rcode, 0,
      `${FIXTURE.noTlsaOwner} must be NODATA (rcode 0), got rcode ${r.rcode}`)
    const tlsa = r.answers.filter((a) => a.type === TYPES.TLSA)
    assert.equal(tlsa.length, 0, 'NODATA must carry no TLSA answer')
  }))

test('a genuinely non-existent name is still a real NXDOMAIN',
  () => withNsd(async () => {
    // A normal (non-underscore) label that does not exist must NOT be softened
    // to NODATA — the fix is scoped to _service._proto owners only.
    const bogus = `zzz-does-not-exist-${Date.now()}.${FIXTURE.zone}`
    const r = await query('127.0.0.1', PORT, bogus, TYPES.A, { timeout: 1000 })
    assert.equal(r.rcode, 3, `${bogus} must stay NXDOMAIN (rcode 3)`)
  }))

test('a TLSA beneath a host that does not exist is still NXDOMAIN',
  () => withNsd(async () => {
    const bogus = `_443._tcp.zzz-nohost-${Date.now()}.${FIXTURE.zone}`
    const r = await query('127.0.0.1', PORT, bogus, TYPES.TLSA, { timeout: 1000 })
    assert.equal(r.rcode, 3,
      `${bogus} sits under no real host and must stay NXDOMAIN (rcode 3)`)
  }))

test('a host that DOES publish a TLSA still answers it (positive path intact)',
  () => withNsd(async () => {
    const r = await query('127.0.0.1', PORT, FIXTURE.tlsaOwner, TYPES.TLSA,
      { timeout: 1000 })
    assert.equal(r.rcode, 0, `${FIXTURE.tlsaOwner} should answer NOERROR with a TLSA`)
    assert.ok(r.answers.some((a) => a.type === TYPES.TLSA),
      `${FIXTURE.tlsaOwner} should carry a TLSA answer`)
  }))
