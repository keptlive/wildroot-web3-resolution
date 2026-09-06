/*
 * What an on-path attacker can do to a SIGNED zone's answers without a key:
 * delete records, forge an empty answer, change bytes. Each of these was
 * possible against the resolver on 2026-09-05 despite the zone being anchored
 * to the chain, because only SOME of the records a resolution rests on were
 * validated:
 *
 *   - the A RRset was never validated (read with DO=0, taken as served), so a
 *     forged address beside a proven "no TLSA" meant plaintext to the
 *     attacker with the padlock reporting the zone as anchored;
 *   - the pointer TXT's ABSENCE was never proven, so deleting an `ipfs=` from
 *     the answer walked the browser down to the A record instead;
 *   - and a signed zone whose "no TLSA" could not be proven hit a call to a
 *     method that did not exist, threw, and fell back to DoH — which serves
 *     plaintext.
 *
 * The proxy is tests/hns/dns-proxy.js; the zone is the frozen wrfixture.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

import { HNSResolver } from '../src/resolver.js'
import { dsDigest, dnskeyRdata, wireName } from '../src/dnssec.js'
import { TYPES } from '../src/dns-query.js'
import { freeUdpPort } from './free-port.js'
import { FIXTURE, withNsd as runNsd } from './nsd.js'
import { dnsProxy, qtypeOf, qnameOf, emptyReply, replaceBytes } from './dns-proxy.js'

const PORT = await freeUdpPort()
const withNsd = (fn) => runNsd({ port: PORT }, fn)

function chainDs () {
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

const SIGNED = [{ type: 'NS', ns: 'ns1.hns.one.' }, chainDs()]
const UNSIGNED = [{ type: 'NS', ns: 'ns1.hns.one.' }]

function resolverAt (port, records) {
  return new HNSResolver({
    spv: { getResource: async () => ({ records }), isSynced: async () => true },
    authoritative: { server: '127.0.0.1', port },
    timeout: 4000
  })
}

const SITE_IP = Buffer.from([203, 0, 113, 20]) // site.wrfixture's real A
const FORGED_IP = Buffer.from([198, 51, 100, 99])

// ---------------------------------------------------------------------------
// the address is a signed record too
// ---------------------------------------------------------------------------

test('BASELINE: the signed fixture validates, address included', () =>
  withNsd(async () => {
    const out = await resolverAt(PORT, SIGNED).resolve(FIXTURE.siteHost)
    assert.equal(out.kind, 'site')
    assert.equal(out.address, '203.0.113.20')
    assert.equal(out.dnssecValidated, true)
  }))

test('a FORGED A record on a signed zone fails closed', () =>
  withNsd(async () => {
    const proxy = await dnsProxy(PORT, {
      onReply: (q, reply) => (qtypeOf(q) === TYPES.A ? replaceBytes(reply, SITE_IP, FORGED_IP) : null)
    })
    try {
      const out = await resolverAt(proxy.port, SIGNED).resolve(FIXTURE.siteHost)
      assert.equal(out.kind, 'dnssec-fail',
        `a forged address was accepted on an anchored zone: ${JSON.stringify(out)}`)
      assert.match(String(out.reason), /A RRSIG|RRSIG/)
    } finally {
      await proxy.close()
    }
  }))

test('a forged A record beside a PROVEN "no TLSA" fails closed — the plaintext downgrade', () =>
  withNsd(async () => {
    // plain.wrfixture has no TLSA and the zone proves it. Before 2026-09-05
    // that honest proof, next to an unvalidated address, was the whole attack.
    const real = Buffer.from([203, 0, 113, 10])
    const proxy = await dnsProxy(PORT, {
      onReply: (q, reply) => (qtypeOf(q) === TYPES.A ? replaceBytes(reply, real, FORGED_IP) : null)
    })
    try {
      const out = await resolverAt(proxy.port, SIGNED).resolve(FIXTURE.noTlsaHost)
      assert.equal(out.kind, 'dnssec-fail', JSON.stringify(out))
      assert.notEqual(out.allowInsecure, true)
    } finally {
      await proxy.close()
    }
  }))

test('on an UNSIGNED zone the same forgery succeeds — which is what "unsigned" means', () =>
  withNsd(async () => {
    // Documented, not defended: there is no anchor, so there is nothing to
    // check the address against. The lock stays open for such a zone.
    const proxy = await dnsProxy(PORT, {
      onReply: (q, reply) => (qtypeOf(q) === TYPES.A ? replaceBytes(reply, SITE_IP, FORGED_IP) : null)
    })
    try {
      const out = await resolverAt(proxy.port, UNSIGNED).resolve(FIXTURE.siteHost)
      assert.equal(out.kind, 'site')
      assert.equal(out.address, '198.51.100.99')
      assert.equal(out.dnssecValidated, false)
    } finally {
      await proxy.close()
    }
  }))

// ---------------------------------------------------------------------------
// the pointer's absence must be proven
// ---------------------------------------------------------------------------

test('a DELETED ipfs= pointer on a signed zone fails closed instead of falling to the A record', () =>
  withNsd(async () => {
    const proxy = await dnsProxy(PORT, {
      onQuery: (q) => (qtypeOf(q) === TYPES.TXT && qnameOf(q) === FIXTURE.pointerHost
        ? emptyReply(q, 0)
        : null)
    })
    try {
      const out = await resolverAt(proxy.port, SIGNED).resolve(FIXTURE.pointerHost)
      assert.equal(out.kind, 'dnssec-fail', JSON.stringify(out))
      assert.match(String(out.reason), /content pointer|DNSKEY|DS/)
    } finally {
      await proxy.close()
    }
  }))

test('a forged NXDOMAIN for the pointer fails closed the same way', () =>
  withNsd(async () => {
    const proxy = await dnsProxy(PORT, {
      onQuery: (q) => (qtypeOf(q) === TYPES.TXT && qnameOf(q) === FIXTURE.pointerHost
        ? emptyReply(q, 3)
        : null)
    })
    try {
      const out = await resolverAt(proxy.port, SIGNED).resolve(FIXTURE.pointerHost)
      assert.equal(out.kind, 'dnssec-fail', JSON.stringify(out))
    } finally {
      await proxy.close()
    }
  }))

test('a host with NO pointer and an honest NODATA still reaches its A record', () =>
  withNsd(async () => {
    // The proof exists (nsd.py answers the TXT NODATA with the host's own
    // NSEC), so requiring it costs a legitimate A-record site nothing.
    const out = await resolverAt(PORT, SIGNED).resolve(FIXTURE.siteHost)
    assert.equal(out.kind, 'site')
    assert.equal(out.dnssecValidated, true)
  }))

test('an UNSIGNED zone\'s empty TXT needs no proof — there is nothing to prove it with', () =>
  withNsd(async () => {
    const proxy = await dnsProxy(PORT, {
      onQuery: (q) => (qtypeOf(q) === TYPES.TXT ? emptyReply(q, 0) : null)
    })
    try {
      const out = await resolverAt(proxy.port, UNSIGNED).resolve(FIXTURE.siteHost)
      assert.equal(out.kind, 'site')
    } finally {
      await proxy.close()
    }
  }))

// ---------------------------------------------------------------------------
// a denial that cannot be proven refuses — and does not throw
// ---------------------------------------------------------------------------

test('a forged "no TLSA" on a signed zone refuses plaintext and does NOT throw', () =>
  withNsd(async () => {
    // Until 2026-09-05 this path called `this._logDenialGap`, which was never
    // defined. The TypeError rejected resolve(), src/hns/index.js caught it
    // and fell back to the DoH resolver — which serves an A-record site over
    // plaintext. A signed zone with a broken denial was therefore LESS safe
    // than an unsigned one.
    const proxy = await dnsProxy(PORT, {
      onQuery: (q) => (qtypeOf(q) === TYPES.TLSA ? emptyReply(q, 3) : null)
    })
    try {
      const out = await resolverAt(proxy.port, SIGNED).resolve(FIXTURE.noTlsaHost)
      assert.equal(out.kind, 'site', JSON.stringify(out))
      assert.equal(out.allowInsecure, false, 'an unproven denial was believed')
      assert.equal(out.dnssecValidated, false)
      assert.equal(out.dnssecAnchored, true)
    } finally {
      await proxy.close()
    }
  }))

test('the honest denial is proven, and the resolution counts as validated', () =>
  withNsd(async () => {
    const out = await resolverAt(PORT, SIGNED).resolve(FIXTURE.noTlsaHost)
    assert.equal(out.kind, 'site')
    assert.equal(out.allowInsecure, true)
    assert.equal(out.dnssecValidated, true,
      'a validated address plus a proven absence of a pin is a validated answer')
  }))

// ---------------------------------------------------------------------------
// failures are not remembered
// ---------------------------------------------------------------------------

test('a failed resolution is re-asked, not cached for the TTL', () =>
  withNsd(async () => {
    let strip = true
    const proxy = await dnsProxy(PORT, {
      onReply: (q, reply) => (strip && qtypeOf(q) === TYPES.A
        ? replaceBytes(reply, SITE_IP, FORGED_IP)
        : null)
    })
    try {
      const r = resolverAt(proxy.port, SIGNED)
      const first = await r.resolve(FIXTURE.siteHost)
      assert.equal(first.kind, 'dnssec-fail')
      strip = false
      const second = await r.resolve(FIXTURE.siteHost)
      assert.equal(second.kind, 'site', 'the failure was served from cache after the network recovered')
    } finally {
      await proxy.close()
    }
  }))

/** A reply to `query` with one CNAME answer and nothing else — what an on-path attacker injects. */
function cnameReply (query, target) {
  const base = emptyReply(query, 0)
  const header = Buffer.from(base.subarray(0, 12))
  header.writeUInt16BE(1, 6) // ANCOUNT
  const question = base.subarray(12)
  const rdata = wireName(target)
  const rr = Buffer.alloc(12 + rdata.length)
  rr.writeUInt16BE(0xc00c, 0) // owner: pointer to the question name
  rr.writeUInt16BE(TYPES.CNAME, 2)
  rr.writeUInt16BE(1, 4) // IN
  rr.writeUInt32BE(60, 6)
  rr.writeUInt16BE(rdata.length, 10)
  rdata.copy(rr, 12)
  return Buffer.concat([header, question, rr])
}

test('a STRIPPED A with an injected CNAME on a signed zone fails closed — the CNAME is a signed record too', () =>
  withNsd(async () => {
    // Until 2026-09-06 the CNAME branch on the address path followed whatever
    // the answer carried: delete the signed A, add `CNAME attacker`, and an
    // anchored zone walked the browser to the attacker's address.
    const proxy = await dnsProxy(PORT, {
      onReply: (q, reply) => (qtypeOf(q) === TYPES.A ? cnameReply(q, 'localhost.') : null)
    })
    try {
      const out = await resolverAt(proxy.port, SIGNED).resolve(FIXTURE.siteHost)
      assert.equal(out.kind, 'dnssec-fail', `an unsigned CNAME was followed on an anchored zone: ${JSON.stringify(out)}`)
      assert.match(String(out.reason), /CNAME RRSIG/)
    } finally {
      await proxy.close()
    }
  }))

test('on an UNSIGNED zone the injected CNAME is followed — which is what "unsigned" means', () =>
  withNsd(async () => {
    const proxy = await dnsProxy(PORT, {
      onReply: (q, reply) => (qtypeOf(q) === TYPES.A ? cnameReply(q, 'localhost.') : null)
    })
    try {
      const out = await resolverAt(proxy.port, UNSIGNED).resolve(FIXTURE.siteHost)
      // localhost resolves to a loopback address, which the safe-address rule blocks.
      assert.equal(out.kind, 'blocked', JSON.stringify(out))
    } finally {
      await proxy.close()
    }
  }))
