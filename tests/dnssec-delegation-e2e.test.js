/*
 * The delegation walk, end to end, against a frozen signed PARENT with one
 * secure and one insecure child — the shape a registry TLD has.
 *
 * Two nameservers run: the parent zone `wrparent` on one port, its children
 * `secure.wrparent` (signed, with a DS in the parent) and `open.wrparent`
 * (unsigned, no DS) on another. The resolver is pointed at the parent and
 * told where the children answer (`serverFor`, a test hook that stands in
 * for the glue → chain → OS address lookup production does).
 *
 * WHAT THIS PINS THAT delegation.test.js COULD NOT. That file proves the DS
 * link with real captured material from `hns` and `pinner.hns`; it drives
 * validateDs and referralIn directly. Nothing drove `_descend` through a live
 * referral, so the one rule RFC 4035 §5.2 adds to a walk — that a MISSING DS
 * must be proven missing before the child is read unsigned — had no test, and
 * was not implemented: an on-path answer that deleted the DS from the referral
 * turned a signed child into an unsigned one, and everything the child would
 * have had to prove (its pin, its pointer, its own denials) was never asked
 * for. Found 2026-09-05.
 *
 * Fixtures: tests/fixtures/resolver/{zones-parent,zones-children}.json and
 * the two signed files beside them, generated with the recipe in that
 * directory's README (20-year windows).
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'

import { HNSResolver } from '../src/resolver.js'
import { dsDigest, keyTag } from '../src/dnssec.js'
import { TYPES } from '../src/dns-query.js'
import { freeUdpPort } from './free-port.js'
import { FIXTURE_DIR, withNsd } from './nsd.js'
import { dnsProxy, qtypeOf, emptyReply } from './dns-proxy.js'

const PARENT_PORT = await freeUdpPort()
const CHILD_PORT = await freeUdpPort()
const PARENT_ZONES = path.join(FIXTURE_DIR, 'zones-parent.json')
const CHILD_ZONES = path.join(FIXTURE_DIR, 'zones-children.json')

/** The DS the chain would carry for the parent zone. */
function parentDs () {
  const signed = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'wrparent.dnssec.json'), 'utf8'))
  const rd = Buffer.from(signed.dnskey, 'base64')
  return { type: 'DS', keyTag: keyTag(rd), algorithm: 13, digestType: 2, digest: dsDigest('wrparent', rd) }
}

const withBoth = (fn) => withNsd({ port: PARENT_PORT, zones: PARENT_ZONES },
  () => withNsd({ port: CHILD_PORT, zones: CHILD_ZONES }, fn))

function resolverAt (parentPort, records) {
  return new HNSResolver({
    spv: { getResource: async () => ({ records }), isSynced: async () => true },
    authoritative: { server: '127.0.0.1', port: parentPort },
    serverFor: () => ({ server: '127.0.0.1', port: CHILD_PORT }),
    timeout: 4000
  })
}

const ANCHORED = [{ type: 'NS', ns: 'ns1.hns.one.' }, parentDs()]
const UNANCHORED = [{ type: 'NS', ns: 'ns1.hns.one.' }]

test('the fixture still has both shapes of delegation', () => {
  const signed = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'wrparent.dnssec.json'), 'utf8'))
  assert.ok(signed.rrsets['secure.wrparent']?.DS, 'secure.wrparent must carry a DS')
  assert.ok(!signed.rrsets['open.wrparent']?.DS, 'open.wrparent must NOT carry a DS')
  assert.ok(signed.rrsets['open.wrparent']?.NSEC, 'open.wrparent needs its NSEC, the proof of that absence')
  const yearsLeft = (signed.expiration - Date.now() / 1000) / (365.25 * 86400)
  assert.ok(yearsLeft > 3, `the parent fixture expires in ${yearsLeft.toFixed(2)} years — re-sign it`)
})

test('a SECURE delegation: the child\'s pin validates up to the parent\'s on-chain DS', () =>
  withBoth(async () => {
    const out = await resolverAt(PARENT_PORT, ANCHORED).resolve('www.secure.wrparent')
    assert.equal(out.kind, 'site', JSON.stringify(out))
    assert.equal(out.address, '203.0.113.30')
    assert.equal(out.dnssecValidated, true, 'the child\'s TLSA must chain to the parent\'s anchor')
    assert.equal(out.dnssecAnchored, true)
    assert.equal(out.tlsa.length, 1)
  }))

test('a SECURE delegation: the child\'s pointer validates too', () =>
  withBoth(async () => {
    const out = await resolverAt(PARENT_PORT, ANCHORED).resolve('pointer.secure.wrparent')
    assert.equal(out.kind, 'ipfs', JSON.stringify(out))
    assert.equal(out.dnssecValidated, true)
  }))

test('a SECURE child that PROVES it has no pin loads in the clear — and counts as validated', () =>
  withBoth(async () => {
    const out = await resolverAt(PARENT_PORT, ANCHORED).resolve('plain.secure.wrparent')
    assert.equal(out.kind, 'site', JSON.stringify(out))
    assert.equal(out.allowInsecure, true, 'a proven denial was refused')
    // The address validated and the absence of a pin was proven: every record
    // this rests on chained to the anchor.
    assert.equal(out.dnssecValidated, true)
    assert.equal(out.dnssecAnchored, true)
  }))

test('an INSECURE delegation the parent PROVES (NSEC at the cut, no DS bit) is read unsigned', () =>
  withBoth(async () => {
    const out = await resolverAt(PARENT_PORT, ANCHORED).resolve('www.open.wrparent')
    assert.equal(out.kind, 'site', JSON.stringify(out))
    assert.equal(out.address, '203.0.113.60')
    assert.equal(out.dnssecAnchored, false, 'the child has no anchor of its own')
    assert.equal(out.dnssecValidated, false)
    assert.equal(out.allowInsecure, true, 'an unsigned child\'s authoritative NODATA stands')
  }))

test('a DS STRIPPED from the referral FAILS CLOSED — it is not an insecure delegation', () =>
  withBoth(async () => {
    // The attacker: answer the DS query with an empty NOERROR and no NSEC. A
    // resolver that reads that as "insecure delegation" never asks the child
    // to prove anything again.
    const proxy = await dnsProxy(PARENT_PORT, {
      onQuery: (q) => (qtypeOf(q) === TYPES.DS ? emptyReply(q, 0) : null)
    })
    try {
      const out = await resolverAt(proxy.port, ANCHORED).resolve('www.secure.wrparent')
      assert.equal(out.kind, 'dnssec-fail',
        `a deleted DS demoted the child to unsigned: ${JSON.stringify(out)}`)
      assert.match(String(out.reason), /DS|prove/)
    } finally {
      await proxy.close()
    }
  }))

test('a DS answered NXDOMAIN without proof fails closed the same way', () =>
  withBoth(async () => {
    const proxy = await dnsProxy(PARENT_PORT, {
      onQuery: (q) => (qtypeOf(q) === TYPES.DS ? emptyReply(q, 3) : null)
    })
    try {
      const out = await resolverAt(proxy.port, ANCHORED).resolve('www.open.wrparent')
      assert.equal(out.kind, 'dnssec-fail', JSON.stringify(out))
    } finally {
      await proxy.close()
    }
  }))

test('dropping the DS query is unreachable, never a silent downgrade', () =>
  withBoth(async () => {
    const proxy = await dnsProxy(PARENT_PORT, {
      onQuery: (q) => (qtypeOf(q) === TYPES.DS ? 'drop' : null)
    })
    try {
      const out = await resolverAt(proxy.port, ANCHORED).resolve('www.secure.wrparent')
      assert.ok(out.kind === 'unreachable' || out.kind === 'dnssec-fail', JSON.stringify(out))
      assert.notEqual(out.dnssecValidated, true)
    } finally {
      await proxy.close()
    }
  }))

test('with no DS on chain the walk still works, unanchored all the way down', () =>
  withBoth(async () => {
    const out = await resolverAt(PARENT_PORT, UNANCHORED).resolve('www.secure.wrparent')
    assert.equal(out.kind, 'site', JSON.stringify(out))
    assert.equal(out.address, '203.0.113.30')
    assert.equal(out.dnssecValidated, false)
    assert.equal(out.dnssecAnchored, false)
    assert.equal(out.tlsa.length, 1, 'the pin still applies; it is simply not chain-anchored')
  }))

test('a name the parent itself holds does not descend', () =>
  withBoth(async () => {
    const out = await resolverAt(PARENT_PORT, ANCHORED).resolve('plain.wrparent')
    assert.equal(out.kind, 'site', JSON.stringify(out))
    assert.equal(out.address, '203.0.113.50')
    assert.equal(out.dnssecValidated, true)
  }))
