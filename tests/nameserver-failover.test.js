/*
 * HS-15: failover at query time. A zone with two nameservers used to go dark
 * with its first — the first NS with an address was the only one asked. Now a
 * server that cannot be ASKED (unreachable, timed out, answered a different
 * question) hands the question to the zone's next server, in the zone's own
 * order; an answer that fails validation is still returned as it is.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'

import { HNSResolver } from '../src/resolver.js'
import { freeUdpPort } from './free-port.js'
import { FIXTURE, withNsd as runNsd } from './nsd.js'

const PORT = await freeUdpPort()
const withNsd = (fn) => runNsd({ port: PORT }, fn)

/** A TCP port nothing listens on (bound, then released). */
async function deadPort () {
  const s = net.createServer()
  await new Promise((resolve) => s.listen(0, '127.0.0.1', resolve))
  const port = s.address().port
  await new Promise((resolve) => s.close(resolve))
  return port
}

function resolverAt (servers, records) {
  return new HNSResolver({
    spv: { getResource: async () => ({ records }), isSynced: async () => true },
    authoritative: servers,
    timeout: 1500
  })
}

const UNSIGNED = [{ type: 'NS', ns: 'ns1.hns.one.' }]

test('a dead first nameserver hands the question to the second', () =>
  withNsd(async () => {
    const dead = { server: '127.0.0.1', port: await deadPort() }
    const out = await resolverAt([dead, { server: '127.0.0.1', port: PORT }], UNSIGNED).resolve(FIXTURE.noTlsaHost)
    assert.equal(out.kind, 'site', JSON.stringify(out))
    assert.equal(out.ns, '127.0.0.1')
  }))

test('txtRecords fails over the same way', () =>
  withNsd(async () => {
    const dead = { server: '127.0.0.1', port: await deadPort() }
    const out = await resolverAt([dead, { server: '127.0.0.1', port: PORT }], UNSIGNED).txtRecords(FIXTURE.pointerHost)
    assert.equal(out.kind, 'txt', JSON.stringify(out))
    assert.ok(out.strings.some((s) => s.startsWith('ipfs=')))
  }))

test('every nameserver dead: the last transport error is what surfaces', async () => {
  const a = { server: '127.0.0.1', port: await deadPort() }
  const b = { server: '127.0.0.1', port: await deadPort() }
  await assert.rejects(resolverAt([a, b], UNSIGNED).resolve(FIXTURE.noTlsaHost))
})

test('candidates: each nameserver in the zone\'s order, IPv4 before IPv6, chain glue before any lookup', async () => {
  const records = [
    { type: 'NS', ns: 'ns1.reg.' }, { type: 'NS', ns: 'ns2.reg.' }, { type: 'NS', ns: 'ns3.example.' },
    { type: 'GLUE6', ns: 'ns1.reg.', address: '2001:db8::1' },
    { type: 'GLUE6', ns: 'ns2.reg.', address: '2001:db8::2' },
    { type: 'GLUE4', ns: 'ns2.reg.', address: '198.51.100.2' }
  ]
  const lookups = []
  const r = new HNSResolver({
    spv: { getResource: async () => null, isSynced: async () => true },
    lookup: async (host) => { lookups.push(host); return '203.0.113.3' }
  })
  const seen = []
  for await (const c of r._nameserverCandidates('reg', records, records.filter((x) => x.type === 'NS'))) seen.push(c.server.server)
  assert.deepEqual(seen, ['2001:db8::1', '198.51.100.2', '2001:db8::2', '203.0.113.3'])
  assert.deepEqual(lookups, ['ns3.example'], 'only the nameserver with no glue and no chain answer was looked up')
})

test('a private glue address is refused where it is met, not skipped', async () => {
  const records = [
    { type: 'NS', ns: 'ns1.reg.' }, { type: 'NS', ns: 'ns2.reg.' },
    { type: 'GLUE4', ns: 'ns1.reg.', address: '10.0.0.5' },
    { type: 'GLUE4', ns: 'ns2.reg.', address: '198.51.100.2' }
  ]
  const r = new HNSResolver({ spv: { getResource: async () => ({ records }), isSynced: async () => true }, timeout: 500 })
  const out = await r.resolve('www.reg')
  assert.equal(out.kind, 'blocked')
  assert.equal(out.address, '10.0.0.5')
})
