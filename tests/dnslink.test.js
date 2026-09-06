/*
 * DNSLink as a first-class content-pointer source.
 *
 * A site published for IPFS Companion, Brave or kubo carries ONE record:
 * `_dnslink.<name> TXT "dnslink=/ipfs/<cid>"`. Wildroot writes that record
 * beside its own `ipfs=` at publish, and reads both — under the same rules:
 * on a signed zone the RRset validates to the anchor and its absence is
 * proven before the resolution moves on to an address. When both records
 * exist and disagree, nothing is rendered: the disagreement is surfaced.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'

import { parseDnslink, dnslinkPointerFrom, mergePointers, dnslinkValue } from '../src/pointers.js'
import { HNSResolver } from '../src/resolver.js'
import { DoHResolver } from '../src/doh.js'
import { TYPES } from '../src/dns-query.js'
import { hnsSteps } from '../src/trust-path.js'
import { stubWireFetch } from './doh-wire.js'
import { freeUdpPort } from './free-port.js'
import { FIXTURE_DIR, withNsd } from './nsd.js'

const CID = 'bafkreigph5cub32tn4ph2au3izioyxnr37lvthzdug4xlmhlbnxj7h3mqu'
const OTHER = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi'
const KEY = 'k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8'

// ---------------------------------------------------------------- the grammar

test('a dnslink= value is read in the shapes every other client writes', () => {
  assert.deepEqual(parseDnslink(`dnslink=/ipfs/${CID}`), { kind: 'ipfs', cid: CID })
  assert.deepEqual(parseDnslink(`dnslink=/ipns/${KEY}`), { kind: 'ipns', key: KEY })
  assert.deepEqual(parseDnslink(`DNSLINK=/IPFS/${CID}/docs/index.html`), { kind: 'ipfs', cid: CID, path: '/docs/index.html' })
  assert.deepEqual(parseDnslink(`dnslink=/ipfs/${CID}/`), { kind: 'ipfs', cid: CID })
  // Not pointers here: other namespaces, malformed addresses, other records.
  for (const bad of ['dnslink=/hyper/abc', 'dnslink=/dnslink/x.example', `dnslink=/ipfs/${CID.slice(0, 20)}`,
    `dnslink=${CID}`, 'v=spf1 -all', `ipfs=${CID}`, '']) {
    assert.equal(parseDnslink(bad), null, bad)
  }
  // What we write is what we read.
  assert.deepEqual(parseDnslink(dnslinkValue({ cid: CID })), { kind: 'ipfs', cid: CID })
  assert.deepEqual(parseDnslink(dnslinkValue({ ipns: KEY })), { kind: 'ipns', key: KEY })
  assert.deepEqual(dnslinkPointerFrom(['v=spf1 -all', `dnslink=/ipfs/${CID}`]), { kind: 'ipfs', cid: CID })
  assert.equal(dnslinkPointerFrom([]), null)
})

test('two sources merge only when they agree; a disagreement is a conflict, never a pick', () => {
  const direct = { kind: 'ipfs', cid: CID }
  assert.deepEqual(mergePointers(null, null), { pointer: null })
  assert.deepEqual(mergePointers(direct, null), { pointer: direct })
  assert.deepEqual(mergePointers(null, { kind: 'ipfs', cid: CID }), { pointer: { kind: 'ipfs', cid: CID, dnslink: true } })
  assert.deepEqual(mergePointers(direct, { kind: 'ipfs', cid: CID }), { pointer: { kind: 'ipfs', cid: CID, dnslink: true } })
  const conflict = mergePointers(direct, { kind: 'ipfs', cid: OTHER })
  assert.equal(conflict.pointer, null)
  assert.deepEqual(conflict.conflict, { direct, dnslink: { kind: 'ipfs', cid: OTHER } })
  // Different kinds are a disagreement too — an ar= beside a dnslink is two answers.
  assert.ok(mergePointers({ kind: 'arweave', txid: 'x' }, { kind: 'ipfs', cid: CID }).conflict)
  // A stated origin on the direct pointer survives an agreeing merge.
  assert.deepEqual(mergePointers({ ...direct, origin: 'https://o.example/ipfs/' + CID }, { kind: 'ipfs', cid: CID }),
    { pointer: { ...direct, origin: 'https://o.example/ipfs/' + CID, dnslink: true } })
})

// ---------------------------------------------------------------- over DoH

const dohFor = (map) => new DoHResolver({ fetchImpl: stubWireFetch(map) })

test('DoH: a name with ONLY a DNSLink record resolves to its content', async () => {
  const out = await dohFor({ '_dnslink.only.14898:TXT': [{ type: TYPES.TXT, data: `dnslink=/ipfs/${CID}` }] }).resolve('only.14898')
  assert.equal(out.kind, 'ipfs')
  assert.equal(out.cid, CID)
  assert.equal(out.dnslink, true)
  assert.equal(out.trust, 'doh')
})

test('DoH: both records agreeing is the normal case; disagreeing is surfaced', async () => {
  const agree = await dohFor({
    'both.14898:TXT': [{ type: TYPES.TXT, data: `ipfs=${CID}` }],
    '_dnslink.both.14898:TXT': [{ type: TYPES.TXT, data: `dnslink=/ipfs/${CID}` }]
  }).resolve('both.14898')
  assert.equal(agree.kind, 'ipfs')
  assert.equal(agree.cid, CID)
  const clash = await dohFor({
    'clash.14898:TXT': [{ type: TYPES.TXT, data: `ipfs=${CID}` }],
    '_dnslink.clash.14898:TXT': [{ type: TYPES.TXT, data: `dnslink=/ipfs/${OTHER}` }]
  }).resolve('clash.14898')
  assert.equal(clash.kind, 'pointer-conflict')
  assert.match(clash.reason, /disagree/)
  assert.match(clash.reason, new RegExp(OTHER))
})

test('DoH: an ipns DNSLink is an ipns pointer, and a name with neither still resolves its address', async () => {
  const named = await dohFor({ '_dnslink.named.14898:TXT': [{ type: TYPES.TXT, data: `dnslink=/ipns/${KEY}` }] }).resolve('named.14898')
  assert.equal(named.kind, 'ipns')
  assert.equal(named.key, KEY)
  const site = await dohFor({ 'site.14898:A': [{ type: TYPES.A, data: '203.0.113.10' }] }).resolve('site.14898')
  assert.equal(site.kind, 'site')
})

// ---------------------------------------------------------------- the chain path, against a real nameserver

const PORT = await freeUdpPort()
const ZONES = path.join(FIXTURE_DIR, 'zones-dnslink.json')
const UNSIGNED = [{ type: 'NS', ns: 'ns1.hns.one.' }]
const resolverAt = (port, records) => new HNSResolver({
  spv: { getResource: async () => ({ records }), isSynced: async () => true },
  authoritative: { server: '127.0.0.1', port },
  timeout: 4000
})

test('chain path: a site published the IPFS-Companion way (DNSLink only) opens', () =>
  withNsd({ port: PORT, zones: ZONES }, async () => {
    const r = resolverAt(PORT, UNSIGNED)
    const only = await r.resolve('only.wrdnslink')
    assert.equal(only.kind, 'ipfs')
    assert.equal(only.cid, CID)
    assert.equal(only.dnslink, true)
    const named = await r.resolve('named.wrdnslink')
    assert.equal(named.kind, 'ipns')
    assert.equal(named.key, KEY)
    const pathed = await r.resolve('pathed.wrdnslink')
    assert.equal(pathed.cid, CID)
    assert.equal(pathed.path, '/docs')
  }))

test('chain path: both records agree → one pointer; both disagree → a conflict, nothing rendered', () =>
  withNsd({ port: PORT, zones: ZONES }, async () => {
    const r = resolverAt(PORT, UNSIGNED)
    const agree = await r.resolve('agree.wrdnslink')
    assert.equal(agree.kind, 'ipfs')
    assert.equal(agree.cid, CID)
    assert.equal(agree.dnslink, true)
    const clash = await r.resolve('conflict.wrdnslink')
    assert.equal(clash.kind, 'pointer-conflict')
    assert.match(clash.reason, /disagree/)
    // An address-only name is untouched by the second query.
    const site = await r.resolve('site.wrdnslink')
    assert.equal(site.kind, 'site')
    assert.equal(site.address, '203.0.113.30')
  }))

test('the trust panel says when a pointer came from the DNSLink record', () => {
  const steps = hnsSteps('only.wrdnslink', { trust: 'spv', kind: 'ipfs', cid: CID, dnslink: true })
  const content = steps.find((s) => s.label === 'Content')
  assert.equal(content.state, 'verified')
  assert.match(content.source, /DNSLink record/)
})
