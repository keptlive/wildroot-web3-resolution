/*
 * HIP-5 `_op`: the Optimism registry route, end to end through HNSResolver.
 *
 * NO NETWORK. The chain resource is a fake spv whose `persist` carries the
 * three NS records the real name carries on mainnet, and the RPC is an
 * injected fetch that answers eth_call by selector — the same fixture shape
 * ~/hns/dsld/service/test.cjs uses to prove the WRITER, so both ends of the
 * ABI are pinned by the same bytes. The fallback half is real: the vendored
 * nsd.py answers as the TLD's nameserver, so "fell back to DNS" is a resolved
 * address and not a mock's say-so.
 *
 * THE SENTINEL. Every name that should be answered by the registry also has a
 * DIFFERENT A record (203.0.113.99) in the zone. A test that comes back with
 * the sentinel proves the nameserver answered — which, for those names, is the
 * bug this file exists to catch.
 *
 * The nodes, name keys and selectors below were computed with the INDEPENDENT
 * implementation that writes these records (~/hns/dsld/service/voucher.cjs)
 * and are hard-coded here, so a matching bug in namehash could not make the
 * fixture and the resolver agree with each other and disagree with the chain.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { HNSResolver } from '../src/resolver.js'
import {
  dnsNameservers, namehash, dnsNameKey, opRegistryFor, resolveOp
} from '../src/hip5-op.js'
import { freeUdpPort } from './free-port.js'
import { withNsd as runNsd } from './nsd.js'

const REGISTRY = '0x233b4fbf4e8f0e60bff0a5f1a24ffa257987dbf2'
const RESOLVER_ADDR = '0x' + '22'.repeat(20)
const RPC_URLS = ['https://rpc.invalid/one', 'https://rpc.invalid/two']

/** Function selectors — `resolver` and `contenthash` are ENS's own, published. */
const SEL = {
  resolver: '0x0178b8bf',
  contenthash: '0xbc1c58d1',
  hasDNSRecords: '0x4cbf6ba4',
  dnsRecord: '0xa8fa5682'
}

/** namehash(<name>.persist), from ~/hns/dsld/service/voucher.cjs. */
const NODE = {
  maya: '0x39f92e0e170eb962b0bd0ca46090a914492cd08b30f1d41d3955ff82de7ea708',
  ark: '0x1d8b0377147f2fd033f3060629ae1bed7315acb36cbb869f897429229b097369',
  gone: '0x34ad2283ecf56a57b86980dd6f9062bdc36c1ecdc0f68760c21014606a938c00',
  dead: '0x38fe178e6e6b3d4f0e8b8129a71f41ad54cbcd49e9ce1647866f1bfff0f1c568',
  evil: '0x1c5fc59838ec5c1674215b9221bea118b06d287549f2acc50c12bddbcc402ba5'
}
/** keccak256(wire-format lowercased owner name) — the RRset storage key. */
const KEY = {
  maya: '0x43067cd83f7b75734d47b43235886bc525028ea1678e0c4b3c19dec7c4bbe378',
  mayaTlsa: '0x334829440a81962b2acf500eef39449c2933fc7862e51f67617373cb4c1d947e',
  evil: '0x2ad34e467f82ac1080558ab59e77eed36b5cc0bc127131608df57fa3ff226d6a'
}

const SITE_IP = '198.44.116.200'
const TLSA_HASH = 'ab'.repeat(32)
const ARWEAVE_RAW = Buffer.alloc(32, 0x2a)
const ARWEAVE_TXID = ARWEAVE_RAW.toString('base64url')
/** The sentinel: what the ZONE says, so a nameserver answer is unmistakable. */
const SENTINEL = '203.0.113.99'

const PORT = await freeUdpPort()

// ─────────────────────────────────────────────── the chain side (fake spv)

const OP_NS = { type: 'NS', ns: `${REGISTRY}._op.` }
const DNS_NS = [{ type: 'NS', ns: 'ns1.hns.one.' }, { type: 'NS', ns: 'ns2.hns.one.' }]

const spvWith = (records) => ({
  getResource: async (tld) => (tld === 'persist' ? { records } : null),
  isSynced: async () => true
})

// ─────────────────────────────────────────────── the RPC side (fake fetch)

const u256 = (n) => {
  const b = Buffer.alloc(32)
  b.writeUInt32BE(n, 28)
  return b
}
const addressWord = (addr) =>
  Buffer.concat([Buffer.alloc(12), Buffer.from(addr.slice(2), 'hex')])
const abiBytes = (b) => Buffer.concat(
  [u256(32), u256(b.length), b, Buffer.alloc((32 - (b.length % 32)) % 32)])

/** One RFC1035 wire RR, exactly as the contract stores it. */
function wireRR (owner, type, ttl, rdata) {
  const labels = owner.split('.').flatMap(
    (l) => [Buffer.from([l.length]), Buffer.from(l, 'utf8')])
  const head = Buffer.alloc(10)
  head.writeUInt16BE(type, 0)
  head.writeUInt16BE(1, 2) // IN
  head.writeUInt32BE(ttl, 4)
  head.writeUInt16BE(rdata.length, 8)
  return Buffer.concat([...labels, Buffer.from([0]), head, rdata])
}

/** An unsigned-varint multicodec prefix (EIP-1577 / ENSIP-7). */
function varint (n) {
  const out = []
  while (n >= 0x80) {
    out.push((n & 0x7f) | 0x80)
    n = Math.floor(n / 128)
  }
  out.push(n)
  return Buffer.from(out)
}
const ARWEAVE_CONTENTHASH = Buffer.concat([varint(0xb29910), ARWEAVE_RAW])

/** What the fixture registry holds, keyed by owner-name key and DNS type. */
function storedRRs (key, type) {
  if (key === KEY.maya && type === 1) {
    return wireRR('maya.persist', 1, 300, Buffer.from([198, 44, 116, 200]))
  }
  if (key === KEY.mayaTlsa && type === 52) {
    return wireRR('_443._tcp.maya.persist', 52, 300,
      Buffer.concat([Buffer.from([3, 1, 1]), Buffer.from(TLSA_HASH, 'hex')]))
  }
  if (key === KEY.evil && type === 1) {
    return wireRR('evil.persist', 1, 300, Buffer.from([127, 0, 0, 1]))
  }
  return Buffer.alloc(0)
}

/** The fixture chain state, as one eth_call answer. */
function answer (to, sel, node, data) {
  if (sel === SEL.resolver) {
    assert.equal(to, REGISTRY, 'resolver() is asked of the registry')
    // gone.persist: the registry has never heard of it.
    return node === NODE.gone ? u256(0) : addressWord(RESOLVER_ADDR)
  }
  assert.equal(to, RESOLVER_ADDR, 'every record read goes to the resolver')
  if (sel === SEL.contenthash) {
    return abiBytes(node === NODE.ark ? ARWEAVE_CONTENTHASH : Buffer.alloc(0))
  }
  if (sel === SEL.hasDNSRecords) {
    return u256(node === NODE.maya || node === NODE.evil ? 1 : 0)
  }
  if (sel === SEL.dnsRecord) {
    const key = '0x' + data.subarray(36, 68).toString('hex')
    return abiBytes(storedRRs(key, data.readUInt16BE(98)))
  }
  throw new Error(`unexpected selector ${sel}`)
}

/**
 * An injected fetch that speaks eth_call. `fail` makes every endpoint refuse,
 * which is the "all RPCs down" case.
 */
function fakeRpc ({ fail = false } = {}) {
  const calls = []
  const fetchImpl = async (url, init) => {
    const { method, params } = JSON.parse(init.body)
    assert.equal(method, 'eth_call')
    const to = String(params[0].to).toLowerCase()
    const data = Buffer.from(String(params[0].data).slice(2), 'hex')
    const sel = '0x' + data.subarray(0, 4).toString('hex')
    const node = '0x' + data.subarray(4, 36).toString('hex')
    calls.push({ url, to, sel, node })
    if (fail) throw new Error('connect ECONNREFUSED')
    return {
      ok: true,
      json: async () => ({
        jsonrpc: '2.0', id: 1, result: '0x' + answer(to, sel, node, data).toString('hex')
      })
    }
  }
  return { fetchImpl, calls }
}

// ─────────────────────────────────────────────── the DNS side (real nsd.py)

/**
 * The TLD's nameserver, holding a DIFFERENT answer for every name the
 * registry also answers — see THE SENTINEL in the header.
 */
function zoneFile (dir) {
  const zones = {
    persist: {
      soa: {
        mname: 'ns1.hns.one.',
        rname: 'hostmaster.ns1.hns.one.',
        serial: 1,
        refresh: 7200,
        retry: 3600,
        expire: 1209600,
        minimum: 300
      },
      ns: ['ns1.hns.one.'],
      records: [
        { name: 'maya', type: 'A', value: SENTINEL },
        { name: 'ark', type: 'A', value: SENTINEL },
        { name: 'evil', type: 'A', value: SENTINEL },
        { name: 'gone', type: 'A', value: '203.0.113.10' },
        { name: 'dead', type: 'A', value: '203.0.113.11' },
        { name: 'plain', type: 'A', value: '203.0.113.12' }
      ]
    }
  }
  const p = path.join(dir, 'zones.json')
  fs.writeFileSync(p, JSON.stringify(zones))
  return p
}

function withNsd (fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hnsone-op-'))
  return runNsd({ port: PORT, zones: zoneFile(dir) }, fn)
}

/** A resolver aimed at the fixture nameserver and the fixture RPC. */
const resolverWith = (records, rpc) => new HNSResolver({
  spv: spvWith(records),
  authoritative: { server: '127.0.0.1', port: PORT },
  opRpcUrls: RPC_URLS,
  fetchImpl: rpc.fetchImpl
})

// ─────────────────────────────────────────────── the encodings

test('namehash matches EIP-137 and the writer that mints these names', () => {
  assert.equal('0x' + namehash('').toString('hex'), '0x' + '00'.repeat(32))
  assert.equal('0x' + namehash('eth').toString('hex'),
    '0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae')
  assert.equal('0x' + namehash('foo.eth').toString('hex'),
    '0xde9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f')
  assert.equal('0x' + namehash('maya.persist').toString('hex'), NODE.maya)
})

test('the RRset storage key is keccak256 of the lowercased wire name', () => {
  assert.equal('0x' + dnsNameKey('maya.persist').toString('hex'), KEY.maya)
  assert.equal('0x' + dnsNameKey('MAYA.Persist.').toString('hex'), KEY.maya)
  assert.equal('0x' + dnsNameKey('_443._tcp.maya.persist').toString('hex'), KEY.mayaTlsa)
})

test('an _op NS is recognised only in the exact 20-byte form', () => {
  assert.equal(opRegistryFor([OP_NS]), REGISTRY)
  assert.equal(opRegistryFor([{ type: 'NS', ns: `${REGISTRY.toUpperCase()}._op.` }]), REGISTRY)
  assert.equal(opRegistryFor([{ type: 'NS', ns: '0x1234._op.' }]), null)
  assert.equal(opRegistryFor([{ type: 'NS', ns: `${REGISTRY}._eth.` }]), null)
  assert.equal(opRegistryFor(DNS_NS), null)
})

test('no _op target is ever offered to the nameserver hop', () => {
  const records = [...DNS_NS, OP_NS, { type: 'NS', ns: '0x1234._op.' }]
  assert.deepEqual(dnsNameservers(records).map((r) => r.ns),
    ['ns1.hns.one.', 'ns2.hns.one.'])
})

// ─────────────────────────────────────────────── the route

test('a name with on-chain A + TLSA answers from the registry, not the zone', () =>
  withNsd(async () => {
    const rpc = fakeRpc()
    const out = await resolverWith([...DNS_NS, OP_NS], rpc).resolve('maya.persist')
    assert.equal(out.kind, 'site')
    assert.equal(out.address, SITE_IP) // not SENTINEL: the zone was never asked
    assert.equal(out.tlsa.length, 1)
    assert.equal(out.tlsa[0].usage, 3)
    assert.equal(out.tlsa[0].selector, 1)
    assert.equal(out.tlsa[0].matchingType, 1)
    assert.equal(out.tlsa[0].certificate, TLSA_HASH)
    assert.equal(out.tlsa[0].name, '_443._tcp.maya.persist')
    assert.equal(out.allowInsecure, false) // it has a pin
    // The hop is named, so the trust panel can say who was trusted for it.
    assert.equal(out.op.registry, REGISTRY)
    assert.equal(out.op.rpc, 'rpc.invalid')
    assert.ok(rpc.calls.length >= 4)
  }))

test('a contenthash answers as the content pointer it names', () =>
  withNsd(async () => {
    const rpc = fakeRpc()
    const out = await resolverWith([...DNS_NS, OP_NS], rpc).resolve('ark.persist')
    assert.equal(out.kind, 'arweave')
    assert.equal(out.txid, ARWEAVE_TXID)
    assert.equal(out.op.registry, REGISTRY)
    // Answered on contenthash alone: no DNS record was ever read.
    assert.deepEqual(rpc.calls.map((c) => c.sel), [SEL.resolver, SEL.contenthash])
  }))

test('a private address in the registry is blocked, never fetched', () =>
  withNsd(async () => {
    const rpc = fakeRpc()
    const out = await resolverWith([...DNS_NS, OP_NS], rpc).resolve('evil.persist')
    assert.equal(out.kind, 'blocked')
    assert.equal(out.address, '127.0.0.1')
  }))

test('a node with no resolver in the registry falls back to the nameservers', () =>
  withNsd(async () => {
    const rpc = fakeRpc()
    const out = await resolverWith([...DNS_NS, OP_NS], rpc).resolve('gone.persist')
    assert.equal(out.kind, 'site')
    assert.equal(out.address, '203.0.113.10')
    assert.equal(out.op, undefined)
    // It gave up after resolver() returned the zero address — nothing further
    // is worth asking a registry that does not know the name.
    assert.deepEqual(rpc.calls.map((c) => c.sel), [SEL.resolver])
  }))

test('a minted name with nothing written falls back to the nameservers', () =>
  withNsd(async () => {
    // dead.persist has a resolver but hasDNSRecords is false and there is no
    // contenthash: the ordinary shape of a name whose holder has published
    // nothing on chain yet. The zone still serves it.
    const rpc = fakeRpc()
    const out = await resolverWith([...DNS_NS, OP_NS], rpc).resolve('dead.persist')
    assert.equal(out.kind, 'site')
    assert.equal(out.address, '203.0.113.11')
    assert.deepEqual(rpc.calls.map((c) => c.sel),
      [SEL.resolver, SEL.contenthash, SEL.hasDNSRecords])
  }))

test('every RPC failing falls back to the nameservers, having tried them all', () =>
  withNsd(async () => {
    const rpc = fakeRpc({ fail: true })
    const out = await resolverWith([...DNS_NS, OP_NS], rpc).resolve('maya.persist')
    assert.equal(out.kind, 'site')
    assert.equal(out.address, SENTINEL) // the zone answered, as it must
    assert.equal(out.op, undefined)
    // Both endpoints were tried before the route was abandoned, and it was
    // abandoned at the first call rather than limping on.
    assert.deepEqual(rpc.calls.map((c) => c.url), RPC_URLS)
  }))

test('a malformed _op label is ignored and Optimism is never asked', () =>
  withNsd(async () => {
    const rpc = fakeRpc()
    const records = [...DNS_NS, { type: 'NS', ns: '0x1234._op.' }]
    const out = await resolverWith(records, rpc).resolve('maya.persist')
    assert.equal(out.kind, 'site')
    assert.equal(out.address, SENTINEL)
    assert.deepEqual(rpc.calls, [])
  }))

test('a TLD with no _op NS resolves exactly as before', () =>
  withNsd(async () => {
    const rpc = fakeRpc()
    const out = await resolverWith(DNS_NS, rpc).resolve('plain.persist')
    assert.equal(out.kind, 'site')
    assert.equal(out.address, '203.0.113.12')
    assert.equal(out.allowInsecure, true) // no TLSA in the zone, said so authoritatively
    assert.deepEqual(rpc.calls, [])
  }))

test('the apex keeps its own behaviour: _op applies below the TLD only', () =>
  withNsd(async () => {
    const rpc = fakeRpc()
    // `persist` itself has NS records and no pointer, so it delegates like any
    // other apex — the registry is for the names underneath it.
    const out = await resolverWith([...DNS_NS, OP_NS], rpc).resolve('persist')
    assert.equal(out.kind, 'unregistered') // the fixture zone has no apex A
    assert.deepEqual(rpc.calls, [])
  }))

/**
 * An RPC that answers `resolver()` and hands back one fixed contenthash — so a
 * test can say "the contract holds exactly these bytes" without threading a
 * new node hash through the shared fixture.
 */
function rpcWithContenthash (hex) {
  const word = (b) => Buffer.concat([Buffer.alloc(32 - b.length), b])
  const payload = Buffer.from(hex.replace(/^0x/, ''), 'hex')
  const pad = (32 - (payload.length % 32)) % 32
  const asBytes = Buffer.concat([
    word(Buffer.from([0x20])),
    word(Buffer.from([payload.length])),
    payload,
    Buffer.alloc(pad)
  ])
  return async (url, init) => {
    const { params } = JSON.parse(init.body)
    const data = Buffer.from(String(params[0].data).slice(2), 'hex')
    const sel = '0x' + data.subarray(0, 4).toString('hex')
    const out = sel === SEL.resolver
      ? word(Buffer.from(RESOLVER_ADDR.slice(2), 'hex'))
      : sel === SEL.contenthash ? asBytes : Buffer.alloc(32)
    return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x' + out.toString('hex') }) }
  }
}

test('a contenthash we cannot USE refuses — it does not go and ask the seller', async () => {
  // The distinction that matters. No contenthash at all is an ordinary
  // minted-but-empty name, and the DNS records are the right next step. A
  // contenthash that is PRESENT and unusable is not: falling through hands the
  // name to the TLD owner's nameserver, which is precisely the box this route
  // exists to avoid trusting for a name its owner may no longer hold.
  //
  // swarm-ns (0xe4) is a real EIP-1577 codec this build cannot fetch.
  const { resolution } = await resolveOp('name.tld', {
    registry: REGISTRY,
    rpcUrls: RPC_URLS,
    fetchImpl: rpcWithContenthash('0xe40101fa011b20' + '11'.repeat(32)),
    timeout: 500
  })
  assert.ok(resolution, 'it fell through to the nameservers instead of refusing')
  assert.equal(resolution.kind, 'unsupported-pointer')
  assert.notEqual(resolution.protocol, 'ipfs')
})

test('a GARBLED contenthash refuses too, rather than being treated as absent', async () => {
  const { resolution } = await resolveOp('name.tld', {
    registry: REGISTRY,
    rpcUrls: RPC_URLS,
    fetchImpl: rpcWithContenthash('0xdeadbeef'),
    timeout: 500
  })
  assert.ok(resolution)
  assert.equal(resolution.kind, 'unsupported-pointer')
})

test('an EMPTY contenthash still falls through — that is a normal minted name', async () => {
  const { resolution } = await resolveOp('name.tld', {
    registry: REGISTRY,
    rpcUrls: RPC_URLS,
    fetchImpl: rpcWithContenthash('0x'),
    timeout: 500
  })
  assert.ok(!resolution || resolution.kind !== 'unsupported-pointer',
    'an empty record must not be mistaken for an unusable one')
})
