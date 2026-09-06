/*
 * IPv6 for Handshake names (RFC 3596; hsd SYNTH6/GLUE6) — the highest-severity
 * item in RESEARCH-STANDARDS-GAP-2026-09-06: an IPv6-only site did not
 * resolve at all, because nothing ever asked for an AAAA.
 *
 * What has to be true now, and is pinned here:
 *
 * 1. THE ONE RULE FOR TWO FAMILIES (`preferV4`). A dual-stack name is reached
 *    over IPv4; IPv6 is the route for a name that has nothing else. Same rule
 *    at the zone, in the chain glue, for a nameserver host and over DoH.
 * 2. A SIGNED ZONE'S AAAA IS VALIDATED EXACTLY AS ITS A. Tampered bytes fail
 *    closed; the A-then-AAAA fall-through needs no denial proof (the attacker
 *    who forges "no A" can only steer to the zone's own signed AAAA).
 * 3. THE SPV PATH DECODES `_synth`. hsd's root server renders SYNTH4/SYNTH6
 *    as a referral to `_<base32hex>._synth.`; the reader used to keep that
 *    as a NAMESERVER and never found the address — so no SYNTH name resolved
 *    from an SPV node. Now the label (or its glue) IS the address.
 * 4. EVERY DIAL TAKES EITHER FAMILY: the DANE-pinned socket, the plain one,
 *    and the SOCKS5 tunnel (ATYP 0x04).
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import net from 'node:net'
import tls from 'node:tls'
import { createHash, X509Certificate } from 'node:crypto'

import { HNSResolver, preferV4 } from '../src/resolver.js'
import { SPVNode, synthFromNs } from '../src/spv.js'
import { DoHResolver } from '../src/doh.js'
import { TYPES } from '../src/dns-query.js'
import { dsDigest, dnskeyRdata } from '../src/dnssec.js'
import { connectDane, connectPlain } from '../src/dane-connect.js'
import { socksDialer } from '../src/socks-dial.js'
import { generateLoopbackCert } from '../src/self-cert.js'
import { freeUdpPort } from './free-port.js'
import { FIXTURE, FIXTURE_DIR, withNsd as runNsd } from './nsd.js'
import { dnsProxy, qtypeOf, replaceBytes } from './dns-proxy.js'
import { stubWireFetch } from './doh-wire.js'

const PORT = await freeUdpPort()
const withNsd = (fn, zones) => runNsd(zones ? { port: PORT, zones } : { port: PORT }, fn)

// dns-query.js renders an AAAA as eight uncompressed groups.
const SIX = '2001:db8:0:0:0:0:0:6'
const DUAL4 = '203.0.113.30'
const DUAL6 = '2001:db8:0:0:0:0:0:30'

/** The DS the chain would carry for the frozen signed fixture. */
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

function resolverAt (port, records) {
  return new HNSResolver({
    spv: { getResource: async () => ({ records }), isSynced: async () => true },
    authoritative: { server: '127.0.0.1', port },
    timeout: 4000
  })
}

const signedChain = () => [{ type: 'NS', ns: 'ns1.hns.one.' }, chainDs()]

// ---------------------------------------------------------------------------
// 1. the rule
// ---------------------------------------------------------------------------

test('preferV4: the IPv4 when there is one, else the IPv6, else nothing', () => {
  assert.equal(preferV4(['2001:db8::1', '198.51.100.1']), '198.51.100.1')
  assert.equal(preferV4(['2001:db8::1']), '2001:db8::1')
  assert.equal(preferV4([]), null)
  assert.equal(preferV4([null, '', '2001:db8::2']), '2001:db8::2')
})

// ---------------------------------------------------------------------------
// 2. the chain resource: SYNTH6 and GLUE6
// ---------------------------------------------------------------------------

function chainOnly (table) {
  return new HNSResolver({
    spv: {
      getResource: async (tld) => Object.prototype.hasOwnProperty.call(table, tld) ? table[tld] : null,
      isSynced: async () => true
    },
    timeout: 1000
  })
}

test('a SYNTH6 TLD serves its own apex over IPv6, plaintext allowed (consensus attests it)', async () => {
  const out = await chainOnly({ six: { records: [{ type: 'SYNTH6', address: '2001:db8::5' }] } }).resolve('six')
  assert.equal(out.kind, 'site')
  assert.equal(out.address, '2001:db8::5')
  assert.equal(out.allowInsecure, true)
})

test('a subdomain never inherits a SYNTH6 apex, exactly as it never inherited SYNTH4', async () => {
  const out = await chainOnly({ six: { records: [{ type: 'SYNTH6', address: '2001:db8::5' }] } }).resolve('www.six')
  assert.notEqual(out.kind, 'site', JSON.stringify(out))
})

test('SYNTH4 beside SYNTH6: the IPv4 is the one used', async () => {
  const out = await chainOnly({
    both: { records: [{ type: 'SYNTH6', address: '2001:db8::5' }, { type: 'SYNTH4', address: '198.51.100.5' }] }
  }).resolve('both')
  assert.equal(out.address, '198.51.100.5')
})

test('a SYNTH6 that is loopback, link-local or an embedded private IPv4 is BLOCKED', async () => {
  for (const address of ['::1', 'fe80::1', 'fc00::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1']) {
    const out = await chainOnly({ bad: { records: [{ type: 'SYNTH6', address }] } }).resolve('bad')
    assert.equal(out.kind, 'blocked', `${address}: ${JSON.stringify(out)}`)
  }
})

test('a nameserver with only GLUE6 gets its IPv6; one with both gets its IPv4', async () => {
  const r = chainOnly({
    reg: {
      records: [
        { type: 'NS', ns: 'ns1.reg.' }, { type: 'NS', ns: 'ns2.reg.' },
        { type: 'GLUE6', ns: 'ns1.reg.', address: '2001:db8::1' },
        { type: 'GLUE6', ns: 'ns2.reg.', address: '2001:db8::2' },
        { type: 'GLUE4', ns: 'ns2.reg.', address: '198.51.100.2' }
      ]
    }
  })
  assert.equal(await r._chainAddress('ns1.reg'), '2001:db8::1')
  assert.equal(await r._chainAddress('ns2.reg'), '198.51.100.2')
  assert.equal(await r._addressForNsHost('ns1.reg', [{ type: 'GLUE6', ns: 'ns1.reg.', address: '2001:db8::9' }]),
    '2001:db8::9', 'handed glue wins, whichever family it is')
})

test('a SYNTH6 apex is an address for the nameserver named by it', async () => {
  const r = chainOnly({ solo: { records: [{ type: 'SYNTH6', address: '2001:db8::7' }] } })
  assert.equal(await r._chainAddress('solo'), '2001:db8::7')
})

test('an IPv6 literal is not a name, any more than an IPv4 literal was', async () => {
  const r = chainOnly({})
  await assert.rejects(r.resolve('2001:db8::1'), /not a name/)
  await assert.rejects(r.resolve('203.0.113.1'), /not a name/)
})

// ---------------------------------------------------------------------------
// 3. the SPV path: what the root server actually sends
// ---------------------------------------------------------------------------

test('synthFromNs decodes hsd\'s _synth nameserver name into the address it encodes', () => {
  // hsd lib/dns/resource.js: `_${base32.encodeHex(ip)}._synth.` — these two
  // come from hsd itself (Resource.fromJSON(...).toDNS()).
  assert.deepEqual(synthFromNs('_oopm818._synth.'), { type: 'SYNTH4', address: '198.51.100.5' })
  assert.deepEqual(synthFromNs('_400gre0000000000000000000k._synth.'), { type: 'SYNTH6', address: '2001:db8:0:0:0:0:0:5' })
  assert.deepEqual(synthFromNs('_OOPM818._SYNTH'), { type: 'SYNTH4', address: '198.51.100.5' }, 'case and the dot do not matter')
  assert.equal(synthFromNs('ns1.woodburn.'), null)
  assert.equal(synthFromNs('_abc._synth.'), null, 'a label of the wrong length is not an address')
  assert.equal(synthFromNs('_oopm81w._synth.'), null, 'outside the base32hex alphabet')
})

/** Wire-encode a DNS name. */
function wireName (name) {
  const parts = String(name).replace(/\.$/, '').split('.').filter(Boolean)
  return Buffer.concat([...parts.map((p) => Buffer.concat([Buffer.from([p.length]), Buffer.from(p)])), Buffer.from([0])])
}

function rr (name, type, rdata) {
  const head = Buffer.alloc(10)
  head.writeUInt16BE(type, 0)
  head.writeUInt16BE(1, 2)
  head.writeUInt32BE(300, 4)
  head.writeUInt16BE(rdata.length, 8)
  return Buffer.concat([wireName(name), head, rdata])
}
const v4 = (a) => Buffer.from(a.split('.').map(Number))
const v6 = (a) => {
  const [head, tail = ''] = a.split('::')
  const h = head ? head.split(':') : []
  const t = tail ? tail.split(':') : []
  const out = Buffer.alloc(16)
  const groups = [...h, ...new Array(8 - h.length - t.length).fill('0'), ...t]
  groups.forEach((g, i) => out.writeUInt16BE(parseInt(g, 16), i * 2))
  return out
}

/**
 * A root nameserver over TCP that answers EVERY question about a TLD with
 * the same referral — the shape hsd's root server gives (authority NS,
 * additional glue, nothing in the answer section).
 * @param {Record<string, {authority: Buffer[], additional: Buffer[]}>} zones
 */
async function fakeRoot (zones) {
  const server = net.createServer((client) => {
    client.on('error', () => {})
    client.once('data', (chunk) => {
      const q = chunk.subarray(2)
      let i = 12
      const labels = []
      while (q[i] !== 0) { labels.push(q.toString('ascii', i + 1, i + 1 + q[i])); i += q[i] + 1 }
      const question = q.subarray(12, i + 5)
      const zone = zones[labels.join('.').toLowerCase()] || { authority: [], additional: [] }
      const header = Buffer.alloc(12)
      header.writeUInt16BE(q.readUInt16BE(0), 0)
      header.writeUInt16BE(0x8180, 2)
      header.writeUInt16BE(1, 4)
      header.writeUInt16BE(0, 6)
      header.writeUInt16BE(zone.authority.length, 8)
      header.writeUInt16BE(zone.additional.length, 10)
      const msg = Buffer.concat([header, question, ...zone.authority, ...zone.additional])
      const framed = Buffer.alloc(2 + msg.length)
      framed.writeUInt16BE(msg.length, 0)
      msg.copy(framed, 2)
      client.end(framed)
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { port: server.address().port, close: () => new Promise((resolve) => server.close(resolve)) }
}

/** An SPVNode whose RPC has nothing (SPV mode) and whose root server is `port`. */
function spvOverRoot (port) {
  const spv = Object.create(SPVNode.prototype)
  spv._rpc = async () => null
  spv._nsPort = async () => port
  return spv
}

test('SPV path: AAAA glue in a referral is GLUE6, beside the GLUE4', async () => {
  const root = await fakeRoot({
    woodburn: {
      authority: [rr('woodburn.', TYPES.NS, wireName('ns1.woodburn.')), rr('woodburn.', TYPES.NS, wireName('ns2.woodburn.'))],
      additional: [
        rr('ns1.woodburn.', TYPES.A, v4('170.187.241.138')),
        rr('ns1.woodburn.', TYPES.AAAA, v6('2400:8907::f03c:93ff:fe5a:8a32')),
        rr('ns2.woodburn.', TYPES.AAAA, v6('2600:3c02::f03c:93ff:fe5a:8adc'))
      ]
    }
  })
  try {
    const { records } = await spvOverRoot(root.port).getResource('woodburn')
    assert.deepEqual(records.filter((r) => r.type === 'NS').map((r) => r.ns), ['ns1.woodburn.', 'ns2.woodburn.'])
    assert.deepEqual(records.filter((r) => r.type === 'GLUE4'), [{ type: 'GLUE4', ns: 'ns1.woodburn.', address: '170.187.241.138' }])
    assert.deepEqual(records.filter((r) => r.type === 'GLUE6').map((r) => [r.ns, r.address]), [
      ['ns1.woodburn.', '2400:8907:0:0:f03c:93ff:fe5a:8a32'],
      ['ns2.woodburn.', '2600:3c02:0:0:f03c:93ff:fe5a:8adc']
    ])
  } finally { await root.close() }
})

test('SPV path: a _synth referral is the SYNTH record, not a nameserver — and the name then resolves', async () => {
  const root = await fakeRoot({
    six: {
      authority: [rr('six.', TYPES.NS, wireName('_400gre0000000000000000000k._synth.'))],
      additional: [rr('_400gre0000000000000000000k._synth.', TYPES.AAAA, v6('2001:db8::5'))]
    },
    four: {
      authority: [rr('four.', TYPES.NS, wireName('_oopm818._synth.'))],
      additional: [rr('_oopm818._synth.', TYPES.A, v4('198.51.100.5'))]
    },
    bare: { // no glue at all: the label carries the address
      authority: [rr('bare.', TYPES.NS, wireName('_oopm818._synth.'))],
      additional: []
    }
  })
  try {
    const spv = spvOverRoot(root.port)
    assert.deepEqual((await spv.getResource('six')).records, [{ type: 'SYNTH6', address: '2001:db8:0:0:0:0:0:5' }])
    assert.deepEqual((await spv.getResource('four')).records, [{ type: 'SYNTH4', address: '198.51.100.5' }])
    assert.deepEqual((await spv.getResource('bare')).records, [{ type: 'SYNTH4', address: '198.51.100.5' }])

    const resolver = new HNSResolver({ spv: { getResource: (tld) => spv.getResource(tld), isSynced: async () => true }, timeout: 1000 })
    const out = await resolver.resolve('six')
    assert.equal(out.kind, 'site', `an SPV node's SYNTH6 apex did not resolve: ${JSON.stringify(out)}`)
    assert.equal(out.address, '2001:db8:0:0:0:0:0:5')
    assert.equal(out.allowInsecure, true)
    const out4 = await resolver.resolve('four')
    assert.equal(out4.kind, 'site', `an SPV node's SYNTH4 apex did not resolve: ${JSON.stringify(out4)}`)
    assert.equal(out4.address, '198.51.100.5')
  } finally { await root.close() }
})

// ---------------------------------------------------------------------------
// 4. the zone: signed AAAA, validated like the A
// ---------------------------------------------------------------------------

test('an AAAA-only host on the signed zone resolves over IPv6, validated and pinned', () =>
  withNsd(async () => {
    const out = await resolverAt(PORT, signedChain()).resolve(`six.${FIXTURE.zone}`)
    assert.equal(out.kind, 'site', JSON.stringify(out))
    assert.equal(out.address, SIX)
    assert.equal(out.dnssecValidated, true, 'the AAAA RRset validates to the on-chain DS')
    assert.equal(out.tlsa.length, 1, 'its TLSA is read and validated like any other')
    assert.equal(out.allowInsecure, false)
  }))

test('a dual-stack host is reached over IPv4; its proven "no TLSA" still permits plaintext', () =>
  withNsd(async () => {
    const out = await resolverAt(PORT, signedChain()).resolve(`dual.${FIXTURE.zone}`)
    assert.equal(out.kind, 'site', JSON.stringify(out))
    assert.equal(out.address, DUAL4)
    assert.equal(out.dnssecValidated, true)
    assert.equal(out.allowInsecure, true)
  }))

test('an attacker who drops the A can only steer to the zone\'s OWN signed AAAA', () =>
  withNsd(async () => {
    const proxy = await dnsProxy(PORT, { onQuery: (q) => (qtypeOf(q) === TYPES.A ? 'drop' : null) })
    try {
      const out = await resolverAt(proxy.port, signedChain()).resolve(`dual.${FIXTURE.zone}`)
      assert.equal(out.kind, 'site', JSON.stringify(out))
      assert.equal(out.address, DUAL6)
      assert.equal(out.dnssecValidated, true, 'the AAAA it fell through to was validated')
    } finally { await proxy.close() }
  }))

test('a tampered AAAA on the signed zone fails closed', () =>
  withNsd(async () => {
    const proxy = await dnsProxy(PORT, {
      onReply: (q, reply) => (qtypeOf(q) === TYPES.AAAA
        ? replaceBytes(reply, v6('2001:db8::6'), v6('2001:db8::66'))
        : null)
    })
    try {
      const out = await resolverAt(proxy.port, signedChain()).resolve(`six.${FIXTURE.zone}`)
      assert.equal(out.kind, 'dnssec-fail', `a forged AAAA was served: ${JSON.stringify(out)}`)
      assert.equal(out.address, '2001:db8:0:0:0:0:0:66', 'the failure names the address it refused')
    } finally { await proxy.close() }
  }))

test('"no A" beside an AAAA that could not be ASKED is not "unregistered"', () =>
  withNsd(async () => {
    const proxy = await dnsProxy(PORT, { onQuery: (q) => (qtypeOf(q) === TYPES.AAAA ? 'drop' : null) })
    try {
      await assert.rejects(resolverAt(proxy.port, signedChain()).resolve(`six.${FIXTURE.zone}`),
        'an answer that could not be had was reported as a fact about the name')
    } finally { await proxy.close() }
  }))

test('an AAAA-only host on an UNSIGNED zone resolves, with its NODATA believed as before', () =>
  withNsd(async () => {
    const out = await resolverAt(PORT, [{ type: 'NS', ns: 'ns1.hns.one.' }]).resolve('only.wrsix')
    assert.equal(out.kind, 'site', JSON.stringify(out))
    assert.equal(out.address, '2001:db8:0:0:0:0:0:60')
    assert.equal(out.allowInsecure, true)
    assert.equal(out.dnssecValidated, false)
  }, `${FIXTURE_DIR}/zones-ipv6.json`))

// ---------------------------------------------------------------------------
// 5. DoH: the ICANN-host lookup and the no-proof site path
// ---------------------------------------------------------------------------

test('DoH addressOf: the A, else the AAAA', async () => {
  const r = new DoHResolver({
    fetchImpl: stubWireFetch({
      'ns.example.com:A': [{ type: TYPES.A, data: '203.0.113.9' }],
      'ns.example.com:AAAA': [{ type: TYPES.AAAA, data: '2001:db8::9' }],
      'six.example.com:AAAA': [{ type: TYPES.AAAA, data: '2001:db8::a' }]
    })
  })
  assert.equal(await r.addressOf('ns.example.com'), '203.0.113.9')
  assert.equal(await r.addressOf('six.example.com'), '2001:db8:0:0:0:0:0:a')
  await assert.rejects(r.addressOf('none.example.com'), /no address/)
})

test('DoH resolves an AAAA-only name as a site, and an IPv6 literal is not a name', async () => {
  const r = new DoHResolver({
    fetchImpl: stubWireFetch({ 'six.14898:AAAA': [{ type: TYPES.AAAA, data: '2001:db8::6' }] })
  })
  const out = await r.resolve('six.14898')
  assert.equal(out.kind, 'site')
  assert.equal(out.address, SIX)
  assert.equal(out.trust, 'doh')
  await assert.rejects(r.resolve('2001:db8::1'), /not a name/)
})

// ---------------------------------------------------------------------------
// 6. the dial
// ---------------------------------------------------------------------------

function pinOf (certPem) {
  return createHash('sha256')
    .update(new X509Certificate(certPem).publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex')
}

async function tlsEchoOn (host) {
  const { cert, key } = generateLoopbackCert()
  const sni = []
  const server = tls.createServer({ cert, key, SNICallback: (name, cb) => { sni.push(name); cb(null, tls.createSecureContext({ cert, key })) } }, (s) => s.pipe(s))
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, host, resolve) })
  return { port: server.address().port, pin: pinOf(cert), sni, close: () => new Promise((resolve) => server.close(resolve)) }
}

/** SOCKS5 that understands ATYP 0x04 and records what it was asked. */
async function fakeSocks6 () {
  const asked = []
  const server = net.createServer((client) => {
    let stage = 'greeting'
    client.on('data', (chunk) => {
      if (stage === 'greeting') { client.write(Buffer.from([5, 0])); stage = 'connect'; return }
      if (stage === 'connect') {
        const atyp = chunk[3]
        assert.equal(atyp, 4, 'an IPv6 address goes out as ATYP 0x04')
        const groups = []
        for (let i = 0; i < 16; i += 2) groups.push(chunk.readUInt16BE(4 + i).toString(16))
        const host = groups.join(':')
        const port = chunk.readUInt16BE(20)
        asked.push({ atyp, host, port })
        stage = 'tunnel'
        const upstream = net.connect({ host, port })
        upstream.on('connect', () => {
          client.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]))
          client.pipe(upstream).pipe(client)
        })
        upstream.on('error', () => client.destroy())
      }
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { url: `socks5://127.0.0.1:${server.address().port}`, asked, close: () => new Promise((resolve) => server.close(resolve)) }
}

const tlsaFor = (pin) => [{ usage: 3, selector: 1, matchingType: 1, certificate: pin }]

test('the DANE-pinned socket and the plain one dial an IPv6 address, directly and through SOCKS', async (t) => {
  let origin
  try {
    origin = await tlsEchoOn('::1')
  } catch (err) {
    t.skip(`no IPv6 loopback here: ${err.message}`)
    return
  }
  const socks = await fakeSocks6()
  try {
    const direct = await connectDane({ address: '::1', port: origin.port, host: 'six', tlsa: tlsaFor(origin.pin) })
    direct.write('v6')
    assert.equal(await new Promise((resolve) => direct.once('data', (d) => resolve(d.toString()))), 'v6')
    direct.destroy()
    assert.deepEqual(origin.sni, ['six'], 'SNI is the Handshake name')

    const viaTor = await connectDane({ address: '::1', port: origin.port, host: 'six', tlsa: tlsaFor(origin.pin), dial: socksDialer(socks.url) })
    viaTor.destroy()
    assert.deepEqual(socks.asked, [{ atyp: 4, host: '0:0:0:0:0:0:0:1', port: origin.port }], 'the proxy is handed the ADDRESS, as 16 bytes')

    await assert.rejects(connectDane({ address: '::1', port: origin.port, host: 'six', tlsa: tlsaFor('00'.repeat(32)) }),
      (err) => /DANE validation failed/.test(err.message))

    const plain = await connectPlain({ address: '::1', port: origin.port })
    plain.destroy()
  } finally { await socks.close(); await origin.close() }
})
