/*
 * The chain proof survives anonymization.
 *
 * With IP Protection on, the two raw-socket paths the resolver owns — the
 * authoritative DNS hop and the SPV node's peer traffic — used to be the
 * reason chain resolution was switched off in favour of DoH. Now the hop is
 * dialled through the device-local Tor's SOCKS5 port (src/hns/socks-dial.js)
 * and the node is started with hsd's own --proxy, so the proof stays and only
 * the asker is hidden. The ICANN lookups a walk needs (a nameserver's name,
 * a CNAME target) go through the DoH/ODoH client in every mode, so the one
 * plaintext lookup on the chain path is gone.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { socksDialer, parseSocksUrl, connectRequest, replyLength } from '../src/socks-dial.js'
import { query, TYPES } from '../src/dns-query.js'
import { HNSResolver } from '../src/resolver.js'
import { DoHResolver } from '../src/doh.js'
import { SPVNode } from '../src/spv.js'
import { stubWireFetch } from './doh-wire.js'
import { freeUdpPort } from './free-port.js'
import { FIXTURE, withNsd } from './nsd.js'

// ---------------------------------------------------------------- SOCKS5

/** A SOCKS5 server that speaks RFC 1928 no-auth CONNECT and records what it was asked. */
async function fakeSocks ({ refuse = false } = {}) {
  const asked = []
  const server = net.createServer((client) => {
    let stage = 'greeting'
    client.on('data', (chunk) => {
      if (stage === 'greeting') {
        assert.equal(chunk[0], 5)
        client.write(Buffer.from([5, 0]))
        stage = 'connect'
        return
      }
      if (stage === 'connect') {
        assert.equal(chunk[0], 5)
        assert.equal(chunk[1], 1)
        const atyp = chunk[3]
        let host, portAt
        if (atyp === 1) { host = [...chunk.subarray(4, 8)].join('.'); portAt = 8 } else if (atyp === 3) { const n = chunk[4]; host = chunk.subarray(5, 5 + n).toString(); portAt = 5 + n } else { host = 'ipv6'; portAt = 20 }
        const port = chunk.readUInt16BE(portAt)
        asked.push({ atyp, host, port })
        if (refuse) { client.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])); return }
        stage = 'tunnel'
        const upstream = net.connect({ host: host === 'ipv6' ? '127.0.0.1' : host, port })
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

/** An echo server: what the tunnel carries comes straight back. */
async function echoServer () {
  const server = net.createServer((s) => s.pipe(s))
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { port: server.address().port, close: () => new Promise((resolve) => server.close(resolve)) }
}

test('the SOCKS5 URL, the CONNECT request and the reply framing', () => {
  assert.deepEqual(parseSocksUrl('socks5://127.0.0.1:9050'), { host: '127.0.0.1', port: 9050 })
  assert.deepEqual(parseSocksUrl('socks5h://[::1]:41000/'), { host: '::1', port: 41000 })
  assert.equal(parseSocksUrl('http://127.0.0.1:9050'), null)
  assert.equal(parseSocksUrl('socks5://127.0.0.1:0'), null)
  // A dotted quad is sent as an address (no name reaches the proxy); a name
  // is sent as a domain for Tor to resolve.
  assert.deepEqual([...connectRequest('203.0.113.7', 53)], [5, 1, 0, 1, 203, 0, 113, 7, 0, 53])
  const dom = connectRequest('ns1.hns.one', 853)
  assert.deepEqual([...dom.subarray(0, 5)], [5, 1, 0, 3, 11])
  assert.equal(dom.subarray(5, 16).toString(), 'ns1.hns.one')
  assert.equal(replyLength(Buffer.from([5, 0, 0, 1, 1, 2, 3, 4, 0, 80])), 10)
  assert.equal(replyLength(Buffer.from([5, 0, 0])), 0)
  assert.equal(replyLength(Buffer.from([5, 0, 0, 9])), -1)
  assert.throws(() => socksDialer('https://x'), /socks5/)
})

test('a dialer opens a connection through the proxy and hands back a clean socket', async () => {
  const proxy = await fakeSocks()
  const echo = await echoServer()
  try {
    const dial = socksDialer(proxy.url, { timeout: 2000 })
    const socket = await dial('127.0.0.1', echo.port)
    const got = new Promise((resolve) => socket.once('data', (d) => resolve(d.toString())))
    socket.write('hello through tor')
    assert.equal(await got, 'hello through tor')
    socket.destroy()
    assert.deepEqual(proxy.asked, [{ atyp: 1, host: '127.0.0.1', port: echo.port }])
  } finally {
    await proxy.close()
    await echo.close()
  }
})

test('a proxy that refuses the connection is an error, never a direct fallback', async () => {
  const proxy = await fakeSocks({ refuse: true })
  try {
    await assert.rejects(socksDialer(proxy.url, { timeout: 2000 })('203.0.113.7', 53), /connection refused/)
  } finally {
    await proxy.close()
  }
})

// ---------------------------------------------------------------- the authoritative hop through the dialer

const PORT = await freeUdpPort()

test('a DNS query takes the dialer it is given, and the answer is the same', () =>
  withNsd({ port: PORT }, async () => {
    const proxy = await fakeSocks()
    try {
      const dial = socksDialer(proxy.url, { timeout: 3000 })
      const reply = await query('127.0.0.1', PORT, FIXTURE.pointerHost, TYPES.TXT, { timeout: 3000, dial })
      assert.ok(reply.answers.some((r) => r.type === TYPES.TXT), 'the pointer TXT arrived through the proxy')
      assert.deepEqual(proxy.asked, [{ atyp: 1, host: '127.0.0.1', port: PORT }])
    } finally {
      await proxy.close()
    }
  }))

test('a whole signed resolution goes through the dialer — the chain proof and DNSSEC are kept', () =>
  withNsd({ port: PORT }, async () => {
    const proxy = await fakeSocks()
    try {
      const { dsDigest, dnskeyRdata } = await import('../src/dnssec.js')
      const signed = JSON.parse(fs.readFileSync(FIXTURE.signed, 'utf8'))
      const raw = Buffer.from(signed.dnskey, 'base64').subarray(4)
      const ds = { type: 'DS', keyTag: signed.key_tag, algorithm: 13, digestType: 2, digest: dsDigest(signed.zone, dnskeyRdata(raw, 257)) }
      const r = new HNSResolver({
        spv: { getResource: async () => ({ records: [{ type: 'NS', ns: 'ns1.hns.one.' }, ds] }), isSynced: async () => true },
        authoritative: { server: '127.0.0.1', port: PORT },
        timeout: 4000,
        dial: socksDialer(proxy.url, { timeout: 3000 })
      })
      const out = await r.resolve(FIXTURE.siteHost)
      assert.equal(out.kind, 'site')
      assert.equal(out.dnssecValidated, true)
      assert.ok(proxy.asked.length >= 3, `every hop went through the proxy (${proxy.asked.length})`)
      assert.ok(proxy.asked.every((a) => a.atyp === 1 && a.host === '127.0.0.1'), 'no name was handed to the proxy for the fixture server')
    } finally {
      await proxy.close()
    }
  }))

// ---------------------------------------------------------------- ICANN hosts in a walk go through DoH

test('a nameserver name and a CNAME target are resolved through the injected lookup, never the OS resolver', async () => {
  const seen = []
  const lookup = async (host) => { seen.push(host); return '203.0.113.99' }
  const r = new HNSResolver({ spv: { getResource: async () => null, isSynced: async () => true }, lookup })
  assert.equal(await r._addressForNsHost('ns1.hns.one', []), '203.0.113.99')
  assert.deepEqual(seen, ['ns1.hns.one'])
  // The DoH client provides exactly that function.
  const doh = new DoHResolver({ fetchImpl: stubWireFetch({ 'ns1.hns.one:A': [{ type: TYPES.A, data: '203.0.113.5' }] }) })
  assert.equal(await doh.addressOf('ns1.hns.one.'), '203.0.113.5')
  await assert.rejects(doh.addressOf('nothing.hns.one'), /no address/)
})

// ---------------------------------------------------------------- the node's own peers

const FAKE = path.join(path.dirname(new URL(import.meta.url).pathname), 'fixtures', 'fake-hsd.cjs')

test('the SPV node is started with hsd --proxy when a Tor SOCKS port is given, and restarted when it changes', async () => {
  const prefix = fs.mkdtempSync(path.join(os.tmpdir(), 'hnsone-spv-'))
  const argsFile = path.join(prefix, 'args.json')
  process.env.FAKE_HSD_ARGS_FILE = argsFile
  const logs = console.log
  console.log = () => {}
  const spv = new SPVNode({ bin: FAKE, pollMs: 50, prefix, proxy: '127.0.0.1:9050' })
  try {
    await spv._spawn()
    let args = JSON.parse(fs.readFileSync(argsFile, 'utf8'))
    assert.ok(args.includes('--proxy=127.0.0.1:9050'), args.join(' '))
    assert.equal(spv._nodeIsProxied('127.0.0.1:9050'), true)
    assert.equal(spv._nodeIsProxied(null), false)
    // The same setting again is a no-op; a different one restarts the child.
    assert.equal(await spv.setProxy('127.0.0.1:9050'), true)
    assert.equal(await spv.setProxy(null), true)
    args = JSON.parse(fs.readFileSync(argsFile, 'utf8'))
    assert.ok(!args.some((a) => a.startsWith('--proxy=')), 'direct again')
    assert.equal(spv._nodeIsProxied(null), true)
  } finally {
    console.log = logs
    await spv.stop()
    delete process.env.FAKE_HSD_ARGS_FILE
    fs.rmSync(prefix, { recursive: true, force: true })
  }
})
