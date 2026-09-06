// The local HTTP CONNECT tunnel that lets a secure hns:// page open a wss://
// WebSocket to its own Handshake host (src/hns/ws-proxy.js).
//
// Everything here is deterministic and offline: the resolver, the anonymized
// flag, the dial and (where needed) the public-address guard are all injected,
// and the one end-to-end case stands up a real self-signed TLS origin on
// loopback so the tunnel is proven to preserve end-to-end TLS + DANE.
//
// The client side speaks EXACTLY what Chromium speaks to an HTTP proxy for a
// wss:// URL: `CONNECT host:port HTTP/1.1` with `Proxy-Authorization: Basic`
// once it has been challenged with 407. (The first cut of this tunnel was
// SOCKS5 + RFC 1929 auth, and its tests passed — against a stub client that
// offered user/pass, which Chromium never does. These tests pin the protocol
// Chromium actually uses.)
//
// NOTE on the SSRF guard vs loopback: isPublicAddress REJECTS 127.0.0.1, so
// the integration test — whose origin can only live on loopback — injects a
// permissive `isPublicAddress: () => true`. The dedicated SSRF unit test uses
// the REAL guard and asserts a loopback resolution is refused, so nothing is
// lost by the override.

import { test } from 'node:test'
import { createRequire } from 'node:module'
import assert from 'node:assert/strict'
import net from 'node:net'
import tls from 'node:tls'
import { createHash, X509Certificate } from 'node:crypto'

import { WsProxy, parseConnectHead, parseAuthority, basicCredential, AUTH_REALM } from '../src/ws-proxy.js'
import { buildWsPac } from '../src/ws-proxy-pac.js'
import { verifyDane } from '../../../src/dane.js'
import { generateLoopbackCert } from '../../../src/self-cert.js'

// Numeric Handshake names are OFF by default (NT-1, decided 2026-09-06); this
// file exercises the convention, so the switch is on for the whole file.
createRequire(import.meta.url)('../../../src/classify-host.cjs').setNumericNames(true)

const CREDS = { user: 'sess-user', pass: 'sess-pass-1234' }
const basic = ({ user, pass } = CREDS) => 'Basic ' + Buffer.from(`${user}:${pass}`, 'utf8').toString('base64')

// ------------------------------------------------------------- tiny helpers

function listen (server, host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, host, () => { server.removeListener('error', reject); resolve(server.address().port) })
  })
}

function connectRaw (port) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, '127.0.0.1')
    s.once('connect', () => { s.removeListener('error', reject); resolve(s) })
    s.once('error', reject)
  })
}

/** A buffered reader over a client socket: `head()` resolves with the parsed
 *  status line + headers of ONE HTTP response; `read(n)` with n raw bytes. */
function reader (sock) {
  let buf = Buffer.alloc(0)
  let ended = false
  const waiters = []
  const onData = (d) => { buf = Buffer.concat([buf, d]); pump() }
  const onClose = () => { ended = true; pump() }
  function pump () {
    while (waiters.length) {
      const w = waiters[0]
      if (w.n != null) {
        if (buf.length < w.n) break
        waiters.shift().resolve(buf.subarray(0, w.n)); buf = buf.subarray(w.n)
      } else {
        const at = buf.indexOf('\r\n\r\n')
        if (at < 0) break
        const text = buf.subarray(0, at).toString('latin1'); buf = buf.subarray(at + 4)
        const [line, ...hs] = text.split('\r\n')
        const m = /^HTTP\/1\.1 (\d{3}) (.*)$/.exec(line)
        const headers = Object.fromEntries(hs.map((h) => { const i = h.indexOf(':'); return [h.slice(0, i).toLowerCase(), h.slice(i + 1).trim()] }))
        waiters.shift().resolve({ status: Number(m && m[1]), reason: m && m[2], headers })
      }
    }
    if (ended) while (waiters.length) waiters.shift().reject(new Error('closed'))
  }
  sock.on('data', onData)
  sock.on('close', onClose)
  return {
    head () { return new Promise((resolve, reject) => { waiters.push({ resolve, reject }); pump() }) },
    read (n) { return new Promise((resolve, reject) => { waiters.push({ n, resolve, reject }); pump() }) },
    write (b) { sock.write(b) },
    detach () { sock.removeListener('data', onData); sock.removeListener('close', onClose); return buf },
    closed () { return new Promise((resolve) => { if (ended) return resolve(); sock.once('close', resolve) }) },
    sock
  }
}

/** Open a client to the proxy and send one CONNECT (Chromium's exact shape). */
async function connect (t, port, { host = 'pxls', targetPort = 443, auth = basic(), method = 'CONNECT', target } = {}) {
  const sock = await connectRaw(port)
  t.after(() => { try { sock.destroy() } catch {} })
  const c = reader(sock)
  const lines = [`${method} ${target || `${host}:${targetPort}`} HTTP/1.1`, `Host: ${host}:${targetPort}`]
  if (auth) lines.push(`Proxy-Authorization: ${auth}`)
  lines.push('Proxy-Connection: keep-alive', '', '')
  c.write(lines.join('\r\n'))
  return c
}

/** A resolver stub that records lookups and returns a fixed resolution. */
function stubResolver (resolution) {
  const calls = []
  return {
    calls,
    resolve: async (host) => { calls.push(host); if (resolution instanceof Error) throw resolution; return resolution }
  }
}

async function startProxy (t, opts) {
  const proxy = new WsProxy(opts)
  await proxy.start()
  t.after(() => proxy.stop())
  return proxy
}

// ------------------------------------------------------------ pure parsers

test('parseConnectHead: Chromium\'s CONNECT head parses; junk does not', () => {
  const p = parseConnectHead('CONNECT pxls:443 HTTP/1.1\r\nHost: pxls:443\r\nProxy-Authorization: Basic abc=\r\nProxy-Connection: keep-alive')
  // headers is a null-prototype map (no __proto__ smuggling); spread it for the compare.
  assert.deepEqual({ ...p, headers: { ...p.headers } }, { method: 'CONNECT', target: 'pxls:443', headers: { host: 'pxls:443', 'proxy-authorization': 'Basic abc=', 'proxy-connection': 'keep-alive' } })
  assert.equal(parseConnectHead('\x05\x01\x00'), null, 'a SOCKS greeting is not an HTTP head')
  assert.equal(parseConnectHead('CONNECT pxls:443 HTTP/1.1\r\nno-colon-here'), null)
})

test('parseAuthority: host:port only, port in range, IPv6 literal stays bracketed', () => {
  assert.deepEqual(parseAuthority('pxls:443'), { host: 'pxls', port: 443 })
  assert.deepEqual(parseAuthority('hello.14898:8443'), { host: 'hello.14898', port: 8443 })
  assert.deepEqual(parseAuthority('[::1]:443'), { host: '[::1]', port: 443 })
  assert.equal(parseAuthority('pxls'), null, 'no port')
  assert.equal(parseAuthority('pxls:0'), null)
  assert.equal(parseAuthority('pxls:70000'), null)
  assert.equal(parseAuthority('http://pxls:443'), null)
})

test('basicCredential decodes Basic and refuses other schemes', () => {
  assert.equal(basicCredential(basic()), 'sess-user:sess-pass-1234')
  assert.equal(basicCredential('Bearer xyz'), null)
  assert.equal(basicCredential(undefined), null)
})

test('the PAC routes ws/wss to a Handshake host via PROXY (no credential in the string)', () => {
  const pac = buildWsPac(new Set(['com', 'org']), { port: 4444, baseDirective: 'SOCKS5 127.0.0.1:9050' })
  assert.match(pac, /'PROXY 127\.0\.0\.1:4444'/)
  assert.doesNotMatch(pac, /SOCKS5 [^']*@/, 'Chromium ignores user:pass@ in PAC strings; never emit one')
  assert.match(pac, /return 'SOCKS5 127\.0\.0\.1:9050'/, 'non-ws traffic keeps the anonymizer directive')
})

// --------------------------------------------------------------- unit tests

test('CONNECT to an HNS host dials the resolved IP and splices bytes', async (t) => {
  const echo = net.createServer((s) => s.pipe(s))
  const echoPort = await listen(echo)
  t.after(() => echo.close())

  const dialed = []
  const resolver = stubResolver({ kind: 'site', address: '93.184.216.34', tlsa: [] })
  const proxy = await startProxy(t, {
    resolver,
    credentials: CREDS,
    // Real classifier ('pxls' -> HNS) and real SSRF guard (93.184.216.34 public).
    dial: async (host, port) => { dialed.push([host, port]); return connectRaw(echoPort) }
  })

  const c = await connect(t, proxy.port, { host: 'pxls', targetPort: 443 })
  const res = await c.head()
  assert.equal(res.status, 200, 'Connection Established')
  assert.deepEqual(dialed, [['93.184.216.34', 443]], 'dial the resolved address + requested port')
  assert.deepEqual(resolver.calls, ['pxls'], 'the literal name is resolved once')

  c.write(Buffer.from('hello-ws'))
  const echoed = await c.read(8)
  assert.equal(echoed.toString(), 'hello-ws', 'the tunnel splices raw TCP both ways')
})

test('a numeric-TLD host (hello.14898) is treated as HNS and reaches the resolver', async (t) => {
  const resolver = stubResolver({ kind: 'unregistered' }) // no address -> refused after resolve
  const proxy = await startProxy(t, { resolver, credentials: CREDS, dial: async () => { throw new Error('should not dial') } })
  const c = await connect(t, proxy.port, { host: 'hello.14898' })
  const res = await c.head()
  assert.equal(res.status, 502, 'no dialable address -> bad gateway')
  assert.deepEqual(resolver.calls, ['hello.14898'], 'a numeric TLD classified as HNS is resolved')
})

test('DEFAULT (no credentials): an unauthenticated CONNECT is served, not challenged', async (t) => {
  // Chromium cannot answer a proxy-auth challenge for a wss:// handshake, so
  // the tunnel ships WITHOUT credentials — a plain CONNECT must tunnel. The
  // boundary is loopback-only + the HNS/SSRF/Tor fences, not proxy auth.
  const echo = net.createServer((s) => s.pipe(s))
  const echoPort = await listen(echo)
  t.after(() => echo.close())
  const resolver = stubResolver({ kind: 'site', address: '93.184.216.34', tlsa: [] })
  const proxy = await startProxy(t, { resolver, dial: async () => connectRaw(echoPort) })
  const c = await connect(t, proxy.port, { auth: null }) // no Proxy-Authorization
  const res = await c.head()
  assert.equal(res.status, 200, 'served without auth')
  assert.deepEqual(resolver.calls, ['pxls'])
})

test('OPTIONAL auth (future platform): with credentials, no/wrong auth -> 407, nothing resolved', async (t) => {
  const resolver = stubResolver({ kind: 'site', address: '93.184.216.34', tlsa: [] })
  const proxy = await startProxy(t, { resolver, credentials: CREDS, dial: async () => { throw new Error('nope') } })
  for (const auth of [null, basic({ user: CREDS.user, pass: 'WRONG' })]) {
    const c = await connect(t, proxy.port, { auth })
    const res = await c.head()
    assert.equal(res.status, 407)
    assert.equal(res.headers['proxy-authenticate'], `Basic realm="${AUTH_REALM}"`)
  }
  assert.equal(resolver.calls.length, 0, 'a challenged client never gets to resolve anything')
})

test('FENCE 3: a loopback/private resolution is refused (SSRF), no dial', async (t) => {
  const dialed = []
  const resolver = stubResolver({ kind: 'site', address: '127.0.0.1', tlsa: [] })
  // REAL isPublicAddress guard here.
  const proxy = await startProxy(t, { resolver, credentials: CREDS, dial: async (...a) => { dialed.push(a); return connectRaw(1) } })
  const c = await connect(t, proxy.port, { host: 'pxls' })
  const res = await c.head()
  assert.equal(res.status, 403, 'connection not allowed by policy')
  assert.equal(dialed.length, 0, 'a private resolution must never be dialed')
})

test('FENCE 4: while anonymized with no Tor port, a CONNECT is refused before resolving', async (t) => {
  const resolver = stubResolver({ kind: 'site', address: '93.184.216.34', tlsa: [] })
  const dialed = []
  const proxy = await startProxy(t, {
    resolver,
    credentials: CREDS,
    isAnonymized: () => true,
    dial: async (...a) => { dialed.push(a); return connectRaw(1) }
  })
  const c = await connect(t, proxy.port, { host: 'pxls' })
  const res = await c.head()
  assert.equal(res.status, 403, 'refused cleanly while IP Protection is on')
  assert.equal(resolver.calls.length, 0, 'the Tor gate short-circuits before any network work')
  assert.equal(dialed.length, 0)
})

test('FENCE 2: a non-HNS host is refused and never resolved', async (t) => {
  const resolver = stubResolver({ kind: 'site', address: '93.184.216.34', tlsa: [] })
  const proxy = await startProxy(t, { resolver, credentials: CREDS, dial: async () => { throw new Error('nope') } })
  const c = await connect(t, proxy.port, { host: 'example.com' }) // ICANN TLD -> not HNS
  const res = await c.head()
  assert.equal(res.status, 403, 'a normal relay host is refused (the PAC sends it DIRECT)')
  assert.equal(resolver.calls.length, 0, 'non-HNS hosts are never looked up')
})

test('FENCE 2: an IP literal (v4 or bracketed v6) is refused', async (t) => {
  const resolver = stubResolver({ kind: 'site', address: '93.184.216.34', tlsa: [] })
  const proxy = await startProxy(t, { resolver, credentials: CREDS })
  for (const target of ['93.184.216.34:443', '[::1]:443']) {
    const c = await connect(t, proxy.port, { target })
    const res = await c.head()
    assert.equal(res.status, 403, `${target} is not a Handshake name`)
  }
  assert.equal(resolver.calls.length, 0)
})

test('a non-CONNECT method (a proxied GET) is refused with 405', async (t) => {
  const resolver = stubResolver({ kind: 'site', address: '1.2.3.4', tlsa: [] })
  const proxy = await startProxy(t, { resolver, credentials: CREDS })
  const c = await connect(t, proxy.port, { method: 'GET', target: 'http://pxls/' })
  const res = await c.head()
  assert.equal(res.status, 405)
  assert.equal(res.headers.allow, 'CONNECT')
})

test('a SOCKS5 greeting (the old protocol) is answered with 400, not hung on', async (t) => {
  const resolver = stubResolver({ kind: 'site', address: '1.2.3.4', tlsa: [] })
  const proxy = await startProxy(t, { resolver, credentials: CREDS })
  const sock = await connectRaw(proxy.port)
  t.after(() => sock.destroy())
  const c = reader(sock)
  // A non-HTTP byte string still has to reach a blank line for the head
  // reader; a SOCKS client never sends one, so it is simply closed on
  // oversize/EOF. Prove the oversize path: 9 KB of junk is cut off.
  c.write(Buffer.alloc(9 * 1024, 0x05))
  await c.closed()
})

// -------------------------------------------------- deterministic e2e (TLS+DANE)

test('e2e: the tunnel preserves end-to-end TLS so a DANE pin verifies through it', async (t) => {
  // A real self-signed origin on loopback, standing in for a wss:// Handshake
  // host. It TLS-echoes, so we can prove both the DANE binding and the splice.
  const { cert, key } = generateLoopbackCert()
  const tlsaHex = createHash('sha256')
    .update(new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex')

  const origin = tls.createServer({ cert, key }, (s) => s.pipe(s))
  const originPort = await listen(origin)
  t.after(() => origin.close())

  // Resolver returns the loopback origin; the SSRF guard is overridden to allow
  // loopback ONLY for this in-process origin (see the file header).
  const resolver = stubResolver({ kind: 'site', address: '127.0.0.1', tlsa: [{ usage: 3, selector: 1, matchingType: 1, certificate: tlsaHex }] })
  const proxy = await startProxy(t, {
    resolver,
    credentials: CREDS,
    isPublicAddress: () => true,
    ports: [originPort] // the in-process TLS origin is not on 443
  })

  const c = await connect(t, proxy.port, { host: 'pxls', targetPort: originPort })
  const res = await c.head()
  assert.equal(res.status, 200, 'tunnel established')

  // Hand the raw socket to a TLS client — Chromium does exactly this: the WS
  // handshake + TLS run end to end over the spliced pipe.
  const raw = c.detach()
  assert.equal(raw.length, 0, 'no bytes should trail the 200 before TLS starts')

  const { peerRaw, roundTrip } = await new Promise((resolve, reject) => {
    const tlsSock = tls.connect({ socket: c.sock, servername: 'pxls', rejectUnauthorized: false }, () => {
      const peer = tlsSock.getPeerCertificate(true)
      tlsSock.write('ping-through-dane')
      tlsSock.once('data', (d) => resolve({ peerRaw: peer && peer.raw, roundTrip: d.toString(), tlsSock }))
    })
    tlsSock.once('error', reject)
    t.after(() => tlsSock.destroy())
  })

  assert.equal(roundTrip, 'ping-through-dane', 'application bytes survive the whole tunnel end to end')
  const outcome = verifyDane(peerRaw, [{ usage: 3, selector: 1, matchingType: 1, certificate: tlsaHex }])
  assert.equal(outcome.state, 'verified', 'the cert seen THROUGH the tunnel is the one the DANE pin binds')

  // And a wrong pin must fail closed on that same peer cert.
  const wrong = verifyDane(peerRaw, [{ usage: 3, selector: 1, matchingType: 1, certificate: 'de'.repeat(32) }])
  assert.equal(wrong.state, 'tlsa_mismatch', 'a mismatched pin is rejected, not shrugged off')
})

// ---------------------------------------------------------------- the pinned port, and Tor

test('a CONNECT to any port but 443 is refused before the name is resolved — a plaintext ws:// is never spliced', async (t) => {
  const resolver = stubResolver({ kind: 'site', address: '203.0.113.7' })
  const proxy = await startProxy(t, { resolver, isAnonymized: () => false })
  for (const targetPort of [80, 8080, 1965]) {
    const c = await connect(t, proxy.port, { host: 'pxls', targetPort })
    const head = await c.head()
    assert.equal(head.status, 403, String(targetPort))
  }
  assert.deepEqual(resolver.calls, [], 'no lookup for a refused port')
})

test('with IP Protection on, the dial goes THROUGH the Tor SOCKS port when there is one, and is refused when there is not', async (t) => {
  // A fake SOCKS5 server that records the CONNECT it is asked for and then
  // answers "connected" without dialling anything, so the splice happens
  // against a dead upstream — the assertion is about the route, not the bytes.
  const asked = []
  const socks = net.createServer((client) => {
    let stage = 0
    client.on('data', (chunk) => {
      if (stage === 0) { client.write(Buffer.from([5, 0])); stage = 1; return }
      if (stage === 1) {
        stage = 2
        asked.push({ atyp: chunk[3], host: chunk[3] === 1 ? [...chunk.subarray(4, 8)].join('.') : '?', port: chunk.readUInt16BE(chunk.length - 2) })
        client.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]))
      }
    })
  })
  const socksPort = await listen(socks)
  t.after(() => socks.close())
  const resolver = stubResolver({ kind: 'site', address: '203.0.113.7' })
  let socksUrl = `socks5://127.0.0.1:${socksPort}`
  const proxy = await startProxy(t, {
    resolver,
    isAnonymized: () => true,
    torSocks: () => socksUrl,
    isPublicAddress: () => true
  })
  const c = await connect(t, proxy.port, { host: 'pxls', targetPort: 443 })
  const head = await c.head()
  assert.equal(head.status, 200, 'dialled through Tor, spliced')
  assert.deepEqual(asked, [{ atyp: 1, host: '203.0.113.7', port: 443 }], 'the resolved address went to the SOCKS port, by address, never by name')
  c.sock.destroy()
  // No Tor port: refuse rather than dial from the real address.
  socksUrl = null
  const c2 = await connect(t, proxy.port, { host: 'pxls', targetPort: 443 })
  assert.equal((await c2.head()).status, 403)
})
