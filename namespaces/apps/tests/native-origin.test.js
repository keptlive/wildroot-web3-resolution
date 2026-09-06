// The routing decisions that put a native Handshake application on the wire:
// the PAC script that selects the tunnel (src/ws-proxy-pac.js) and the parts of
// the tunnel itself (src/ws-proxy.js) that are pure or observable without a
// browser. SPEC.md §4.
//
// The PAC runs INSIDE Chromium as ordinary JavaScript, so it is exercised the
// way Chromium runs it: the generated source is evaluated and FindProxyForURL
// is called with the (url, host) pair Chromium would pass. Its host rule is a
// third copy of the one classifier — the classifier itself, the omnibox's copy
// and this one — so the corpus below holds it to isHnsHost's answer rather
// than to a hand-written expectation.
//
// Nothing here reaches the network: the resolver and the dial are injected, and
// the one live listener binds loopback and is torn down with the test.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'

import { WsProxy, parseConnectHead, parseAuthority, basicCredential } from '../src/ws-proxy.js'
import { buildWsPac, rulesToPacDirective } from '../src/ws-proxy-pac.js'
import { isHnsHost } from '../../../src/hns-host.js'
import icannTlds from '../../../src/icann-tlds.cjs'
import { createRequire } from 'node:module'
// Numeric Handshake names are OFF by default (NT-1, decided 2026-09-06); this
// file exercises the convention, so the switch is on for the whole file.
createRequire(import.meta.url)('../../../src/classify-host.cjs').setNumericNames(true)

const PORT = 4444
const PROXY = `PROXY 127.0.0.1:${PORT}`
const TOR = 'SOCKS5 127.0.0.1:9050'

/** Evaluate a generated PAC exactly as Chromium does: source in, decision out. */
function pacRunner ({ baseDirective = 'DIRECT', tlds = icannTlds } = {}) {
  const source = buildWsPac(tlds, { port: PORT, baseDirective, numericNames: true })
  // eslint-disable-next-line no-new-func
  const find = new Function('url', 'host', `${source}\nreturn FindProxyForURL(url, host)`)
  return { source, find, wss: (h) => find(`wss://${h}/ws`, h), ws: (h) => find(`ws://${h}/ws`, h), https: (h) => find(`https://${h}/`, h) }
}

// ------------------------------------------------------------------ the PAC

test('the PAC sends wss:// to a Handshake host through the tunnel, everything else DIRECT', () => {
  const pac = pacRunner()
  for (const host of ['pxls', 'matt.w3', 'hnshosting', 'foo.bar.baz', 'PXLS', 'pxls.']) {
    assert.equal(pac.wss(host), PROXY, `${host} is a Handshake host`)
  }
  for (const host of ['example.com', 'sub.example.co.uk', 'vitalik.eth', 'expyuzz4wqqyqhjn.onion']) {
    assert.equal(pac.wss(host), 'DIRECT', `${host} is not Handshake and must not reach the tunnel`)
  }
})

test('the PAC treats a numeric TLD as Handshake in both its name and its URL form', () => {
  // A URL cannot carry a bare numeric final label (Chapter 10 Part B), so the
  // host Chromium hands the PAC for a page at hns://hello._14898 is the marked
  // form. Both must route, or the marked form silently falls to DIRECT.
  const pac = pacRunner()
  assert.equal(pac.wss('hello.14898'), PROXY)
  assert.equal(pac.wss('hello._14898'), PROXY)
  assert.equal(pac.wss('_14898'), PROXY)
})

test('the PAC keeps reserved names and IP literals off the tunnel', () => {
  const pac = pacRunner()
  // RFC 6761/6762/8375 and the home-router labels: the user's own device is
  // never a Handshake lookup, so `nas.local` stays direct for the same reason
  // `localhost` does.
  for (const host of ['localhost', 'nas.local', 'printer.home', 'box.lan', 'thing.internal', 'test', 'x.invalid']) {
    assert.equal(pac.wss(host), 'DIRECT', `${host} is network-reserved`)
  }
  for (const host of ['127.0.0.1', '93.184.216.34', '[::1]', '::1', '[fe80::1]']) {
    assert.equal(pac.wss(host), 'DIRECT', `${host} is an IP literal, never a Handshake name`)
  }
})

test('the PAC agrees with the one host classifier across a corpus', () => {
  // Three copies of this rule exist (the classifier, the omnibox, this PAC).
  // A divergence means wss:// either escapes the tunnel or is captured by it
  // for a host the rest of the browser calls ICANN.
  const pac = pacRunner()
  const corpus = [
    'pxls', 'hello.14898', 'hello._14898', '_14898', 'matt.w3', 'hnshosting',
    'foo.bar.baz', 'example.com', 'a.example.org', 'vitalik.eth', 'sub.vitalik.eth',
    'expyuzz4wqqyqhjn.onion', 'localhost', 'nas.local', 'test', 'x.invalid',
    'thing.arpa', '127.0.0.1', '93.184.216.34', '[::1]', '::1', 'PXLS', 'pxls.'
  ]
  for (const host of corpus) {
    assert.equal(pac.wss(host) === PROXY, isHnsHost(host),
      `PAC and isHnsHost disagree about ${host}`)
  }
})

test('every non-WebSocket URL gets the anonymizer’s own directive, unchanged', () => {
  // The PAC is composed INTO the privacy controller's single proxy config, so
  // its non-ws branch must be exactly what that controller asked for — page,
  // search and DoH traffic keeps riding Tor while ws/wss is diverted.
  const off = pacRunner({ baseDirective: 'DIRECT' })
  const on = pacRunner({ baseDirective: TOR })
  for (const host of ['pxls', 'example.com']) {
    assert.equal(off.https(host), 'DIRECT')
    assert.equal(on.https(host), TOR)
    assert.equal(on.find(`http://${host}/`, host), TOR)
  }
  // ...and the Handshake ws rule still wins over the Tor directive, which is
  // what the tunnel's own Tor gate (SPEC §4.4 fence 3) then refuses.
  assert.equal(on.wss('pxls'), PROXY)
})

test('the PAC routes plaintext ws:// to the tunnel too (AP-1)', () => {
  // Pinned as the CURRENT behaviour, not as a desired one: no secure hns://
  // page can produce a ws:// (the renderer blocks it), but a non-secure page
  // can, and this rule would splice it in the clear with no certificate gate.
  const pac = pacRunner()
  assert.equal(pac.ws('pxls'), PROXY)
  assert.equal(pac.ws('example.com'), 'DIRECT')
})

test('the PAC never embeds a credential in a proxy directive', () => {
  // Chromium ignores `user:pass@` in a PAC proxy string, so one written here
  // would be silently dropped and give false assurance.
  const { source } = pacRunner({ baseDirective: TOR })
  assert.doesNotMatch(source, /(PROXY|SOCKS5)\s+[^'";]*@/)
})

test('rulesToPacDirective maps the anonymizer’s rules to a directive', () => {
  assert.equal(rulesToPacDirective(null), 'DIRECT')
  assert.equal(rulesToPacDirective(''), 'DIRECT')
  assert.equal(rulesToPacDirective('socks5://127.0.0.1:9150'), 'SOCKS5 127.0.0.1:9150')
  assert.equal(rulesToPacDirective('socks://127.0.0.1:9150'), 'SOCKS5 127.0.0.1:9150')
  assert.equal(rulesToPacDirective('http://proxy.example:8080'), 'DIRECT', 'an unrecognised rule is never guessed at')
})

// ------------------------------------------------------------- head parsing

test('parseConnectHead keeps the first value of a repeated header and lowercases names', () => {
  const p = parseConnectHead('CONNECT pxls:443 HTTP/1.1\r\nHost: pxls:443\r\nX-Dup: first\r\nX-DUP: second')
  assert.equal(p.headers['x-dup'], 'first')
  assert.equal(Object.getPrototypeOf(p.headers), null, 'a null-prototype map: no __proto__ smuggling')
  assert.equal(parseConnectHead('connect pxls:443 HTTP/1.1'), null, 'the method is case-sensitive')
  assert.equal(parseConnectHead('CONNECT pxls:443 HTTP/2.0'), null, 'only HTTP/1.x')
  assert.equal(parseConnectHead(''), null)
})

test('parseAuthority refuses everything that is not exactly host:port', () => {
  assert.deepEqual(parseAuthority('hello._14898:443'), { host: 'hello._14898', port: 443 })
  assert.deepEqual(parseAuthority('[fe80::1]:8443'), { host: '[fe80::1]', port: 8443 })
  assert.equal(parseAuthority(':443'), null, 'no host')
  assert.equal(parseAuthority('pxls:443:443'), null)
  assert.equal(parseAuthority('pxls:44a'), null)
  assert.equal(parseAuthority('pxls:'), null)
  assert.equal(parseAuthority(''), null)
})

test('basicCredential decodes only a well-formed Basic value', () => {
  assert.equal(basicCredential('basic ' + Buffer.from('u:p').toString('base64')), 'u:p', 'the scheme is case-insensitive')
  assert.equal(basicCredential('Basic not base64!'), null)
  assert.equal(basicCredential(''), null)
})

// -------------------------------------------------------------- the tunnel

function stubResolver (resolution) {
  const calls = []
  return { calls, resolve: async (host) => { calls.push(host); if (resolution instanceof Error) throw resolution; return resolution } }
}

async function startProxy (t, opts) {
  const proxy = new WsProxy(opts)
  await proxy.start()
  t.after(() => proxy.stop())
  return proxy
}

function connect (t, port, target) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1')
    t.after(() => { try { sock.destroy() } catch {} })
    let buf = ''
    sock.on('data', (d) => {
      buf += d.toString('latin1')
      const at = buf.indexOf('\r\n\r\n')
      if (at < 0) return
      const [line, ...hs] = buf.slice(0, at).split('\r\n')
      const m = /^HTTP\/1\.1 (\d{3}) (.*)$/.exec(line)
      resolve({
        status: Number(m && m[1]),
        reason: m && m[2],
        headers: Object.fromEntries(hs.map((h) => { const i = h.indexOf(':'); return [h.slice(0, i).toLowerCase(), h.slice(i + 1).trim()] })),
        closed: new Promise((resolve) => sock.once('close', resolve))
      })
    })
    sock.once('error', reject)
    sock.once('connect', () => sock.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`))
  })
}

test('FENCE 0: the tunnel binds loopback only', async (t) => {
  // The whole reason an unauthenticated proxy is tolerable (SPEC §4.4): a LAN
  // peer must not be able to reach something that resolves Handshake names and
  // dials for it.
  const proxy = await startProxy(t, { resolver: stubResolver({ kind: 'unregistered' }) })
  const address = proxy.server.address()
  assert.equal(address.address, '127.0.0.1')
  assert.equal(address.family, 'IPv4')
  assert.ok(proxy.port > 0 && proxy.port === address.port)
})

test('the CONNECT host is decoded before it is classified or resolved', async (t) => {
  // Chromium sends the URL form of the host, so a numeric TLD arrives carrying
  // its Chapter 10 Part B marker. The resolver must be asked for the NAME.
  const resolver = stubResolver({ kind: 'unregistered' })
  const proxy = await startProxy(t, { resolver, dial: async () => { throw new Error('should not dial') } })
  const res = await connect(t, proxy.port, 'hello._14898:443')
  assert.equal(res.status, 502, 'no dialable address')
  assert.deepEqual(resolver.calls, ['hello.14898'], 'the marker is stripped before resolution')
})

test('a refusal is a complete response followed by a graceful close', async (t) => {
  // `end`, not `destroy`: the page must get a clean proxy error rather than a
  // transport reset, and the response must not be left half-written.
  const resolver = stubResolver({ kind: 'site', address: '93.184.216.34', tlsa: [] })
  const proxy = await startProxy(t, { resolver })
  const res = await connect(t, proxy.port, 'example.com:443')
  assert.equal(res.status, 403)
  assert.equal(res.headers['content-length'], '0')
  assert.equal(res.headers.connection, 'close')
  assert.equal(res.headers['proxy-connection'], 'close')
  await res.closed
  assert.equal(resolver.calls.length, 0, 'a refused host is never looked up')
})

test('a resolver failure is 502, and nothing is dialed', async (t) => {
  const dialed = []
  const proxy = await startProxy(t, {
    resolver: stubResolver(new Error('spv down')),
    dial: async (...a) => { dialed.push(a); throw new Error('should not dial') }
  })
  const res = await connect(t, proxy.port, 'pxls:443')
  assert.equal(res.status, 502)
  assert.equal(dialed.length, 0)
})

test('the tunnel refuses to be constructed without a resolver', () => {
  // It exists to resolve Handshake names with the browser's OWN resolver; one
  // built without it would be a bare open proxy.
  assert.throws(() => new WsProxy({}), /resolver/)
  assert.throws(() => new WsProxy({ resolver: {} }), /resolver/)
})
