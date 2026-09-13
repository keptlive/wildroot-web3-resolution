// A SOCKS5 CONNECT dialer (RFC 1928, "no authentication" method only).
//
// WHY THIS EXISTS. Three of this browser's own network paths are raw TCP
// from the main process, which Electron's session proxy does not cover: the
// resolver's authoritative DNS hop (src/hns/resolver.js → dns-query.js), the
// WebSocket tunnel's upstream dial (src/hns/ws-proxy.js) and a gemini://
// capsule's TLS socket (src/protocols/gemini-protocol.js). With IP
// Protection on, each would otherwise be refused or degraded rather than
// leak the real address. A dialer that speaks SOCKS5 to the device-local Tor
// port lets them keep working — the chain proof stays, the DANE pin stays,
// only the socket goes through Tor. The only SOCKS server this ever talks to is
// the one the anonymizer chose (src/hns/anonymize.js), on loopback.
//
// Address type: a dotted-quad target is sent as ATYP IPv4 so no name reaches
// the proxy; anything else is sent as a domain name (ATYP 0x03) and resolved
// by Tor, never by the local resolver. No username/password: Tor's SocksPort
// accepts the no-auth method, and per-origin credentials for stream
// isolation are a separate design (Chapter 8 of the public specification).

import net from 'node:net'

const VERSION = 0x05
const NO_AUTH = 0x00
const CONNECT = 0x01
const ATYP_IPV4 = 0x01
const ATYP_DOMAIN = 0x03
const ATYP_IPV6 = 0x04
const REPLY_TEXT = {
  0x01: 'general SOCKS server failure',
  0x02: 'connection not allowed by ruleset',
  0x03: 'network unreachable',
  0x04: 'host unreachable',
  0x05: 'connection refused',
  0x06: 'TTL expired',
  0x07: 'command not supported',
  0x08: 'address type not supported'
}

/** `socks5://host:port` -> { host, port }, or null for anything else. */
export function parseSocksUrl (url) {
  const m = /^socks5?h?:\/\/(?:\[([^\]]+)\]|([^:/]+)):(\d+)\/?$/i.exec(String(url || '').trim())
  if (!m) return null
  const port = Number(m[3])
  if (!(port >= 1 && port <= 65535)) return null
  return { host: m[1] || m[2], port }
}

/** The CONNECT request for a target, with the right address type. */
export function connectRequest (host, port) {
  const target = String(host)
  let addr
  if (net.isIPv4(target)) {
    addr = Buffer.concat([Buffer.from([ATYP_IPV4]), Buffer.from(target.split('.').map(Number))])
  } else if (net.isIPv6(target)) {
    const groups = expandIpv6(target)
    addr = Buffer.concat([Buffer.from([ATYP_IPV6]), Buffer.from(groups)])
  } else {
    const name = Buffer.from(target, 'utf8')
    if (!name.length || name.length > 255) throw new Error('SOCKS5: domain name must be 1..255 bytes')
    addr = Buffer.concat([Buffer.from([ATYP_DOMAIN, name.length]), name])
  }
  const p = Buffer.alloc(2)
  p.writeUInt16BE(Number(port), 0)
  return Buffer.concat([Buffer.from([VERSION, CONNECT, 0x00]), addr, p])
}

function expandIpv6 (ip) {
  const [head, tail = ''] = ip.split('::')
  const h = head ? head.split(':') : []
  const t = tail ? tail.split(':') : []
  const groups = [...h, ...Array(8 - h.length - t.length).fill('0'), ...t]
  const out = []
  for (const g of groups) {
    const v = parseInt(g || '0', 16)
    out.push((v >> 8) & 0xff, v & 0xff)
  }
  return out
}

/**
 * How many bytes a CONNECT reply occupies, or 0 if `buf` does not hold a
 * whole one yet.
 */
export function replyLength (buf) {
  if (buf.length < 4) return 0
  const atyp = buf[3]
  if (atyp === ATYP_IPV4) return 4 + 4 + 2
  if (atyp === ATYP_IPV6) return 4 + 16 + 2
  if (atyp === ATYP_DOMAIN) return buf.length < 5 ? 0 : 4 + 1 + buf[4] + 2
  return -1
}

/**
 * A dial function `(host, port) => Promise<net.Socket>` that opens every
 * connection through the SOCKS5 server at `socksUrl`. The returned socket is
 * connected end to end and carries no SOCKS framing; leftover bytes are none,
 * because a SOCKS server sends nothing after its reply.
 * @param {string} socksUrl `socks5://127.0.0.1:9050`
 * @param {{timeout?: number}} [opts]
 */
export function socksDialer (socksUrl, { timeout = 20000 } = {}) {
  const proxy = parseSocksUrl(socksUrl)
  if (!proxy) throw new Error(`not a socks5:// URL: ${String(socksUrl).slice(0, 60)}`)
  return (host, port, { signal, pauseOnConnect = false } = {}) => new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(signal.reason || new Error('SOCKS5: canceled')); return }
    const socket = net.connect({ host: proxy.host, port: proxy.port })
    let stage = 'greeting'
    let buf = Buffer.alloc(0)
    let settled = false
    const cleanup = () => {
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
    }
    const fail = (message) => {
      if (settled) return
      settled = true
      cleanup()
      socket.destroy()
      reject(new Error(`SOCKS5 via ${proxy.host}:${proxy.port}: ${message}`))
    }
    const onAbort = () => fail('canceled')
    const timer = setTimeout(() => fail('timed out'), timeout)
    timer.unref?.()
    signal?.addEventListener('abort', onAbort, { once: true })
    socket.once('error', (err) => fail(err.message))
    socket.once('close', () => { if (stage !== 'done') fail('closed before the connect reply') })
    socket.once('connect', () => {
      socket.write(Buffer.from([VERSION, 1, NO_AUTH]))
    })
    socket.on('data', (chunk) => {
      if (stage === 'done') return
      buf = Buffer.concat([buf, chunk])
      if (stage === 'greeting') {
        if (buf.length < 2) return
        if (buf[0] !== VERSION || buf[1] !== NO_AUTH) return fail('no acceptable authentication method')
        buf = buf.subarray(2)
        stage = 'connect'
        let request
        try { request = connectRequest(host, port) } catch (err) { return fail(err.message) }
        socket.write(request)
      }
      if (stage === 'connect') {
        const len = replyLength(buf)
        if (len < 0) return fail('malformed connect reply')
        if (len === 0 || buf.length < len) return
        if (buf[0] !== VERSION) return fail('malformed connect reply')
        if (buf[1] !== 0x00) return fail(REPLY_TEXT[buf[1]] || `connect failed (${buf[1]})`)
        stage = 'done'
        settled = true
        cleanup()
        if (pauseOnConnect) socket.pause()
        socket.removeAllListeners('data')
        socket.removeAllListeners('close')
        const leftover = buf.subarray(len)
        if (leftover.length) socket.unshift(leftover)
        resolve(socket)
      }
    })
  })
}
