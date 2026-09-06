/*
 * A local, auth-gated, HNS-only HTTP CONNECT tunnel so secure hns:// pages
 * can open WebSockets to their own Handshake host.
 *
 * WHY THIS EXISTS. hns:// is a `secure:true` scheme (src/main.cjs), so an
 * hns:// document is a SECURE CONTEXT. Chromium blocks mixed content in a
 * secure context BEFORE the network layer, so a plaintext `ws://` from an
 * hns:// page never even reaches us — it is killed in the renderer. The only
 * WebSocket a secure page may open is `wss://`. So a realtime Handshake app
 * must use `wss://<name>/path`, and the browser must be able to ROUTE that
 * wss to the Handshake host without a public CA and without breaking the
 * end-to-end TLS that DANE pins.
 *
 * MECHANISM. Chromium never resolves the destination of an HTTP proxy itself:
 * when the web session's proxy PAC points `wss://pxls/ws` at this server, it
 * sends `CONNECT pxls:443` with the LITERAL name. We resolve it with the
 * browser's own HNSResolver at connect time, dial the resolved IP, answer
 * `200 Connection Established`, and splice raw TCP. Chromium performs the WS
 * handshake and the end-to-end TLS itself, so the certificate the origin
 * presents is the same one the document's DANE pin is checked against (that
 * DANE check lives in the web session's setCertificateVerifyProc, not here —
 * this stays a dumb TCP pipe so it CANNOT terminate or weaken the TLS it is
 * carrying).
 *
 * WHY HTTP CONNECT AND NOT SOCKS5. The first cut of this tunnel was SOCKS5
 * with RFC 1929 username/password auth. It could never work: Chromium's
 * SOCKS5 client offers ONLY the "no authentication" method (it does not
 * implement RFC 1929 at all) and ignores `user:pass@` in PAC proxy strings,
 * so the greeting was refused and every wss:// died on the spot. HTTP CONNECT
 * is the one proxy protocol Chromium drives correctly for a wss:// upgrade.
 *
 * ON PROXY AUTH (and why there is none). A second cut required
 * `Proxy-Authorization: Basic` and answered the 407 from Electron's app
 * 'login' event. That ALSO could not work: Chromium does not surface a
 * proxy-auth challenge for a WebSocket handshake to the embedder — the
 * 'login' event never fires for a wss:// CONNECT, so the 407 is never answered
 * and every socket dies. So the tunnel does not require auth; its boundary is
 * that it is bound to 127.0.0.1 ONLY and fenced to HNS hosts. A rogue local
 * process gains nothing it could not already do itself — resolve a Handshake
 * name over public DoH and open a TCP connection to its public IP; the tunnel
 * only performs that same name→IP→dial for a caller already on loopback. (If
 * a `credentials` object is passed it is still enforced, so a future platform
 * that CAN authenticate a wss:// proxy re-enables the gate with no code change;
 * today none is passed.)
 *
 * THREE MITIGATIONS, all enforced here (plus loopback-only binding above):
 *   (a) HNS-ONLY — a CONNECT to any non-Handshake host is refused (normal
 *       wss:// relays are sent DIRECT by the PAC and never reach us; this is
 *       the defence in depth if one ever does).
 *   (b) SSRF — the resolved address is run through the same isPublicAddress
 *       guard as every other HNS fetch, so a name pointing at loopback /
 *       private / link-local / metadata is refused.
 *   (c) TOR GATE — while IP Protection is on, a direct dial would leak the
 *       real IP, so the CONNECT is refused with a clean 403 (the page sees
 *       ws.onerror), mirroring the 523 gate on the raw-socket HNS path in
 *       src/hns/index.js. Tor-CHAINING so wss works while anonymized is a
 *       documented follow-up, not this.
 *
 * Pure and injectable: the resolver, the anonymized-check, the dial, the HNS
 * classifier and the public-address guard are all constructor inputs so the
 * whole thing is exercised over loopback with stubs. No http module, no
 * framing — it parses one CONNECT head and then it is raw TCP.
 */

import net from 'node:net'
import { timingSafeEqual } from 'node:crypto'

import { isHnsHost as defaultIsHnsHost } from '../../../src/hns-host.js'
import { decodeHnsHost } from '../../../src/hns-url.cjs'
import { isPublicAddress as defaultIsPublicAddress } from '../../../src/safe-address.js'
import { anyFreePort } from './free-port.js'
import { socksDialer } from '../../../src/socks-dial.js'

/**
 * The one port a CONNECT may name. A DANE pin is looked up at `_443._tcp`
 * (Chapter 1 HS-6), so 443 is the only port on which the TLS Chromium runs
 * through this tunnel is pinned to the name. A CONNECT to 80 is what a
 * plaintext `ws://` from a non-secure page becomes; refusing it here means
 * no Handshake WebSocket is ever spliced unpinned — and nothing about the
 * refusal reaches a system resolver, which sending `ws:` DIRECT would.
 */
export const TUNNEL_PORT = 443

const HEAD_END = Buffer.from('\r\n\r\n')
// A CONNECT head is a request line + a handful of headers. Anything larger is
// not a proxy client talking to us.
const MAX_HEAD_BYTES = 8 * 1024
export const AUTH_REALM = 'wildroot-hns-ws'

/** Constant-time string compare that never short-circuits on length. */
function safeEqual (a, b) {
  const ab = Buffer.from(String(a), 'utf8')
  const bb = Buffer.from(String(b), 'utf8')
  if (ab.length !== bb.length) {
    // Still burn a compare so length is not a timing oracle.
    timingSafeEqual(ab, ab)
    return false
  }
  return timingSafeEqual(ab, bb)
}

function defaultDial (host, port) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port })
    const onErr = (err) => { s.destroy(); reject(err) }
    s.once('error', onErr)
    s.once('connect', () => { s.removeListener('error', onErr); resolve(s) })
  })
}

/**
 * Read one HTTP request head (through the blank line) off a fresh socket.
 * Resolves `{ head, leftover }`; rejects if the socket ends first or the head
 * exceeds MAX_HEAD_BYTES. Bytes after the blank line are returned untouched —
 * a well-behaved CONNECT client sends none before our 200, but if any arrive
 * they belong to the tunnel and are forwarded, not dropped.
 */
function readHead (socket) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0)
    const onData = (d) => {
      buf = Buffer.concat([buf, d])
      const at = buf.indexOf(HEAD_END)
      if (at >= 0) {
        cleanup()
        resolve({ head: buf.subarray(0, at).toString('latin1'), leftover: buf.subarray(at + HEAD_END.length) })
      } else if (buf.length > MAX_HEAD_BYTES) {
        cleanup()
        reject(new Error('request head too large'))
      }
    }
    const onEnd = () => { cleanup(); reject(new Error('socket ended mid-head')) }
    const cleanup = () => {
      socket.removeListener('data', onData)
      socket.removeListener('end', onEnd)
      socket.removeListener('error', onEnd)
    }
    socket.on('data', onData)
    socket.on('end', onEnd)
    socket.on('error', onEnd)
  })
}

/**
 * Parse a CONNECT head into `{ method, target, headers }` (header names
 * lowercased; a repeated header keeps its first value). Returns null for
 * anything that is not a well-formed HTTP/1.x request head.
 */
export function parseConnectHead (head) {
  const lines = String(head).split('\r\n')
  const m = /^([A-Z]+) (\S+) HTTP\/1\.[01]$/.exec(lines[0] || '')
  if (!m) return null
  const headers = Object.create(null)
  for (const line of lines.slice(1)) {
    if (!line) continue
    const i = line.indexOf(':')
    if (i <= 0) return null
    const name = line.slice(0, i).trim().toLowerCase()
    if (!(name in headers)) headers[name] = line.slice(i + 1).trim()
  }
  return { method: m[1], target: m[2], headers }
}

/**
 * `host:port` from a CONNECT target. Returns null when it is not exactly
 * `<host>:<1..65535>`. An IPv6 literal (`[::1]:443`) parses to a bracketed
 * host, which the HNS classifier then refuses — an IP literal is never HNS.
 */
export function parseAuthority (target) {
  const m = /^(\[[^\]]*\]|[^:\[\]]+):(\d{1,5})$/.exec(String(target)) // eslint-disable-line no-useless-escape
  if (!m) return null
  const port = Number(m[2])
  if (!(port >= 1 && port <= 65535)) return null
  return { host: m[1], port }
}

/** The `user:pass` inside a `Basic` Proxy-Authorization value, or null. */
export function basicCredential (headerValue) {
  const m = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(String(headerValue || '').trim())
  if (!m) return null
  try { return Buffer.from(m[1], 'base64').toString('utf8') } catch { return null }
}

export class WsProxy {
  /**
   * @param {object} opts
   * @param {{resolve:(host:string)=>Promise<any>}} opts.resolver shared HNSResolver
   * @param {() => boolean} [opts.isAnonymized] true while IP Protection is on
   * @param {{user:string, pass:string}} opts.credentials per-session proxy creds
   * @param {(host:string, port:number)=>Promise<import('node:net').Socket>} [opts.dial]
   * @param {() => (string|null)} [opts.torSocks] the device-local Tor's
   *        `socks5://…` while IP Protection is on, else null. With it, an
   *        anonymized request is dialled THROUGH Tor instead of refused.
   * @param {(host:string)=>boolean} [opts.isHnsHost] host classifier (test override)
   * @param {(addr:string)=>boolean} [opts.isPublicAddress] SSRF guard (test override)
   */
  constructor ({ resolver, isAnonymized, credentials, dial, isHnsHost, isPublicAddress, torSocks, ports } = {}) {
    this.torSocks = typeof torSocks === 'function' ? torSocks : () => null
    /** The ports a CONNECT may name. TUNNEL_PORT alone in the browser; a test's TLS server sits elsewhere. */
    this.ports = new Set(Array.isArray(ports) && ports.length ? ports : [TUNNEL_PORT])
    if (!resolver || typeof resolver.resolve !== 'function') {
      throw new Error('ws-proxy: a resolver with .resolve() is required')
    }
    this.resolver = resolver
    this.isAnonymized = typeof isAnonymized === 'function' ? isAnonymized : () => false
    // Optional. Chromium cannot authenticate a wss:// proxy (see file header),
    // so none is passed today and the auth gate is skipped; a well-formed
    // {user, pass} still enforces it, for a future platform that can.
    this.credentials = (credentials && credentials.user && credentials.pass) ? credentials : null
    this.dial = dial || defaultDial
    this.isHnsHost = isHnsHost || defaultIsHnsHost
    this.isPublicAddress = isPublicAddress || defaultIsPublicAddress
    this.server = null
    this.port = null
    /** @type {Set<import('node:net').Socket>} live client sockets, so stop()
     *  can tear an in-flight tunnel down instead of hanging on server.close. */
    this._conns = new Set()
  }

  /** Bind on loopback and start accepting. Resolves with the chosen port. */
  async start (port) {
    const chosen = port || await anyFreePort('127.0.0.1')
    this.server = net.createServer((sock) => {
      this._conns.add(sock)
      sock.on('close', () => this._conns.delete(sock))
      this._handle(sock)
    })
    await new Promise((resolve, reject) => {
      this.server.once('error', reject)
      // 127.0.0.1 ONLY — never a routable interface. A LAN peer must not be
      // able to reach a proxy that resolves Handshake names and dials for it.
      this.server.listen(chosen, '127.0.0.1', () => {
        this.server.removeListener('error', reject)
        resolve()
      })
    })
    this.port = this.server.address().port
    return this.port
  }

  stop () {
    return new Promise((resolve) => {
      if (!this.server) return resolve()
      const server = this.server
      this.server = null
      // Drop any live tunnels first, or server.close waits on them forever.
      for (const s of this._conns) { try { s.destroy() } catch {} }
      this._conns.clear()
      server.close(() => resolve())
    })
  }

  /** Send a failure response and half-close gracefully. `end` flushes the
   *  response before the FIN, where a bare `destroy` could drop the queued
   *  bytes and leave the page with a reset instead of a clean proxy error. */
  _refuse (client, status, reason, extraHeaders = []) {
    const lines = [
      `HTTP/1.1 ${status} ${reason}`,
      ...extraHeaders,
      'Content-Length: 0',
      'Proxy-Connection: close',
      'Connection: close',
      '', ''
    ]
    client.end(lines.join('\r\n'))
  }

  _authOk (headers) {
    const presented = basicCredential(headers['proxy-authorization'])
    if (presented == null) return false
    return safeEqual(presented, `${this.credentials.user}:${this.credentials.pass}`)
  }

  async _handle (client) {
    client.on('error', () => client.destroy())
    let parsed
    let leftover
    try {
      const got = await readHead(client)
      leftover = got.leftover
      parsed = parseConnectHead(got.head)
    } catch {
      // A malformed/oversized head, or the client vanished mid-request.
      try { client.destroy() } catch {}
      return
    }
    if (!parsed) return this._refuse(client, 400, 'Bad Request')

    // 1. Optional proxy auth (skipped when no credentials — the default; see
    // header). When enforced, an unauthenticated peer gets 407 and learns
    // nothing else about what this proxy accepts.
    if (this.credentials && !this._authOk(parsed.headers)) {
      return this._refuse(client, 407, 'Proxy Authentication Required',
        [`Proxy-Authenticate: Basic realm="${AUTH_REALM}"`])
    }

    // 2. Only CONNECT. A plain proxied GET is not a tunnel and is not served.
    if (parsed.method !== 'CONNECT') {
      return this._refuse(client, 405, 'Method Not Allowed', ['Allow: CONNECT'])
    }
    const authority = parseAuthority(parsed.target)
    if (!authority) return this._refuse(client, 400, 'Bad Request')
    // The page's origin host is the URL form; a numeric TLD carries its `_`.
    const host = decodeHnsHost(authority.host)
    const { port } = authority

    // 3. Only the pinned port (see TUNNEL_PORT). Before the gate and before
    // resolving: a refused port costs no lookup.
    if (!this.ports.has(port)) {
      return this._refuse(client, 403, 'Forbidden')
    }

    // 4. MITIGATION (c): while IP Protection is on, a direct dial from this
    // process would leak the real IP. With the device-local Tor's SOCKS port
    // to hand, the dial goes THROUGH it — the chain proof and the DANE pin
    // are unchanged, only the socket's route differs; without it, refuse.
    // Checked BEFORE resolving so nothing about the request touches the
    // network on the refusal path.
    let dial = this.dial
    if (this.isAnonymized()) {
      const socks = this.torSocks()
      if (!socks) return this._refuse(client, 403, 'Forbidden')
      dial = socksDialer(socks)
    }

    // 5. MITIGATION (a): HNS-only. Chromium sends the literal name for a
    // Handshake host; anything else (an ICANN relay, an IP literal) is
    // refused — the PAC should never route it here in the first place.
    if (!this.isHnsHost(host)) {
      return this._refuse(client, 403, 'Forbidden')
    }

    // 6. Resolve via the shared HNSResolver (the SAME lookups an hns://
    // navigation makes), and take the dialable address.
    let resolution
    try {
      resolution = await this.resolver.resolve(host)
    } catch {
      return this._refuse(client, 502, 'Bad Gateway')
    }
    const address = resolution && resolution.address
    if (!address) {
      // No A/SYNTH address to dial (unregistered, or an ipfs=/ar= name that
      // has no TCP origin a WebSocket could reach).
      return this._refuse(client, 502, 'Bad Gateway')
    }

    // 7. MITIGATION (b): SSRF. Refuse loopback / private / link-local /
    // metadata, exactly like the raw-socket HNS fetch path.
    if (!this.isPublicAddress(address)) {
      return this._refuse(client, 403, 'Forbidden')
    }

    // 8. Dial and splice. Chromium does TLS + the WS handshake end to end
    // over this pipe; we never look inside it.
    let upstream
    try {
      upstream = await dial(address, port)
    } catch {
      return this._refuse(client, 502, 'Bad Gateway')
    }
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n')
    if (leftover && leftover.length) upstream.write(leftover)
    splice(client, upstream)
  }
}

/** Bidirectional raw pipe with a single, idempotent teardown of both ends. */
function splice (a, b) {
  let done = false
  const teardown = () => {
    if (done) return
    done = true
    a.destroy()
    b.destroy()
  }
  a.pipe(b)
  b.pipe(a)
  for (const s of [a, b]) {
    s.on('error', teardown)
    s.on('close', teardown)
    s.on('end', teardown)
  }
}

export default WsProxy
