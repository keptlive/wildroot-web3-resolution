/*
 * A WebSocket class whose every connection is dialled through the device-local
 * Tor's SOCKS port — the Nostr handler's `WebSocketImpl` seam, in Private mode.
 *
 * WHY. A relay must see the question to answer it (there is no oblivious
 * NIP-01), so the only thing Private mode can hide from a relay is who is
 * asking. Node's built-in WebSocket takes no transport, so this uses the `ws`
 * client with an https Agent whose createConnection is: SOCKS5 CONNECT to the
 * relay BY NAME (RFC 1928 ATYP 0x03 — Tor resolves it; the operating system's
 * resolver is never asked), then TLS over that socket with the relay's name as
 * SNI and ordinary WebPKI verification, exactly as the direct client does.
 * Only `wss://` is dialled: a plaintext relay is refused before any socket
 * (the relay guard, src/protocols/nostr/relay.js isSafeRelayUrl, refuses it
 * anyway, and inside Tor a plaintext hop would be readable at the exit).
 *
 * The event surface is the browser's (`onopen`/`onmessage`/`onerror`/
 * `onclose`, `send`, `close`), which is what relay.js drives; `ws` (7 and 8
 * alike) hands a text frame to `onmessage` as a string, so the relay code
 * sees the same `msg.data` either way.
 */

import https from 'node:https'
import tls from 'node:tls'
import WebSocket from 'ws'

import { socksDialer } from '../../../src/socks-dial.js'

/** An https Agent that gets its sockets from a SOCKS dialer and layers TLS on top. */
class TorAgent extends https.Agent {
  constructor (dial, tlsOptions = {}) {
    super({ keepAlive: false })
    this.dial = dial
    this.tlsOptions = tlsOptions
  }

  createConnection (options, cb) {
    const host = String(options.host || options.hostname || '')
    const port = Number(options.port) || 443
    this.dial(host, port).then((raw) => {
      const socket = tls.connect({
        socket: raw,
        servername: options.servername || host,
        ...this.tlsOptions
      })
      const fail = (err) => { socket.destroy(); cb(err) }
      socket.once('secureConnect', () => {
        socket.removeListener('error', fail)
        cb(null, socket)
      })
      socket.once('error', fail)
    }).catch(cb)
  }
}

/**
 * The WebSocket class for one Tor port. Build one per SOCKS URL and reuse it;
 * the agent inside keeps no sockets alive.
 * @param {string} socksUrl `socks5://127.0.0.1:<port>` — the anonymizer's
 * @param {{tls?: object, timeout?: number}} [options] `tls` is for tests
 *   (a loopback certificate); the browser passes none and verifies WebPKI
 * @returns {typeof WebSocket}
 */
export function torWebSocketClass (socksUrl, { tls: tlsOptions = {}, timeout } = {}) {
  const dial = socksDialer(socksUrl, timeout ? { timeout } : {})
  const agent = new TorAgent(dial, tlsOptions)
  return class TorWebSocket extends WebSocket {
    constructor (url, protocols) {
      const parsed = new URL(String(url))
      if (parsed.protocol !== 'wss:') {
        throw new Error(`only a wss:// relay is dialled through Tor (got ${parsed.protocol})`)
      }
      super(url, Array.isArray(protocols) ? protocols : [], { agent })
    }
  }
}
