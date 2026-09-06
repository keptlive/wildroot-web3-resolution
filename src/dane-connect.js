/*
 * One DANE-pinned TLS connection to a Handshake site's resolved address.
 *
 * WHY ITS OWN MODULE. The hns:// handler used to build this socket inline,
 * and the socket is where two rules meet that must hold on every route:
 *   - the certificate is checked against the zone's TLSA on THIS handshake,
 *     before a byte of the request is written, and the socket is never
 *     pooled (a reused keep-alive connection could skip verification);
 *   - the ROUTE may change — direct, or through the device-local Tor's SOCKS
 *     port in Private mode — and the pin check must be identical on both.
 * Taking the raw socket from an injected `dial` keeps the second rule true
 * by construction: TLS is layered over whatever transport was handed in, and
 * verifyDane sees the same certificate either way. The dial is by ADDRESS
 * (the chain already resolved the name), so Tor learns an IP and no name.
 */

import net from 'node:net'
import tls from 'node:tls'

import { verifyDane } from './dane.js'

/**
 * @param {object} args
 * @param {string} args.address the resolved, public-checked address (IPv4 or IPv6)
 * @param {string} args.host the Handshake name (SNI, and the pin's owner)
 * @param {Array} args.tlsa the zone's TLSA records
 * @param {((host: string, port: number) => Promise<import('node:net').Socket>)|null} [args.dial]
 *   the raw-socket dialer (src/hns/socks-dial.js) — null for a direct connection
 * @param {number} [args.port]
 * @param {number} [args.timeout] ms for the connection and the handshake
 * @returns {Promise<import('node:tls').TLSSocket>} the verified socket
 */
export async function connectDane ({ address, host, tlsa, dial = null, port = 443, timeout = 15000 }) {
  const raw = dial ? await dial(address, port) : null
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      ...(raw ? { socket: raw } : { host: address, port }),
      servername: host,
      rejectUnauthorized: false // trust is DANE, not WebPKI
    })
    let settled = false
    const fail = (err) => {
      if (settled) return
      settled = true
      socket.destroy()
      reject(err)
    }
    socket.once('secureConnect', () => {
      const peer = socket.getPeerCertificate(true)
      const outcome = verifyDane(peer && peer.raw, tlsa)
      if (outcome.state !== 'verified') {
        const err = new Error('DANE validation failed')
        err.dane = `${outcome.state}${outcome.detail ? ': ' + outcome.detail : ''}`
        fail(err)
        return
      }
      settled = true
      socket.setTimeout(0)
      resolve(socket)
    })
    socket.setTimeout(timeout, () => fail(new Error('TLS timeout')))
    socket.on('error', (err) => fail(err))
  })
}

/**
 * The plaintext counterpart, for a zone that authoritatively allows HTTP:
 * the same route choice, no pin (there is nothing to pin).
 * @param {{address: string, dial?: Function|null, port?: number}} args
 * @returns {Promise<import('node:net').Socket>}
 */
export async function connectPlain ({ address, dial = null, port = 80 }) {
  if (dial) return dial(address, port)
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: address, port })
    socket.once('connect', () => resolve(socket))
    socket.once('error', reject)
  })
}
