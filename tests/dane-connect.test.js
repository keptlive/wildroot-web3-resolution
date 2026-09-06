/*
 * The DANE-pinned socket to a Handshake site, on both routes
 * (src/hns/dane-connect.js).
 *
 * Private mode (docs/MODES.md) dials the site's resolved address through the
 * device-local Tor's SOCKS port instead of refusing the page. What has to be
 * true for that to be honest: the TLSA check runs on the very handshake that
 * rides the tunnel, a mismatched pin is refused on that route exactly as it
 * is directly, and the proxy is handed an ADDRESS (the chain resolved the
 * name) — never the name.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import tls from 'node:tls'
import { createHash, X509Certificate } from 'node:crypto'

import { connectDane, connectPlain } from '../src/dane-connect.js'
import { socksDialer } from '../src/socks-dial.js'
import { generateLoopbackCert } from '../src/self-cert.js'

/** A SOCKS5 server (RFC 1928, no-auth CONNECT) that records what it was asked and splices to it. */
async function fakeSocks () {
  const asked = []
  const server = net.createServer((client) => {
    let stage = 'greeting'
    client.on('data', (chunk) => {
      if (stage === 'greeting') { client.write(Buffer.from([5, 0])); stage = 'connect'; return }
      if (stage === 'connect') {
        const atyp = chunk[3]
        let host, portAt
        if (atyp === 1) { host = [...chunk.subarray(4, 8)].join('.'); portAt = 8 } else { const n = chunk[4]; host = chunk.subarray(5, 5 + n).toString(); portAt = 5 + n }
        const port = chunk.readUInt16BE(portAt)
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

function pinOf (certPem) {
  return createHash('sha256')
    .update(new X509Certificate(certPem).publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex')
}

async function tlsEcho () {
  const { cert, key } = generateLoopbackCert()
  const sni = []
  const server = tls.createServer({ cert, key, SNICallback: (name, cb) => { sni.push(name); cb(null, tls.createSecureContext({ cert, key })) } }, (s) => s.pipe(s))
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { port: server.address().port, pin: pinOf(cert), sni, close: () => new Promise((resolve) => server.close(resolve)) }
}

const tlsaFor = (pin) => [{ usage: 3, selector: 1, matchingType: 1, certificate: pin }]

test('direct: the handshake is pinned to the TLSA and the socket is handed back verified', async () => {
  const origin = await tlsEcho()
  try {
    const socket = await connectDane({ address: '127.0.0.1', port: origin.port, host: 'pxls', tlsa: tlsaFor(origin.pin) })
    socket.write('hello')
    const echoed = await new Promise((resolve) => socket.once('data', (d) => resolve(d.toString())))
    assert.equal(echoed, 'hello')
    assert.deepEqual(origin.sni, ['pxls'], 'SNI is the Handshake name, on the direct route')
    socket.destroy()
  } finally { await origin.close() }
})

test('through Tor: the same pin check rides the SOCKS tunnel, and the proxy is handed the ADDRESS, not the name', async () => {
  const origin = await tlsEcho()
  const socks = await fakeSocks()
  try {
    const dial = socksDialer(socks.url)
    const socket = await connectDane({ address: '127.0.0.1', port: origin.port, host: 'pxls', tlsa: tlsaFor(origin.pin), dial })
    socket.write('over tor')
    const echoed = await new Promise((resolve) => socket.once('data', (d) => resolve(d.toString())))
    assert.equal(echoed, 'over tor')
    assert.deepEqual(socks.asked, [{ atyp: 1, host: '127.0.0.1', port: origin.port }], 'ATYP IPv4: Tor learns an IP and no name')
    assert.deepEqual(origin.sni, ['pxls'], 'SNI is still the name — the origin serves the same certificate either way')
    socket.destroy()
  } finally { await socks.close(); await origin.close() }
})

test('through Tor: a mismatched pin is refused on the tunnel exactly as it is directly', async () => {
  const origin = await tlsEcho()
  const socks = await fakeSocks()
  try {
    const wrong = tlsaFor('00'.repeat(32))
    for (const dial of [null, socksDialer(socks.url)]) {
      await assert.rejects(
        connectDane({ address: '127.0.0.1', port: origin.port, host: 'pxls', tlsa: wrong, dial }),
        (err) => /DANE validation failed/.test(err.message) && /tlsa_mismatch/.test(err.dane))
    }
    assert.equal(socks.asked.length, 1, 'the tunnel was used for the second attempt')
  } finally { await socks.close(); await origin.close() }
})

test('connectPlain: direct, or through the same dialer', async () => {
  const echo = net.createServer((s) => s.pipe(s))
  await new Promise((resolve) => echo.listen(0, '127.0.0.1', resolve))
  const socks = await fakeSocks()
  try {
    const port = echo.address().port
    const direct = await connectPlain({ address: '127.0.0.1', port })
    direct.destroy()
    const viaTor = await connectPlain({ address: '127.0.0.1', port, dial: socksDialer(socks.url) })
    viaTor.write('x')
    assert.equal(await new Promise((resolve) => viaTor.once('data', (d) => resolve(d.toString()))), 'x')
    viaTor.destroy()
    assert.deepEqual(socks.asked, [{ atyp: 1, host: '127.0.0.1', port }])
  } finally { await socks.close(); await new Promise((resolve) => echo.close(resolve)) }
})
