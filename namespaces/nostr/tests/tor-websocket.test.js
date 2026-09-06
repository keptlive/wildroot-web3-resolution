/*
 * Nostr relays through Tor (src/protocols/nostr/tor-websocket.js) — row 15
 * of the divergence inventory, in Private mode.
 *
 * A relay must see the question to answer it; what Private mode hides is the
 * asker. So the WebSocket to a relay is dialled through the device-local
 * Tor's SOCKS port BY NAME (Tor resolves it — the operating system's resolver
 * is never asked) and TLS is layered over that socket with the relay's name
 * as SNI. Driven here by the real relay client (queryRelay) against a real
 * wss:// server behind a fake SOCKS5 server that records what it was asked.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import https from 'node:https'
import tls from 'node:tls'
import * as ws from 'ws'

import { torWebSocketClass } from '../src/tor-websocket.js'
import { queryRelay } from '../src/relay.js'
import { generateLoopbackCert } from '../../../src/self-cert.js'

// ws 8 exports the server class by name; ws 7 hangs it on the default export.
const WebSocketServer = ws.WebSocketServer || ws.default.Server

/** SOCKS5 no-auth CONNECT; a name is mapped to loopback so the test relay answers for `relay.test`. */
async function fakeSocks () {
  const asked = []
  const open = new Set()
  const server = net.createServer((client) => {
    open.add(client)
    client.on('close', () => open.delete(client))
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
        const upstream = net.connect({ host: '127.0.0.1', port })
        open.add(upstream)
        upstream.on('close', () => open.delete(upstream))
        upstream.on('connect', () => {
          client.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]))
          client.pipe(upstream).pipe(client)
        })
        upstream.on('error', () => client.destroy())
      }
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return {
    url: `socks5://127.0.0.1:${server.address().port}`,
    asked,
    close: () => new Promise((resolve) => { for (const s of open) s.destroy(); server.close(resolve) })
  }
}

/** A wss:// relay that answers every REQ with EOSE and records the SNI it was offered. */
async function wssRelay () {
  const { cert, key } = generateLoopbackCert()
  const sni = []
  const frames = []
  const server = https.createServer({ cert, key, SNICallback: (name, cb) => { sni.push(name); cb(null, tls.createSecureContext({ cert, key })) } })
  const sockets = new Set()
  server.on('connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)) })
  const wss = new WebSocketServer({ server })
  wss.on('connection', (socket) => {
    socket.on('message', (raw) => {
      const frame = JSON.parse(String(raw))
      frames.push(frame)
      if (frame[0] === 'REQ') socket.send(JSON.stringify(['EOSE', frame[1]]))
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return {
    port: server.address().port,
    sni,
    frames,
    close: () => new Promise((resolve) => { wss.close(); for (const s of sockets) s.destroy(); server.close(resolve) })
  }
}

test('a relay is dialled through the SOCKS port BY NAME, TLS carries the relay name as SNI, and the query completes', async () => {
  const relay = await wssRelay()
  const socks = await fakeSocks()
  try {
    const WS = torWebSocketClass(socks.url, { tls: { rejectUnauthorized: false } })
    const url = `wss://relay.test:${relay.port}`
    const res = await queryRelay(url, { kinds: [1], limit: 1 }, { timeout: 3000, WebSocketImpl: WS })
    assert.equal(res.error, undefined, JSON.stringify(res))
    assert.deepEqual(res.events, [])
    assert.deepEqual(socks.asked, [{ atyp: 3, host: 'relay.test', port: relay.port }], 'ATYP DOMAINNAME: Tor resolves the relay, the OS never sees it')
    assert.deepEqual(relay.sni, ['relay.test'])
    assert.equal(relay.frames[0][0], 'REQ', 'the question reached the relay through the tunnel')
  } finally { await socks.close(); await relay.close() }
})

test('a plaintext ws:// relay is refused before any socket is opened', async () => {
  const socks = await fakeSocks()
  try {
    const WS = torWebSocketClass(socks.url)
    assert.throws(() => new WS('ws://relay.test/'), /only a wss:\/\/ relay/)
    assert.deepEqual(socks.asked, [])
  } finally { await socks.close() }
})

test('when the SOCKS port refuses, the relay is reported unreachable — never dialled directly', async () => {
  const relay = await wssRelay()
  const dead = net.createServer((c) => c.destroy())
  await new Promise((resolve) => dead.listen(0, '127.0.0.1', resolve))
  try {
    const WS = torWebSocketClass(`socks5://127.0.0.1:${dead.address().port}`, { tls: { rejectUnauthorized: false } })
    const res = await queryRelay(`wss://127.0.0.1:${relay.port}`, { kinds: [1] }, { timeout: 3000, WebSocketImpl: WS })
    assert.ok(res.error, 'an error is reported')
    assert.deepEqual(relay.frames, [], 'nothing reached the relay by any other route')
  } finally { await new Promise((resolve) => dead.close(resolve)); await relay.close() }
})
