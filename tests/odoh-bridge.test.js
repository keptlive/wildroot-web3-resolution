// The loopback ODoH bridge: the thing that lets ORDINARY web browsing use the
// oblivious path, since Chromium cannot speak ODoH itself.
//
// The failures that matter here are quiet ones: a bridge that answers from
// somewhere other than the oblivious transport, a certificate Chromium was
// never told to trust, or a key written where it could be stolen and used to
// impersonate any site (the pin switch trusts that key for ALL hosts).

import test from 'node:test'
import assert from 'node:assert/strict'
import https from 'node:https'
import { X509Certificate, createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

import { OdohBridge, servfail } from '../src/odoh-bridge.js'
import { generateLoopbackCert } from '../src/self-cert.js'

const query = (id = 0xabcd) => Buffer.concat([
  Buffer.from([id >> 8, id & 0xff, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]),
  Buffer.from([7]), Buffer.from('example'), Buffer.from([3]), Buffer.from('com'),
  Buffer.from([0, 0, 1, 0, 1])
])

/** A transport that answers without touching the network. */
function fakeTransport (answer, fail = false) {
  return {
    calls: 0,
    relays: ['https://relay.example/relay'],
    targets: [{ host: 'odoh.example', path: '/dns-query' }],
    async query (wire) {
      this.calls++
      if (fail) throw new Error('relay down')
      const out = Buffer.from(wire)
      out[2] |= 0x80
      return { answer: answer || out, via: 'relay.example' }
    }
  }
}

async function withBridge (transport, fn) {
  const bridge = new OdohBridge({ transport, targets: [], relays: [] })
  await bridge.start()
  try {
    return await fn(bridge)
  } finally {
    await bridge.stop()
  }
}

function doh (bridge, { method = 'GET', wire = query(), body = true } = {}) {
  const agent = new https.Agent({ ca: bridge._tls.cert, checkServerIdentity: () => undefined })
  let path = bridge.secretPath
  const opts = { agent, method, headers: {} }
  if (method === 'GET') path += '?dns=' + wire.toString('base64url')
  else opts.headers['content-type'] = 'application/dns-message'
  return new Promise((resolve, reject) => {
    const req = https.request(`https://127.0.0.1:${bridge.port}${path}`, opts, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({
        status: res.statusCode, type: res.headers['content-type'], body: Buffer.concat(chunks)
      }))
    })
    req.on('error', reject)
    if (method === 'POST' && body) req.write(wire)
    req.end()
  })
}

test('the certificate is valid, self-signed, and names only loopback', () => {
  const { cert, spkiPin } = generateLoopbackCert()
  const x = new X509Certificate(cert)
  assert.ok(x.verify(x.publicKey), 'must be a valid self-signature')
  assert.match(x.subjectAltName, /DNS:localhost/)
  assert.match(x.subjectAltName, /IP Address:127\.0\.0\.1/)
  assert.ok(!/hns\.one|\*/.test(x.subjectAltName), 'must not name anything real')
  // The pin is what goes on Chromium's command line; if it does not match the
  // certificate actually served, every ICANN lookup fails.
  const computed = createHash('sha256')
    .update(x.publicKey.export({ type: 'spki', format: 'der' })).digest('base64')
  assert.equal(computed, spkiPin)
  assert.ok(Date.parse(x.validTo) > Date.now())
})

test('two launches never share a key — the pin dies with the process', () => {
  // That switch trusts the key for ANY host, so a stable on-disk key would be
  // a permanent MITM key for this browser.
  const a = generateLoopbackCert()
  const b = generateLoopbackCert()
  assert.notEqual(a.spkiPin, b.spkiPin)
  assert.notEqual(a.key, b.key)
})

test('the private key is never written to disk by this code', () => {
  const src = readFileSync(new URL('../src/self-cert.js', import.meta.url), 'utf8') +
    readFileSync(new URL('../src/odoh-bridge.js', import.meta.url), 'utf8')
  for (const f of ['writeFile', 'writeFileSync', 'createWriteStream', 'appendFile']) {
    assert.ok(!src.includes(f), `${f} must not appear near the bridge key`)
  }
})

test('GET and POST both answer, from the oblivious transport', async () => {
  const transport = fakeTransport()
  await withBridge(transport, async (bridge) => {
    for (const method of ['GET', 'POST']) {
      const res = await doh(bridge, { method })
      assert.equal(res.status, 200, method)
      assert.equal(res.type, 'application/dns-message')
      assert.equal(res.body[2] & 0x80, 0x80, 'a response, not the query echoed')
    }
    assert.equal(transport.calls, 2, 'every answer came through ODoH')
    assert.deepEqual(bridge.stats, { queries: 2, oblivious: 2, failed: 0 })
  })
})

test('a failed oblivious lookup is SERVFAIL, never a quiet fallback', async () => {
  // What happens next is Chromium's secure-DNS mode to decide, and the user
  // can see that setting. Resolving it here by some other route would hide a
  // privacy downgrade inside a component whose whole purpose is privacy.
  const transport = fakeTransport(null, true)
  await withBridge(transport, async (bridge) => {
    const res = await doh(bridge)
    assert.equal(res.status, 200)
    assert.equal(res.body[3] & 0x0f, 2, 'RCODE must be SERVFAIL')
    assert.deepEqual(res.body.subarray(0, 2), query().subarray(0, 2), 'id preserved')
    assert.equal(bridge.stats.failed, 1)
  })
})

test('it refuses anything that is not a DoH query', async () => {
  await withBridge(fakeTransport(), async (bridge) => {
    const agent = new https.Agent({ ca: bridge._tls.cert, checkServerIdentity: () => undefined })
    const get = (path) => new Promise((resolve, reject) => {
      const req = https.request(`https://127.0.0.1:${bridge.port}${path}`, { agent }, (res) => {
        res.resume()
        res.on('end', () => resolve(res.statusCode))
      })
      req.on('error', reject)
      req.end()
    })
    assert.equal(await get('/'), 404, 'only the secret path exists')
    assert.equal(await get('/dns-query'), 404, 'the old guessable path is gone')
    assert.equal(await get(bridge.secretPath), 400, 'a GET with no ?dns is a bad request')
    assert.equal(await get(bridge.secretPath + '?dns=' + 'A'.repeat(9000)), 400, 'oversized is refused')
  })
})

test('the template Chromium is given points at loopback only', async () => {
  await withBridge(fakeTransport(), async (bridge) => {
    const url = new URL(bridge.template)
    assert.equal(url.protocol, 'https:', 'Chromium accepts only https templates')
    assert.equal(url.hostname, '127.0.0.1')
    assert.equal(url.pathname, bridge.secretPath)
    assert.match(url.pathname, /^\/[0-9a-f]{32}\/dns-query$/)
    assert.ok(bridge.port > 0)
  })
})

test('servfail keeps the question and clears the counts', () => {
  const q = query(0x1234)
  const r = servfail(q)
  assert.deepEqual(r.subarray(0, 2), q.subarray(0, 2))
  assert.equal(r[2] & 0x80, 0x80)
  assert.equal(r[3] & 0x0f, 2)
  assert.equal(r.readUInt16BE(6), 0)
  assert.equal(servfail(Buffer.alloc(3)).length, 0, 'a runt query yields nothing')
})

test('one lookup does not vouch for every parent domain', async () => {
  // Observed before the fix: a single oblivious lookup for
  // `victim-chosen.example.com` made servedRecently('example.com') AND
  // servedRecently('com') both true — the padlock claiming obliviousness for
  // pages that were never resolved here.
  await withBridge(fakeTransport(), async (bridge) => {
    bridge._remember('victim-chosen.example.com')
    assert.equal(bridge.servedRecently('victim-chosen.example.com'), true)
    assert.equal(bridge.servedRecently('sub.victim-chosen.example.com'), true, 'subdomains count')
    assert.equal(bridge.servedRecently('example.com'), false, 'a parent must NOT count')
    assert.equal(bridge.servedRecently('com'), false, 'and certainly not the TLD')
    assert.equal(bridge.servedRecently('other.example.com'), false)
  })
})

test('a web page cannot reach the bridge, or write into what it vouches for', async () => {
  await withBridge(fakeTransport(), async (bridge) => {
    const agent = new https.Agent({ ca: bridge._tls.cert, checkServerIdentity: () => undefined })
    const call = (path, headers = {}) => new Promise((resolve, reject) => {
      const req = https.request(`https://127.0.0.1:${bridge.port}${path}`,
        { agent, method: 'GET', headers }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)) })
      req.on('error', reject)
      req.end()
    })
    const wire = query().toString('base64url')
    // Everything a PAGE could do, first — while `recent` is still empty, so a
    // write by any of them is unmistakable.
    assert.equal(await call('/dns-query?dns=' + wire), 404, 'the old guessable path is gone')
    assert.equal(await call(`${bridge.secretPath}?dns=${wire}`, { origin: 'https://evil.example' }), 403)
    assert.equal(await call(`${bridge.secretPath}?dns=${wire}`, { 'sec-fetch-site': 'cross-site' }), 403)
    assert.equal(bridge.recent.size, 0, 'nothing a page can do writes into the vouching record')

    // And the caller we DO mean — Chromium's DoH client, which sends neither
    // header — still works and is recorded.
    assert.equal(await call(`${bridge.secretPath}?dns=${wire}`), 200)
    assert.equal(bridge.recent.size, 1)
    assert.ok(bridge.servedRecently('example.com'))
  })
})

test('the secret path is per-launch and in the template Chromium is given', () => {
  const a = new OdohBridge({ targets: [], relays: [], transport: fakeTransport() })
  const b = new OdohBridge({ targets: [], relays: [], transport: fakeTransport() })
  assert.notEqual(a.secretPath, b.secretPath)
  assert.match(a.secretPath, /^\/[0-9a-f]{32}\/dns-query$/)
  assert.ok(a.template.endsWith(a.secretPath))
})
