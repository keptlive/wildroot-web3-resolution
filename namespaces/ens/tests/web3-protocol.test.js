/*
 * web3:// (ERC-4804) — the things this code actually owns.
 *
 * ERC-4804 itself is implemented by the third-party `web3protocol` package and
 * is not under test here; what IS under test is the contract around it —
 * method gating, lazy loading, CORS, the clamp on a contract-chosen status,
 * the response-header allowlist, and the fact that a failure neither takes the
 * process with it nor ships a stack trace. All of it runs offline.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import createHandler, { web3Response } from '../src/web3-protocol.js'
import fetchToHandler from '../src/fetch-to-handler.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const CONTRACT = 'web3://0x1111111111111111111111111111111111111111/'

// A chain entry that exists and cannot be reached: enough to construct the
// client, never enough to make a call succeed.
const CHAIN_LIST = { 1: { id: 1, name: 'Ethereum', rpcUrls: ['http://127.0.0.1:1/'], contracts: {} } }

test('a method other than GET is refused with 405, before any chain call', async () => {
  const { handler } = await createHandler({ chainList: CHAIN_LIST })
  for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
    const res = await handler(new Request(CONTRACT, { method }))
    assert.equal(res.status, 405, method)
    assert.equal(await res.text(), 'Method Not Allowed')
  }
})

test('the CORS headers a protocol handler needs are present', async () => {
  const { handler } = await createHandler({ chainList: CHAIN_LIST })
  const res = await handler(new Request(CONTRACT, { method: 'POST' }))
  assert.equal(res.headers.get('Access-Control-Allow-Origin'), '*')
  assert.equal(res.headers.get('Allow-CSP-From'), '*')
})

test('a failing chain call is an error response, not a throw', async () => {
  // The scheme must fail closed inside its own namespace: an unreachable RPC
  // is a status, never an exception escaping into the protocol layer.
  const { handler } = await createHandler({ chainList: CHAIN_LIST })
  const res = await handler(new Request(CONTRACT))
  assert.equal(res.status, 500)
})

test('web3protocol is imported LAZILY, never at module load', () => {
  // The library plus its default chain registry costs roughly half a second to
  // import, for a scheme most sessions never touch. A static import at the top
  // of this module would put that on every browser start. Asserted against the
  // source, because "it was fast" is not a testable property.
  const src = readFileSync(join(HERE, '..', 'src', 'web3-protocol.js'), 'utf8')
  const staticImports = [...src.matchAll(/^\s*import\s[^\n]*?from\s+['"]([^'"]+)['"]/gm)]
    .map((m) => m[1])
  assert.deepEqual(staticImports, ['./fetch-to-handler.js', '../../../src/safe-status.js'],
    'the only static imports are the local lazy-loader helper and the status clamp')
  assert.match(src, /await Promise\.all\(\[\s*import\('web3protocol'\)/,
    'the library is imported inside the lazily-invoked callback')
})

test('the ERC-4804 short form w3:// is not offered by this module', () => {
  // `.w3` is a Handshake TLD in active use: `web3://` executes an EVM call and
  // `proof.w3` is an ordinary Handshake name. An alias would make one typo
  // route a Handshake site into a contract read (SPEC §8.2).
  const src = readFileSync(join(HERE, '..', 'src', 'web3-protocol.js'), 'utf8')
  assert.doesNotMatch(src, /['"]w3['"]|w3:\/\//)
})

// ---------------------------------------------------------------------------
// what a contract may and may not choose
// ---------------------------------------------------------------------------

test('a status Chromium has no reason phrase for becomes 502', () => {
  // The status is an ERC-5219 uint16 chosen by the contract, and it goes
  // straight into net::GetHttpReasonPhrase(), which NOTREACHEDs on a code
  // Chromium does not define — so a contract returning 523 would be choosing
  // a crash. Node's Response also refuses anything outside 200–599, and the
  // dangerous band is precisely the one Node allows and Chromium does not know.
  assert.equal(web3Response({ httpCode: 523, output: 'x' }).status, 502)
  assert.equal(web3Response({ httpCode: 599, output: 'x' }).status, 502)
  assert.equal(web3Response({ httpCode: 'abc', output: 'x' }).status, 502)
  assert.equal(web3Response({ output: 'x' }).status, 502)
  // A code it does know is carried unchanged.
  for (const code of [200, 206, 404, 451, 503]) {
    assert.equal(web3Response({ httpCode: code, output: 'x' }).status, code)
  }
  assert.equal(web3Response({ httpCode: 304, output: null }).status, 304)
})

test('only headers that describe the body survive the contract', async () => {
  const res = web3Response({
    httpCode: 200,
    httpHeaders: {
      'Content-Type': 'text/html',
      'Cache-Control': 'no-store',
      ETag: '"v1"',
      Location: 'https://evil.example/',
      'Set-Cookie': 'a=b',
      'Service-Worker-Allowed': '/',
      'Content-Security-Policy': "default-src 'none'"
    },
    output: 'x'
  })
  assert.equal(res.headers.get('content-type'), 'text/html')
  assert.equal(res.headers.get('cache-control'), 'no-store')
  assert.equal(res.headers.get('etag'), '"v1"')
  assert.equal(res.headers.get('location'), null, 'a contract does not get to redirect')
  assert.equal(res.headers.get('set-cookie'), null)
  assert.equal(res.headers.get('service-worker-allowed'), null)
  assert.equal(res.headers.get('content-security-policy'), null)
  assert.equal(await res.text(), 'x')
})

test('a header value that is not a string is dropped rather than coerced', () => {
  const res = web3Response({ httpCode: 200, httpHeaders: { ETag: 42 }, output: 'x' })
  assert.equal(res.headers.get('etag'), null)
})

test('a failure serves the message, never the stack', async () => {
  // The body is readable by any page on a scheme with supportFetchAPI and CORS
  // `*`, and a stack carries this installation's absolute paths.
  const { handler } = fetchToHandler(async () => {
    throw new Error('the RPC endpoint refused the connection')
  })
  const res = await handler(new Request(CONTRACT))
  assert.equal(res.status, 500)
  assert.equal(res.headers.get('content-type'), 'text/plain; charset=utf-8')
  const body = await res.text()
  assert.equal(body, 'the RPC endpoint refused the connection')
  assert.doesNotMatch(body, /\bat .*:\d+:\d+|file:\/\//, 'no stack frames, no install path')
})
