/*
 * CCIP-read (ERC-3668) — the round trip, and every rule that stops it being a
 * way to make this browser fetch things on someone else's behalf.
 *
 * The gateway URL arrives inside a contract REVERT. That is the whole security
 * story: the URL is chosen by whoever deployed the contract, the browser is
 * being asked to fetch it, and the result is handed back to the chain as
 * though it were an answer. So most of what follows is about refusing.
 *
 * ENSIP-21 gets its own section because skipping it is not a missing feature
 * but a privacy leak: the outer URL of a modern ENS lookup is ENS's own batch
 * gateway, so a client without a local implementation tells a third party every
 * name its user resolves.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { encodeAbiParameters, decodeAbiParameters, encodeErrorResult } from 'viem'

import {
  ccipCall, isSafeGatewayUrl, OFFCHAIN_LOOKUP, BATCH_SELECTOR, BATCH_SENTINEL,
  MAX_LOOKUPS, MAX_BATCH_REQUESTS
} from '../src/ccip-read.js'
import { isPublicAddress } from '../../../src/safe-address.js'

const CONTRACT = '0x1111111111111111111111111111111111111111'
const OTHER = '0x2222222222222222222222222222222222222222'
const CALLBACK = '0xdeadbeef'

const LOOKUP_ABI = [{
  type: 'error',
  name: 'OffchainLookup',
  inputs: [
    { type: 'address' }, { type: 'string[]' }, { type: 'bytes' },
    { type: 'bytes4' }, { type: 'bytes' }
  ]
}]

/** The revert an ERC-3668 contract raises. */
function lookup ({ sender = CONTRACT, urls, callData = '0xaabb', extraData = '0xccdd' }) {
  return encodeErrorResult({
    abi: LOOKUP_ABI,
    errorName: 'OffchainLookup',
    args: [sender, urls, callData, CALLBACK, extraData]
  })
}

const deps = (over = {}) => ({
  encodeAbiParameters, decodeAbiParameters, isPublicAddress, timeout: 2000, ...over
})

/** A `call` that reverts with `revert` once, then returns `then`. */
function callOnce (revert, then = '0x2a') {
  const seen = []
  const call = async (to, data) => {
    seen.push({ to, data })
    return seen.length === 1 ? { revertData: revert } : { result: then }
  }
  call.seen = seen
  return call
}

const okGateway = (body = { data: '0xf00d' }) => {
  const seen = []
  const fetchImpl = async (url, init) => {
    seen.push({ url, method: init.method, body: init.body })
    return {
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () => JSON.stringify(body)
    }
  }
  fetchImpl.seen = seen
  return fetchImpl
}

// ---------------------------------------------------------------------------
// the round trip
// ---------------------------------------------------------------------------

test('a lookup is followed and the answer handed back to the contract', async () => {
  const call = callOnce(lookup({ urls: ['https://gw.example/{sender}/{data}.json'] }))
  const fetchImpl = okGateway()
  const out = await ccipCall({
    to: CONTRACT, data: '0x01', call, deps: deps({ fetchImpl })
  })
  assert.equal(out, '0x2a')
  assert.equal(call.seen.length, 2, 'the callback was never issued')
  assert.ok(call.seen[1].data.startsWith(CALLBACK), 'the callback selector leads the calldata')
  // The gateway answer and the contract's extraData both ride back, in order.
  const [answer, extra] = decodeAbiParameters(
    [{ type: 'bytes' }, { type: 'bytes' }], `0x${call.seen[1].data.slice(10)}`)
  assert.equal(answer, '0xf00d')
  assert.equal(extra, '0xccdd')
})

test('a {data} template is a GET; one without it is a POST carrying JSON', async () => {
  const get = okGateway()
  await ccipCall({
    to: CONTRACT,
    data: '0x01',
    call: callOnce(lookup({ urls: ['https://gw.example/{sender}/{data}.json'] })),
    deps: deps({ fetchImpl: get })
  })
  assert.equal(get.seen[0].method, 'GET')
  assert.match(get.seen[0].url, /0x1111.*\/0xaabb\.json$/i)

  const post = okGateway()
  await ccipCall({
    to: CONTRACT,
    data: '0x01',
    call: callOnce(lookup({ urls: ['https://gw.example/lookup'] })),
    deps: deps({ fetchImpl: post })
  })
  assert.equal(post.seen[0].method, 'POST')
  assert.deepEqual(JSON.parse(post.seen[0].body),
    { data: '0xaabb', sender: CONTRACT.toLowerCase() })
})

test('a call that does not revert never contacts a gateway', async () => {
  const fetchImpl = okGateway()
  const out = await ccipCall({
    to: CONTRACT,
    data: '0x01',
    call: async () => ({ result: '0x99' }),
    deps: deps({ fetchImpl })
  })
  assert.equal(out, '0x99')
  assert.equal(fetchImpl.seen.length, 0)
})

// ---------------------------------------------------------------------------
// the refusals
// ---------------------------------------------------------------------------

test('a lookup naming a DIFFERENT contract is refused', async () => {
  // ERC-3668 makes this a MUST. Without it any contract could point the
  // browser at another contract's callback and have the result attributed to
  // it.
  const fetchImpl = okGateway()
  await assert.rejects(() => ccipCall({
    to: CONTRACT,
    data: '0x01',
    call: callOnce(lookup({ sender: OTHER, urls: ['https://gw.example/x'] })),
    deps: deps({ fetchImpl })
  }), /different contract/)
  assert.equal(fetchImpl.seen.length, 0, 'and no gateway was contacted first')
})

test('recursion is capped — the contract controls how deep this goes', async () => {
  const revert = lookup({ urls: ['https://gw.example/x'] })
  const call = async () => ({ revertData: revert }) // reverts forever
  await assert.rejects(() => ccipCall({
    to: CONTRACT, data: '0x01', call, deps: deps({ fetchImpl: okGateway() })
  }), new RegExp(`more than ${MAX_LOOKUPS}`))
})

test('a non-OffchainLookup revert is passed up, not followed', async () => {
  const call = callOnce('0x77209fe8' + '00'.repeat(32))
  await assert.rejects(() => ccipCall({
    to: CONTRACT, data: '0x01', call, deps: deps({ fetchImpl: okGateway() })
  }), (err) => {
    assert.match(err.message, /reverted/)
    assert.ok(err.revertData.startsWith('0x77209fe8'), 'the selector must survive')
    return true
  })
})

test('4xx stops; 5xx moves to the next gateway', async () => {
  const tried = []
  const fetchImpl = async (url) => {
    tried.push(new URL(url).host)
    const status = tried.length === 1 ? 500 : 200
    return {
      ok: status === 200,
      status,
      headers: new Headers(),
      text: async () => JSON.stringify({ data: '0xf00d' })
    }
  }
  await ccipCall({
    to: CONTRACT,
    data: '0x01',
    call: callOnce(lookup({ urls: ['https://a.example/x', 'https://b.example/x'] })),
    deps: deps({ fetchImpl })
  })
  assert.deepEqual(tried, ['a.example', 'b.example'])

  const only = []
  const four = async (url) => {
    only.push(new URL(url).host)
    return { ok: false, status: 404, headers: new Headers(), text: async () => '' }
  }
  await assert.rejects(() => ccipCall({
    to: CONTRACT,
    data: '0x01',
    call: callOnce(lookup({ urls: ['https://a.example/x', 'https://b.example/x'] })),
    deps: deps({ fetchImpl: four })
  }))
  assert.deepEqual(only, ['a.example'], 'a 4xx is an answer; the second must not be asked')
})

test('gateway URLs pointed at the user\'s own network are refused', () => {
  // The URL comes from a revert, so this is the SSRF surface in full.
  for (const bad of [
    'http://gw.example/x', // not https
    'https://localhost/x',
    'https://foo.localhost/x',
    'https://printer.local/x',
    'https://thing.internal/x',
    'https://127.0.0.1/x',
    'https://10.0.0.5/x',
    'https://169.254.169.254/latest/meta-data',
    'file:///etc/passwd',
    'not a url'
  ]) {
    assert.equal(isSafeGatewayUrl(bad, { isPublicAddress }), false, bad)
  }
  for (const good of ['https://gw.example/x', 'https://1.2.3.4/x']) {
    assert.equal(isSafeGatewayUrl(good, { isPublicAddress }), true, good)
  }
})

test('a refused URL is fatal for that lookup, not skipped past', async () => {
  const fetchImpl = okGateway()
  await assert.rejects(() => ccipCall({
    to: CONTRACT,
    data: '0x01',
    call: callOnce(lookup({ urls: ['https://127.0.0.1/x'] })),
    deps: deps({ fetchImpl })
  }))
  assert.equal(fetchImpl.seen.length, 0, 'a refused URL must never be fetched')
})

test('a gateway answer that is not JSON, or carries no data, is refused', async () => {
  for (const text of ['<html>nope</html>', '{}', '{"data":"not-hex"}']) {
    const fetchImpl = async () => ({
      ok: true, status: 200, headers: new Headers(), text: async () => text
    })
    await assert.rejects(() => ccipCall({
      to: CONTRACT,
      data: '0x01',
      call: callOnce(lookup({ urls: ['https://gw.example/x'] })),
      deps: deps({ fetchImpl })
    }), undefined, text)
  }
})

test('an over-large answer is refused before it is buffered', async () => {
  const fetchImpl = async () => ({
    ok: true,
    status: 200,
    headers: new Headers({ 'content-length': String(1 << 24) }),
    text: async () => { throw new Error('should never be read') }
  })
  await assert.rejects(() => ccipCall({
    to: CONTRACT,
    data: '0x01',
    call: callOnce(lookup({ urls: ['https://gw.example/x'] })),
    deps: deps({ fetchImpl })
  }), /too large/)
})

test('redirects are never followed', async () => {
  const fetchImpl = okGateway()
  await ccipCall({
    to: CONTRACT,
    data: '0x01',
    call: callOnce(lookup({ urls: ['https://gw.example/x'] })),
    deps: deps({ fetchImpl })
  })
  assert.equal(fetchImpl.seen.length, 1)
})

// ---------------------------------------------------------------------------
// ENSIP-21 — the privacy one
// ---------------------------------------------------------------------------

test('the batch sentinel is handled LOCALLY — no third-party batch gateway', async () => {
  // Not a missing feature if skipped: using ENS's batch gateway would disclose
  // every name this browser resolves to a third party.
  const requests = encodeAbiParameters(
    [{
      type: 'tuple[]',
      components: [{ type: 'address' }, { type: 'string[]' }, { type: 'bytes' }]
    }],
    [[[CONTRACT, ['https://inner.example/{sender}/{data}.json'], '0x1234']]]
  )
  const call = callOnce(lookup({
    urls: [BATCH_SENTINEL, 'https://ccip-v3.ens.xyz/'],
    callData: `0xa780bab6${requests.slice(2)}`
  }))
  const fetchImpl = okGateway()
  await ccipCall({ to: CONTRACT, data: '0x01', call, deps: deps({ fetchImpl }) })

  const hosts = fetchImpl.seen.map((s) => new URL(s.url).host)
  assert.deepEqual(hosts, ['inner.example'],
    'the inner request must be made directly, and the batch gateway never contacted')

  // The callback receives (bool[] failures, bytes[] responses).
  const [answer] = decodeAbiParameters(
    [{ type: 'bytes' }, { type: 'bytes' }], `0x${call.seen[1].data.slice(10)}`)
  const [failures, responses] = decodeAbiParameters(
    [{ type: 'bool[]' }, { type: 'bytes[]' }], answer)
  assert.deepEqual([...failures], [false])
  assert.deepEqual([...responses], ['0xf00d'])
})

test('a failed sub-request is reported as a failure, not as a failed batch', async () => {
  const requests = encodeAbiParameters(
    [{
      type: 'tuple[]',
      components: [{ type: 'address' }, { type: 'string[]' }, { type: 'bytes' }]
    }],
    [[[CONTRACT, ['https://127.0.0.1/x'], '0x1234']]]
  )
  const call = callOnce(lookup({
    urls: [BATCH_SENTINEL], callData: `0xa780bab6${requests.slice(2)}`
  }))
  await ccipCall({ to: CONTRACT, data: '0x01', call, deps: deps({ fetchImpl: okGateway() }) })
  const [answer] = decodeAbiParameters(
    [{ type: 'bytes' }, { type: 'bytes' }], `0x${call.seen[1].data.slice(10)}`)
  const [failures] = decodeAbiParameters([{ type: 'bool[]' }, { type: 'bytes[]' }], answer)
  assert.deepEqual([...failures], [true], 'the interface reports per-request failure')
})

test('the OffchainLookup selector is the published one', () => {
  assert.equal(OFFCHAIN_LOOKUP, '0x556f1830')
})

test('a batch whose calldata is not query() is refused, and never fetched', async () => {
  // The sentinel says "substitute your own batch gateway", not "decode
  // whatever follows against the batch shape": a contract that sets the
  // sentinel and sends different calldata would otherwise be decoded against
  // an interface it never named.
  const call = callOnce(lookup({ urls: [BATCH_SENTINEL], callData: '0xdeadbeef' + '00'.repeat(64) }))
  const fetchImpl = okGateway()
  await assert.rejects(ccipCall({ to: CONTRACT, data: '0x01', call, deps: deps({ fetchImpl }) }), /not query\(\)/)
  assert.equal(fetchImpl.seen.length, 0)
})

test('the ENSIP-21 batch selector is the published one', () => {
  assert.equal(BATCH_SELECTOR, '0xa780bab6')
})

test('a batch over the sub-request cap is refused whole, never truncated', async () => {
  // Every triple is a fetch and every triple is chosen by the contract. A
  // batch over the cap is refused entire, so the callback never receives a
  // silently short array.
  const triple = () => [CONTRACT, ['https://inner.example/{sender}/{data}.json'], '0x1234']
  const encode = (rows) => encodeAbiParameters(
    [{ type: 'tuple[]', components: [{ type: 'address' }, { type: 'string[]' }, { type: 'bytes' }] }],
    [rows])

  const many = Array.from({ length: MAX_BATCH_REQUESTS + 1 }, triple)
  const call = callOnce(lookup({ urls: [BATCH_SENTINEL], callData: `${BATCH_SELECTOR}${encode(many).slice(2)}` }))
  const fetchImpl = okGateway()
  await assert.rejects(ccipCall({ to: CONTRACT, data: '0x01', call, deps: deps({ fetchImpl }) }), /exceeds the cap/)
  assert.equal(fetchImpl.seen.length, 0, 'nothing is fetched for a refused batch')

  // At the cap it runs.
  const atCap = many.slice(0, MAX_BATCH_REQUESTS)
  const ok = callOnce(lookup({ urls: [BATCH_SENTINEL], callData: `${BATCH_SELECTOR}${encode(atCap).slice(2)}` }))
  const gateway = okGateway()
  await ccipCall({ to: CONTRACT, data: '0x01', call: ok, deps: deps({ fetchImpl: gateway }) })
  assert.equal(ok.seen.length, 2, 'the callback was issued')
  assert.equal(gateway.seen.length, MAX_BATCH_REQUESTS)
})
