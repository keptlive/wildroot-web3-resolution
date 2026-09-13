/*
 * "The chain answered" versus "we could not ask" — SPEC §5.6.
 *
 * The rule that decides which *sentence* a failure produces is the most
 * consequential one in the namespace. A 404 is a claim about the chain's
 * answer; showing one because our RPC list was down states a fact we never
 * obtained. An error is an ANSWER only when it carries revert data, and what
 * it answers is about the RESOLVER — never about registration or ownership.
 * Everything else — no RPC reachable, a CCIP gateway that does not answer, a
 * result that will not decode — is `unreachable`, served 502.
 *
 * Everything here runs offline against a stub RPC.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encodeErrorResult, encodeFunctionResult } from 'viem'

import createEnsHandler from '../src/ens-protocol.js'

const REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'
const RESOLVER = '0x1111111111111111111111111111111111111111'
const IPFS_CH = '0xe3010170122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f'
// swarm-ns: a codec we recognise and cannot fetch.
const SWARM_CH = '0xe40101fa01122044eb92b46360c22af3395633b6e3014a30afa97b02305b385c51d3feebceda9c'

const UNIVERSAL_RESOLVER = '0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe'
const CONTENTHASH_ABI = [{ type: 'function', name: 'contenthash', stateMutability: 'view', inputs: [{ type: 'bytes32' }], outputs: [{ type: 'bytes' }] }]
const UR_ABI = [{ type: 'function', name: 'resolve', stateMutability: 'view', inputs: [{ type: 'bytes' }, { type: 'bytes' }], outputs: [{ type: 'bytes' }, { type: 'address' }] }]

/** The Universal Resolver's own errors (SPEC §5.6). */
const RESOLVER_NOT_FOUND = '0x77209fe8' + '00'.repeat(32)
const UNSUPPORTED_PROFILE = '0x7b1c461b' + '00'.repeat(32)

// Two endpoints, so "the first one failed" and "every one failed" differ.
const CHAIN_LIST = [{
  id: 1,
  name: 'Ethereum',
  rpcUrls: ['http://rpc-a.test', 'http://rpc-b.test'],
  contracts: { ensRegistry: { address: REGISTRY } }
}]

const ok = (body) => ({ ok: true, json: async () => body })
const reverting = (data) => async () => ok({ jsonrpc: '2.0', id: 1, error: { code: 3, data } })
const answering = (contenthash) => async () => ok({
  jsonrpc: '2.0',
  id: 1,
  result: encodeFunctionResult({
    abi: UR_ABI,
    functionName: 'resolve',
    result: [encodeFunctionResult({ abi: CONTENTHASH_ABI, functionName: 'contenthash', result: contenthash }), RESOLVER]
  })
})

const handlerWith = (fetchImpl) => createEnsHandler({ chainList: CHAIN_LIST, fetchImpl }).handler

// ---------------------------------------------------------------------------
// the rule
// ---------------------------------------------------------------------------

test('every RPC failing is 502 "unknown, not absent" — never a 404 about the name', async () => {
  const tried = []
  const res = await handlerWith(async (url) => {
    tried.push(url)
    throw new Error('fetch failed')
  })(new Request('ens://vitalik.eth/'))

  assert.equal(res.status, 502, 'a 404 here states something we never learned')
  assert.deepEqual(tried, ['http://rpc-a.test', 'http://rpc-b.test'],
    'each endpoint gets its own attempt, or a list of two is worth one')
  const body = await res.text()
  assert.match(body, /unknown — not absent/)
  assert.doesNotMatch(body, /not registered|usable resolver|has no website/)
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'ens')
})

test('a 5xx from the first endpoint moves to the second rather than failing', async () => {
  const tried = []
  const answer = answering(IPFS_CH)
  const ipfsFetch = async (req) => new Response(`FETCHED ${req.url}`, { status: 200 })
  const { handler } = createEnsHandler({
    chainList: CHAIN_LIST,
    ipfsFetch,
    fetchImpl: async (url, opts) => {
      tried.push(url)
      if (tried.length === 1) return { ok: false, status: 503, json: async () => ({}) }
      return answer(url, opts)
    }
  })
  const res = await handler(new Request('ens://vitalik.eth/'))
  assert.equal(res.status, 200)
  assert.equal(tried.length, 2)
})

test('a revert is an ANSWER: the first endpoint\'s revert ends the lookup', async () => {
  // Asking the next endpoint would fetch the same revert more slowly, and
  // ERC-3668 delivers its whole protocol through one — so a revert must never
  // be collapsed into "RPC error".
  const tried = []
  const revert = reverting(RESOLVER_NOT_FOUND)
  const res = await handlerWith(async (url, opts) => { tried.push(url); return revert(url, opts) })(
    new Request('ens://nothing.eth/'))
  assert.equal(res.status, 404)
  assert.deepEqual(tried, ['http://rpc-a.test'], 'the second endpoint must not be asked')
})

test('WHICH revert decides the sentence: no usable resolver ≠ no contenthash', async () => {
  const noResolver = await handlerWith(reverting(RESOLVER_NOT_FOUND))(new Request('ens://nothing.eth/'))
  assert.equal(noResolver.status, 404)
  const resolverBody = await noResolver.text()
  assert.match(resolverBody, /has no usable resolver/)
  // The revert answers a question about the RESOLVER. A registered name whose
  // owner never set one reverts identically, so the page must not turn the
  // answer into a claim about registration.
  assert.match(resolverBody, /does not establish whether the name is registered/)
  assert.doesNotMatch(resolverBody, /is not registered/)

  // A resolver that does not implement contenthash: the resolver answered and
  // simply has no website to offer.
  const noProfile = await handlerWith(reverting(UNSUPPORTED_PROFILE))(new Request('ens://wallet-only.eth/'))
  assert.equal(noProfile.status, 404)
  const body = await noProfile.text()
  assert.match(body, /has no website/)
  assert.doesNotMatch(body, /is not registered|usable resolver/)
})

test('an unknown revert selector is "no website", never a resolver or registration claim', async () => {
  const res = await handlerWith(reverting('0xdeadbeef' + '00'.repeat(32)))(new Request('ens://x.eth/'))
  assert.equal(res.status, 404)
  const body = await res.text()
  assert.match(body, /has no website/)
  assert.doesNotMatch(body, /is not registered|usable resolver/)
})

test('a CCIP-Read lookup whose gateway never answers is 502, not "has no website"', async () => {
  // The Universal Resolver reverts OffchainLookup naming a gateway, and the
  // gateway is unreachable. The lookup did not complete, so nothing was
  // learned about the name — and these are exactly the offchain names
  // (*.base.eth, uni.eth, every DNSSEC-imported domain) that CCIP-Read exists
  // to support.
  const revert = encodeErrorResult({
    abi: [{
      type: 'error',
      name: 'OffchainLookup',
      inputs: [{ type: 'address' }, { type: 'string[]' }, { type: 'bytes' }, { type: 'bytes4' }, { type: 'bytes' }]
    }],
    errorName: 'OffchainLookup',
    args: [UNIVERSAL_RESOLVER, ['https://gateway.example/{sender}/{data}.json'], '0xaabb', '0xdeadbeef', '0xccdd']
  })
  const res = await handlerWith(async (url) => {
    if (/gateway\.example/.test(url)) throw new Error('fetch failed')
    return ok({ jsonrpc: '2.0', id: 1, error: { code: 3, data: revert } })
  })(new Request('ens://offchain.eth/'))
  assert.equal(res.status, 502)
  assert.doesNotMatch(await res.text(), /has no website|usable resolver|not registered/)
})

test('a well-formed answer that will not decode is 502, never a claim about the name', async () => {
  // A broken or hostile endpoint can return valid JSON whose result is not the
  // declared ABI shape. That is a fact about the endpoint, not about the name.
  const res = await handlerWith(async () => ok({ jsonrpc: '2.0', id: 1, result: '0x1234' }))(
    new Request('ens://vitalik.eth/'))
  assert.equal(res.status, 502)
  assert.doesNotMatch(await res.text(), /has no website|usable resolver|not registered/)
})

// ---------------------------------------------------------------------------
// the other kinds
// ---------------------------------------------------------------------------

test('a name ENSIP-15 rejects is 400, and the RPC is never contacted', async () => {
  const tried = []
  const res = await handlerWith(async (url) => { tried.push(url); throw new Error('unreachable') })(
    new Request('ens://not_a_valid.eth/'))
  assert.equal(res.status, 400)
  assert.match(await res.text(), /is not a valid ENS name/)
  assert.equal(tried.length, 0, 'normalisation happens before the network')
})

test('a codec we cannot fetch is refused BY NAME, never mis-routed', async () => {
  const ipfsFetch = async () => new Response('should never be reached', { status: 200 })
  const { handler } = createEnsHandler({ chainList: CHAIN_LIST, fetchImpl: answering(SWARM_CH), ipfsFetch })
  const res = await handler(new Request('ens://swarmy.eth/'))
  assert.equal(res.status, 501)
  assert.match(await res.text(), /swarm/i)
})

test('every failure page is tagged as the ENS namespace answering', async () => {
  for (const [fetchImpl, url] of [
    [reverting(RESOLVER_NOT_FOUND), 'ens://nothing.eth/'],
    [reverting(UNSUPPORTED_PROFILE), 'ens://wallet-only.eth/'],
    [async () => { throw new Error('fetch failed') }, 'ens://down.eth/'],
    [answering(SWARM_CH), 'ens://swarmy.eth/']
  ]) {
    const res = await handlerWith(fetchImpl)(new Request(url))
    assert.equal(res.headers.get('X-Resolution-Namespace'), 'ens', url)
    // L2: nothing in this namespace ever names another one.
    assert.doesNotMatch(await res.text(), /hns:\/\//, url)
  }
})
