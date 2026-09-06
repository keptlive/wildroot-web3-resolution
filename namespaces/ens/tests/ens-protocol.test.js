/*
 * ens:// resolution — no network, no real Ethereum. The RPC is a stub that
 * answers `UniversalResolver.resolve(dnsEncode(name), contenthash(node))` with
 * ABI-encoded results built by viem, exactly as a real node would.
 *
 * IT ANSWERS THE CALL WE ACTUALLY MAKE. The stub used to model two eth_calls
 * — registry.resolver then resolver.contenthash — which is how this browser
 * resolved ENS until 2026-09-04 and is why `jesse.base.eth` came back "not
 * registered": the REGISTRY holds an entry for `base.eth`, not for names under
 * it, so a subname's resolver is only reachable through ENSIP-10 wildcard
 * resolution. A stub that models the old shape would keep passing while every
 * such name failed. It proves:
 *   - a contenthash is decoded and handed to the ipfs/ar handler (with the
 *     URL path carried through),
 *   - the served response is tagged as an (unverified) ENS resolution,
 *   - a name with no resolver / no contenthash fails honestly, and
 *   - it NEVER constructs an hns:// URL (no .eth-as-Handshake fallback).
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encodeFunctionResult, decodeFunctionData } from 'viem'

import createEnsHandler, { parseEnsUrl } from '../src/ens-protocol.js'

const REGISTRY = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'
const RESOLVER = '0x1111111111111111111111111111111111111111'
const ZERO = '0x0000000000000000000000000000000000000000'
const IPFS_CH = '0xe3010170122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f1f'
// arweave-ns + 32-byte txid (see contenthash.test.js)
const AR_CH = '0x90b2ca0570a189aae8a5d118311f080010d15d9db5e57cb0f602850cff93ed9f68fd9b5a'

const UNIVERSAL_RESOLVER = '0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe'
const CONTENTHASH_ABI = [{ type: 'function', name: 'contenthash', stateMutability: 'view', inputs: [{ type: 'bytes32' }], outputs: [{ type: 'bytes' }] }]
const UR_ABI = [{ type: 'function', name: 'resolve', stateMutability: 'view', inputs: [{ type: 'bytes' }, { type: 'bytes' }], outputs: [{ type: 'bytes' }, { type: 'address' }] }]
const TEXT_ABI = [{ type: 'function', name: 'text', stateMutability: 'view', inputs: [{ type: 'bytes32' }, { type: 'string' }], outputs: [{ type: 'string' }] }]
/** ResolverNotFound(bytes) — what the live contract reverts for an unregistered name. */
const RESOLVER_NOT_FOUND = '0x77209fe8' + '00'.repeat(32)

const CHAIN_LIST = [{ id: 1, name: 'Ethereum', rpcUrls: ['http://rpc.test'], contracts: { ensRegistry: { address: REGISTRY } } }]

/**
 * A fake Ethereum RPC answering the Universal Resolver.
 *
 * `resolver: ZERO` stands for "no resolver", which the real contract signals
 * by REVERTING with ResolverNotFound rather than returning a zero address —
 * so the stub reverts too.
 */
function rpcStub ({ resolver = RESOLVER, contenthash = IPFS_CH, texts = null } = {}) {
  return async (_url, opts) => {
    const { params } = JSON.parse(opts.body)
    if (params[0].to.toLowerCase() !== UNIVERSAL_RESOLVER.toLowerCase()) {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: 3, data: RESOLVER_NOT_FOUND } }) }
    }
    if (resolver === ZERO) {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: 3, data: RESOLVER_NOT_FOUND } }) }
    }
    // An ENSIP-5 text(node, key) call inside the Universal Resolver's resolve().
    try {
      const { args } = decodeFunctionData({ abi: UR_ABI, data: params[0].data })
      const innerCall = decodeFunctionData({ abi: TEXT_ABI, data: args[1] })
      if (innerCall.functionName === 'text') {
        const value = (texts && texts[innerCall.args[1]]) || ''
        const innerRes = encodeFunctionResult({ abi: TEXT_ABI, functionName: 'text', result: value })
        const result = encodeFunctionResult({ abi: UR_ABI, functionName: 'resolve', result: [innerRes, resolver] })
        return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result }) }
      }
    } catch { /* not a text call */ }
    const inner = encodeFunctionResult({ abi: CONTENTHASH_ABI, functionName: 'contenthash', result: contenthash })
    const result = encodeFunctionResult({ abi: UR_ABI, functionName: 'resolve', result: [inner, resolver] })
    return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result }) }
  }
}

/** A content handler that records the URL it was asked for. */
function recordingFetch (tag) {
  const seen = []
  const fn = async (req) => { seen.push(req.url); return new Response(`${tag}-BODY`, { status: 200, headers: { 'content-type': 'text/html' } }) }
  fn.seen = seen
  return fn
}

test('parseEnsUrl splits name and path, lower-cases the name, drops the fragment', () => {
  assert.deepEqual(parseEnsUrl('ens://Vitalik.eth/'), { name: 'vitalik.eth', path: '/' })
  assert.deepEqual(parseEnsUrl('ens://vitalik.eth/dir/page?x=1#frag'), { name: 'vitalik.eth', path: '/dir/page?x=1' })
  assert.deepEqual(parseEnsUrl('ens://vitalik.eth'), { name: 'vitalik.eth', path: '/' })
})

test('an ipfs contenthash is decoded and handed to the ipfs handler, path carried through', async () => {
  const ipfsFetch = recordingFetch('IPFS')
  const arFetch = recordingFetch('AR')
  const { handler } = createEnsHandler({ chainList: CHAIN_LIST, fetchImpl: rpcStub(), ipfsFetch, arFetch })

  const res = await handler(new Request('ens://vitalik.eth/docs/intro'))
  assert.equal(res.status, 200)
  assert.equal(await res.text(), 'IPFS-BODY')
  assert.equal(arFetch.seen.length, 0)
  assert.equal(ipfsFetch.seen.length, 1)
  // ipfs://<cid>/docs/intro — a real content pointer, NEVER an hns:// URL.
  assert.match(ipfsFetch.seen[0], /^ipfs:\/\/bafybe[a-z0-9]+\/docs\/intro$/)
  // Served as an unverified ENS resolution (lock stays open).
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'ens')
})

test('an arweave contenthash is handed to the ar handler', async () => {
  const ipfsFetch = recordingFetch('IPFS')
  const arFetch = recordingFetch('AR')
  const { handler } = createEnsHandler({ chainList: CHAIN_LIST, fetchImpl: rpcStub({ contenthash: AR_CH }), ipfsFetch, arFetch })

  const res = await handler(new Request('ens://somedapp.eth/'))
  assert.equal(await res.text(), 'AR-BODY')
  assert.equal(ipfsFetch.seen.length, 0)
  assert.match(arFetch.seen[0], /^ar:\/\/cKGJquil0RgxHwgAENFdnbXlfLD2AoUM_5Ptn2j9m1o$/)
})

test('a name with no resolver fails honestly — and is NOT looked up as Handshake', async () => {
  const ipfsFetch = recordingFetch('IPFS')
  const { handler } = createEnsHandler({ chainList: CHAIN_LIST, fetchImpl: rpcStub({ resolver: ZERO }), ipfsFetch, arFetch: recordingFetch('AR') })
  const res = await handler(new Request('ens://nothing.eth/'))
  assert.equal(res.status, 404)
  const body = await res.text()
  assert.match(body, /not registered/i)
  assert.match(body, /NOT looked up as a Handshake name/i)
  assert.equal(ipfsFetch.seen.length, 0)
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'ens')
})

test('a name with an empty contenthash reports "no website content record"', async () => {
  const { handler } = createEnsHandler({ chainList: CHAIN_LIST, fetchImpl: rpcStub({ contenthash: '0x' }), ipfsFetch: recordingFetch('IPFS'), arFetch: recordingFetch('AR') })
  const res = await handler(new Request('ens://wallet-only.eth/'))
  assert.equal(res.status, 404)
  const body = await res.text()
  assert.match(body, /no <code>contenthash<\/code> record|has no website/i)
  assert.match(body, /NOT looked up as a Handshake name/i)
})

test('resolve() returns a content pointer and never an hns target', async () => {
  const { resolve, ensureDeps } = createEnsHandler({ chainList: CHAIN_LIST, fetchImpl: rpcStub() })
  await ensureDeps()
  const r = await resolve('vitalik.eth')
  assert.equal(r.kind, 'content')
  assert.equal(r.pointer.protocol, 'ipfs')
  assert.match(r.pointer.url, /^ipfs:\/\//)
  assert.doesNotMatch(r.pointer.url, /hns:/)
})

// ---------------------------------------------------------------------------
// "Not registered" versus "we could not ask". The rule: an error is an ANSWER
// about the name only when it carries revert data. Everything else — no RPC
// reachable, a CCIP gateway that did not answer, a malformed result — is us
// not getting an answer, and a 404 there would state a fact never obtained.
// ---------------------------------------------------------------------------

const TWO_RPCS = [{ id: 1, name: 'Ethereum', rpcUrls: ['http://rpc-a.test', 'http://rpc-b.test'] }]
const handlerWith = (fetchImpl) => createEnsHandler({ chainList: TWO_RPCS, fetchImpl, ipfsFetch: recordingFetch('IPFS'), arFetch: recordingFetch('AR') }).handler

test('every RPC failing is 502 "unknown, not absent" — never a 404 about the name', async () => {
  const tried = []
  const res = await handlerWith(async (url) => { tried.push(url); throw new Error('fetch failed') })(
    new Request('ens://vitalik.eth/'))
  assert.equal(res.status, 502, 'a 404 here states something we never learned')
  assert.deepEqual(tried, ['http://rpc-a.test', 'http://rpc-b.test'], 'each endpoint gets its own attempt')
  const body = await res.text()
  assert.match(body, /unknown — not absent/)
  assert.doesNotMatch(body, /not registered|has no website/)
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'ens')
})

test('a CCIP-Read lookup whose gateway never answers is 502, not "has no website"', async () => {
  // The Universal Resolver reverts OffchainLookup naming a gateway; the
  // gateway is unreachable. Nothing was learned about the name.
  const { encodeErrorResult } = await import('viem')
  const revert = encodeErrorResult({
    abi: [{ type: 'error', name: 'OffchainLookup', inputs: [{ type: 'address' }, { type: 'string[]' }, { type: 'bytes' }, { type: 'bytes4' }, { type: 'bytes' }] }],
    errorName: 'OffchainLookup',
    args: [UNIVERSAL_RESOLVER, ['https://gateway.example/{sender}/{data}.json'], '0xaabb', '0xdeadbeef', '0xccdd']
  })
  const res = await handlerWith(async (url) => {
    if (/gateway\.example/.test(url)) throw new Error('fetch failed')
    return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: 3, data: revert } }) }
  })(new Request('ens://offchain.eth/'))
  assert.equal(res.status, 502)
  assert.doesNotMatch(await res.text(), /has no website|not registered/)
})

test('a malformed RPC result is 502, never a claim about the name', async () => {
  const res = await handlerWith(async () => ({ ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x1234' }) }))(
    new Request('ens://vitalik.eth/'))
  assert.equal(res.status, 502)
  assert.doesNotMatch(await res.text(), /has no website|not registered/)
})

test('WHICH revert decides the sentence, and an unknown selector is "no website"', async () => {
  const reverting = (data) => async () => ({ ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: 3, data } }) })
  const notFound = await handlerWith(reverting(RESOLVER_NOT_FOUND))(new Request('ens://nothing.eth/'))
  assert.equal(notFound.status, 404)
  assert.match(await notFound.text(), /is not registered/)
  const noProfile = await handlerWith(reverting('0x7b1c461b' + '00'.repeat(32)))(new Request('ens://wallet-only.eth/'))
  assert.equal(noProfile.status, 404)
  assert.match(await noProfile.text(), /has no website/)
  const unknown = await handlerWith(reverting('0xdeadbeef' + '00'.repeat(32)))(new Request('ens://x.eth/'))
  assert.equal(unknown.status, 404)
  assert.match(await unknown.text(), /has no website/)
})

test('an emoji name is percent-decoded before normalisation', async () => {
  // `ens:` is non-standard, so the URL parser percent-encodes the name.
  assert.equal(new Request('ens://🚀.eth/x').url, 'ens://%F0%9F%9A%80.eth/x')
  assert.deepEqual(parseEnsUrl(new Request('ens://🚀.eth/x').url), { name: '🚀.eth', path: '/x' })
  assert.deepEqual(parseEnsUrl('ens://caf%C3%A9.eth?x=1'), { name: 'café.eth', path: '?x=1' })
  // A lone `%` is not valid encoding: kept as written, refused as a name.
  assert.equal(parseEnsUrl('ens://100%.eth/').name, '100%.eth')
  const asked = []
  const res = await handlerWith(async (url, opts) => { asked.push(JSON.parse(opts.body)); return rpcStub()(url, opts) })(
    new Request('ens://🚀.eth/'))
  assert.equal(res.status, 200, 'the emoji name resolved')
})

test('resolve() loads its own dependencies when called directly', async () => {
  const { resolve } = createEnsHandler({ chainList: CHAIN_LIST, fetchImpl: rpcStub() })
  const r = await resolve('vitalik.eth')
  assert.equal(r.kind, 'content')
})

test('an RPC error that merely echoes hex is not revert data — 502, never a claim about the name', async () => {
  const echo = async () => ({ ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: -32602, message: 'invalid argument 0: json: cannot unmarshal 0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe' } }) })
  const res = await handlerWith(echo)(new Request('ens://vitalik.eth/'))
  assert.equal(res.status, 502)
  assert.doesNotMatch(await res.text(), /has no website|not registered/)
  // Structured revert data, and a message that says "reverted", are answers.
  const structured = async () => ({ ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: 3, message: 'execution reverted', data: RESOLVER_NOT_FOUND } }) })
  assert.equal((await handlerWith(structured)(new Request('ens://nothing.eth/'))).status, 404)
  const inMessage = async () => ({ ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: 3, message: `execution reverted: ${RESOLVER_NOT_FOUND}` } }) })
  assert.equal((await handlerWith(inMessage)(new Request('ens://nothing.eth/'))).status, 404)
})

test('ENSIP-5: a name with no website lists its text records — url as a link only when https, everything else as text', async () => {
  const texts = { url: 'https://example.org/', description: 'A <b>person</b>', 'com.twitter': 'someone', avatar: 'eip155:1/erc721:0xabc/1' }
  const { handler, textRecords } = await createEnsHandler({ fetchImpl: rpcStub({ contenthash: '0x', texts }) })
  assert.deepEqual(await textRecords('someone.eth'), texts)
  const res = await handler(new Request('ens://someone.eth/'))
  assert.equal(res.status, 404)
  const html = await res.text()
  assert.match(html, /has no website/)
  assert.match(html, /<a href="https:\/\/example.org\/" rel="noopener noreferrer">https:\/\/example.org\/<\/a>/)
  assert.match(html, /A &lt;b&gt;person&lt;\/b&gt;/, 'a record is text on the page, never markup')
  assert.match(html, /Twitter<\/dt><dd>someone/)
  assert.match(html, /taken on its word/)
  // No records: the page is the old page, with nothing added.
  const { handler: bare } = await createEnsHandler({ fetchImpl: rpcStub({ contenthash: '0x' }) })
  const plain = await (await bare(new Request('ens://someone.eth/'))).text()
  assert.doesNotMatch(plain, /ENSIP-5/)
  // A javascript: url is never a link.
  const { handler: evil } = await createEnsHandler({ fetchImpl: rpcStub({ contenthash: '0x', texts: { url: 'javascript:alert(1)' } }) })
  const evilHtml = await (await evil(new Request('ens://someone.eth/'))).text()
  assert.doesNotMatch(evilHtml, /<a href="javascript/)
  assert.match(evilHtml, /javascript:alert\(1\)/)
})
