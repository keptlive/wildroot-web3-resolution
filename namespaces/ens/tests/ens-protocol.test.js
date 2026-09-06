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
import { encodeFunctionResult } from 'viem'

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
function rpcStub ({ resolver = RESOLVER, contenthash = IPFS_CH } = {}) {
  return async (_url, opts) => {
    const { params } = JSON.parse(opts.body)
    if (params[0].to.toLowerCase() !== UNIVERSAL_RESOLVER.toLowerCase()) {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: 3, data: RESOLVER_NOT_FOUND } }) }
    }
    if (resolver === ZERO) {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', id: 1, error: { code: 3, data: RESOLVER_NOT_FOUND } }) }
    }
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

test('a non-ASCII name is percent-decoded before it reaches the normaliser', async () => {
  // `ens:` is a non-standard scheme, so the URL parser treats everything after
  // `ens://` as an opaque path and percent-encodes the name. Emoji names are a
  // large and deliberate part of ENS, so the name is decoded before ENSIP-15
  // sees it.
  assert.equal(new Request('ens://\u{1F680}.eth/x').url, 'ens://%F0%9F%9A%80.eth/x')
  assert.deepEqual(parseEnsUrl(new Request('ens://\u{1F680}.eth/x').url),
    { name: '\u{1F680}.eth', path: '/x' })
  assert.deepEqual(parseEnsUrl('ens://caf%C3%A9.eth?x=1'), { name: 'caf\u00E9.eth', path: '?x=1' })
  // A lone `%` is not valid percent-encoding: the name is kept as written and
  // ENSIP-15 is the one that refuses it.
  assert.equal(parseEnsUrl('ens://100%.eth/').name, '100%.eth')

  const { handler } = createEnsHandler({
    chainList: CHAIN_LIST, fetchImpl: rpcStub(), ipfsFetch: recordingFetch('IPFS'), arFetch: recordingFetch('AR')
  })
  assert.equal((await handler(new Request('ens://\u{1F680}.eth/'))).status, 200,
    'the emoji name resolved')
  assert.equal((await handler(new Request('ens://100%.eth/'))).status, 400,
    'and a name ENSIP-15 refuses is still refused')
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
  // Served as an ENS resolution whose name->content binding is RPC-trusted:
  // the lock closes in the neutral TRUSTED colour, never the green one.
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'ens')
  assert.equal(res.headers.get('X-HNS-Trust'), 'ens-rpc-unverified')
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
  // resolve() loads its own dependencies: it is part of the returned interface
  // and a caller that has not called ensureDeps() gets an answer, not a
  // destructuring TypeError.
  const { resolve } = createEnsHandler({ chainList: CHAIN_LIST, fetchImpl: rpcStub() })
  const r = await resolve('vitalik.eth')
  assert.equal(r.kind, 'content')
  assert.equal(r.pointer.protocol, 'ipfs')
  assert.match(r.pointer.url, /^ipfs:\/\//)
  assert.doesNotMatch(r.pointer.url, /hns:/)
})
