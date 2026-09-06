/* globals Response, Request */

/*
 * ens:// — resolve an Ethereum Name Service name's website by reading its
 * EIP-1577 `contenthash` record, then handing the decoded pointer to the
 * IPFS / Arweave handlers that already render (and, for IPFS, verify) content.
 *
 * TRUST / LOCK STATE — TRUSTED, never trustless.
 *   The name -> contenthash binding is read from a PUBLIC Ethereum RPC over
 *   HTTPS. We do NOT run a light client and do NOT verify a Merkle proof of
 *   the record against a block header, so the RPC provider is trusted for the
 *   mapping (it also sees which .eth name you asked for). The bytes we then
 *   fetch ARE content-addressed (a CID is checked by the IPFS node), but the
 *   step that says "this name points at that CID" is unproven. So ens:// pages
 *   carry the verdict `partial` (src/hns/trust-path.js): the lock is closed in
 *   the neutral TRUSTED colour, exactly where an https:// page sits, and never
 *   the green trustless one. The panel names the RPC hop as the unverified step.
 *
 * NO CROSS-NAMESPACE FALLBACK (LAW L2).
 *   This handler resolves ENS or it fails as ENS. It NEVER constructs an
 *   hns:// URL — a .eth name is never quietly looked up as a Handshake name
 *   and never sends the user to whoever owns the Handshake TLD "eth".
 *
 * LAZY IMPORTS.
 *   viem and the web3protocol chain registry cost real startup time for a
 *   scheme most sessions never touch, so both are imported on the FIRST
 *   ens:// request, never at module load — mirroring web3-protocol.js.
 */

import { decodeContenthash } from '../../../src/contenthash.js'
import { ccipCall } from './ccip-read.js'
import { isPublicAddress } from '../../../src/safe-address.js'
import { escapeHtml } from './html.js'

const ENS_MAINNET_CHAIN_ID = 1
/**
 * The revert bytes from a JSON-RPC error, whichever shape the endpoint used.
 * Node-specific: geth puts them in `error.data`, some proxies nest them one
 * deeper, and a few only ever put the hex in the message.
 */
function revertDataOf (error) {
  // Structure first: `data` (or `data.data`) that IS a hex string is the
  // revert data. A message is consulted only when it says the call reverted —
  // an endpoint that echoes the request into a plain error ("invalid
  // argument: 0xeEeE…") carries a hex run that is not an answer, and reading
  // it as one would turn a transport failure into a claim about the name.
  for (const c of [error && error.data, error && error.data && error.data.data]) {
    if (typeof c === 'string' && /^0x[0-9a-fA-F]{8,}$/.test(c.trim())) return c.trim()
  }
  const message = error && typeof error.message === 'string' ? error.message : ''
  if (/revert/i.test(message)) {
    const m = /\b0x[0-9a-fA-F]{8,}\b/.exec(message)
    if (m) return m[0]
  }
  return null
}

/** How long one eth_call may take before it loses its turn to the next RPC. */
const RPC_TIMEOUT_MS = 8000

/**
 * The ENS Universal Resolver — a DAO-owned upgradable proxy on mainnet.
 *
 * VERIFIED, because a wrong address here is a silent failure and the wrong one
 * circulates: `0xb8c2C29ee19D8307cb7255e1Cd9CbDE883A267d5` is quoted as this
 * contract in places and has ZERO bytecode — it is an externally owned
 * account. This address answered `eth_getCode` with 2,491 bytes on 2026-09-04,
 * and resolved `vitalik.eth` through it.
 *
 * Using the PROXY rather than pinning an implementation means ENSv2 arrives
 * without a change here: the read interface is unchanged and the DAO upgrades
 * behind it.
 */
const UNIVERSAL_RESOLVER = '0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe'

/**
 * The Universal Resolver's own errors, by selector — so "this name has no
 * resolver" can be told apart from "it resolved, and does not publish this
 * record", which are very different sentences to show someone about their own
 * name. Confirmed against the live contract on 2026-09-04:
 * `definitelynotregistered12345.eth` reverts 0x77209fe8, while `pokersback.com`
 * — a real DNSSEC-imported name with no contenthash — reverts through the
 * CCIP path instead.
 */
const UR_ERRORS = {
  '0x77209fe8': 'no-resolver', // ResolverNotFound(bytes)
  '0x7199966d': 'no-resolver', // ResolverNotFound()
  '0x1e9535f2': 'no-resolver', // ResolverNotContract(bytes,address)
  '0x7b1c461b': 'no-content', //  UnsupportedResolverProfile(bytes4)
  '0x95c0c752': 'no-content' //   ResolverError(bytes)
}

/** ENSIP-10 `resolve(bytes name, bytes data)` -> the inner result + resolver. */
const UNIVERSAL_RESOLVER_ABI = [{
  name: 'resolve',
  type: 'function',
  stateMutability: 'view',
  inputs: [{ name: 'name', type: 'bytes' }, { name: 'data', type: 'bytes' }],
  outputs: [{ type: 'bytes' }, { type: 'address' }]
}]

const CONTENTHASH_ABI = [{
  type: 'function',
  name: 'contenthash',
  stateMutability: 'view',
  inputs: [{ type: 'bytes32' }],
  outputs: [{ type: 'bytes' }]
}]

/** ENSIP-5 `text(node, key)`. */
const TEXT_ABI = [{
  type: 'function',
  name: 'text',
  stateMutability: 'view',
  inputs: [{ type: 'bytes32' }, { type: 'string' }],
  outputs: [{ type: 'string' }]
}]

/**
 * The ENSIP-5 text records shown when a name has no website: the global keys
 * the specification names (plus ENSIP-12's `avatar`) and the service keys in
 * common use. Read only for a name with no contenthash — one RPC call per key
 * — and rendered as text; `url` becomes a link only when it is https.
 */
export const TEXT_KEYS = Object.freeze(['url', 'description', 'avatar', 'email', 'com.twitter', 'com.github', 'org.telegram'])

/**
 * @param {object} [options]
 * @param {Function} [options.fetchImpl]  proxied fetch for the Ethereum RPC
 *        (session/net.fetch, so the lookup rides the active proxy/Tor and does
 *        not leak the real IP). Defaults to the global fetch.
 * @param {any[]} [options.chainList]  override the web3protocol chain list
 *        (tests / rc). When absent, the bundled default registry is used.
 * @param {(request: Request) => Promise<Response>} [options.ipfsFetch]
 * @param {(request: Request) => Promise<Response>} [options.arFetch]
 */
export default function createEnsHandler ({
  fetchImpl, chainList, ipfsFetch, arFetch, universalResolver = UNIVERSAL_RESOLVER
} = {}) {
  const doRpc = fetchImpl || ((...a) => globalThis.fetch(...a))
  let deps = null

  // Load viem and the mainnet chain's RPC list once. Nothing else is read
  // from the chain list: resolution goes through the Universal Resolver at the
  // address pinned above (UNIVERSAL_RESOLVER), deliberately, because the
  // bundled registry names an older deployment.
  async function ensureDeps () {
    if (deps) return deps
    const [viem, viemEns, list] = await Promise.all([
      import('viem'),
      import('viem/ens'),
      chainList
        ? Promise.resolve(chainList)
        : import('web3protocol/chains').then(({ getDefaultChainList }) => getDefaultChainList())
    ])
    const chain = Object.values(list).find((c) => Number(c.id) === ENS_MAINNET_CHAIN_ID)
    if (!chain) throw new Error('Ethereum mainnet is not in the chain list')
    deps = {
      encodeFunctionData: viem.encodeFunctionData,
      decodeFunctionResult: viem.decodeFunctionResult,
      encodeAbiParameters: viem.encodeAbiParameters,
      decodeAbiParameters: viem.decodeAbiParameters,
      normalize: viemEns.normalize,
      namehash: viemEns.namehash,
      packetToBytes: viemEns.packetToBytes,
      toHex: viem.toHex,
      rpcUrls: chain.rpcUrls || [],
      universalResolver
    }
    return deps
  }

  // A single eth_call, tried across the chain's RPCs in order (the same
  // fallback the web3protocol client uses). Returns the result hex, or null
  // for an empty/`0x` return, or throws when every RPC fails/reverts.
  async function ethCall (to, data) {
    const { rpcUrls } = deps
    let lastErr = null
    for (const rpcUrl of rpcUrls) {
      try {
        const res = await doRpc(rpcUrl, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to, data }, 'latest'] }),
          // EVERY ATTEMPT CARRIES ITS OWN DEADLINE. Without one, an RPC that
          // accepts the connection and then says nothing holds the navigation
          // open forever and the second endpoint is never tried — so a list of
          // two "independent operators" is worth exactly one. hip5-op.js's
          // createRpc applies the same rule.
          signal: AbortSignal.timeout(RPC_TIMEOUT_MS)
        })
        if (!res.ok) { lastErr = new Error(`RPC HTTP ${res.status}`); continue }
        const json = await res.json()
        if (json.error) {
          // A REVERT IS AN ANSWER, not a transport failure — and since
          // ERC-3668 delivers its entire protocol through one, it must be
          // surfaced rather than collapsed into "RPC error". Endpoints differ
          // about where they put the bytes: some use `error.data`, some a
          // nested `{data}`, some only the message. Take the first that looks
          // like revert data and hand it back; trying the next RPC would just
          // get the same revert more slowly.
          const revert = revertDataOf(json.error)
          if (revert) return { revertData: revert }
          lastErr = new Error(json.error.message || 'RPC error')
          continue
        }
        const result = json.result
        return { result: result && result !== '0x' ? result : null }
      } catch (err) {
        lastErr = err
      }
    }
    throw lastErr || new Error('all Ethereum RPCs failed')
  }

  /** An eth_call that follows ERC-3668, returning the result hex or null. */
  async function call (to, data) {
    return ccipCall({
      to,
      data,
      call: ethCall,
      deps: {
        decodeAbiParameters: deps.decodeAbiParameters,
        encodeAbiParameters: deps.encodeAbiParameters,
        fetchImpl: doRpc,
        isPublicAddress,
        timeout: RPC_TIMEOUT_MS
      }
    })
  }

  /**
   * Resolve a .eth name to a content pointer.
   *
   * THE RULE THAT DECIDES THE SENTENCE. An error is an ANSWER about the name
   * only when it carries revert data — the chain spoke, and WHICH revert
   * decides between "not registered" and "no website". Every other failure
   * (no RPC reachable, a CCIP gateway that did not answer, a lookup that did
   * not terminate, a malformed result) is us not getting an answer, and is
   * reported as `unreachable`: nothing was learned about this name, so
   * nothing may be claimed about it. The default is the safer one.
   *
   * @returns {Promise<
   *   { kind: 'content', pointer: object } |
   *   { kind: 'no-resolver' } |
   *   { kind: 'unreachable', detail: string } |
   *   { kind: 'no-content' } |
   *   { kind: 'unsupported', pointer: object } |
   *   { kind: 'invalid-name', detail: string }>}
   */
  async function resolve (name) {
    await ensureDeps()
    const { encodeFunctionData, normalize, namehash, packetToBytes, toHex } = deps
    let node
    let dnsName
    try {
      const normalized = normalize(name)
      node = namehash(normalized)
      dnsName = toHex(packetToBytes(normalized))
    } catch (err) {
      return { kind: 'invalid-name', detail: String((err && err.message) || err) }
    }

    // ONE CALL, THROUGH THE UNIVERSAL RESOLVER.
    //
    // The registry only holds an entry for the name that was actually
    // registered — `base.eth`, not `jesse.base.eth` — so asking it directly
    // for a subname's resolver returns nothing, and the browser reported some
    // of the most-used names in ENS as unregistered. ENSIP-10 says a client
    // walks up to the nearest ancestor WITH a resolver and calls
    // `resolve(dnsEncode(name), data)` on it; the Universal Resolver does that
    // walk on chain, and reverts with OffchainLookup when the answer lives
    // off it — which ccip-read.js now follows. One call replaces the walk, the
    // wildcard handling and the CCIP plumbing.
    const inner = encodeFunctionData({
      abi: CONTENTHASH_ABI, functionName: 'contenthash', args: [node]
    })
    const outer = encodeFunctionData({
      abi: UNIVERSAL_RESOLVER_ABI, functionName: 'resolve', args: [dnsName, inner]
    })
    let raw
    try {
      raw = await call(deps.universalResolver, outer)
    } catch (err) {
      // A REVERT IS THE CHAIN ANSWERING. The Universal Resolver reverts when
      // no resolver exists for the name, which is "not registered"; a
      // resolver that does not implement contenthash is registered and
      // simply has no website. Saying the first about the second tells
      // someone their own name does not exist. An error WITHOUT revert data
      // is not an answer at all.
      const revert = String((err && err.revertData) || '')
      if (!revert) return { kind: 'unreachable', detail: String((err && err.message) || err) }
      return { kind: UR_ERRORS[revert.slice(0, 10).toLowerCase()] || 'no-content' }
    }
    if (!raw) return { kind: 'no-resolver' }

    // A well-formed JSON-RPC answer whose result is not the declared ABI
    // shape is a broken or hostile endpoint, not a fact about the name.
    let hashBytes = null
    try {
      const [encoded] = deps.decodeAbiParameters(
        [{ type: 'bytes' }, { type: 'address' }], raw)
      if (!encoded || encoded === '0x') return { kind: 'no-content' }
      const [value] = deps.decodeAbiParameters([{ type: 'bytes' }], encoded)
      hashBytes = value
    } catch (err) {
      return { kind: 'unreachable', detail: `the RPC answer could not be decoded: ${String((err && err.message) || err)}` }
    }

    const pointer = decodeContenthash(hashBytes)
    if (!pointer) return { kind: 'no-content' }
    if (!pointer.supported) return { kind: 'unsupported', pointer }
    return { kind: 'content', pointer }
  }

  /**
   * ENSIP-5 text records for `name`, through the same Universal Resolver
   * path as the contenthash (so wildcard and CCIP names answer too). A key
   * that reverts, is empty or cannot be read is simply absent; nothing about
   * the name is claimed from it. Values are capped, and are TEXT to the
   * page — never markup, never fetched.
   * @param {string} name
   * @param {readonly string[]} [keys]
   * @returns {Promise<Record<string, string>>}
   */
  async function textRecords (name, keys = TEXT_KEYS) {
    await ensureDeps()
    const { encodeFunctionData, normalize, namehash, packetToBytes, toHex } = deps
    let node, dnsName
    try {
      const normalized = normalize(name)
      node = namehash(normalized)
      dnsName = toHex(packetToBytes(normalized))
    } catch {
      return {}
    }
    const out = {}
    await Promise.all(keys.map(async (key) => {
      try {
        const inner = encodeFunctionData({ abi: TEXT_ABI, functionName: 'text', args: [node, key] })
        const outer = encodeFunctionData({ abi: UNIVERSAL_RESOLVER_ABI, functionName: 'resolve', args: [dnsName, inner] })
        const raw = await call(deps.universalResolver, outer)
        if (!raw) return
        const [encoded] = deps.decodeAbiParameters([{ type: 'bytes' }, { type: 'address' }], raw)
        if (!encoded || encoded === '0x') return
        const [value] = deps.decodeAbiParameters([{ type: 'string' }], encoded)
        const text = String(value || '').trim()
        if (text) out[key] = text.slice(0, 512)
      } catch { /* absent */ }
    }))
    return out
  }

  /** The no-website page's record list, as safe HTML (or '' when there is nothing). */
  function textRecordsHtml (records) {
    const rows = []
    for (const key of TEXT_KEYS) {
      const value = records[key]
      if (!value) continue
      const label = { url: 'Website', description: 'Description', avatar: 'Avatar', email: 'Email', 'com.twitter': 'Twitter', 'com.github': 'GitHub', 'org.telegram': 'Telegram' }[key] || key
      let shown = escapeHtml(value)
      if (key === 'url' && /^https:\/\/[^\s"'<>]+$/i.test(value)) {
        shown = `<a href="${escapeHtml(value)}" rel="noopener noreferrer">${escapeHtml(value)}</a>`
      }
      rows.push(`<dt>${escapeHtml(label)}</dt><dd>${shown}</dd>`)
    }
    if (!rows.length) return ''
    return '<p>The name does publish these records (ENSIP-5), read from the same resolver and taken on its word:</p>' +
      `<dl>${rows.join('')}</dl>`
  }

  async function handler (request) {
    const { name, path } = parseEnsUrl(request.url)
    if (!name) return page(400, 'Not an ENS address', 'This does not name a .eth name to resolve.')

    try {
      await ensureDeps()
    } catch (err) {
      return page(502, 'ENS is unavailable', `Could not load the Ethereum resolver: ${escapeHtml(String((err && err.message) || err))}.`)
    }

    let resolution
    try {
      resolution = await resolve(name)
    } catch (err) {
      return page(502, `Could not resolve ${escapeHtml(name)}`,
        `The Ethereum RPC lookup failed: ${escapeHtml(String((err && err.message) || err))}.`)
    }

    if (resolution.kind === 'invalid-name') {
      return page(400, `${escapeHtml(name)} is not a valid ENS name`, escapeHtml(resolution.detail))
    }
    if (resolution.kind === 'unreachable') {
      // 502, not 404: nothing was learned about this name, so nothing may be
      // claimed about it. A 404 here told people their friend's name did not
      // exist because our RPC list was down.
      return page(502, `Could not reach Ethereum to look up ${escapeHtml(name)}`,
        'Every Ethereum RPC endpoint this browser knows failed, so what this ' +
        'name points at is unknown — not absent. ' +
        `(${escapeHtml(resolution.detail || 'no endpoint answered')})`)
    }
    if (resolution.kind === 'no-resolver') {
      return page(404, `${escapeHtml(name)} is not registered`,
        'This .eth name has no resolver set on Ethereum, so there is nothing to load. ' +
        'It was NOT looked up as a Handshake name.')
    }
    if (resolution.kind === 'no-content') {
      let records = {}
      try { records = await textRecords(name) } catch { records = {} }
      return page(404, `${escapeHtml(name)} has no website`,
        'This .eth name has no <code>contenthash</code> record — it may hold only an ' +
        'address (for receiving funds) and no website content. Nothing was guessed at, ' +
        'and it was NOT looked up as a Handshake name.' + textRecordsHtml(records))
    }
    if (resolution.kind === 'unsupported') {
      const proto = escapeHtml(resolution.pointer.protocol)
      return page(501, `${escapeHtml(name)} points at ${proto}`,
        `Its content record is a <b>${proto}</b> address, which this build cannot fetch yet. ` +
        'It was decoded honestly rather than mis-routed to another network.')
    }

    // A supported pointer: hand the CID/txid to the handler that renders it.
    // The content is content-addressed and (for IPFS) integrity-checked, but
    // the ENS mapping above is RPC-trusted — so the verdict stays TRUSTED.
    const { pointer } = resolution
    const target = pointer.url + (path && path !== '/' ? path : '')
    const forward = (fetchFn) => {
      if (!fetchFn) {
        return page(501, `Cannot render ${escapeHtml(pointer.protocol)}`,
          `${escapeHtml(name)} resolves to ${escapeHtml(pointer.protocol)} content, but that handler is not wired.`)
      }
      return fetchFn(reissue(request, target))
    }

    let res
    if (pointer.protocol === 'ipfs' || pointer.protocol === 'ipns') res = await forward(ipfsFetch)
    else if (pointer.protocol === 'arweave') res = await forward(arFetch)
    else return page(501, `Cannot render ${escapeHtml(pointer.protocol)}`, 'Unsupported content pointer.')

    return tagEns(res)
  }

  return { handler, resolve, textRecords, ensureDeps }
}

/**
 * Parse `ens://<name>[/path][?query]` into its name and path (fragment dropped).
 *
 * `ens:` is a non-standard scheme, so the URL parser percent-encodes any
 * non-ASCII in the name (`ens://🚀.eth/` arrives as `ens://%F0%9F%9A%80.eth/`).
 * Emoji names are a large and deliberate part of ENS, so the name is decoded
 * before normalisation; a name that is not valid percent-encoding is kept as
 * written and ENSIP-15 refuses it.
 */
export function parseEnsUrl (url) {
  const raw = String(url).replace(/^ens:\/\//i, '').split('#')[0]
  const slash = raw.indexOf('/')
  const q = raw.indexOf('?')
  const end = slash === -1 ? q : (q === -1 ? slash : Math.min(slash, q))
  let name = (end === -1 ? raw : raw.slice(0, end)).replace(/\.$/, '')
  try { name = decodeURIComponent(name) } catch { /* keep the raw form */ }
  return { name: name.toLowerCase(), path: end === -1 ? '/' : raw.slice(end) }
}

/** Re-issue the request at a new content URL, carrying method + body. */
function reissue (request, target) {
  const init = { method: request.method, headers: request.headers }
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    init.body = request.body
    init.duplex = 'half'
  }
  return new Request(target, init)
}

/** Mark the served response as an (unverified) ENS resolution for the trust UI. */
function tagEns (res) {
  try {
    const headers = new Headers(res.headers)
    headers.set('X-Resolution-Namespace', 'ens')
    // Honest signal that the name->content binding was not chain-proven.
    if (!headers.has('X-HNS-Trust')) headers.set('X-HNS-Trust', 'ens-rpc-unverified')
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers })
  } catch {
    return res
  }
}

function page (status, title, detailHtml) {
  const body = `<!doctype html>
<html><head><meta charset="utf-8">
<title>${escapeHtml(title)}</title>
<meta name="color-scheme" content="light dark">
<style>
  body { font: 16px/1.6 system-ui, sans-serif; margin: 0; padding: 3rem 1.5rem;
         max-width: 40rem; margin-inline: auto; }
  code { background: color-mix(in srgb, currentColor 10%, transparent);
         padding: .15em .4em; border-radius: 4px; word-break: break-all; }
</style></head><body>
<h1>${escapeHtml(title)}</h1>
<p>${detailHtml}</p>
</body></html>`
  return new Response(body, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'X-Resolution-Namespace': 'ens',
      'Access-Control-Allow-Origin': 'null'
    }
  })
}
