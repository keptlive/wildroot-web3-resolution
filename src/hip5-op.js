/*
 * HIP-5 `_op`: a name's records read straight from a registry contract on
 * Optimism, with no nameserver of the TLD owner's in the path.
 *
 * A Handshake TLD that publishes `NS 0x<registry>._op.` is not naming a host.
 * `_op` is a pseudo-TLD — the Optimism sibling of the `_eth` form the HIP-5
 * draft describes and imperviousinc/handover implements for ENS — and the
 * label is a contract address on chainId 10. A resolver is meant to strip the
 * suffix and ask the contract; one that does not simply sees a nameserver that
 * has never existed, fails to look it up, and moves on. Wildroot did exactly
 * that until this file.
 *
 * THE HOPS, deliberately ENS-shaped so generic tooling can read the same
 * registry (src/protocols/ens-protocol.js reads mainnet ENS the same way):
 *
 *   node     = namehash(<label>.<tld>)                       EIP-137
 *   resolver = Registry.resolver(node)                       0x0178b8bf
 *   content  = Resolver.contenthash(node)                    EIP-1577
 *   records  = Resolver.dnsRecord(node, keccak(wire owner), type)   wire RRs
 *
 * TRUST — exactly the standing ens:// has, for the same reason. The SPV proof
 * covers the TLD -> registry pointer: consensus itself says this contract
 * answers for this name. It does NOT cover the contract's ANSWER, which is
 * read from a public JSON-RPC endpoint over HTTPS with no light client and no
 * Merkle proof against a block header. So the RPC is trusted for the record
 * (and sees which name was asked) and the trust panel says so in words
 * (src/hns/trust-path.js). The padlock follows the DNS route's rule: that
 * route also takes an unsigned answer from the chain-named server on its word
 * (over plaintext, where this is HTTPS), so `_op` is neither stricter nor
 * looser — content pointers close on the chain proof, an A-record site still
 * needs its DANE pin. The registry's own review reached the
 * same conclusion from the other side: REVIEW.md F8, "no trustless resolution
 * path, because we are not on L1", and F6, ENS compatibility is interface-only.
 *
 * WHY IT IS STILL THE PREFERRED ROUTE. The alternative is not a proof, it is
 * the TLD owner's own nameserver: one box that can answer anything it likes
 * about every name under the TLD, including names it sold. The registry answer
 * is at least the thing the holder wrote, and anyone can re-read it from any
 * RPC or their own node. So `_op` is tried first and the nameservers are the
 * fallback, not the other way round.
 *
 * DEPENDENCY-FREE ON PURPOSE. This runs on every navigation to an `_op` TLD,
 * so there is no viem here (ens-protocol.js can afford to lazy-load it; a
 * resolver cannot): an eth_call is a selector plus some 32-byte words over
 * `fetch`, and keccak comes from @noble/hashes, already in the tree. The
 * encodings are ported from the service that WRITES these records
 * (~/hns/dsld/service/resolve.cjs and voucher.cjs), so reader and writer
 * cannot drift; docs/HIP5-OP.md carries the ABI, the fallback order and the
 * draft text.
 */

import { keccak_256 as keccakHash } from '@noble/hashes/sha3.js'

import { TYPES } from './dns-query.js'
import { isPublicAddress } from './safe-address.js'
import { pointerFrom, txtStringsFrom } from './pointers.js'
import { decodeContenthash } from './contenthash.js'

/** An NS target that delegates to an Optimism registry: `0x<40 hex>._op.` */
export const OP_NS_RE = /^0x([0-9a-f]{40})\._op\.?$/i
/**
 * ANY `._op.` target, well-formed or not. Nothing under this pseudo-TLD is a
 * real host, so a malformed one (a short label, a typo) is not a nameserver
 * either — leaving it in the list bought one dead dns.lookup per resolution.
 */
const OP_SUFFIX_RE = /\._op\.?$/i

/**
 * Optimism mainnet (chainId 10), tried in order. Overridable per resolver
 * (`opRpcUrls`) and, for a user, through config.hnsOptions.resolver.
 * Two independent operators on purpose: a single fallback is no fallback.
 */
export const DEFAULT_OP_RPC_URLS = Object.freeze([
  'https://mainnet.optimism.io',
  'https://optimism-rpc.publicnode.com'
])

/** How long one eth_call may take before it loses its turn. */
export const DEFAULT_OP_TIMEOUT = 4000

const buf = (b) => (Buffer.isBuffer(b) ? b : Buffer.from(b))
const keccak = (...parts) => Buffer.from(keccakHash(Buffer.concat(parts.map(buf))))
const selector = (sig) => keccak(Buffer.from(sig, 'utf8')).subarray(0, 4)

const SEL_RESOLVER = selector('resolver(bytes32)')
const SEL_CONTENTHASH = selector('contenthash(bytes32)')
const SEL_HAS_DNS_RECORDS = selector('hasDNSRecords(bytes32,bytes32)')
const SEL_DNS_RECORD = selector('dnsRecord(bytes32,bytes32,uint16)')

const ZERO_ADDRESS = '0x' + '00'.repeat(20)

/** A uint16 in the low bytes of an ABI word. */
const u16word = (n) => {
  const b = Buffer.alloc(32)
  b.writeUInt16BE(n, 30)
  return b
}

/** EIP-137 namehash: labels hashed right-to-left onto the zero root. */
export function namehash (name) {
  let node = Buffer.alloc(32)
  if (name === '') return node
  const labels = String(name).split('.')
  for (let i = labels.length - 1; i >= 0; i--) {
    if (!labels[i]) throw new Error(`empty label in "${name}"`)
    node = keccak(node, keccak(Buffer.from(labels[i], 'utf8')))
  }
  return node
}

/** RFC1035 wire form: each label length-prefixed, terminated by a root byte. */
export function wireName (name) {
  const parts = []
  for (const label of String(name).split('.')) {
    const b = Buffer.from(label, 'utf8')
    if (b.length === 0 || b.length > 63) throw new Error(`bad label "${label}"`)
    parts.push(Buffer.from([b.length]), b)
  }
  parts.push(Buffer.from([0]))
  return Buffer.concat(parts)
}

/**
 * The storage key an RRset lives under: keccak256 of the LOWERCASED wire FQDN.
 * Lowercasing is done here, once: getting it wrong returns nothing rather than
 * erroring, which is the worst way for a resolver to be wrong.
 */
export function dnsNameKey (fqdn) {
  return keccak(wireName(String(fqdn).toLowerCase().replace(/\.$/, '')))
}

/**
 * The registry a TLD's on-chain records delegate to, or null.
 * @param {Array<{type:string, ns?:string}>} records the TLD's chain resource
 * @returns {string|null} the contract address, lowercased
 */
export function opRegistryFor (records) {
  for (const r of records || []) {
    if (r.type !== 'NS') continue
    const m = OP_NS_RE.exec(String(r.ns || ''))
    if (m) return ('0x' + m[1]).toLowerCase()
  }
  return null
}

/**
 * The NS records that name a real host to query — every `._op.` target
 * dropped, whether or not it parsed as a registry.
 * @param {Array<{type:string, ns?:string}>} records
 */
export function dnsNameservers (records) {
  return (records || []).filter(
    (r) => r.type === 'NS' && !OP_SUFFIX_RE.test(String(r.ns || '')))
}

/**
 * One `eth_call`, tried across the RPC list in order — the same fallback loop
 * ens-protocol.js runs for Ethereum mainnet. Each attempt carries its own
 * AbortSignal: an RPC that accepts the connection and then says nothing must
 * lose its turn, not hold a navigation open.
 */
function createRpc ({ rpcUrls, fetchImpl, timeout }) {
  const doFetch = fetchImpl || ((...args) => globalThis.fetch(...args))
  const urls = (rpcUrls && rpcUrls.length) ? rpcUrls : DEFAULT_OP_RPC_URLS
  const state = { used: null }

  async function call (to, data) {
    let lastErr = null
    for (const url of urls) {
      try {
        const res = await doFetch(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'eth_call',
            params: [{ to, data: '0x' + buf(data).toString('hex') }, 'latest']
          }),
          signal: AbortSignal.timeout(timeout)
        })
        if (!res.ok) { lastErr = new Error(`RPC HTTP ${res.status}`); continue }
        const json = await res.json()
        if (json.error) { lastErr = new Error(json.error.message || 'RPC error'); continue }
        state.used = url
        return Buffer.from(String(json.result || '0x').replace(/^0x/, ''), 'hex')
      } catch (err) {
        lastErr = err
      }
    }
    throw lastErr || new Error('no Optimism RPC endpoint is configured')
  }

  return { call, state }
}

/**
 * Decode an ABI-encoded `bytes` return value (offset word, length word,
 * payload). Every offset is bounds-checked, unlike the writer-side copy in
 * ~/hns/dsld: these bytes come from a public RPC, not from our own contract
 * call, so a length word of 2^200 must produce "no record", not a throw deep
 * inside a subarray.
 */
function decodeBytes (ret) {
  if (ret.length < 64) return Buffer.alloc(0)
  const word = (at) => Number(BigInt('0x' + ret.subarray(at, at + 32).toString('hex')))
  const off = word(0)
  if (!Number.isSafeInteger(off) || off < 0 || off + 32 > ret.length) return Buffer.alloc(0)
  const len = word(off)
  if (!Number.isSafeInteger(len) || len < 0 || off + 32 + len > ret.length) return Buffer.alloc(0)
  return ret.subarray(off + 32, off + 32 + len)
}

/**
 * Walk one RFC1035 owner name, returning the offset just past it.
 *
 * A compression pointer is REFUSED (-1), not followed. The contract's write
 * path guarantees no stored record contains one — that guarantee is what lets
 * the persist.click nameserver splice these bytes verbatim — and following a
 * pointer in bytes an RPC handed us is how a parser becomes a loop.
 */
function skipName (bytes, off) {
  for (;;) {
    if (off >= bytes.length) return -1
    const len = bytes[off]
    if (len === 0) return off + 1
    if (len > 63) return -1 // 0xc0.. is a compression pointer
    off += 1 + len
  }
}

/**
 * Split a stored RRset (concatenated wire RRs) into {type, ttl, rdata}. The
 * owner name is read only to step over it: the registry stores each RR under
 * the ON-CHAIN owner (`maya.persist`), and we already know what we asked for.
 */
export function parseRRset (bytes) {
  const out = []
  let off = 0
  while (off < bytes.length) {
    off = skipName(bytes, off)
    if (off < 0 || off + 10 > bytes.length) break
    const type = bytes.readUInt16BE(off)
    const ttl = bytes.readUInt32BE(off + 4)
    const rdlength = bytes.readUInt16BE(off + 8)
    off += 10
    if (off + rdlength > bytes.length) break
    out.push({ type, ttl, rdata: bytes.subarray(off, off + rdlength) })
    off += rdlength
  }
  return out
}

/** The first A record's dotted quad, in the string form dns-query.js produces. */
function addressFrom (rrs) {
  const a = rrs.find((r) => r.type === TYPES.A && r.rdata.length === 4)
  return a ? Array.from(a.rdata).join('.') : null
}

/**
 * TLSA records in the EXACT shape src/hns/dns-query.js hands to dane.js — the
 * DANE check and the trust panel are shared with the DNS route and must not
 * learn that this one exists.
 */
function tlsaFrom (rrs, owner) {
  return rrs
    .filter((r) => r.type === TYPES.TLSA && r.rdata.length > 3)
    .map((r) => ({
      name: owner,
      type: TYPES.TLSA,
      ttl: r.ttl,
      usage: r.rdata[0],
      selector: r.rdata[1],
      matchingType: r.rdata[2],
      certificate: r.rdata.subarray(3).toString('hex'),
      rdataRaw: Buffer.from(r.rdata)
    }))
}

/**
 * An EIP-1577 contenthash -> the pointer shapes the resolver already returns.
 *
 * THREE OUTCOMES, NOT TWO. A contract that holds no contenthash is an ordinary
 * minted-but-empty name and the DNS records below are the right next step. A
 * contract that holds one we cannot USE — a swarm address, an unknown codec, a
 * garbled record — is not: falling through hands the name to the TLD owner's
 * nameserver, which is the box this whole route exists to avoid trusting for a
 * name its owner may no longer hold. The ENS path already refuses honestly in
 * the same situation (`ens-protocol.js` renders a 501 naming the protocol);
 * this one quietly went and asked the seller instead.
 *
 * @returns {{kind: string}|null|{unusable: true, protocol: string}}
 */
function contentPointer (bytes) {
  let decoded = null
  try {
    decoded = decodeContenthash(bytes)
  } catch {
    return { unusable: true, protocol: 'unreadable' }
  }
  if (!decoded) return { unusable: true, protocol: 'unreadable' }
  if (!decoded.supported) {
    return { unusable: true, protocol: String(decoded.protocol || 'unknown') }
  }
  if (decoded.protocol === 'ipfs') return { kind: 'ipfs', cid: decoded.id }
  if (decoded.protocol === 'ipns') return { kind: 'ipns', key: decoded.id }
  if (decoded.protocol === 'arweave') return { kind: 'arweave', txid: decoded.id }
  return { unusable: true, protocol: String(decoded.protocol || 'unknown') }
}

const message = (err) => String((err && err.message) || err)
const hostOf = (url) => {
  try {
    return new URL(url).host
  } catch {
    return String(url || '')
  }
}

/**
 * Resolve one name from its TLD's Optimism registry.
 *
 * Answers with a resolution in the same shapes the DNS route produces, or with
 * a REASON and no resolution — the caller then falls back to the TLD's
 * ordinary nameservers. "Nothing here" and "could not ask" are both fallbacks,
 * but they are different sentences and the log says which.
 *
 * @param {string} host the full name, e.g. `maya.persist`
 * @param {{registry: string, rpcUrls?: string[], fetchImpl?: Function,
 *          timeout?: number}} options
 * @returns {Promise<{resolution: object|null, reason: string|null}>}
 */
export async function resolveOp (host, {
  registry,
  rpcUrls = DEFAULT_OP_RPC_URLS,
  fetchImpl = null,
  timeout = DEFAULT_OP_TIMEOUT
} = {}) {
  const name = String(host).toLowerCase().replace(/\.$/, '')
  const rpc = createRpc({ rpcUrls, fetchImpl, timeout })
  const found = (resolution) => ({
    resolution: { ...resolution, op: { registry, rpc: hostOf(rpc.state.used) } },
    reason: null
  })
  const fall = (reason) => ({ resolution: null, reason })

  let node
  try {
    node = namehash(name)
  } catch (err) {
    return fall(`${name} is not a namehashable name (${message(err)})`)
  }

  // 1. Which resolver serves this name? A registry that has never heard of it
  //    answers the zero address.
  let resolverAddr
  try {
    const ret = await rpc.call(registry, Buffer.concat([SEL_RESOLVER, node]))
    resolverAddr = ret.length >= 32 ? '0x' + ret.subarray(12, 32).toString('hex') : ZERO_ADDRESS
  } catch (err) {
    return fall(`no Optimism RPC answered (${message(err)})`)
  }
  if (resolverAddr === ZERO_ADDRESS) {
    return fall(`registry ${registry} has no resolver for ${name}`)
  }

  // 2. Content first: a name that publishes a contenthash is answered without
  //    any DNS record at all, and those bytes verify themselves.
  //    A resolver that does not implement contenthash() REVERTS — that is "no
  //    content", not a failure worth abandoning the route over, so it falls
  //    through to the DNS records below.
  try {
    const content = decodeBytes(
      await rpc.call(resolverAddr, Buffer.concat([SEL_CONTENTHASH, node])))
    if (content.length) {
      const pointer = contentPointer(content)
      if (pointer && pointer.unusable) {
        // Present and unusable: say so, do NOT go and ask the seller's
        // nameserver what this name points at.
        return found({ kind: 'unsupported-pointer', protocol: pointer.protocol })
      }
      if (pointer) return found(pointer)
    }
  } catch { /* no contenthash on this resolver */ }

  // 3. DNS records. hasDNSRecords is the contract's own "is there anything
  //    here", which is what makes the fallback sentence honest: a minted name
  //    with nothing written is a different case from an RPC that would not
  //    answer, and only the first is normal.
  const ownerKey = dnsNameKey(name)
  try {
    const ret = await rpc.call(resolverAddr,
      Buffer.concat([SEL_HAS_DNS_RECORDS, node, ownerKey]))
    if (!(ret.length >= 32 && ret[31] === 1)) {
      return fall(`registry ${registry} holds no records for ${name}`)
    }
  } catch (err) {
    return fall(`no Optimism RPC answered (${message(err)})`)
  }

  const tlsaOwner = `_443._tcp.${name}`
  const record = (owner, type) => rpc
    .call(resolverAddr, Buffer.concat(
      [SEL_DNS_RECORD, node, dnsNameKey(owner), u16word(type)]))
    .then((ret) => parseRRset(decodeBytes(ret)))

  let txtRRs, aRRs, tlsaRRs
  try {
    [txtRRs, aRRs, tlsaRRs] = await Promise.all([
      record(name, TYPES.TXT),
      record(name, TYPES.A),
      record(tlsaOwner, TYPES.TLSA)
    ])
  } catch (err) {
    // A PARTIAL answer is never used. An endpoint that serves the A record and
    // then fails on the TLSA one would strip the pin and look like a name that
    // simply has none — so one failure retires the whole route.
    return fall(`no Optimism RPC answered (${message(err)})`)
  }

  // Same precedence the DNS route uses: a content pointer in TXT beats an A
  // record, and pointerFrom (src/publish/pointers.js) picks between pointers.
  const pointer = pointerFrom(txtStringsFrom(txtRRs, TYPES.TXT))
  if (pointer) return found(pointer)

  const address = addressFrom(aRRs)
  if (!address) return fall(`${name} has no A record in registry ${registry}`)
  // The address is whatever the name's holder wrote; a query to 127.0.0.1 or
  // 169.254.169.254 is SSRF whichever route named it. Blocked, not fallen back
  // from: the record was found, and it says something we refuse to fetch.
  if (!isPublicAddress(address)) return found({ kind: 'blocked', address })

  const tlsa = tlsaFrom(tlsaRRs, tlsaOwner)
  return found({
    kind: 'site',
    address,
    tlsa,
    // The registry answered for this name and published no pin — the same
    // "authoritatively empty" rule the DNS route applies. It is not a weaker
    // statement than that route's: every byte on this path is RPC-trusted,
    // as every byte on that one is nameserver-trusted (see the header).
    allowInsecure: tlsa.length === 0
  })
}
