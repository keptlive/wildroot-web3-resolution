/*
 * Handshake host resolution: chain proof first, then one authoritative hop.
 *
 *   hello.14898
 *     │  SPV getnameresource("14898")     <- Urkel proof, verified locally
 *     │    ├─ TXT ipfs=<cid> (apex, no NS) -> render from IPFS directly
 *     │    ├─ SYNTH4/SYNTH6, GLUE4/GLUE6  -> IP straight from the chain
 *     │    ├─ NS 0x<addr>._op            -> HIP-5: read the records from that
 *     │    │                                Optimism registry (hip5-op.js),
 *     │    │                                falling through to the NS below
 *     │    │                                when it holds nothing
 *     │    └─ NS ns1.hns.one             -> resolve NS host, then:
 *     │         TXT hello.14898           -> ipfs=<cid>? render from IPFS
 *     │         A or AAAA / TLSA          -> connect + DANE-pin the cert
 *
 * The authoritative hop is the one part not covered by a chain proof (the
 * zone could lie about its own contents), but it cannot lie about *which*
 * zone answers — that is proven — and the content itself is addressed by
 * CID, so a lying zone can only point at different content, not tamper
 * with what a CID names. TLSA pins close the TLS half the same way.
 */

import { timers } from './resolution-timing.js'
import dns from 'node:dns/promises'
import { isIP } from 'node:net'
import { query, TYPES } from './dns-query.js'
import { isPublicAddress } from './safe-address.js'
import { provesDenial, provesInsecureDelegation } from './denial.js'
import {
  validateChain as validateChainUntimed, validateDs, anchorZoneKeys, isSupportedDs,
  isWildcardExpanded, WILDCARD_REASON, wireName
} from './dnssec.js'
import { originFrom, pointerFrom, txtStringsFrom, dnslinkPointerFrom, mergePointers, DNSLINK_PREFIX } from './pointers.js'
import {
  DEFAULT_OP_RPC_URLS, DEFAULT_OP_TIMEOUT, dnsNameservers, opRegistryFor, resolveOp
} from './hip5-op.js'

/**
 * validateChain with its cost recorded as 'dnssec' (src/hns/resolution-timing.js).
 * The validation is synchronous crypto, so it is measured by hand rather than
 * through timers.time(); a chain that does not verify is a failed sample.
 */
function validateChain (opts) {
  const start = performance.now()
  let result
  try {
    result = validateChainUntimed(opts)
  } catch (err) {
    timers.record('dnssec', performance.now() - start, false)
    throw err
  }
  timers.record('dnssec', performance.now() - start, !!(result && result.ok))
  return result
}

/**
 * Why a chain-anchored lookup could not answer yet. Reaches the user through
 * the sharing gate's `unverified` sentence — "couldn't be checked safely right
 * now. Try again in a moment." — which is the truth while headers are still
 * coming in.
 */
const SYNCING = 'the Handshake chain is still catching up'

/**
 * A failed validateChain result -> the resolution that describes it.
 *
 * Two very different things end up here and they used to share one sentence.
 * A signature that does not check out IS an attack or a broken zone, and
 * `dnssec-fail` says so. A zone we simply cannot verify — a wildcard, whose
 * acceptance needs the NSEC proof this browser does not have — is neither, and
 * telling its owner that "someone is tampering with its DNS answers" was both
 * false and unactionable. Same refusal, honest reason.
 *
 * @param {{reason?: string}|null} result
 * @param {string} fallback
 * @param {object} [extra] merged into the resolution (e.g. the address)
 */
function dnssecFailure (result, fallback, extra = {}) {
  const reason = (result && result.reason) || fallback
  const kind = reason === WILDCARD_REASON ? 'dnssec-unsupported' : 'dnssec-fail'
  return { kind, reason, ...extra }
}

/**
 * How many delegations below a TLD this browser will follow. Registry TLDs
 * delegate one level (`pinner.hns` -> `ns1.lumeweb`); the bound exists so a
 * zone that refers to itself, or a pair that refer to each other, costs a
 * handful of queries rather than the tab.
 */
const MAX_DELEGATIONS = 3

/** The resolution kinds worth remembering — every failure is re-asked. */
const CACHEABLE = new Set(['ipfs', 'ipns', 'bittorrent', 'hyper', 'arweave', 'site', 'txt'])

/** The on-chain DS records of a TLD, in validateChain's shape. */
function chainDs (records) {
  return (records || [])
    .filter((r) => r.type === 'DS')
    .map((r) => ({
      keyTag: r.keyTag,
      algorithm: r.algorithm,
      digestType: r.digestType,
      digest: r.digest
    }))
}

/**
 * The answers that are actually ABOUT `host` — its own RRs, plus anything at
 * the end of a CNAME chain starting there.
 *
 * A nameserver's answer section is whatever it chose to put in it. Nothing
 * required the owner name to match the question, and nothing checked: on an
 * UNSIGNED zone a record published for `other.example` was accepted as
 * `host.example`'s content pointer, because the parser only ever saw the
 * strings. On a signed zone the RRSIG's owner would have caught it, which is
 * exactly why the unsigned case is the one that needed this.
 *
 * The CNAME chain is followed rather than ignored because pointing a name at
 * another name is a legitimate setup this browser already supports for A
 * records.
 *
 * @param {Array<{name?: string, type?: number, target?: string}>} answers
 * @param {string} host
 * @param {number} cnameType
 */
const norm = (n) => String(n || '').toLowerCase().replace(/\.$/, '')

export function answersAbout (answers, host, cnameType) {
  const owners = new Set([norm(host)])
  // A chain is short in practice; the bound stops a server looping us.
  for (let i = 0; i < 8; i++) {
    let grew = false
    for (const r of answers || []) {
      if (r && r.type === cnameType && r.target && owners.has(norm(r.name))) {
        const target = norm(r.target)
        if (!owners.has(target)) { owners.add(target); grew = true }
      }
    }
    if (!grew) break
  }
  return (answers || []).filter((r) => r && owners.has(norm(r.name)))
}

/**
 * A referral in a reply, or null: this zone holds no answer for `host` and
 * has handed the question to a sub-zone.
 *
 * The distinction that matters is referral vs NODATA, and the SOA is what
 * tells them apart: a zone that OWNS the name and simply has no record of
 * that type returns its own SOA in AUTHORITY, while a zone that delegated the
 * name returns the child's NS records and no SOA (RFC 1034 §4.3.2). Reading a
 * NODATA as a referral would send the browser off to re-ask a zone that
 * already gave it the honest answer.
 *
 * The child must sit strictly BELOW the zone that named it and be at or above
 * `host` — a zone cannot delegate sideways, and a referral to an unrelated
 * name is not a referral, it is a redirect to somewhere we never asked about.
 *
 * @param {object} response a parsed DNS reply
 * @param {string} zone the apex of the zone that answered
 * @param {string} host the name being resolved
 * @returns {{child:string, targets:string[]}|null}
 */
export function referralIn (response, zone, host) {
  if (!response) return null
  const authority = response.authority || []
  if ((response.answers || []).length) return null
  if (authority.some((r) => r.type === TYPES.SOA)) return null

  const strip = (n) => String(n || '').toLowerCase().replace(/\.$/, '')
  const z = strip(zone)
  const h = strip(host)
  const under = (name, parent) => name === parent || name.endsWith(`.${parent}`)

  let child = null
  const targets = []
  for (const r of authority) {
    if (r.type !== TYPES.NS || !r.target) continue
    const owner = strip(r.name)
    if (owner === z || !under(owner, z)) continue
    if (!under(h, owner)) continue
    if (child && owner !== child) continue // one delegation point per step
    child = owner
    targets.push(strip(r.target))
  }
  return child && targets.length ? { child, targets } : null
}
/**
 * Content pointer from TXT strings — the shared convention and its precedence
 * live in src/publish/pointers.js, so this path and the DoH path (src/hns/doh.js)
 * read every name the same way and the publish page cannot drift from either.
 */
export class HNSResolver {
  constructor ({
    spv, authoritative = null, serverFor = null, timeout = 5000,
    opRpcUrls = DEFAULT_OP_RPC_URLS, opTimeout = DEFAULT_OP_TIMEOUT, fetchImpl = null,
    dial = null, lookup = null
  } = {}) {
    this.spv = spv
    // Tests inject {server, port} to aim the authoritative hop at a local
    // nameserver; production discovers it from the chain's NS records.
    this.authoritative = authoritative
    // Tests only, like `authoritative`: where a DELEGATED zone's server is,
    // by child apex — `(child, targets) => {server, port} | null`. Production
    // resolves the referral's nameserver names (glue, chain, OS) and dials 53;
    // a test has no public address to hand out and no port 53 to bind.
    this.serverFor = serverFor
    this.timeout = timeout
    // The Optimism endpoints a HIP-5 `_op` delegation is read from, in order
    // (src/hns/hip5-op.js; the user-visible default is config.hnsOptions).
    // fetchImpl is the proxied session fetch in production
    // (src/protocols/index.js) and a fake in tests; the global-fetch default
    // in hip5-op.js is for library use only, and it is NOT proxied.
    this.opRpcUrls = opRpcUrls
    this.opTimeout = opTimeout
    this.fetchImpl = fetchImpl
    // The socket factory for every authoritative query. null = a direct
    // `net.connect`; the browser hands in a SOCKS5 dialer to the device-local
    // Tor while IP Protection is on, so the chain proof survives anonymization.
    this.dial = dial
    // How an ICANN host that appears in a walk (a nameserver name, a CNAME
    // target) is turned into an address. The library default is the OS
    // resolver, in the clear; the browser hands in its DoH/ODoH client so the
    // one plaintext lookup this path used to make is gone on every mode.
    this.lookup = lookup || (async (host) =>
      preferV4((await dns.lookup(host, { all: true })).map((r) => r.address)))
    // Which `_op` fallbacks have already been explained. A page pulls dozens
    // of subresources from one name, and the reason is the same every time.
    this.opFallbacksLogged = new Set()
    this.cache = new Map()
    this.cacheTtl = 60 * 1000
    this.cacheMax = 512 // bound the map: a hostile page can name thousands of subhosts
  }

  /** Drop every cached resolution — the hard-reload hook (src/hard-reload.js).
   *  Whole-cache on purpose: a page's subresources span hosts, entries cost
   *  one re-resolution each, and per-host eviction would miss exactly the
   *  stale record the user is hard-reloading to escape. */
  clearCache () {
    this.cache.clear()
  }

  /**
   * Forget one name — and everything under it.
   *
   * The narrow companion to clearCache(), for the moment we KNOW an answer
   * went stale: a publish just moved a name's `ipfs=` pointer, and until this
   * existed the browser went on serving the previous CID from this cache for
   * up to a minute. Opening your own name straight after publishing to it
   * showed the old page, which reads as "the publish did not work" and is the
   * single worst moment to be lying to someone (Matt, 2026-09-04).
   *
   * Descendants go too, because what changed may be a TLD: republishing `w3`
   * changes what every `*.w3` resolves through, and keeping those would leave
   * the cache internally inconsistent with the name above them.
   *
   * @param {string} host
   * @returns {number} how many entries were dropped
   */
  forget (host) {
    const h = String(host || '').toLowerCase().replace(/\.$/, '')
    if (!h) return 0
    let dropped = 0
    for (const key of [...this.cache.keys()]) {
      if (key === h || key.endsWith(`.${h}`)) {
        this.cache.delete(key)
        dropped++
      }
    }
    return dropped
  }

  /** @returns {{kind:'ipfs',cid:string}|{kind:'site',address:string,tlsa:Array}|{kind:'unregistered'}} */
  async resolve (host) {
    host = String(host || '').toLowerCase().replace(/\.$/, '')
    if (!host || isIP(host)) throw new Error(`not a name: ${host}`)

    const cached = this.cache.get(host)
    if (cached && cached.at + this.cacheTtl > Date.now()) {
      // Refresh LRU position on hit.
      this.cache.delete(host)
      this.cache.set(host, cached)
      return cached.value
    }
    if (cached) this.cache.delete(host)

    const value = await this._resolve(host)
    // Only a POSITIVE resolution is remembered. A transient empty answer would
    // otherwise pin a real name as dead for the whole TTL, and — the case
    // that bit on 2026-09-04 — one dropped DNSKEY query or a nameserver mid-
    // restart used to be remembered as `dnssec-fail` / `unreachable` for a
    // minute, so the retry the user was already making could not succeed.
    if (CACHEABLE.has(value.kind)) {
      if (this.cache.size >= this.cacheMax) {
        this.cache.delete(this.cache.keys().next().value) // evict oldest
      }
      this.cache.set(host, { at: Date.now(), value })
    }
    return value
  }

  async _resolve (host) {
    // Timed here, not in resolve(): a cache hit is not a resolution, and
    // counting it would flatter the chain-proof numbers we intend to publish.
    // 'spv' spans the WHOLE chain-side resolution — the name lookup on the
    // local node, the zone's nameserver, its TXT/TLSA queries and the DNSSEC
    // validation (timed again on its own as 'dnssec') — not the SPV proof
    // alone. That is the number a plain DoH lookup is compared against.
    return timers.time('spv', () => this.__resolve(host))
  }

  /**
   * The zone's nameserver, from its on-chain NS (+GLUE) records. Tries each
   * in turn: a zone with two NS records that goes dark on the first should
   * still resolve via the second. The address is attacker-controlled
   * (on-chain GLUE or an NS host they registered); a query to 127.0.0.1:53
   * is SSRF too, so a private address is `blocked`, never queried.
   * @returns {Promise<{ server?: {server:string, port:number}, blocked?: object }>}
   */
  async _nameserverFor (tld, records, nsRecords) {
    for await (const candidate of this._nameserverCandidates(tld, records, nsRecords)) {
      return candidate
    }
    throw new Error(`no reachable nameserver for ${tld}`)
  }

  /**
   * Every server the zone can be asked at, lazily, in the order it named them
   * (HS-15: failover at query time). For each NS: its glue addresses (IPv4
   * first, then IPv6), else the chain's answer for the nameserver's own name,
   * else the ICANN lookup — resolved only when the walk reaches that entry,
   * so a zone whose first nameserver answers costs no lookup for the rest.
   * A private or reserved address is yielded as `blocked`, exactly where it
   * was met: a zone that names one is refused, not skipped.
   *
   * @param {string} tld
   * @param {Array} records the chain resource
   * @param {Array} nsRecords its NS records, in order
   * @returns {AsyncGenerator<{server?: {server: string, port: number}, blocked?: object}>}
   */
  async * _nameserverCandidates (tld, records, nsRecords) {
    for (const ns of nsRecords) {
      const nsHost = ns.ns.replace(/\.$/, '')
      let addresses = glueAddresses(records, nsHost)
      if (!addresses.length) {
        let address = null
        try {
          address = (await this._chainAddress(nsHost)) || (await this.lookup(nsHost))
        } catch {
          address = null
        }
        if (address) addresses = [address]
      }
      for (const address of addresses) {
        if (!isPublicAddress(address)) {
          yield { blocked: { kind: 'blocked', address } }
          return
        }
        yield { server: { server: address, port: 53 } }
      }
    }
  }

  /**
   * The servers a question may be put to: the configured `authoritative`
   * (one, or a list, in order) when there is one, else the zone's own
   * nameservers. One shape for both, so the failover loop is written once.
   * @param {string} tld
   * @param {Array} records
   * @param {Array} nsRecords
   */
  async * _servers (tld, records, nsRecords) {
    if (this.authoritative) {
      for (const server of [].concat(this.authoritative)) yield { server }
      return
    }
    yield * this._nameserverCandidates(tld, records, nsRecords)
  }

  /**
   * Put a question to the zone, moving to its next nameserver when one
   * cannot be ASKED. A server that could not be reached, timed out, or
   * answered a different question (a transport-level failure, thrown by
   * `query`) is not the zone's answer; the next server in the zone's own
   * order is. An answer that fails validation is a RESULT and is returned as
   * it is — a second server cannot make a forged answer honest, and asking
   * it would only give an attacker who controls the path a second try.
   * Until 2026-09-06 the first nameserver with an address was the only one
   * asked, and a zone with two nameservers went dark with its first
   * (HS-15); the same held for a nameserver whose only glue was an IPv6 on
   * a network without one.
   *
   * @param {string} tld
   * @param {Array} records
   * @param {Array} nsRecords
   * @param {(server: {server: string, port: number}) => Promise<any>} ask
   */
  async _withFailover (tld, records, nsRecords, ask) {
    let lastErr = null
    let asked = 0
    for await (const candidate of this._servers(tld, records, nsRecords)) {
      if (candidate.blocked) return candidate.blocked
      asked++
      try {
        return await ask(candidate.server)
      } catch (err) {
        lastErr = err
      }
    }
    if (!asked) throw lastErr || new Error(`no reachable nameserver for ${tld}`)
    throw lastErr
  }

  /**
   * An address for a nameserver host: glue we were handed, then the CHAIN,
   * then the OS resolver. IPv4 when the host has one, IPv6 when that is all
   * it has (`glueAddress`, `preferV4`).
   *
   * The chain step is not an optimisation, it is the difference between
   * resolving a name and not. `pinner.hns` is delegated to `ns1.lumeweb` — a
   * nameserver whose name exists ONLY on Handshake, with its address in the
   * `lumeweb` TLD's on-chain glue. `dns.lookup` cannot see it, so without this
   * every name sold under a registry TLD came back `unregistered`.
   *
   * Chain BEFORE the OS resolver is also the right precedence, and the same
   * one hsd's own resolver applies: the Handshake root is authoritative for
   * any name registered on it, and a TLD with no chain records at all — which
   * today is every ICANN TLD, `one` and `io` included — is the only case that
   * falls through to ICANN.
   *
   * @param {string} nsHost
   * @param {Array} glueRecords GLUE4/GLUE6 records to consult first
   * @returns {Promise<string|null>}
   */
  async _addressForNsHost (nsHost, glueRecords) {
    const glue = glueAddress(glueRecords, nsHost)
    if (glue) return glue

    const chained = await this._chainAddress(nsHost)
    if (chained) return chained

    return this.lookup(nsHost)
  }

  /**
   * A nameserver host resolved through Handshake, or null if its TLD is not
   * a registered Handshake name (so ICANN owns the question).
   *
   * Deliberately ONE level deep: chain glue, a SYNTH4/SYNTH6 apex, or one
   * query to the TLD's own nameservers. A nameserver whose address needs a nameserver
   * whose address needs a nameserver is a loop waiting to happen, and there
   * is no legitimate zone that requires it.
   *
   * @param {string} nsHost
   * @returns {Promise<string|null>}
   */
  async _chainAddress (nsHost) {
    const labels = nsHost.split('.')
    const tld = labels[labels.length - 1]
    let resource = null
    try {
      resource = await this.spv.getResource(tld)
    } catch {
      return null
    }
    if (!resource || !Array.isArray(resource.records)) return null
    const records = resource.records

    const glue = glueAddress(records, nsHost)
    if (glue) return glue

    if (nsHost === tld) {
      const synth = synthRecord(records)
      if (synth) return synth.address
    }

    for (const ns of dnsNameservers(records)) {
      const target = ns.ns.replace(/\.$/, '')
      if (target === nsHost) continue // its own address is what we are asking for
      let address = glueAddress(records, target)
      if (!address) {
        try {
          address = await this.lookup(target)
        } catch {
          continue
        }
      }
      if (!isPublicAddress(address)) continue
      try {
        const found = await this._addressAt(address, 53, nsHost)
        if (found) return found
      } catch {
        continue
      }
    }
    return null
  }

  /**
   * The address a server gives for `name`: its A, else its AAAA. Both are
   * asked at once — one round trip either way — and neither is validated,
   * which is why this only ever answers for a NAMESERVER host (whose zone is
   * then verified on its own terms), never for a site.
   * @param {string} server
   * @param {number} port
   * @param {string} name
   * @returns {Promise<string|null>}
   */
  async _addressAt (server, port, name) {
    const opts = { timeout: this.timeout, dial: this.dial }
    const [a, aaaa] = await Promise.allSettled([
      query(server, port, name, TYPES.A, opts),
      query(server, port, name, TYPES.AAAA, opts)
    ])
    const of = (settled, type) => settled.status === 'fulfilled'
      ? settled.value.answers.filter((r) => r.type === type && r.address).map((r) => r.address)
      : []
    const found = preferV4([...of(a, TYPES.A), ...of(aaaa, TYPES.AAAA)])
    if (found) return found
    if (a.status === 'rejected' && aaaa.status === 'rejected') throw a.reason
    return null
  }

  /**
   * Say once, quietly, why a name with an `_op` delegation is being answered
   * by the TLD's nameservers after all. Not an error — a minted name with no
   * records on chain is the ordinary case — but a silent fallback is how a
   * dead RPC endpoint stays unnoticed for a release.
   * @param {string} host
   * @param {string} reason
   */
  _logOpFallback (host, reason) {
    const key = `${host}|${reason}`
    if (this.opFallbacksLogged.has(key)) return
    if (this.opFallbacksLogged.size > 256) this.opFallbacksLogged.clear()
    this.opFallbacksLogged.add(key)
    console.log(`hns: ${host} — _op route yielded nothing (${reason}); using the zone's nameservers`)
  }

  /**
   * The chain answered, and it had nothing for this TLD. Is that a FACT, or
   * is the node simply not there yet?
   *
   * A SYNCING node answers every getnameresource with nothing, because it has
   * not seen the block the name was registered in. Reported as `unregistered`
   * that becomes the sentence "There is no name alice.w3." — said with total
   * confidence about a name that plainly exists, for the whole first hour of
   * a fresh install. It is the same confusion this file already guards one
   * step earlier for a node that is DOWN, and the same one `isSynced()` was
   * written for: its own comment records a version that "declared a node
   * synced at height 10k and made every name resolve as unregistered".
   *
   * Browsing does not hit this — src/hns/index.js picks the DoH resolver
   * until the node reaches the tip. The paths that come HERE are the ones
   * that must be chain-anchored (the sharing gate's `_hns` lookup takes its
   * DNSSEC trust root from the on-chain DS, which no DoH answer can supply),
   * so the honest answer for them is "ask me again in a moment", not "no".
   *
   * @param {'unregistered'} kind what it would have been on a synced node
   */
  async _absent (kind) {
    const spv = this.spv
    if (spv && typeof spv.isSynced === 'function' && !(await spv.isSynced())) {
      return { kind: 'unreachable', reason: SYNCING }
    }
    return { kind }
  }

  /**
   * The TXT strings at an arbitrary owner name under a Handshake TLD —
   * `_hns.alice.w3`, say — validated up to the on-chain DS when the zone is
   * signed. This is how a person is resolved to a key (SHARED-FOLDERS.md
   * §3.3): the same server discovery and the same DNSSEC chain the pointer
   * path uses, with the answer's strings handed back instead of interpreted.
   *
   * @param {string} host
   * @returns {Promise<{ kind: 'txt', strings: string[], dnssecValidated: boolean }
   *   | { kind: 'unregistered' } | { kind: 'blocked', address: string }
   *   | { kind: 'unreachable', reason: string }
   *   | { kind: 'dnssec-fail', reason: string }>}
   */
  async txtRecords (host) {
    host = String(host || '').toLowerCase().replace(/\.$/, '')
    const labels = host.split('.')
    const tld = labels[labels.length - 1]
    const resource = await this.spv.getResource(tld)
    // "I could not ask the chain" is not "there is no such name". Callers act
    // very differently on the two — the sharing gate turns unregistered into
    // "There is no name X", which is a lie when the node is merely down.
    if (resource && resource.unreachable) {
      return { kind: 'unreachable', reason: 'the Handshake node could not be reached' }
    }
    if (!resource || !Array.isArray(resource.records)) return this._absent('unregistered')
    const records = resource.records
    const nsRecords = dnsNameservers(records)
    if (!this.authoritative && !nsRecords.length) return { kind: 'unregistered' }
    return this._withFailover(tld, records, nsRecords, (server) =>
      this._txtFromServer(host, tld, records, server))
  }

  /**
   * txtRecords, asked at ONE server (the failover loop above picks it).
   * @param {string} host
   * @param {string} tld
   * @param {Array} records
   * @param {{server: string, port: number}} server
   */
  async _txtFromServer (host, tld, records, server) {
    const opts = { timeout: this.timeout, dial: this.dial }
    // Same delegation walk the site path takes (`_fromZone`): an identity TXT
    // under a registry TLD lives in the delegated zone, not the TLD's own, and
    // the sharing gate must not call a real person unregistered because their
    // name was sold to them by a sub-registry.
    let ctx = { zone: tld, server, dsRecords: chainDs(records) }
    let txt = null
    for (let depth = 0; ; depth++) {
      const dnssecZone = ctx.dsRecords.length > 0
      txt = await query(ctx.server.server, ctx.server.port, host, TYPES.TXT,
        { ...opts, dnssec: dnssecZone })
      const referral = referralIn(txt, ctx.zone, host)
      if (!referral) break
      if (depth >= MAX_DELEGATIONS) {
        return { kind: 'unreachable', reason: `delegation chain deeper than ${MAX_DELEGATIONS} for ${host}` }
      }
      const zoneCtx = ctx
      const next = await this._descend(zoneCtx, referral, txt,
        () => this._dnskeysAt(zoneCtx, opts))
      if (next.fail) return next.fail
      ctx = next.ctx
    }
    const dsRecords = ctx.dsRecords
    const dnssecZone = dsRecords.length > 0
    const mine = answersAbout(txt.answers, host, TYPES.CNAME)
    const strings = txtStringsFrom(mine, TYPES.TXT)
    if (!strings.length) return { kind: 'unregistered' }
    if (!dnssecZone) return { kind: 'txt', strings, dnssecValidated: false }
    const txtRRSIG = txt.answers.find((r) => r.type === TYPES.RRSIG && r.typeCovered === TYPES.TXT)
    const txtRdatas = txt.answers.filter((r) => r.type === TYPES.TXT && r.rdataRaw).map((r) => r.rdataRaw)
    let result = null
    try {
      const fetchDnskeys = () => this._dnskeysAt(ctx, opts)
      const { dnskeys, dnskeyRRSIG } = await fetchDnskeys()
      // The same §5.3.4 proof the site path demands: a wildcard-expanded
      // identity record must come with the NSEC showing no closer match.
      const denial = txtRRSIG && await this._wildcardProof(
        txtRRSIG, host, txt.authority, ctx, { dsRecords, fetchDnskeys })
      result = txtRRSIG && validateChain({
        dsRecords,
        dnskeys,
        dnskeyRRSIG,
        leafOwner: host,
        leafType: TYPES.TXT,
        leafRdatas: txtRdatas,
        leafRRSIG: txtRRSIG,
        denial
      })
    } catch {
      result = null
    }
    if (!result || !result.ok) return dnssecFailure(result, 'TXT RRSIG missing')
    return { kind: 'txt', strings, dnssecValidated: true }
  }

  /**
   * The DNSKEY RRset of the zone a context points at, with the RRSIG that
   * self-signs it. One query, no caching: the callers that need it need it
   * once, and a stale key set is a validation failure rather than a miss.
   * @param {{zone:string, server:{server:string,port:number}}} ctx
   * @param {object} opts query options
   */
  async _dnskeysAt (ctx, opts) {
    const dk = await query(ctx.server.server, ctx.server.port, ctx.zone,
      TYPES.DNSKEY, { ...opts, dnssec: true })
    return {
      dnskeys: dk.answers.filter((r) => r.type === TYPES.DNSKEY),
      dnskeyRRSIG: dk.answers.find(
        (r) => r.type === TYPES.RRSIG && r.typeCovered === TYPES.DNSKEY)
    }
  }

  async __resolve (host) {
    const labels = host.split('.')
    const tld = labels[labels.length - 1]
    const resource = await this.spv.getResource(tld)
    // "I could not ask the chain" is not "there is no such name". txtRecords
    // has always drawn this line; the BROWSING path did not, so a node that
    // was down fell to _absent(), whose isSynced() then reported the reason as
    // "the Handshake chain is still catching up" — a confident, wrong
    // diagnosis of a dead node. Two copies of one rule; one grew the branch.
    if (resource && resource.unreachable) {
      return { kind: 'unreachable', reason: 'the Handshake node could not be reached' }
    }
    if (!resource || !Array.isArray(resource.records)) {
      return this._absent('unregistered')
    }
    const records = resource.records

    // Apex request answered entirely on-chain: a pointer, no delegation.
    if (host === tld) {
      const pointer = onchainPointer(records)
      if (pointer && !records.some((r) => r.type === 'NS')) {
        return pointer
      }
    }

    // Decided from the chain resource alone, before anyone is contacted: if
    // the zone's only anchors use an algorithm we cannot verify, no nameserver
    // answer could change the outcome.
    const tldDs = chainDs(records)
    if (tldDs.length && !tldDs.some(isSupportedDs)) {
      return {
        kind: 'dnssec-unsupported',
        reason: `this zone is signed with algorithm ${tldDs[0].algorithm}, ` +
          'which this browser cannot verify'
      }
    }

    const synth = synthRecord(records)
    const hasNs = records.some((r) => r.type === 'NS')
    let server = this.authoritative
    // THE TLD'S OWN ADDRESS IS THE TLD'S OWN, and only when there is nothing
    // better to ask. Both guards were missing, and each was a real hole:
    //
    //   host === tld — without it, `www.example` never reached ns1.example. It
    //     was served the TLD APEX's IP over plaintext, and if the apex also
    //     carried an `ipfs=` TXT, every subdomain served the TLD's own site.
    //     The plaintext was justified by "the IP came straight from the chain",
    //     which is true of the apex and false of every name beneath it.
    //   !hasNs — the sibling apex branch above already refuses to answer from
    //     the chain when the zone names a nameserver, because a nameserver can
    //     be asked for a TLSA and this branch cannot. Same rule, same reason.
    if (!server && synth && host === tld && !hasNs) {
      const pointer = onchainPointer(records)
      if (pointer) return pointer
      if (!isPublicAddress(synth.address)) {
        return { kind: 'blocked', address: synth.address }
      }
      // A SYNTH record has no zone server to ask for a TLSA, but the IP came
      // straight from the SPV-proven on-chain resource — consensus itself
      // attests it, which is a stronger source than an off-chain A record.
      // Allow plaintext to it rather than leaving the whole SYNTH name class
      // unreachable. SYNTH6 is the same statement about an IPv6 address.
      return { kind: 'site', address: synth.address, tlsa: [], allowInsecure: true }
    }

    // HIP-5 `_op` (docs/HIP5-OP.md): the TLD delegates to a registry contract
    // on Optimism. Tried BEFORE the nameservers because it is the
    // trust-minimised route — the chain itself names the contract, and no box
    // belonging to the TLD's owner gets to answer for a name it sold. Only
    // below the apex: the TLD's own records are the chain resource above.
    if (host !== tld) {
      const registry = opRegistryFor(records)
      if (registry) {
        const { resolution, reason } = await resolveOp(host, {
          registry,
          rpcUrls: this.opRpcUrls,
          fetchImpl: this.fetchImpl,
          timeout: this.opTimeout
        })
        if (resolution) return resolution
        this._logOpFallback(host, reason)
      }
    }

    const nsRecords = dnsNameservers(records)
    if (!server && !nsRecords.length) {
      // The chain resource is the TLD's. Handing it to a SUBDOMAIN would
      // serve the TLD's own site at every name under it — the same mistake
      // the SYNTH4 guard above exists to prevent. With no nameserver there
      // is nobody who can answer for a sub-name, and that is `unregistered`.
      const pointer = host === tld ? onchainPointer(records) : null
      if (pointer) return pointer
      return this._absent('unregistered')
    }

    // Everything below is the ZONE's answer, and a zone can hand the question
    // on: `pinner.hns` lives in a zone `hns` delegates to `ns1.lumeweb`, so
    // the work is a re-entrant step over a delegation chain, not a single hop.
    // Asked at each of the zone's nameservers in turn until one can be asked.
    const dsRecords = chainDs(records)
    return this._withFailover(tld, records, nsRecords, (server) =>
      this._fromZone(host, { zone: tld, server, dsRecords }, 0))
  }

  /**
   * Ask ONE zone about `host`, following a secure delegation if that zone
   * answers with a referral instead of records.
   *
   * `ctx` is the zone currently authoritative for the question: its apex
   * name, the server that answers for it, and the DS records that anchor its
   * keys — on-chain DS at the top, and at every level below, the DS its
   * parent published and this browser verified (`_descend`). `depth` bounds
   * the walk.
   *
   * @param {string} host
   * @param {{zone:string, server:{server:string,port:number}, dsRecords:Array}} ctx
   * @param {number} depth
   */
  /**
   * Validate the TXT RRset in `reply` at `owner` up to the zone's anchor,
   * with the §5.3.4 wildcard proof when the RRSIG says the answer was
   * synthesised. Returns null when it validates, else the failure result.
   * Used for the pointer at the name and for its `_dnslink` record, which
   * are held to the same standard.
   */
  async _validateTxtRRset (owner, reply, ctx, fetchDnskeys, missing) {
    const { dsRecords } = ctx
    const rrsig = reply.answers.find(
      (r) => r.type === TYPES.RRSIG && r.typeCovered === TYPES.TXT)
    const rdatas = reply.answers
      .filter((r) => r.type === TYPES.TXT && r.rdataRaw)
      .map((r) => r.rdataRaw)
    let result = null
    try {
      const { dnskeys, dnskeyRRSIG } = await fetchDnskeys()
      const denial = rrsig && await this._wildcardProof(
        rrsig, owner, reply.authority, ctx, { dsRecords, fetchDnskeys })
      result = rrsig && validateChain({
        dsRecords,
        dnskeys,
        dnskeyRRSIG,
        leafOwner: owner,
        leafType: TYPES.TXT,
        leafRdatas: rdatas,
        leafRRSIG: rrsig,
        denial
      })
    } catch {
      result = null
    }
    if (!result || !result.ok) return dnssecFailure(result, missing)
    return null
  }

  async _fromZone (host, ctx, depth) {
    const opts = { timeout: this.timeout, dial: this.dial }

    // If this zone has a DS anchor it is DNSSEC-signed and its answers MUST
    // validate up to it — the TLD's on-chain DS at the top, and below a
    // delegation the DS its parent published and `_descend` verified. Read
    // BEFORE the pointer query: the ipfs= TXT used to be fetched with DO=0
    // and trusted unvalidated — tenant names resolved here by accident of
    // that default while every honest validator got a signed NXDOMAIN
    // (OPEN-ISSUES 2026-08-24, the DO-bit entry).
    const { zone, server } = ctx
    const dsRecords = ctx.dsRecords
    // A zone can be signed with an algorithm this browser cannot verify. That
    // is not the same as a signature that does not check out, and it must not
    // be reported as one: dsRecords of every algorithm used to be carried
    // through as "this zone is signed", validation then found no usable DS,
    // and the user was told someone was "tampering with its DNS answers"
    // about a zone that had simply chosen RSASHA256. Fail closed either way —
    // we cannot verify it — but say the true thing.
    if (dsRecords.length && !dsRecords.some(isSupportedDs)) {
      return {
        kind: 'dnssec-unsupported',
        reason: `this zone is signed with algorithm ${dsRecords[0].algorithm}, ` +
          'which this browser cannot verify'
      }
    }
    const dnssecZone = dsRecords.length > 0

    // One DNSKEY fetch per resolution, shared by the pointer validation here
    // and the TLSA validation below.
    let dnskeySet = null
    const fetchDnskeys = async () => {
      if (!dnskeySet) {
        const dk = await query(server.server, server.port, zone, TYPES.DNSKEY,
          { ...opts, dnssec: true })
        dnskeySet = {
          dnskeys: dk.answers.filter((r) => r.type === TYPES.DNSKEY),
          dnskeyRRSIG: dk.answers.find(
            (r) => r.type === TYPES.RRSIG && r.typeCovered === TYPES.DNSKEY)
        }
      }
      return dnskeySet
    }

    const txt = await query(server.server, server.port, host, TYPES.TXT,
      { ...opts, dnssec: dnssecZone })

    // A REFERRAL, not an answer: this zone does not hold `host`, it delegates
    // a sub-zone that does. Detected from the TXT reply we already made rather
    // than a speculative NS query, so an ordinary name costs nothing extra.
    const referral = referralIn(txt, zone, host)
    if (referral) {
      if (depth >= MAX_DELEGATIONS) {
        return { kind: 'unreachable', reason: `delegation chain deeper than ${MAX_DELEGATIONS} for ${host}` }
      }
      const next = await this._descend(ctx, referral, txt, fetchDnskeys)
      if (next.fail) return next.fail
      return this._fromZone(host, next.ctx, depth + 1)
    }

    const strings = txtStringsFrom(answersAbout(txt.answers, host, TYPES.CNAME), TYPES.TXT)
    const direct = withOrigin(strings)
    if (direct && dnssecZone) {
      // The zone is signed, so the pointer must PROVE itself up to the
      // on-chain DS, exactly like a TLSA pin. A signed zone whose pointer
      // does not validate is an attack or a broken zone — fail closed
      // rather than render whatever an on-path answer named.
      const failure = await this._validateTxtRRset(host, txt, ctx, fetchDnskeys, 'pointer TXT RRSIG missing')
      if (failure) return failure
    }

    // THE SECOND POINTER SOURCE: DNSLink (dnslink.dev), `_dnslink.<host>`.
    // It is the record every other IPFS client reads — IPFS Companion, Brave,
    // kubo's `ipns://<domain>` — and the one Wildroot writes beside `ipfs=`
    // at publish, so a site published either way opens in both. It is held
    // to the SAME rules as the pointer at the name: on a signed zone the
    // RRset validates to the anchor, and its absence is proven (below)
    // before the resolution moves on to an address. The two sources are
    // merged by pointers.js mergePointers: agreement is normal, either alone
    // is fine, and a disagreement is surfaced as `pointer-conflict` rather
    // than settled by a precedence rule nobody published.
    const dnslinkOwner = `${DNSLINK_PREFIX}.${host}`
    const dl = await query(server.server, server.port, dnslinkOwner, TYPES.TXT,
      { ...opts, dnssec: dnssecZone })
    const dlStrings = referralIn(dl, zone, dnslinkOwner)
      ? [] // a delegation at the underscore label is not a DNSLink answer
      : txtStringsFrom(answersAbout(dl.answers, dnslinkOwner, TYPES.CNAME), TYPES.TXT)
    const viaDnslink = dnslinkPointerFrom(dlStrings)
    if (viaDnslink && dnssecZone) {
      const failure = await this._validateTxtRRset(dnslinkOwner, dl, ctx, fetchDnskeys, 'DNSLink TXT RRSIG missing')
      if (failure) return failure
    }

    const merged = mergePointers(direct, viaDnslink)
    if (merged.conflict) {
      const show = (p) => `${p.kind} ${p.cid || p.key || p.txid}`
      return {
        kind: 'pointer-conflict',
        reason: `${host} publishes two content pointers that disagree: ` +
          `${show(merged.conflict.direct)} at the name and ${show(merged.conflict.dnslink)} in its DNSLink record`,
        ...(dnssecZone ? { dnssecValidated: true, dnssecAnchored: true } : {})
      }
    }
    const pointer = merged.pointer
    if (pointer) {
      // The stated origin (`car=`) is a record at the NAME, whichever source
      // named the content: a DNSLink-only site with a `car=` beside it gets
      // its origin too, exactly as it does over DoH.
      if (pointer.kind === 'ipfs' && !pointer.origin) {
        const origin = originFrom(strings)
        if (origin) pointer.origin = origin
      }
      // Set only when true, like dnssecValidated: a pointer's shape is
      // compared field-by-field by its callers and its tests, and a
      // permanently-present `false` is noise in every unsigned zone.
      if (dnssecZone) {
        pointer.dnssecValidated = true
        pointer.dnssecAnchored = true
      }
      return pointer
    }

    // NO POINTER. On a signed zone that absence has to be PROVEN before the
    // question moves on to the A record, for the same reason the TLSA absence
    // below does: a content-addressed site is the most protected thing a zone
    // can publish, and an on-path answer that simply withholds its `ipfs=`
    // TXT — or its `_dnslink` TXT — must not be able to walk the browser down
    // to an address instead. Only an EMPTY answer needs the proof — a TXT
    // that exists and is not a pointer (SPF, a verification token) is an
    // ordinary non-answer.
    const txtAbout = answersAbout(txt.answers, host, TYPES.CNAME)
      .filter((r) => r.type === TYPES.TXT || r.type === TYPES.CNAME)
    if (dnssecZone && !txtAbout.length) {
      const nsecs = await this._validatedNsecs(txt.authority, { dsRecords, fetchDnskeys })
      if (!provesDenial(nsecs, host, TYPES.TXT, zone)) {
        return await this._anchorFailure(fetchDnskeys, dsRecords, zone,
          `the zone did not prove that ${host} has no content pointer (RFC 4035 §5.4)`)
      }
    }
    const dlAbout = answersAbout(dl.answers, dnslinkOwner, TYPES.CNAME)
      .filter((r) => r.type === TYPES.TXT || r.type === TYPES.CNAME)
    if (dnssecZone && !dlAbout.length) {
      const nsecs = await this._validatedNsecs(dl.authority, { dsRecords, fetchDnskeys })
      if (!provesDenial(nsecs, dnslinkOwner, TYPES.TXT, zone)) {
        return await this._anchorFailure(fetchDnskeys, dsRecords, zone,
          `the zone did not prove that ${host} has no DNSLink record (RFC 4035 §5.4)`)
      }
    }

    // A and AAAA, asked together (one round trip, the same as A alone was),
    // and the IPv4 is used when the name has one: it reaches the site from
    // every network, and IPv6 is the route for a name that has ONLY an
    // IPv6 (RFC 3596). Whichever RRset is used is validated below to the same
    // anchor by the same rule; the other is not consulted. On a signed zone
    // the fall-through from "no A" to the AAAA needs no denial proof: an
    // attacker who forges an empty A answer can only steer the browser to the
    // zone's OWN signed AAAA, and suppressing both is the denial of service
    // an on-path attacker always had.
    const askAddress = (type) => query(server.server, server.port, host, type,
      { ...opts, dnssec: dnssecZone })
    const [aSettled, aaaaSettled] = await Promise.allSettled([
      askAddress(TYPES.A), askAddress(TYPES.AAAA)])
    const a = aSettled.status === 'fulfilled' ? aSettled.value : null
    const aaaa = aaaaSettled.status === 'fulfilled' ? aaaaSettled.value : null
    if (!a && !aaaa) throw aSettled.reason
    const addressesIn = (reply, type) => reply
      ? answersAbout(reply.answers, host, TYPES.CNAME)
        .filter((r) => r.type === type && r.address && r.rdataRaw)
      : []
    let reply = a || aaaa
    let addressType = TYPES.A
    let addressRecords = addressesIn(a, TYPES.A)
    if (!addressRecords.length) {
      const six = addressesIn(aaaa, TYPES.AAAA)
      if (six.length) {
        reply = aaaa
        addressType = TYPES.AAAA
        addressRecords = six
      }
    }
    let address = (addressRecords[0] || {}).address
    let aValidated = false
    if (address && dnssecZone) {
      // THE ADDRESS IS A SIGNED RECORD TOO. Until 2026-09-05 only the TLSA and
      // the pointer were validated; the A RRset was read with DO=0 and taken
      // as served. With a proven "no TLSA" beside it that was a complete
      // downgrade: forge the A, let the zone's own honest NSEC prove there is
      // no pin, and the browser connects in the clear to the forged address
      // with the padlock reporting the zone as anchored.
      const rrsig = reply.answers.find(
        (r) => r.type === TYPES.RRSIG && r.typeCovered === addressType)
      let result = null
      try {
        const { dnskeys, dnskeyRRSIG } = await fetchDnskeys()
        const denial = rrsig && await this._wildcardProof(
          rrsig, host, reply.authority, ctx, { dsRecords, fetchDnskeys })
        result = rrsig && validateChain({
          dsRecords,
          dnskeys,
          dnskeyRRSIG,
          leafOwner: rrsig.name ? String(rrsig.name).toLowerCase().replace(/\.$/, '') : host,
          leafType: addressType,
          leafRdatas: addressRecords
            .filter((r) => norm(r.name) === norm(rrsig.name))
            .map((r) => r.rdataRaw),
          leafRRSIG: rrsig,
          denial
        })
      } catch {
        result = null
      }
      if (!result || !result.ok) {
        const label = addressType === TYPES.A ? 'A' : 'AAAA'
        return dnssecFailure(result, `${label} RRSIG could not be validated`, { address })
      }
      aValidated = true
    }
    if (!address) {
      // The zone may answer with a CNAME to an ICANN host instead of an A;
      // follow it through system DNS (a common "point my HNS name at my
      // existing website" setup). The target's address is ICANN's word, so
      // on a signed zone it counts as unvalidated and the answer says so.
      //
      // BUT THE CNAME ITSELF IS A SIGNED RECORD. Until 2026-09-06 it was
      // followed as served: strip the signed A, inject `CNAME attacker`, and
      // an anchored zone walked the browser to the attacker's address (the
      // lock stayed open, the page still loaded). On a signed zone the CNAME
      // RRset must validate, exactly as the A above — an unsigned or invalid
      // one fails closed. A validated CNAME also proves no A exists at the
      // name (RFC 1034 §3.6.2: a CNAME stands alone), so no separate denial
      // proof is needed.
      const cname = reply.answers.find((r) => r.type === TYPES.CNAME && r.target)
      if (cname) {
        if (dnssecZone) {
          const rrsig = reply.answers.find(
            (r) => r.type === TYPES.RRSIG && r.typeCovered === TYPES.CNAME)
          let result = null
          try {
            const { dnskeys, dnskeyRRSIG } = await fetchDnskeys()
            const denial = rrsig && await this._wildcardProof(
              rrsig, host, reply.authority, ctx, { dsRecords, fetchDnskeys })
            result = rrsig && validateChain({
              dsRecords,
              dnskeys,
              dnskeyRRSIG,
              leafOwner: rrsig.name ? String(rrsig.name).toLowerCase().replace(/\.$/, '') : host,
              leafType: TYPES.CNAME,
              // Canonical rdata (RFC 4034 §6.2): the target name, lowercased, in wire form.
              leafRdatas: [wireName(String(cname.target).toLowerCase())],
              leafRRSIG: rrsig,
              denial
            })
          } catch {
            result = null
          }
          if (!result || !result.ok) {
            return dnssecFailure(result, 'CNAME RRSIG could not be validated', { target: cname.target })
          }
        }
        try {
          address = await this.lookup(cname.target.replace(/\.$/, ''))
        } catch { /* fall through to unregistered */ }
      }
    }
    // One family answered empty and the other could not be ASKED: that is
    // not "no such name". Say what actually happened, as the caller does for
    // a zone that gave no answer at all.
    if (!address && (!a || !aaaa)) throw (aSettled.reason || aaaaSettled.reason)
    if (!address) return { kind: 'unregistered' }
    if (!isPublicAddress(address)) {
      return { kind: 'blocked', address }
    }

    // TLSA lookup distinguishes three cases, because "no answer" is
    // attacker-forgeable on the cleartext DNS hop and must not silently
    // downgrade to plaintext:
    //   - answers present        -> HTTPS, DANE-pinned (verified state)
    //   - authenticated NODATA    -> the zone declares no HTTPS pin (allowInsecure)
    //   - lookup error/timeout    -> unknown; refuse rather than downgrade
    const tlsaName = `_443._tcp.${host}`
    let tlsa = []
    let tlsaKnown = false
    let dnssecValidated = false
    let tlsaAnswers = []
    let tlsaAuthority = []
    try {
      const t = await query(server.server, server.port, tlsaName, TYPES.TLSA,
        { ...opts, dnssec: dnssecZone })
      tlsaAnswers = t.answers
      tlsaAuthority = t.authority || []
      // An authoritative answer about the pin is NOERROR (0, records or
      // NODATA) or NXDOMAIN (3, the _443._tcp node simply does not exist —
      // the normal "no TLSA published" reply). A *server error* — SERVFAIL
      // (2), NOTIMP (4), REFUSED (5) — is NOT an authoritative statement and
      // must not be read as consent to plaintext, since a minimal server or
      // an on-path attacker can produce it. Those fail closed.
      if (t.rcode === 0 || t.rcode === 3) {
        tlsa = t.answers.filter((r) => r.type === TYPES.TLSA)
        tlsaKnown = true
      }
      // Whether that empty answer may be BELIEVED is decided below: on an
      // unsigned zone it is the only signal there is; on a signed zone it has
      // to be proven by the zone's own NSEC/NSEC3 (src/hns/denial.js).
    } catch {
      tlsaKnown = false // could not determine — do not assume "no pin"
    }

    // VALIDATION LIVES OUTSIDE THAT CATCH, DELIBERATELY.
    //
    // It used to sit inside it, and the catch turned every throw into
    // `tlsaKnown = false` — which skipped the `dnssec-fail` return below and
    // fell through to a normal `site` carrying an UNVALIDATED pin. One dropped
    // DNSKEY query was the whole exploit: answer the A and TLSA lookups with
    // your own address and your own pin, reset the DNSKEY connection, and the
    // browser pins to your certificate while the padlock reports the zone as
    // merely unsigned. The on-chain DS — the one thing that would have caught
    // it — was never consulted. Demonstrated end to end 2026-09-04 against the
    // frozen signed fixture with a proxy that dropped only QTYPE 48.
    //
    // The rule this restores is the one dnssec-e2e.test.js already states: a
    // resolver that validates when it can and shrugs when it cannot is a
    // resolver an attacker simply makes unable to validate. So a failure to
    // FETCH the keys is a validation failure, exactly like a bad signature.
    // The pointer path (above) and txtRecords always got this right; this copy
    // had drifted.
    if (dnssecZone && tlsa.length) {
      let result = null
      try {
        const rrsig = tlsaAnswers.find(
          (r) => r.type === TYPES.RRSIG && r.typeCovered === TYPES.TLSA)
        const { dnskeys, dnskeyRRSIG } = await fetchDnskeys()
        const denial = rrsig && await this._wildcardProof(
          rrsig, tlsaName, tlsaAuthority, ctx, { dsRecords, fetchDnskeys })
        result = rrsig && validateChain({
          dsRecords,
          dnskeys,
          dnskeyRRSIG,
          leafOwner: tlsaName,
          leafType: TYPES.TLSA,
          leafRdatas: tlsa.map((r) => r.rdataRaw),
          leafRRSIG: rrsig,
          denial
        })
      } catch {
        result = null
      }
      if (!result || !result.ok) {
        // The chain says this zone is signed, but the pin did not validate.
        // That is an attack (or a broken zone) — fail closed, hard.
        return dnssecFailure(result, 'TLSA RRSIG could not be validated', { address })
      }
      dnssecValidated = true
    }

    // MAY THE "NO PIN HERE" BE BELIEVED?
    //
    // On an UNSIGNED zone this is as strong as it gets: nothing about the zone
    // is authenticated, so an authoritative empty answer is the only signal
    // there is, and there is no DANE guarantee to downgrade FROM.
    //
    // On a SIGNED zone it was a hole, and a documented one. An on-path
    // attacker forges an NXDOMAIN for `_443._tcp.<host>`, the real TLSA
    // disappears, and the connection falls to plaintext — the exact downgrade
    // DANE exists to prevent, accepted because the denial was trusted without
    // proof. RFC 4035 §5.4 says what to do instead, and src/hns/nsec.js now
    // does it: the zone's own NSEC records, their own signatures verified up
    // to the same anchor, must actually prove that nothing of this type lives
    // at this name.
    //
    // Unproven on a signed zone is NOT permission to downgrade. It leaves
    // allowInsecure false and the caller refuses, which is the whole point of
    // having asked.
    let allowInsecure = tlsaKnown && tlsa.length === 0
    if (allowInsecure && dnssecZone) {
      const nsecs = await this._validatedNsecs(tlsaAuthority, { dsRecords, fetchDnskeys })
      allowInsecure = provesDenial(nsecs, tlsaName, TYPES.TLSA, zone)
      if (!allowInsecure) this._logDenialGap(host, nsecs.length)
      // A PROVEN absence is a validated answer about the pin, as much as a
      // validated TLSA is: every record this resolution rests on — the
      // address, and the signed statement that there is nothing to pin to —
      // chained to the on-chain DS. The trust panel used to render this case
      // as "signatures NOT checked", which was false.
      if (allowInsecure && aValidated) dnssecValidated = true
    }
    // A pin that validated over an address that did not is still a validated
    // resolution — the handshake pins the bytes — but the address itself must
    // have come from the zone's signed A RRset for the whole answer to count.
    if (dnssecValidated && !aValidated) dnssecValidated = false

    return {
      kind: 'site',
      address,
      tlsa,
      dnssecValidated,
      // Whether the zone is ANCHORED at all — i.e. the chain carries a DS for
      // it — as opposed to whether we managed to validate against that anchor.
      // Without this the two are indistinguishable downstream, and the trust
      // panel picked the wrong one: a signed zone we failed to validate was
      // rendered "No DS record on chain for this zone / this zone is not
      // signed", which is false and understates the problem in exactly the
      // case that matters most (src/hns/trust-path.js).
      dnssecAnchored: dnssecZone,
      // Which nameserver actually answered, so the lock can name its source
      // rather than saying "DNS" and leaving the user to guess.
      ns: server && server.server,
      // Plaintext HTTP is only allowed when the zone said it has no TLSA — and
      // for a signed zone that denial is now PROVEN rather than believed (see
      // where allowInsecure is computed).
      allowInsecure
    }
  }

  /**
   * The `dnssec-fail` for a denial that could not be proven — naming the ROOT
   * cause when there is a deeper one. A missing proof usually means the zone's
   * keys did not anchor at all (a tampered DS, a dropped DNSKEY), and "the
   * zone did not prove X" would be true but unhelpful about that; the anchor
   * reason is what the person can act on.
   */
  async _anchorFailure (fetchDnskeys, dsRecords, zone, fallback) {
    let anchored = null
    try {
      const { dnskeys, dnskeyRRSIG } = await fetchDnskeys()
      anchored = anchorZoneKeys({ dsRecords, dnskeys, dnskeyRRSIG, zone })
    } catch (err) {
      return { kind: 'dnssec-fail', reason: `the zone's DNSKEY set could not be fetched (${err.message})` }
    }
    if (anchored && !anchored.ok) return { kind: 'dnssec-fail', reason: anchored.reason }
    return { kind: 'dnssec-fail', reason: fallback }
  }

  /**
   * Say once why a signed zone's "no pin" was not believed. Not an error page
   * — the caller refuses the connection and the trust panel explains — but a
   * silent refusal is how a zone with a broken denial chain stays broken.
   */
  _logDenialGap (host, nsecCount) {
    const key = `${host}|denial`
    if (this.opFallbacksLogged.has(key)) return
    if (this.opFallbacksLogged.size > 256) this.opFallbacksLogged.clear()
    this.opFallbacksLogged.add(key)
    console.log(`hns: ${host} — signed zone said "no TLSA" but proved nothing ` +
      `(${nsecCount} validated NSEC/NSEC3 records); refusing plaintext`)
  }

  /**
   * The §5.3.4 proof to hand validateChain, or null when none is needed.
   *
   * Only a WILDCARD-expanded answer requires one, and computing it costs a
   * DNSKEY fetch and a signature check per NSEC RRset — so it is not done for
   * the ordinary answers that are the overwhelming majority. When it IS
   * needed and cannot be built, validateChain refuses: an unproven wildcard is
   * an answer for a name the zone may never have meant to answer for.
   */
  async _wildcardProof (rrsig, owner, authority, ctx, deps) {
    if (!isWildcardExpanded(rrsig, owner)) return null
    const records = await this._validatedNsecs(authority, deps)
    return { records, zone: ctx.zone }
  }

  /**
   * The NSEC records in an AUTHORITY section whose own signatures validate up
   * to the anchor — the only ones a denial may be built from.
   *
   * An unverified NSEC is just an assertion by whoever answered, which is the
   * party a forged denial would be coming from. Grouped by owner because an
   * RRSIG covers an RRset, not a record.
   */
  async _validatedNsecs (authority, { dsRecords, fetchDnskeys }) {
    // Either scheme: NSEC names the next NAME, NSEC3 the next HASH. A zone
    // signs with one, and provesDenial refuses a mixed set rather than reading
    // it as either.
    const nsecs = (authority || []).filter(
      (r) => (r.type === TYPES.NSEC || r.type === TYPES.NSEC3) && r.rdataRaw)
    if (!nsecs.length) return []
    const sigs = (authority || []).filter(
      (r) => r.type === TYPES.RRSIG &&
        (r.typeCovered === TYPES.NSEC || r.typeCovered === TYPES.NSEC3))
    const byOwner = new Map()
    for (const n of nsecs) {
      const key = `${n.type}|${String(n.name).toLowerCase().replace(/\.$/, '')}`
      if (!byOwner.has(key)) byOwner.set(key, [])
      byOwner.get(key).push(n)
    }
    let keys = null
    try {
      keys = await fetchDnskeys()
    } catch {
      return []
    }
    const out = []
    for (const [owner, set] of byOwner) {
      const [ownerType, ownerName] = owner.split('|')
      const rrsig = sigs.find(
        (r) => r.typeCovered === Number(ownerType) &&
          String(r.name).toLowerCase().replace(/\.$/, '') === ownerName)
      if (!rrsig) continue
      let result = null
      try {
        result = validateChain({
          dsRecords,
          dnskeys: keys.dnskeys,
          dnskeyRRSIG: keys.dnskeyRRSIG,
          leafOwner: ownerName,
          leafType: set[0].type,
          leafRdatas: set.map((n) => n.rdataRaw),
          leafRRSIG: rrsig
        })
      } catch {
        result = null
      }
      if (result && result.ok) out.push(...set)
    }
    return out
  }

  /**
   * One step down a delegation: verify the child's DS under the parent's
   * anchored keys, find a server for the child zone, and hand back the
   * context to ask again.
   *
   * The DS link is the whole point. Following a referral WITHOUT it would
   * hand every name under a registry TLD to whichever box the referral names,
   * on nobody's authority — the exact failure `_op` exists to avoid one level
   * up. So: parent signed and a signed DS present -> the child is anchored to
   * it; parent signed and NO DS -> an insecure delegation, the child zone is
   * treated as unsigned (its TLSA pin still applies, its answers just are not
   * chain-anchored); parent signed and a DS that does not verify -> refuse.
   *
   * @param {object} ctx the PARENT context
   * @param {{child:string, targets:string[]}} referral
   * @param {object} response the reply the referral came in
   * @param {Function} fetchDnskeys the parent zone's DNSKEY set, fetched once
   * @returns {Promise<{ctx?:object, fail?:object}>}
   */
  async _descend (ctx, referral, response, fetchDnskeys) {
    const opts = { timeout: this.timeout, dial: this.dial }
    let childDs = []

    if (ctx.dsRecords.length) {
      let ds
      try {
        ds = await query(ctx.server.server, ctx.server.port, referral.child,
          TYPES.DS, { ...opts, dnssec: true })
      } catch (err) {
        return { fail: { kind: 'unreachable', reason: `DS lookup for ${referral.child} failed: ${err.message}` } }
      }
      const answers = ds.answers.filter((r) => r.type === TYPES.DS && r.rdataRaw)
      if (answers.length) {
        const rrsig = ds.answers.find(
          (r) => r.type === TYPES.RRSIG && r.typeCovered === TYPES.DS)
        let result = null
        try {
          const { dnskeys, dnskeyRRSIG } = await fetchDnskeys()
          result = validateDs({
            dsRecords: ctx.dsRecords,
            dnskeys,
            dnskeyRRSIG,
            parentZone: ctx.zone,
            childOwner: referral.child,
            childDs: answers,
            childDsRRSIG: rrsig
          })
        } catch {
          result = null
        }
        if (!result || !result.ok) {
          return {
            fail: {
              kind: 'dnssec-fail',
              reason: (result && result.reason) || `DS for ${referral.child} did not verify`
            }
          }
        }
        childDs = answers.map((r) => ({
          keyTag: r.keyTag,
          algorithm: r.algorithm,
          digestType: r.digestType,
          digest: r.digest
        }))
      }
      if (!answers.length) {
        // NO DS: an insecure delegation — IF THE PARENT PROVES IT. RFC 4035
        // §5.2: the validator "MUST have an authenticated denial" of the DS
        // before treating the child as unsigned. Without that, an on-path
        // answer deletes the DS from the referral and the whole child zone
        // — its pin, its pointer, its own denials — is never asked to prove
        // anything. The proof is the cut's own NSEC/NSEC3 lacking the DS bit,
        // or for NSEC3 an Opt-Out gap over the cut (RFC 5155 §8.9), which is
        // the one thing opt-out proves.
        const nsecs = await this._validatedNsecs(ds.authority, { dsRecords: ctx.dsRecords, fetchDnskeys })
        if (!provesInsecureDelegation(nsecs, referral.child, ctx.zone)) {
          return {
            fail: await this._anchorFailure(fetchDnskeys, ctx.dsRecords, ctx.zone,
              `${ctx.zone} did not prove that its delegation of ${referral.child} carries no DS (RFC 4035 §5.2)`)
          }
        }
        // Proven insecure: childDs stays empty and the child zone is read
        // unsigned — the same posture this file takes for a TLD with no
        // on-chain DS.
      }
    }

    if (this.serverFor) {
      const server = this.serverFor(referral.child, referral.targets)
      if (server) return { ctx: { zone: referral.child, server, dsRecords: childDs } }
    }

    // Glue first (it rode along with the referral), then the chain, then the
    // OS resolver — `_addressForNsHost`, so a nameserver that is itself a
    // Handshake name resolves at all.
    const glue = (response.additional || [])
      .filter((r) => (r.type === TYPES.A || r.type === TYPES.AAAA) && r.address)
      .map((r) => ({
        type: r.type === TYPES.A ? 'GLUE4' : 'GLUE6',
        ns: `${String(r.name).replace(/\.$/, '')}.`,
        address: r.address
      }))
    let lastErr = null
    for (const target of referral.targets) {
      let address = null
      try {
        address = await this._addressForNsHost(target, glue)
      } catch (err) {
        lastErr = err
        continue
      }
      if (!address) continue
      if (!isPublicAddress(address)) return { fail: { kind: 'blocked', address } }
      return {
        ctx: {
          zone: referral.child,
          server: { server: address, port: 53 },
          dsRecords: childDs
        }
      }
    }
    return {
      fail: {
        kind: 'unreachable',
        reason: `no reachable nameserver for ${referral.child}` +
          (lastErr ? `: ${lastErr.message}` : '')
      }
    }
  }
}

/**
 * The first IPv4 among `addresses`, else the first IPv6, else null. The one
 * rule for choosing between families, so a dual-stack host is reached the
 * same way from every path: IPv4 works from every network, and IPv6 is the
 * route for a host that has nothing else.
 * @param {string[]} addresses
 * @returns {string|null}
 */
export function preferV4 (addresses) {
  const list = (addresses || []).filter((x) => typeof x === 'string' && x)
  return list.find((x) => !x.includes(':')) || list.find((x) => x.includes(':')) || null
}

/**
 * The address a chain resource's glue gives for `nsHost`: its GLUE4, else its
 * GLUE6 (`preferV4`). hsd writes the nameserver name with a trailing dot.
 * @param {Array} records
 * @param {string} nsHost
 * @returns {string|null}
 */
function glueAddress (records, nsHost) {
  return glueAddresses(records, nsHost)[0] || null
}

/**
 * Every glue address a chain resource gives for `nsHost`, IPv4 first, then
 * IPv6 — the order the failover loop asks them in.
 * @param {Array} records
 * @param {string} nsHost
 * @returns {string[]}
 */
function glueAddresses (records, nsHost) {
  const of = (type) => (records || [])
    .filter((r) => r.type === type && r.ns && r.address &&
      String(r.ns).replace(/\.$/, '') === nsHost)
    .map((r) => r.address)
  return [...of('GLUE4'), ...of('GLUE6')]
}

/**
 * The apex address record of a chain resource: SYNTH4 when there is one,
 * else SYNTH6 — the chain-attested address of the top-level name itself.
 * @param {Array} records
 * @returns {{type: string, address: string}|null}
 */
function synthRecord (records) {
  return (records || []).find((r) => r.type === 'SYNTH4' && r.address) ||
    (records || []).find((r) => r.type === 'SYNTH6' && r.address) || null
}

/**
 * The content pointer among a chain resource's TXT records. hsd's `txt` array
 * is the character-strings of ONE record (each ≤ 255 bytes), so — like the
 * DNS paths, through the same assembler — they are joined, not spread.
 */
function onchainPointer (records) {
  return withOrigin(txtStringsFrom(
    (records || []).filter((r) => r.type === 'TXT').map((r) => ({ txt: r.txt || [] }))))
}

/**
 * The pointer among a name's TXT strings — and, for an IPFS pointer, the
 * archive's STATED ORIGIN beside it (`car=`, src/publish/pointers.js): where
 * the exact bytes can be fetched from the publisher's own storage provider
 * and verified against the CID. Carried on the resolution, never resolved to.
 */
function withOrigin (strings) {
  const pointer = pointerFrom(strings)
  if (!pointer || pointer.kind !== 'ipfs') return pointer
  const origin = originFrom(strings)
  return origin ? { ...pointer, origin } : pointer
}
