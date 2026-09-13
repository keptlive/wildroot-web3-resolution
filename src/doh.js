/*
 * DNS-over-HTTPS fallback resolver for Handshake names.
 *
 * The SPV node is the trust root: it resolves names with an Urkel proof the
 * browser verifies itself. But hsd has native dependencies and a sync cost,
 * and on some machines (a fresh Windows box without a build toolchain, or
 * before the node has synced) it will not be available. Rather than leave
 * hns:// dead, we fall back to a DoH resolver that performs the Handshake
 * resolution server-side and returns the final records.
 *
 * THE TRADE, STATED PLAINLY: this path trusts the DoH resolver's word for a
 * name's records — there is no chain proof and no DNSSEC/DANE validation of
 * the answer. It is strictly weaker than the SPV path and is marked as such
 * (`trust: 'doh'`) so the UI can show it. It exists so the browser degrades to
 * "works, less verified" instead of "broken" — never as the default when the
 * SPV node is available. A TLSA the resolver returns IS still used to pin the
 * TLS handshake (as the resolver's word, not as proof) — see _resolveTimed.
 *
 * Wire format: RFC 8484 (GET ?dns=<base64url>, application/dns-message),
 * encoded/decoded with our own DNS codec. The JSON DoH API is NOT used —
 * Handshake DoH servers (hnsdoh.com included) reject it.
 */

import { isIP } from 'node:net'
import { timers } from './resolution-timing.js'
import { buildQuery, parseAnswers, assertAnswersTo, TYPES } from './dns-query.js'
import { originFrom, pointerFrom, txtStringsFrom, dnslinkPointerFrom, mergePointers, DNSLINK_PREFIX } from './pointers.js'

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/

// Handshake-aware DoH endpoints: ours first, community resolver as fallback.
export const DEFAULT_DOH = [
  'https://query.hns.one/dns-query',
  'https://hnsdoh.com/dns-query',
  'https://dns.easyhns.com/dns-query'
]

function b64url (buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * The error a strict (Private mode) lookup ends in. `private` marks it so the
 * page that shows it can say which promise was kept.
 * @param {string} why
 */
function privateLookupFailure (why) {
  const err = new Error(`the private lookup failed (${why}) and no unprotected lookup was made`)
  err.private = true
  return err
}

export class DoHResolver {
  constructor ({ endpoints = DEFAULT_DOH, timeout = 6000, fetchImpl, odoh = null, strictOblivious = false } = {}) {
    this.endpoints = endpoints
    this.timeout = timeout
    this.fetchImpl = fetchImpl || ((...a) => globalThis.fetch(...a))
    /** Oblivious transport (src/hns/odoh.js), tried before plain DoH. */
    this.odoh = odoh
    /**
     * Private mode (src/hns/delivery-mode.js, row 3 of the divergence
     * inventory): a boolean or a live predicate. While true, a name is looked
     * up obliviously or not at all — the plain-DoH fallback below is never
     * taken, and the failure says so in words rather than resolving in the
     * clear. Read per query, so a mode switch applies to the next lookup.
     */
    this.strictOblivious = strictOblivious
    this.freshNames = new Map()
    this.freshAllUntil = 0
    this.cacheEpoch = 0
  }

  forget (host) {
    const name = String(host || '').toLowerCase().replace(/\.$/, '')
    if (!name) return 0
    this.cacheEpoch++
    for (const [key, until] of this.freshNames) if (until <= Date.now()) this.freshNames.delete(key)
    this.freshNames.delete(name)
    this.freshNames.set(name, Date.now() + 300000)
    if (this.freshNames.size > 512) this.freshNames.delete(this.freshNames.keys().next().value)
    return 1
  }

  clearCache () {
    this.cacheEpoch++
    this.freshAllUntil = Date.now() + 300000
    this.freshNames.clear()
  }

  _fresh (host) {
    const now = Date.now()
    if (now < this.freshAllUntil) return true
    const name = String(host || '').toLowerCase().replace(/\.$/, '')
    for (const [key, until] of this.freshNames) {
      if (until <= now) this.freshNames.delete(key)
      else if (name === key || name.endsWith(`.${key}`)) return true
    }
    return false
  }

  /** Is the plain-DoH fallback refused right now? */
  _strict () {
    return typeof this.strictOblivious === 'function' ? !!this.strictOblivious() : !!this.strictOblivious
  }

  /**
   * A short name for whoever answered, for the security panel's "source"
   * line. The host only — a full DoH URL in the UI is noise, and the query
   * string of a resolved name has no business being displayed back.
   */
  get endpointLabel () {
    const first = this.endpoints && this.endpoints[0]
    try {
      return new URL(first).host
    } catch {
      return String(first || 'DoH resolver')
    }
  }

  /** One wire-format query; returns { rcode, answers } or throws. */
  async _query (name, typeName) {
    const wire = buildQuery(name, TYPES[typeName], 0)
    const param = b64url(wire)
    // The id is fixed at zero over DoH (RFC 8484 §4.1), so the question
    // section is the only thing that binds a reply to this query.
    const parse = (buf) => assertAnswersTo(parseAnswers(buf), name, TYPES[typeName])
    let lastErr = null
    let emptyNoerror = null
    const strict = this._strict()
    if (strict && !this.odoh) {
      throw privateLookupFailure('no oblivious resolver is configured')
    }

    // Oblivious first: same answer semantics as a plain endpoint (weak
    // empty-NOERROR is remembered but double-checked downstream, SERVFAIL
    // falls through), and any transport failure falls back to plain DoH so
    // a relay outage can never break resolution — it only costs privacy,
    // and the log says exactly that.
    if (this.odoh) {
      const label = this.odoh.label
      try {
        const { answer, via } = await this.odoh.query(wire)
        const parsed = parse(Buffer.from(answer))
        const outcome = `rcode ${parsed.rcode}, ${parsed.answers.length} answers (via relay ${via})`
        if (parsed.rcode === 0 && parsed.answers.length === 0) {
          // Weak empty-NOERROR needs confirmation — but confirming via PLAIN
          // DoH would leak the name for every A-record site (their TXT query
          // is always empty), quietly defeating ODoH in the common case.
          // Confirm obliviously instead: a second independent ODoH answer
          // agreeing on empty stands, mirroring the all-endpoints-agree rule
          // of the plain path. Only if the confirmation TRANSPORT fails does
          // plain DoH get involved.
          try {
            const second = parse(Buffer.from((await this.odoh.query(wire)).answer))
            if (second.rcode === 0 && second.answers.length === 0) {
              this._log(name, typeName, label, `${outcome} — empty confirmed obliviously`)
              second.oblivious = true
              second.via = via
              return second
            }
            if (second.rcode === 0 || second.rcode === 3) {
              this._log(name, typeName, label,
                `${outcome} — reconfirmed with rcode ${second.rcode}, ${second.answers.length} answers`)
              second.oblivious = true
              second.via = via
              return second
            }
          } catch {}
          emptyNoerror = parsed
          this._log(name, typeName, label, `${outcome} — weak, ${strict ? 'not confirmed (Private mode: no plain lookup)' : 'checking plain DoH'}`)
        } else if (parsed.rcode !== 0 && parsed.rcode !== 3) {
          lastErr = new Error(`ODoH rcode ${parsed.rcode}`)
          this._log(name, typeName, label, outcome)
        } else {
          this._log(name, typeName, label, outcome)
          parsed.oblivious = true
          parsed.via = via // the relay that carried it, for the lock
          return parsed
        }
      } catch (err) {
        lastErr = err
        this._log(name, typeName, label,
          `FAILED (${err.message || err}) — ${strict ? 'no fallback (Private mode)' : 'falling back to plain DoH'}`)
      }
    }
    if (strict) {
      // Row 3: the fallback exists because the relays are few and can all
      // fail; in Private mode that outage costs availability, never privacy.
      // Whatever the oblivious path could not settle is reported as a
      // private-lookup failure, and no plain query leaves this machine.
      throw privateLookupFailure(lastErr
        ? (lastErr.message || String(lastErr))
        : 'the oblivious answer could not be confirmed')
    }
    for (const base of this.endpoints) {
      let outcome
      try {
        const res = await this.fetchImpl(`${base}?dns=${param}`, {
          // There is no JS answer cache here, but Electron's net.fetch has
          // an HTTP cache. Revalidate recently published names and DNSLink
          // descendants without changing the transport or accepting a hint
          // as a DNS answer. An upstream recursive cache still owns its TTL.
          ...(this._fresh(name) ? { cache: 'reload' } : {}),
          headers: { accept: 'application/dns-message', ...(this._fresh(name) ? { 'cache-control': 'no-cache' } : {}) },
          signal: AbortSignal.timeout(this.timeout)
        })
        if (!res.ok) {
          lastErr = new Error(`DoH ${res.status} from ${base}`)
          outcome = `http ${res.status}`
        } else {
          const body = Buffer.from(await res.arrayBuffer())
          const parsed = parse(body)
          outcome = `rcode ${parsed.rcode}, ${parsed.answers.length} answers`
          if (parsed.rcode === 0 && parsed.answers.length === 0) {
            // NOERROR with nothing in it is a weak answer: a cold or
            // misbehaving resolver transiently returns exactly this for
            // names that DO exist, and accepting the first one 404s a live
            // site (seen in the field with our own endpoint). Remember it,
            // but ask the remaining endpoints; only if nobody has records
            // does empty stand.
            if (!emptyNoerror) emptyNoerror = parsed
          } else if (parsed.rcode !== 0 && parsed.rcode !== 3) {
            // SERVFAIL and friends: retry elsewhere.
            lastErr = new Error(`DoH rcode ${parsed.rcode} from ${base}`)
          } else {
            // Records, or a definitive NXDOMAIN — authoritative enough.
            this._log(name, typeName, base, outcome)
            return parsed
          }
        }
      } catch (err) {
        lastErr = err
        outcome = String(err.message || err)
      }
      this._log(name, typeName, base, outcome)
    }
    if (emptyNoerror) return emptyNoerror
    throw lastErr || new Error('no DoH endpoint answered')
  }

  // Per-endpoint outcomes were previously invisible, which made field
  // failures (one flaky resolver 404ing a live name) undiagnosable.
  _log (name, typeName, base, outcome) {
    try {
      let label = base
      try { label = new URL(base).host } catch {}
      console.log(`DoH ${name} ${typeName} @ ${label}: ${outcome}`)
    } catch {}
  }

  /**
   * The TXT strings at an arbitrary owner name — `_hns.alice.w3` — the same
   * shape HNSResolver.txtRecords returns, but WITHOUT a chain proof and
   * without DNSSEC validation. `dnssecValidated` is therefore false, always,
   * and `trust` says who was believed.
   *
   * WHY THIS EXISTS AND WHAT IT IS FOR. The chain-anchored path cannot answer
   * at all until the SPV node reaches the tip — the first sync, once per
   * install, and a user should not be locked out of their own product while
   * it runs (Matt, 2026-09-01). The trade is the one this file's header
   * already states for browsing, now available to the sharing gate: we are
   * trusting the resolver's word for which key controls a name, instead of
   * the chain's. That is a REAL downgrade — a resolver that lies substitutes
   * the recipient — so the only correct use of this is one the person is told
   * about before they act on it. src/folders/index.js resolveRecipient marks
   * it, membership.js says it in words, and nothing here decides on its own.
   *
   * @param {string} host
   * @returns {Promise<{ kind: 'txt', strings: string[], dnssecValidated: false, trust: 'doh' }
   *   | { kind: 'unregistered' } | { kind: 'unreachable', reason: string }>}
   */
  async txtRecords (host) {
    host = String(host || '').toLowerCase().replace(/\.$/, '')
    let txt
    try {
      txt = await this._query(host, 'TXT')
    } catch (err) {
      return { kind: 'unreachable', reason: (err && err.message) || 'the lookup failed' }
    }
    const strings = []
    for (const ans of (txt && txt.answers) || []) {
      if (ans.type === TYPES.TXT && ans.txt) strings.push(...txtStringsFrom([ans], TYPES.TXT))
    }
    if (!strings.length) return { kind: 'unregistered' }
    return { kind: 'txt', strings, dnssecValidated: false, trust: 'doh' }
  }

  /**
   * The address of an ICANN host, over this resolver's DoH/ODoH transport:
   * its A, else its AAAA (asked only when there is no A — the common case
   * costs one lookup). The chain resolver uses it for the nameserver names
   * and CNAME targets that are ICANN hosts, so that hop never goes out in
   * the clear.
   * @param {string} host
   * @returns {Promise<string>} throws when there is no address
   */
  async addressOf (host) {
    const name = String(host || '').toLowerCase().replace(/\.$/, '')
    const a = await this._query(name, 'A')
    const rec = (a.answers || []).find((r) => r.type === TYPES.A && r.address)
    if (rec) return rec.address
    const aaaa = await this._query(name, 'AAAA')
    const six = (aaaa.answers || []).find((r) => r.type === TYPES.AAAA && r.address)
    if (!six) throw new Error(`no address for ${host}`)
    return six.address
  }

  /** Same shape as HNSResolver.resolve, but via DoH (no proof). */
  async resolve (host) {
    // The method is decided by the ANSWER, not the resolver: obliviousness is
    // per-lookup (`parsed.oblivious`), because a query can fall back from ODoH
    // to plain DoH mid-flight. Keying off the resolver would have filed every
    // oblivious lookup as plain DoH and quietly misreported the one number
    // that distinguishes the two paths.
    const start = Date.now()
    try {
      let out
      for (let attempt = 0; attempt < 3; attempt++) {
        const epoch = this.cacheEpoch
        out = await this._resolveTimed(host)
        if (epoch === this.cacheEpoch) break
        if (attempt === 2) throw new Error('The name changed during resolution; retry the lookup.')
      }
      timers.record(out && out.oblivious ? 'odoh' : 'doh', Date.now() - start, true)
      return out
    } catch (err) {
      timers.record('doh', Date.now() - start, false)
      throw err
    }
  }

  async _resolveTimed (host) {
    host = String(host || '').toLowerCase().replace(/\.$/, '')
    if (!host || isIP(host)) throw new Error(`not a name: ${host}`)

    // TXT first: a content pointer wins. The convention, the address shapes
    // and the precedence between kinds are shared with the SPV path
    // (src/publish/pointers.js) — this used to be a second, subtly different
    // parser that returned on the first matching ANSWER, so a name carrying
    // `ar=` before `ipfs=` resolved differently here than it did there.
    // Both pointer sources, as on the chain path (src/hns/resolver.js): the
    // `ipfs=` family at the name and DNSLink at `_dnslink.<name>`, merged by
    // the one rule in pointers.js. Asked together — one round trip.
    const [txt, dl] = await Promise.all([
      this._query(host, 'TXT').catch(() => null),
      this._query(`${DNSLINK_PREFIX}.${host}`, 'TXT').catch(() => null)
    ])
    const stringsOf = (reply) => {
      const out = []
      for (const ans of (reply && reply.answers) || []) {
        if (ans.type !== TYPES.TXT || !ans.txt) continue
        out.push(...txtStringsFrom([ans], TYPES.TXT))
      }
      return out
    }
    const strings = stringsOf(txt)
    const merged = mergePointers(pointerFrom(strings), dnslinkPointerFrom(stringsOf(dl)))
    if (merged.conflict) {
      const show = (p) => `${p.kind} ${p.cid || p.key || p.txid}${p.path || '/'}`
      return {
        kind: 'pointer-conflict',
        reason: `${host} publishes two content pointers that disagree: ` +
          `${show(merged.conflict.direct)} at the name and ${show(merged.conflict.dnslink)} in its DNSLink record`,
        trust: 'doh',
        oblivious: !!(txt && txt.oblivious),
        via: (txt && txt.via) || null,
        endpoint: this.endpointLabel
      }
    }
    const pointer = merged.pointer
    if (pointer) {
      const origin = pointer.kind === 'ipfs' ? originFrom(strings) : null
      return {
        ...pointer,
        ...(origin ? { origin } : {}),
        trust: 'doh',
        oblivious: !!(txt && txt.oblivious),
        via: (txt && txt.via) || null,
        endpoint: this.endpointLabel
      }
    }

    let a = null
    let aErr = null
    try {
      a = await this._query(host, 'A')
    } catch (err) {
      aErr = err
    }
    if (!a) {
      // The A lookup could not be ASKED. That is not "no such name" — a DoH
      // outage (or a captive network) used to tell people their friend's site
      // did not exist — and it is not one whether or not the TXT lookup a
      // moment earlier got through: an answer that could not be had is
      // `unreachable`, never `unregistered`. In Private mode, where a single
      // oblivious transport is the only one, this is the common failure.
      return { kind: 'unreachable', reason: (aErr && aErr.message) || 'no DoH endpoint answered' }
    }
    let addr = ((a && a.answers) || []).find(
      (r) => r.type === TYPES.A && IPV4_RE.test(String(r.address)))
    if (!addr) {
      // No A: the name may be IPv6-only (RFC 3596). Asked only now, so a
      // dual-stack name costs one lookup, as the chain path prefers IPv4.
      let aaaa = null
      try {
        aaaa = await this._query(host, 'AAAA')
      } catch (err) {
        return { kind: 'unreachable', reason: (err && err.message) || 'no DoH endpoint answered' }
      }
      addr = ((aaaa && aaaa.answers) || []).find((r) => r.type === TYPES.AAAA && r.address)
      if (!addr) return { kind: 'unregistered' }
      a = aaaa
    }

    // THE PIN, ON THE RESOLVER'S WORD. This path cannot PROVE a TLSA — there
    // is no chain anchor and no DNSSEC validation here — but it can still
    // READ one and pin the handshake to it, which is strictly better than
    // the plaintext it used to hand every A-record site: until 2026-09-05 a
    // DoH-resolved site was always `tlsa: []`, so an attacker who merely made
    // the chain path fail (drop our TCP to the authoritative server) got
    // every DANE-pinned site downgraded to HTTP. Now the downgrade needs the
    // resolver's answer too, which rides HTTPS to a server we run.
    //
    // The trust is unchanged and stated: `trust: 'doh'` on the whole answer,
    // so the lock stays TRUSTED (never trustless) whether or not a pin was
    // used. The pin lookup FAILING (as opposed to answering empty) leaves
    // `allowInsecure` false: unknown is not permission, on this path as on
    // the chain one.
    let tlsa = []
    let tlsaKnown = false
    try {
      const t = await this._query(`_443._tcp.${host}`, 'TLSA')
      if (t && (t.rcode === 0 || t.rcode === 3)) {
        tlsa = (t.answers || []).filter((r) => r.type === TYPES.TLSA && r.certificate)
        tlsaKnown = true
      }
    } catch { /* unknown: refuse to downgrade */ }
    return {
      kind: 'site',
      address: addr.address,
      tlsa,
      allowInsecure: tlsaKnown && tlsa.length === 0,
      tlsaKnown,
      trust: 'doh',
      oblivious: !!(a && a.oblivious),
      via: (a && a.via) || null,
      endpoint: this.endpointLabel
    }
  }
}
