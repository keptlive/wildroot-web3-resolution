/*
 * Hashed authenticated denial of existence (NSEC3, RFC 5155).
 *
 * WHY, given nsec.js already exists. Since a signed zone's denial must be
 * PROVEN before this browser will downgrade to plaintext, a zone whose denials
 * it cannot read is a zone it must refuse. NSEC3 is not exotic — Namebase's
 * `hns`, the registry TLD every `pinner.hns`-shaped name hangs off, signs with
 * it — so "we only read NSEC" meant refusing a whole branch of the namespace
 * to protect it. This closes that.
 *
 * WHAT NSEC3 CHANGES. The zone publishes the same gaps, but over the HASHES of
 * names rather than the names: an NSEC3 record is owned by
 * `base32hex(H(name)).<zone>` and points at the next hash in order. So every
 * predicate here is nsec.js's, moved into hashed space — with one genuinely
 * new idea, the CLOSEST ENCLOSER PROOF (§8.3), because a validator can no
 * longer read ancestry off the names and has to establish it hash by hash.
 *
 * THE OPT-OUT TRAP. A covering NSEC3 with the Opt-Out flag set proves only
 * that no *signed delegation* exists in that gap — RFC 5155 §6 is explicit
 * that unsigned delegations may be present and unproven. Treating it as a
 * denial of existence is the classic NSEC3 mistake, and it is exactly the
 * hole an attacker wants when the thing being denied is a TLSA record. Every
 * proof below refuses when the gap it depends on is opt-out.
 *
 * ITERATIONS ARE CAPPED. RFC 9276 §3.1 says zones SHOULD use 0 and validators
 * MAY treat high counts as insecure; the cost is paid by the validator, so an
 * uncapped count is a denial-of-service the zone chooses for us. Zones seen in
 * the wild here use 0.
 */

import { createHash } from 'node:crypto'

import { isUnder, parentOf } from './nsec.js'

/** RFC 4648 §7 base32hex, uppercase and unpadded — the NSEC3 owner encoding. */
const B32HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV'

/** SHA-1 is the only NSEC3 hash algorithm ever assigned (RFC 5155 §11). */
const NSEC3_SHA1 = 1

/**
 * The most hash iterations we will compute. RFC 9276 §3.1: zones SHOULD use
 * zero, and a validator MAY refuse a higher count. The work is ours to do, so
 * an unbounded count would be a cost a hostile zone gets to impose on us.
 */
export const MAX_ITERATIONS = 100

const TYPE_CNAME = 5
const TYPE_NS = 2
const TYPE_SOA = 6
const TYPE_DS = 43

export function base32hexEncode (buf) {
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of buf) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += B32HEX[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += B32HEX[(value << (5 - bits)) & 31]
  return out
}

/** The RFC 1035 wire form of a name, lowercased — what gets hashed. */
export function wireNameLower (name) {
  const parts = []
  for (const label of String(name || '').toLowerCase().replace(/\.$/, '').split('.')) {
    if (!label) continue
    const b = Buffer.from(label, 'utf8')
    parts.push(Buffer.from([b.length]), b)
  }
  parts.push(Buffer.from([0]))
  return Buffer.concat(parts)
}

/**
 * RFC 5155 §5: IH(salt, x, 0) = H(x | salt), IH(salt, x, k) = H(IH(…k-1) | salt).
 * Returns null for an algorithm we do not implement or a count we refuse.
 */
export function nsec3Hash (name, { hashAlgorithm = NSEC3_SHA1, salt = Buffer.alloc(0), iterations = 0 } = {}) {
  if (hashAlgorithm !== NSEC3_SHA1) return null
  if (!Number.isInteger(iterations) || iterations < 0 || iterations > MAX_ITERATIONS) return null
  let hash = createHash('sha1').update(Buffer.concat([wireNameLower(name), salt])).digest()
  for (let i = 0; i < iterations; i++) {
    hash = createHash('sha1').update(Buffer.concat([hash, salt])).digest()
  }
  return hash
}

/** The hashed label of an NSEC3 record's owner, as raw bytes, or null. */
export function ownerHashOf (rr) {
  const label = String(rr && rr.name ? rr.name : '').split('.')[0].toUpperCase()
  if (!label) return null
  let bits = 0
  let value = 0
  const out = []
  for (const ch of label) {
    const idx = B32HEX.indexOf(ch)
    if (idx < 0) return null
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(out)
}

/** All NSEC3 records agree on parameters, or the set is not usable. */
function paramsOf (rrs) {
  const first = rrs[0]
  const params = {
    hashAlgorithm: first.hashAlgorithm,
    salt: first.salt || Buffer.alloc(0),
    iterations: first.iterations
  }
  for (const rr of rrs) {
    if (rr.hashAlgorithm !== params.hashAlgorithm) return null
    if (rr.iterations !== params.iterations) return null
    if (Buffer.compare(rr.salt || Buffer.alloc(0), params.salt) !== 0) return null
  }
  return params
}

/** An NSEC3 whose owner hash IS the hash of this name. */
export function nsec3Matches (rr, name, params) {
  const h = nsec3Hash(name, params)
  const owner = ownerHashOf(rr)
  return !!(h && owner && Buffer.compare(h, owner) === 0)
}

/**
 * Does this NSEC3's gap strictly contain the hash of `name`?
 *
 * Hashes are compared as raw byte strings, and the last NSEC3 of a zone wraps
 * (its next-hash sorts at or below its own owner), exactly as NSEC does.
 */
export function nsec3Covers (rr, name, params) {
  const h = nsec3Hash(name, params)
  const owner = ownerHashOf(rr)
  const next = rr && rr.nextHashed
  if (!h || !owner || !next || !next.length) return false
  const fromOwner = Buffer.compare(owner, h)
  const toNext = Buffer.compare(h, next)
  if (fromOwner === 0) return false // it NAMES this hash: it exists
  const wraps = Buffer.compare(owner, next) >= 0
  return wraps ? (fromOwner < 0 || toNext < 0) : (fromOwner < 0 && toNext < 0)
}

/**
 * The closest encloser proof, RFC 5155 §8.3.
 *
 * Walk up from the queried name until an NSEC3 MATCHES an ancestor — that is
 * the closest encloser, the deepest name the zone admits exists. The child of
 * it on the way back down is the "next closer" name, and an NSEC3 must COVER
 * that for the queried name to be absent.
 *
 * `allowOptOut` is for ONE caller: the DS lookup at a delegation. RFC 5155
 * §8.9 says a next-closer name covered by an Opt-Out NSEC3 makes the
 * referral INSECURE — that is what opt-out is for, and the only thing it
 * proves. Everywhere else an opt-out gap is refused, because "no signed
 * delegation here" is not "no TLSA here".
 *
 * @returns {{encloser: string, nextCloser: string, cover: object, optOut: boolean}|null}
 */
export function closestEncloserProof (rrs, qname, zone, params, { allowOptOut = false } = {}) {
  let name = String(qname || '').toLowerCase().replace(/\.$/, '')
  let child = null
  // Bounded by the label count; a name cannot have more ancestors than labels.
  for (let i = 0; i <= 128 && name && isUnder(name, zone); i++) {
    const match = rrs.find((rr) => nsec3Matches(rr, name, params))
    if (match) {
      if (!child) return null // the NAME itself exists; nothing is being denied
      // A matching NSEC3 at a delegation says nothing about names below the
      // cut — that is the parent zone's boundary, not an assertion of absence.
      if (match.types && match.types.has(TYPE_NS) && !match.types.has(TYPE_SOA)) return null
      const cover = rrs.find((rr) => nsec3Covers(rr, child, params))
      if (!cover) return null
      // OPT-OUT: this gap only ever proved "no signed delegation here".
      if (cover.optOut && !allowOptOut) return null
      return { encloser: name, nextCloser: child, cover, optOut: !!cover.optOut }
    }
    child = name
    name = parentOf(name)
  }
  return null
}

/** Does this bitmap deny `type`? Same rules as nsec.js, DS-at-a-cut included. */
function bitmapDenies (types, type) {
  if (!types || typeof types.has !== 'function') return false
  if (types.has(type) || types.has(TYPE_CNAME)) return false
  if (types.has(TYPE_NS) && !types.has(TYPE_SOA) && type !== TYPE_DS) return false
  return true
}

/**
 * NODATA, RFC 5155 §8.5 and §8.7: the name exists and its bitmap lacks the
 * type — or (the wildcard form) a closest encloser proof shows the name has
 * no records of its own and the NSEC3 matching `*.<encloser>` lacks the type.
 */
export function nsec3ProvesNoData (rrs, name, type, params, zone = null) {
  for (const rr of rrs) {
    if (!nsec3Matches(rr, name, params)) continue
    return bitmapDenies(rr.types, type)
  }
  if (!zone) return false
  const proof = closestEncloserProof(rrs, name, zone, params)
  if (!proof) return false
  const star = rrs.find((rr) => nsec3Matches(rr, `*.${proof.encloser}`, params))
  return !!star && bitmapDenies(star.types, type)
}

/**
 * NXDOMAIN, RFC 5155 §8.4: a closest encloser proof, plus an NSEC3 covering
 * the wildcard at that encloser — because a `*.<encloser>` could otherwise
 * have been expanded to answer, and its absence has to be proven too.
 */
export function nsec3ProvesNxdomain (rrs, qname, zone, params) {
  const proof = closestEncloserProof(rrs, qname, zone, params)
  if (!proof) return false
  const wildcard = `*.${proof.encloser}`
  for (const rr of rrs) {
    if (nsec3Matches(rr, wildcard, params)) return false // it EXISTS
    if (nsec3Covers(rr, wildcard, params)) return !rr.optOut
  }
  return false
}

/**
 * Is there NO exact match for `qname`? The hashed half of RFC 4035 §5.3.4's
 * requirement beside a wildcard-expanded answer.
 *
 * A closest encloser proof establishes exactly this: it finds the deepest
 * ancestor the zone admits exists and shows the next name down to be COVERED,
 * i.e. absent. Opt-out is refused inside that proof, as everywhere else.
 */
/**
 * RFC 5155 §8.2: an NSEC3 RR with any Flags bit set other than Opt-Out
 * (bit 0) MUST be ignored — a future flag we do not understand could change
 * what the record means. A record with no flags field (a test double) is
 * taken as 0.
 */
export function usableNsec3 (rr) {
  if (!rr || !rr.nextHashed || !rr.types) return false
  const flags = Number(rr.flags || 0)
  return (flags & 0xFE) === 0
}

export function nsec3NoExactMatch (rrs, qname, zone) {
  const usable = (rrs || []).filter(usableNsec3)
  if (!usable.length) return false
  const params = paramsOf(usable)
  if (!params || nsec3Hash(qname, params) === null) return false
  // A matching NSEC3 says the name EXISTS, which defeats the claim outright.
  if (usable.some((rr) => nsec3Matches(rr, qname, params))) return false
  return !!closestEncloserProof(usable, qname, zone, params)
}

/**
 * Is a denial for (name, type) proven by these NSEC3 records?
 *
 * @param {Array} rrs NSEC3 records whose own signatures already validated
 * @param {string} name the queried name
 * @param {number} type the queried rrtype
 * @param {string} zone the signing zone's apex
 */
export function nsec3ProvesDenial (rrs, name, type, zone) {
  const usable = (rrs || []).filter(usableNsec3)
  if (!usable.length) return false
  const params = paramsOf(usable)
  if (!params) return false // mixed parameters: not one coherent proof
  if (nsec3Hash(name, params) === null) return false // unsupported alg or too many iterations
  return nsec3ProvesNoData(usable, name, type, params, zone) ||
    nsec3ProvesNxdomain(usable, name, zone, params)
}

/**
 * Is the delegation at `child` proven INSECURE — no DS, and the zone says so?
 *
 * RFC 4035 §5.2 / RFC 5155 §8.9. Either the cut's own NSEC3 exists and lacks
 * the DS bit (a plain NODATA, handled by nsec3ProvesDenial), or the cut is
 * inside an Opt-Out gap: the closest encloser proof for `child` succeeds with
 * an opt-out cover over the next closer name. The second is the ONE place
 * opt-out proves anything, and it proves exactly this — an unsigned
 * delegation may exist there. Both mean the child zone is to be read
 * unsigned, not refused.
 */
export function nsec3ProvesInsecureDelegation (rrs, child, zone) {
  const usable = (rrs || []).filter(usableNsec3)
  if (!usable.length) return false
  const params = paramsOf(usable)
  if (!params || nsec3Hash(child, params) === null) return false
  if (nsec3ProvesNoData(usable, child, TYPE_DS, params, zone)) return true
  if (usable.some((rr) => nsec3Matches(rr, child, params))) return false // exists, with a DS bit
  const proof = closestEncloserProof(usable, child, zone, params, { allowOptOut: true })
  return !!(proof && proof.optOut)
}
