/*
 * Authenticated denial of existence (NSEC, RFC 4035 §5.4).
 *
 * WHY THIS EXISTS. Everything this browser refuses to take on trust bottoms
 * out in one question the code could not previously answer: *did the zone
 * really say there is nothing here?* Without an answer, a signed zone's
 * silence is indistinguishable from an attacker's, and two documented holes
 * follow from the same gap:
 *
 *   1. A forged NXDOMAIN at `_443._tcp.<host>` strips a real TLSA record and
 *      forces the connection to plaintext. The zone published a pin; the
 *      attacker deleted it; we believed the deletion. That is exactly the
 *      downgrade DANE exists to stop, and src/hns/resolver.js has carried a
 *      "PRINCIPLED PATH, not yet taken" note about it.
 *   2. A wildcard-expanded answer cannot be authenticated, because RFC 4035
 *      §5.3.4 says a validator "must take additional steps to verify the
 *      non-existence of an exact match or closer wildcard match for the
 *      query" — and those steps are these.
 *
 * WHAT THIS IS NOT. It is not cryptography. The signatures over these NSEC
 * records are verified by dnssec.js exactly like any other RRset; what is
 * here is the ORDERING logic that decides whether a proof, once verified,
 * actually proves the thing being claimed. Getting that wrong in the
 * permissive direction is the only real hazard, so every predicate below
 * returns false when it is unsure, and the tests carry as many negative cases
 * as positive ones.
 *
 * NSEC3 LIVES NEXT DOOR, in nsec3.js: the same proofs over hashed names. A
 * zone signs with one scheme or the other, and denial.js chooses between them.
 * The two modules never import each other — the name helpers live here and
 * nsec3.js reads them, one direction only. Our own signer emits NSEC;
 * Namebase's `hns` emits NSEC3.
 */

/** rrtypes this module needs to reason about, by number (RFC 1035 / 4034). */
const TYPE_CNAME = 5
const TYPE_NS = 2
const TYPE_SOA = 6
const TYPE_DNAME = 39
const TYPE_DS = 43

/** A name as canonical labels, RIGHTMOST FIRST, lowercased and dot-stripped. */
function labelsOf (name) {
  return String(name || '')
    .toLowerCase()
    .replace(/\.$/, '')
    .split('.')
    .filter(Boolean)
    .reverse()
}

/**
 * Canonical DNS name order, RFC 4034 §6.1: compare the rightmost labels
 * first, each as a left-justified unsigned octet string, and treat a missing
 * label as sorting before any label.
 *
 * @returns {number} <0, 0, >0
 */
export function canonicalCompareNames (a, b) {
  const la = labelsOf(a)
  const lb = labelsOf(b)
  const n = Math.max(la.length, lb.length)
  for (let i = 0; i < n; i++) {
    if (la[i] === undefined) return -1
    if (lb[i] === undefined) return 1
    const c = Buffer.compare(Buffer.from(la[i], 'utf8'), Buffer.from(lb[i], 'utf8'))
    if (c !== 0) return c < 0 ? -1 : 1
  }
  return 0
}

/** Is `name` equal to, or below, `ancestor`? (Both canonicalised.) */
export function isUnder (name, ancestor) {
  const n = labelsOf(name)
  const a = labelsOf(ancestor)
  if (a.length > n.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== n[i]) return false
  return true
}

/** The name with its leftmost label removed — `a.b.c` -> `b.c`. */
export function parentOf (name) {
  const parts = String(name || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean)
  return parts.slice(1).join('.')
}

/** An NSEC whose owner IS this name. */
export function nsecMatches (nsec, name) {
  return !!nsec && canonicalCompareNames(nsec.name, name) === 0
}

/**
 * Does this NSEC prove `name` does not exist — i.e. does the gap it describes
 * strictly contain it?
 *
 * The last NSEC of a zone wraps: its next-name is the apex, so `owner > next`.
 * In that one case the gap is everything after the owner, to the end.
 */
export function nsecCovers (nsec, name) {
  if (!nsec || !nsec.nextName) return false
  const fromOwner = canonicalCompareNames(nsec.name, name)
  const toNext = canonicalCompareNames(name, nsec.nextName)
  // The name itself is never "covered" by an NSEC that names it: that NSEC
  // asserts the name EXISTS, which is the opposite claim.
  if (fromOwner === 0) return false
  const wraps = canonicalCompareNames(nsec.name, nsec.nextName) >= 0
  return wraps ? (fromOwner < 0 || toNext < 0) : (fromOwner < 0 && toNext < 0)
}

/**
 * Does this bitmap deny `type` at a name the NSEC says exists?
 *
 * The bitmap must lack the queried type, and must also lack CNAME — a CNAME at
 * the name would have meant the answer should have been a redirect, not an
 * empty set. A delegation (NS without SOA) is refused for every type but one:
 * that name is not this zone's to answer for, so its bitmap says nothing about
 * what lives below the cut. The exception is DS, which the PARENT owns at the
 * cut (RFC 4035 §2.4, §5.2) — an NSEC at a delegation with no DS bit is
 * precisely the proof that the delegation is insecure rather than bogus.
 */
function bitmapDenies (types, type) {
  if (!types || typeof types.has !== 'function') return false
  if (types.has(type) || types.has(TYPE_CNAME)) return false
  if (types.has(TYPE_NS) && !types.has(TYPE_SOA) && type !== TYPE_DS) return false
  return true
}

/**
 * A NODATA proof: the name EXISTS and has no record of this type.
 *
 * RFC 4035 §5.4, in both of its shapes. The plain one: an NSEC MATCHES the
 * name and its bitmap lacks the type. The wildcard one (§3.1.3.4, "Wildcard No
 * Data"): no NSEC matches the name, one COVERS it (so it has no records of its
 * own), and the NSEC matching `*.<closest encloser>` lacks the type — the
 * answer the zone would have synthesised from the wildcard has no RRset of
 * this type either. A zone that answers every name under it through a
 * wildcard produces only the second shape, and refusing it made every such
 * zone unloadable in the clear even when the denial was honest.
 *
 * @param {Array} nsecs NSEC records from the AUTHORITY section
 * @param {string} name the queried name
 * @param {number} type the queried rrtype
 * @param {string} [zone] the apex, needed for the wildcard shape only
 */
export function provesNoData (nsecs, name, type, zone = null) {
  const set = nsecs || []
  for (const nsec of set) {
    if (!nsecMatches(nsec, name)) continue
    return bitmapDenies(nsec.types, type)
  }
  if (!zone) return false
  const covering = set.find((n) => nsecCovers(n, name))
  if (!covering) return false
  let encloser = closestEncloser(covering, name)
  if (!encloser || !isUnder(encloser, zone)) encloser = zone
  if (canonicalCompareNames(encloser, name) === 0) return false
  const wildcard = `*.${encloser}`
  const star = set.find((n) => nsecMatches(n, wildcard))
  return !!star && bitmapDenies(star.types, type)
}

/**
 * The closest encloser of `qname` implied by an NSEC that covers it: the
 * longest ancestor of `qname` that the NSEC shows to exist.
 *
 * An NSEC names two existing points — its owner and its next-name — so the
 * longest suffix `qname` shares with either of them is an ancestor known to
 * exist. The longer of the two is the closest encloser (the same derivation
 * RFC 5155 §8.3 spells out for NSEC3).
 */
export function closestEncloser (nsec, qname) {
  const longestCommonSuffix = (a, b) => {
    const la = labelsOf(a)
    const lb = labelsOf(b)
    const out = []
    for (let i = 0; i < Math.min(la.length, lb.length); i++) {
      if (la[i] !== lb[i]) break
      out.push(la[i])
    }
    return out.reverse().join('.')
  }
  const fromOwner = longestCommonSuffix(qname, nsec.name)
  const fromNext = longestCommonSuffix(qname, nsec.nextName)
  return labelsOf(fromOwner).length >= labelsOf(fromNext).length ? fromOwner : fromNext
}

/**
 * An NXDOMAIN proof: the name does not exist, AND no wildcard could have been
 * expanded to answer for it.
 *
 * BOTH HALVES ARE REQUIRED (RFC 4035 §5.4). Accepting the first alone is the
 * classic mistake: a zone may well hold `*.example` whose answer the attacker
 * simply withheld, and "this exact name is absent" says nothing about that.
 * The source of synthesis is `*.<closest encloser>` (RFC 4592 §3.3.1), and one
 * NSEC frequently proves both — which is why the two searches are separate
 * rather than requiring two distinct records.
 *
 * @param {Array} nsecs NSEC records from the AUTHORITY section
 * @param {string} qname the queried name
 * @param {string} zone the apex, so the encloser cannot be walked above it
 */
export function provesNxdomain (nsecs, qname, zone) {
  const covering = (nsecs || []).find((n) => nsecCovers(n, qname))
  if (!covering) return false
  let encloser = closestEncloser(covering, qname)
  // The encloser must sit inside the zone and strictly above the name.
  if (!encloser || !isUnder(encloser, zone)) encloser = zone
  if (canonicalCompareNames(encloser, qname) === 0) return false
  const wildcard = `*.${encloser}`
  // Either some NSEC covers the wildcard (it does not exist), or one names it
  // — and a wildcard that EXISTS means the answer should have been synthesised
  // from it, so an NXDOMAIN was the wrong reply and the proof fails.
  for (const nsec of nsecs) {
    if (nsecMatches(nsec, wildcard)) return false
    if (nsecCovers(nsec, wildcard)) return true
  }
  return false
}

/**
 * Is there NO exact match for `qname` in this zone, by NSEC?
 *
 * The proof RFC 4035 §5.3.4 demands beside a WILDCARD-expanded answer: before
 * such an answer may be believed, the validator must check "that there is no
 * RRset that would have been a closer match". Without it, a zone's wildcard
 * signature can be lifted and replayed at a name that has its own records,
 * and the real ones simply withheld.
 *
 * This is NOT provesNxdomain. There the wildcard must be shown absent; here it
 * plainly exists — that is what produced the answer — and the thing to prove is
 * only that the queried name itself does not.
 */
export function nsecNoExactMatch (nsecs, qname) {
  const set = (nsecs || []).filter((r) => r && r.nextName)
  if (!set.length) return false
  // A matching NSEC says the name EXISTS, which defeats the claim outright.
  if (set.some((n) => nsecMatches(n, qname))) return false
  return set.some((n) => nsecCovers(n, qname))
}

/**
 * Whether a DENIAL for (name, type) is proven by these NSEC records.
 *
 * Both shapes of "there is nothing here" are accepted, because both are how a
 * zone legitimately says it: NODATA when the name exists with other types
 * (which is what our own nsd.py answers for a host with no pin), and NXDOMAIN
 * when the name does not exist at all.
 *
 * The NSEC3 equivalent lives in nsec3.js and the two are chosen between in
 * denial.js — kept apart so neither module imports the other.
 */
export function nsecProvesDenial (nsecs, name, type, zone) {
  const set = (nsecs || []).filter((r) => r && r.nextName)
  if (!set.length) return false
  if (set.some((n) => n.types && n.types.has && n.types.has(TYPE_DNAME))) {
    // A DNAME rewrites the name below it; reasoning about the original name's
    // absence from these records would be wrong. Refuse rather than guess.
    return false
  }
  return provesNoData(set, name, type, zone) || provesNxdomain(set, name, zone)
}
