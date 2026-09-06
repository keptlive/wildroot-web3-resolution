/*
 * Which denial scheme is this zone using, and does its proof hold?
 *
 * A zone signs with NSEC or with NSEC3, never both, and the two are read by
 * modules that do not know about each other: nsec.js holds the name helpers
 * and the plain proofs, nsec3.js reads those helpers and does the same work
 * over hashed names. Choosing between them is this file's whole job, and it
 * lives apart from both so neither ends up importing the other — a cycle
 * between two security-critical modules is the kind of thing that works until
 * a bundler decides otherwise.
 *
 * A MIXED SET IS REFUSED. Records of both kinds in one answer is not a zone
 * being generous; it is either a broken signer or someone splicing. Reading it
 * as either scheme would let the other kind's records sit there unexamined and
 * unaccounted for, so the whole set proves nothing.
 */

import { nsecProvesDenial, nsecNoExactMatch, provesNoData as nsecNoData } from './nsec.js'
import { nsec3ProvesDenial, nsec3NoExactMatch, nsec3ProvesInsecureDelegation } from './nsec3.js'

const TYPE_DS = 43

/** Split a validated authority section into the one scheme it may use. */
function schemeOf (records) {
  const all = records || []
  const nsec3 = all.filter((r) => r && r.nextHashed)
  const nsec = all.filter((r) => r && r.nextName)
  if (nsec3.length && nsec.length) return null // mixed: proves nothing
  if (nsec3.length) return { kind: 'nsec3', records: nsec3 }
  if (nsec.length) return { kind: 'nsec', records: nsec }
  return null
}

/**
 * Is a denial for (name, type) proven?
 *
 * This is what stands between a signed zone's "there is no TLSA here" and a
 * plaintext connection. Unproven is not permission.
 *
 * @param {Array} records NSEC/NSEC3 records whose own signatures already validated
 * @param {string} name the queried name
 * @param {number} type the queried rrtype
 * @param {string} zone the signing zone's apex
 */
export function provesDenial (records, name, type, zone) {
  const scheme = schemeOf(records)
  if (!scheme) return false
  return scheme.kind === 'nsec3'
    ? nsec3ProvesDenial(scheme.records, name, type, zone)
    : nsecProvesDenial(scheme.records, name, type, zone)
}

/**
 * Is a delegation at `child` proven to carry NO DS — an insecure delegation,
 * as opposed to one whose DS was stripped by whoever answered?
 *
 * RFC 4035 §5.2: a validator that finds no DS at a cut "MUST have an
 * authenticated denial" of it before treating the child as unsigned; without
 * that, an on-path attacker deletes the DS from the referral and every proof
 * the child zone would have had to give is never asked for. For NSEC the proof
 * is the cut's own NSEC lacking the DS bit; for NSEC3 also an Opt-Out gap over
 * the cut (RFC 5155 §8.9), the one place opt-out is a proof of anything.
 *
 * @param {Array} records NSEC/NSEC3 records whose own signatures already validated
 * @param {string} child the delegated name
 * @param {string} zone the PARENT apex
 */
export function provesInsecureDelegation (records, child, zone) {
  const scheme = schemeOf(records)
  if (!scheme) return false
  return scheme.kind === 'nsec3'
    ? nsec3ProvesInsecureDelegation(scheme.records, child, zone)
    : nsecNoData(scheme.records, child, TYPE_DS, zone)
}

/**
 * Is there NO exact match for `qname`? The proof RFC 4035 §5.3.4 requires
 * beside a WILDCARD-expanded answer, before that answer may be believed.
 */
export function provesNoExactMatch (records, qname, zone) {
  const scheme = schemeOf(records)
  if (!scheme) return false
  return scheme.kind === 'nsec3'
    ? nsec3NoExactMatch(scheme.records, qname, zone)
    : nsecNoExactMatch(scheme.records, qname)
}
