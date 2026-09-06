// The registry's half of the binding: the `_hns` control record.
//
//   _hns.alice.wildroot TXT
//   "v=hns1;pubkey=<64-hex>;epoch=1;receipt=<created_at>.<base64url sig>"
//
// SAME SCHEMA, DIFFERENT RECORD (Matt, 2026-08-20). Every field here is the
// one `nostr/DESIGN.md` §2 already defines and `~/hns/nostr/src/record.js`
// already parses — `v=`, `pubkey=`, `epoch=`, `receipt=`, multi-string merge,
// unknown fields ignored. Only the owner name and the version tag differ,
// because this record answers a different question:
//
//   _hns.<name>    WHO CONTROLS this name (the delegable capability)
//   _nostr.<name>  who the name IS on Nostr (a social identity, later)
//
// Keeping them apart is what lets an owner hand a delegate the control key
// for one domain without handing over their social identity — and lets the
// `_nostr` binding, when it comes, be attested BY the control key, which is
// exactly the managed-SLD receipt RES-1 already expects.
//
// `receipt=` is the compact claim receipt: created_at + the 64-byte event
// signature, enough to reconstruct and verify the kind-30078 claim event
// OFFLINE — no relay fetch, no trust in the registry.

import { verifyClaim } from './receipt.js'
import { isPublicKeyHex, normalizeName } from './keys.js'

export const RECORD_VERSION = 'hns1'
export const RECORD_PREFIX = '_hns'

/** The owner name of the control record for a name. */
export function recordName (name) {
  return `${RECORD_PREFIX}.${normalizeName(name)}`
}

/** Encode the compact receipt field value. */
export function encodeReceipt ({ createdAt, sig }) {
  if (!Number.isInteger(createdAt) || createdAt <= 0) throw new Error('bad createdAt')
  if (!/^[0-9a-f]{128}$/.test(sig)) throw new Error('sig must be 128 lowercase hex')
  return `${createdAt}.${Buffer.from(sig, 'hex').toString('base64url')}`
}

/** Decode a receipt field value, or null (untrusted input never throws). */
export function decodeReceipt (value) {
  if (typeof value !== 'string') return null
  const dot = value.indexOf('.')
  if (dot < 1) return null
  const createdAt = Number(value.slice(0, dot))
  if (!Number.isInteger(createdAt) || createdAt <= 0) return null
  let sig
  try {
    const raw = Buffer.from(value.slice(dot + 1), 'base64url')
    if (raw.length !== 64) return null
    sig = raw.toString('hex')
  } catch {
    return null
  }
  return { createdAt, sig }
}

/** Build the TXT strings for `_hns.<name>`. */
export function buildRecord ({ publicKey, epoch, receipt }) {
  if (!isPublicKeyHex(publicKey)) throw new Error('publicKey must be 64 lowercase hex')
  if (!Number.isInteger(epoch) || epoch < 1) throw new Error('epoch must be an integer >= 1')
  // The record has no variable-length field: `v=hns1` (6) + `pubkey=` and 64
  // hex (71) + `epoch=` and an integer + `receipt=` and a 10-digit timestamp,
  // a dot and 86 base64url characters (105), plus three separators — under
  // 200 bytes for any epoch that fits in a JavaScript integer, so it always
  // fits one 255-byte TXT <character-string> (RFC 1035 §3.3.14).
  return [`v=${RECORD_VERSION};pubkey=${publicKey};epoch=${epoch}` +
    `;receipt=${encodeReceipt(receipt)}`]
}

/** The longest TXT <character-string> the wire allows (RFC 1035 §3.3.14). */
const MAX_TXT_STRING = 255

/**
 * Parse TXT strings. Each TXT record's character-strings are already
 * concatenated by the caller (RFC 1035 §3.3.14); separate records are
 * separate values, and a field is never merged across them. Unknown fields
 * are ignored (forward compat), but a DUPLICATED identity field is tampering
 * rather than merging.
 */
export function parseRecord (txtStrings) {
  if (!Array.isArray(txtStrings) || !txtStrings.length) return null
  const fields = new Map()
  for (const raw of txtStrings) {
    if (typeof raw !== 'string' || raw.length > MAX_TXT_STRING) return null
    for (const part of raw.split(';')) {
      const trimmed = part.trim()
      if (!trimmed) continue
      const eq = trimmed.indexOf('=')
      if (eq === -1) continue
      const key = trimmed.slice(0, eq).trim().toLowerCase()
      if (fields.has(key)) return null
      fields.set(key, trimmed.slice(eq + 1).trim())
    }
  }
  if (fields.get('v') !== RECORD_VERSION) return null
  const publicKey = (fields.get('pubkey') || '').toLowerCase()
  const epoch = Number(fields.get('epoch'))
  const receipt = decodeReceipt(fields.get('receipt'))
  if (!isPublicKeyHex(publicKey) || !Number.isInteger(epoch) || epoch < 1 || !receipt) return null
  return { publicKey, epoch, receipt }
}

/**
 * The full check a resolver runs AFTER verifying the DNSSEC chain for the
 * TXT: does the embedded receipt prove the named keyholder claimed exactly
 * this name at exactly this epoch?
 */
export function verifyRecord (name, txtStrings) {
  const parsed = parseRecord(txtStrings)
  if (!parsed) return { bound: false, reason: 'malformed record' }
  const ok = verifyClaim({
    name,
    publicKey: parsed.publicKey,
    epoch: parsed.epoch,
    createdAt: parsed.receipt.createdAt,
    sig: parsed.receipt.sig
  })
  if (!ok) return { bound: false, reason: 'receipt signature invalid' }
  return { bound: true, publicKey: parsed.publicKey, epoch: parsed.epoch }
}
