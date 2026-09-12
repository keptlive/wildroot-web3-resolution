/*
 * An Arweave transaction header, checked against the identifier END TO END.
 *
 * The identifier is SHA-256 of the transaction's SIGNATURE, and that is all it
 * is: hashing the signature proves the gateway did not invent a signature, and
 * proves NOTHING about `owner`, `data_root`, `data_size`, `tags`, `target`,
 * `quantity`, `reward` or `last_tx`, which a gateway could swap freely while
 * keeping the signature — and `ar-merkle.js` would then check the bytes
 * against the wrong root. The signature is what binds those fields, so it has
 * to be verified, not merely hashed:
 *
 *   id  = SHA-256(signature)                                   (both formats)
 *   sig = RSA-PSS(SHA-256) over the signature payload, under the key whose
 *         modulus is `owner` (base64url) and whose exponent is 65537
 *
 *   format 2: payload = deepHash([ "2", owner, target, quantity, reward,
 *                                  last_tx, [[name, value]…], data_size,
 *                                  data_root ])
 *   format 1: payload = owner ‖ target ‖ data ‖ quantity ‖ reward ‖ last_tx ‖
 *                       (name ‖ value)…                        (a plain concatenation)
 *
 * Numbers are their DECIMAL STRINGS as bytes; every other field is its
 * base64url decoding; an absent field is zero bytes.
 *
 * PROVENANCE. The deep hash (SHA-384, "blob"/"list" tags) and the payload
 * field order are arweave-js's — `arweave/node/lib/deepHash.js` and
 * `Transaction.getSignatureData()` in `arweave/node/lib/transaction.js`
 * (v1.15.7, MIT) — re-implemented here synchronously on `node:crypto` so this
 * module adds no dependency; `~/hns/dsld/service/ans104.cjs`, our ANS-104
 * bundler, calls the same function out of that package for data items. The
 * verification parameters are arweave-js's `NodeCryptoDriver.verify()`:
 * RSA-PSS, SHA-256, the salt length left AUTOMATIC (`RSA_PSS_SALTLEN_AUTO`,
 * which is what Node uses when arweave-js passes none), the key built from
 * `{ kty: 'RSA', e: 'AQAB', n: owner }`.
 *
 * WHAT IS STILL NOT PROVEN. That this owner is the wallet the network accepted:
 * the header is self-describing, and only the block index says which
 * transaction was mined. A gateway that wants to be believed less can also
 * serve a header this module cannot check (see UNSUPPORTED) — which is the
 * same standing as a second gateway that did not answer, and is reported as
 * nothing checked, never as checked.
 */

import { createHash, createPublicKey, verify as rsaVerify, constants } from 'node:crypto'

/** Arweave wallets are RSA-4096: a 512-byte modulus and a 512-byte signature. */
export const MODULUS_BYTES = 512

/** The largest format-1 `data` this module will hold to check a signature. */
export const MAX_FORMAT_1_DATA = 8 * 1024 * 1024

const EMPTY = Buffer.alloc(0)

/** base64url → bytes (an absent field is zero bytes). */
function b64 (value) {
  if (value === undefined || value === null || value === '') return EMPTY
  if (typeof value !== 'string') return null
  try { return Buffer.from(value, 'base64url') } catch { return null }
}

/** A decimal string (`quantity`, `reward`, `data_size`, the format) as its ASCII bytes. */
function digits (value) {
  const s = value === undefined || value === null ? '' : String(value)
  return /^\d*$/.test(s) ? Buffer.from(s, 'utf8') : null
}

function sha384 (...parts) {
  const h = createHash('sha384')
  for (const p of parts) h.update(p)
  return h.digest()
}

/**
 * Arweave's deep hash: a tagged, recursive SHA-384 over a tree of byte
 * strings, so that no two differently-shaped inputs hash alike.
 *   blob: H( H("blob" ‖ len) ‖ H(bytes) )
 *   list: acc = H("list" ‖ count); acc = H(acc ‖ deepHash(item)) for each item
 * @param {Buffer|Array} data
 * @returns {Buffer} 48 bytes
 */
export function deepHash (data) {
  if (Array.isArray(data)) {
    let acc = sha384(Buffer.from('list', 'utf8'), Buffer.from(String(data.length), 'utf8'))
    for (const item of data) acc = sha384(acc, deepHash(item))
    return acc
  }
  const tag = sha384(Buffer.from('blob', 'utf8'), Buffer.from(String(data.length), 'utf8'))
  return sha384(tag, sha384(data))
}

/** `tags` as [[name, value]…] raw bytes, or null if the field is not that shape. */
function tagPairs (tags) {
  if (tags === undefined || tags === null) return []
  if (!Array.isArray(tags)) return null
  const out = []
  for (const tag of tags) {
    if (!tag || typeof tag !== 'object') return null
    const name = b64(tag.name)
    const value = b64(tag.value)
    if (name === null || value === null) return null
    out.push([name, value])
  }
  return out
}

/**
 * The bytes the transaction's signature is over, or null when this module
 * cannot construct them — an unknown format, a field of the wrong shape, or a
 * format-1 transaction whose `data` the gateway did not send (or sent longer
 * than MAX_FORMAT_1_DATA). Null is "not checkable here", never "invalid".
 * @param {object} header a `/tx/<id>` document
 */
export function signatureData (header) {
  if (!header || typeof header !== 'object') return null
  // An absent `format` is format 1: the field was added with format 2.
  const format = header.format === undefined || header.format === null ? 1 : Number(header.format)
  const owner = b64(header.owner)
  const target = b64(header.target)
  const lastTx = b64(header.last_tx)
  const quantity = digits(header.quantity === undefined ? '0' : header.quantity)
  const reward = digits(header.reward === undefined ? '0' : header.reward)
  const pairs = tagPairs(header.tags)
  if (!owner || !owner.length || !target || !lastTx || !quantity || !reward || !pairs) return null

  if (format === 2) {
    const dataSize = digits(header.data_size === undefined ? '0' : header.data_size)
    const dataRoot = b64(header.data_root)
    if (!dataSize || !dataRoot) return null
    return deepHash([
      Buffer.from('2', 'utf8'), owner, target, quantity, reward, lastTx, pairs, dataSize, dataRoot
    ])
  }
  if (format === 1) {
    // The DATA itself is inside a format-1 signature, so the header must carry
    // it and it must be the size the header declares; without that there is
    // nothing to hash and the transaction is not checkable from the header.
    const data = b64(header.data)
    if (!data) return null
    const declared = Number(header.data_size === undefined ? data.length : header.data_size)
    if (!Number.isFinite(declared) || declared !== data.length) return null
    if (data.length > MAX_FORMAT_1_DATA) return null
    const flat = []
    for (const [name, value] of pairs) flat.push(name, value)
    return Buffer.concat([owner, target, data, quantity, reward, lastTx, ...flat])
  }
  return null
}

/**
 * The verdict on a transaction header served for `txid`:
 *
 *   'verified'    — SHA-256(signature) is the id AND the signature verifies
 *                   over this header's own fields under this owner's key.
 *                   Every field above is bound to the id.
 *   'mismatch'    — the header is NOT the transaction the id names: no
 *                   signature, a signature that does not hash to the id, or a
 *                   signature that does not verify over the fields served
 *                   with it. A caller refuses this; it is a caught lie.
 *   'unsupported' — the id check passed and the rest could not be made: a
 *                   format this module does not construct a payload for, a
 *                   key that is not RSA-4096, a format-1 header with no data.
 *                   Nothing is proven and nothing may be claimed — the same
 *                   standing as no header at all.
 *
 * @param {object} header a `/tx/<id>` document
 * @param {string} txid the canonical base64url id that was asked for
 * @returns {'verified'|'mismatch'|'unsupported'}
 */
export function headerVerdict (header, txid) {
  const sig = header && typeof header.signature === 'string' ? b64(header.signature) : null
  if (!sig || !sig.length) return 'mismatch'
  if (createHash('sha256').update(sig).digest().toString('base64url') !== txid) return 'mismatch'
  const owner = b64(header.owner)
  if (!owner || owner.length !== MODULUS_BYTES || sig.length !== MODULUS_BYTES) return 'unsupported'
  const payload = signatureData(header)
  if (!payload) return 'unsupported'
  let key
  try {
    key = createPublicKey({ key: { kty: 'RSA', n: owner.toString('base64url'), e: 'AQAB' }, format: 'jwk' })
  } catch {
    return 'unsupported'
  }
  let ok = false
  try {
    ok = rsaVerify('sha256', payload, {
      key,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: constants.RSA_PSS_SALTLEN_AUTO
    }, sig)
  } catch {
    return 'unsupported'
  }
  // The signature IS the id, so a signature that does not verify over these
  // fields means the fields were changed after signing: a lie, not a gap.
  return ok ? 'verified' : 'mismatch'
}
