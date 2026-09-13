/*
 * An Arweave transaction header, authenticated against the identifier.
 *
 * The identifier is SHA-256 of the transaction's SIGNATURE, and that is ALL it
 * is: hashing the signature proves the gateway did not invent one, and proves
 * nothing about `owner`, `data_root`, `data_size`, `tags`, `target`,
 * `quantity`, `reward` or `last_tx`, which a gateway could swap freely while
 * keeping the signature — and ar-merkle.js would then check the bytes against
 * a root of the gateway's choosing. The signature is what binds those fields,
 * so it is VERIFIED, not merely hashed:
 *
 *   id  = SHA-256(signature)                                    (both formats)
 *   sig = RSA-PSS(SHA-256) over the signature payload, under the key whose
 *         modulus is `owner` (base64url) and whose exponent is 65537
 *
 *   format 2: payload = deepHash([ denomination?, "2", owner, target,
 *                                  quantity, reward, last_tx,
 *                                  [[name, value]…], data_size, data_root ])
 *   format 1: payload = owner ‖ target ‖ data ‖ quantity ‖ reward ‖ last_tx ‖
 *                       (name ‖ value)…            (a plain concatenation)
 *
 * Numbers are their DECIMAL STRINGS as bytes; every other field is its
 * canonical base64url decoding; an absent field is zero bytes.
 *
 * THREE OUTCOMES, which the caller must keep apart (src/hns/ar.js):
 *
 *   verified    — the signature is the identifier's AND signs these fields.
 *   mismatch    — this is not the identifier's transaction, or its document is
 *                 not a transaction: a caught lie, which the handler refuses.
 *   unsupported — the identity check passed and the rest CANNOT be made here:
 *                 a format or account type this module does not construct a
 *                 payload for, an owner that is not RSA-4096, a format-1
 *                 header served without the data it signed. Nothing is
 *                 proven, so nothing is claimed — `X-Arweave-Verified: none`,
 *                 the same standing as a header gateway that did not answer.
 *                 Refusing instead would buy nothing: any header gateway can
 *                 already produce that standing by not answering, so the only
 *                 thing a refusal stops is honest content we cannot check.
 *
 * WHAT IS STILL NOT PROVEN. That this owner is the wallet the network
 * accepted, or that the transaction was mined, confirmed or is permanent: a
 * header is self-describing and only the block index settles that, which is a
 * chain read this browser does not make.
 *
 * Protocol references: ArweaveTeam/arweave apps/arweave/src/ar_tx.erl (the
 * signature payload, both formats, and the optional denomination) and
 * ArweaveTeam/arweave-js src/common/lib/{transaction,deepHash}.ts plus
 * lib/crypto/node-driver.ts (RSA-PSS/SHA-256, the salt length left automatic,
 * the key built from { kty: 'RSA', e: 'AQAB', n: owner }). Re-implemented
 * here on node:crypto — no Arweave dependency.
 */

import { constants, createHash, createPublicKey, verify } from 'node:crypto'
import { isCanonicalTxid } from '../../../src/pointers.js'

/**
 * Arweave wallets are RSA-4096 (ar_wallet.erl generates and the network
 * accepts nothing else), so a 512-byte modulus is the only supported owner.
 * It is also the one parameter an attacker would shrink: given a fixed
 * signature, fitting a chosen modulus to chosen fields is a divisor-finding
 * problem that only gets easier as the modulus gets smaller.
 */
export const MODULUS_BYTES = 512

/** The largest format-1 `data` this module will hold to check a signature. */
export const MAX_FORMAT_1_DATA = 256 * 1024

const b64Limit = (bytes) => Math.ceil(bytes * 4 / 3)

function fail (verdict, message) {
  const err = new Error(message)
  err.verdict = verdict
  return err
}

/** Not checkable here: claim nothing, refuse nothing. */
const unsupported = (message) => fail('unsupported', message)
/** Caught: this is not the transaction the identifier names. */
const mismatch = (message) => fail('mismatch', message)

function decoded (value, max) {
  if (typeof value !== 'string' || value.length > b64Limit(max) || !/^[A-Za-z0-9_-]*$/.test(value)) throw mismatch('invalid base64url field')
  const bytes = Buffer.from(value, 'base64url')
  if (bytes.length > max || bytes.toString('base64url') !== value) throw mismatch('noncanonical base64url field')
  return bytes
}

function decimal (value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,29})$/.test(value)) throw mismatch('invalid decimal transaction field')
  return value
}

/**
 * Arweave's deep hash: a tagged, recursive SHA-384 over a tree of byte
 * strings, so that no two differently-shaped inputs hash alike.
 *   blob: H( H("blob" ‖ len) ‖ H(bytes) )
 *   list: acc = H("list" ‖ count); acc = H(acc ‖ deepHash(item)) per item
 */
export function deepHash (value) {
  const hash = (bytes) => createHash('sha384').update(bytes).digest()
  if (Array.isArray(value)) {
    return value.reduce((acc, item) => hash(Buffer.concat([acc, deepHash(item)])), hash(Buffer.from(`list${value.length}`)))
  }
  return hash(Buffer.concat([hash(Buffer.from(`blob${value.length}`)), hash(value)]))
}

/** The tags as [[name, value]…] raw bytes, within the protocol's own limits. */
function tagPairs (header) {
  if (!Array.isArray(header.tags) || header.tags.length > 2048) throw mismatch('invalid transaction tags')
  let tagBytes = 0
  return header.tags.map((tag) => {
    const pair = [decoded(tag?.name, 2048), decoded(tag?.value, 2048)]
    tagBytes += pair[0].length + pair[1].length
    if (tagBytes > 2048) throw mismatch('transaction tags exceed limit')
    return pair
  })
}

/**
 * @param {object} header a `/tx/<id>` document, as the gateway served it
 * @param {string} txid the canonical base64url identifier that was asked for
 * @returns {{ok: boolean, verdict: 'verified'|'mismatch'|'unsupported', reason?: string,
 *            dataSize?: bigint, dataRoot?: string|null, data?: Buffer|null, tags?: Buffer[][]}}
 *          `dataSize`, `dataRoot`, `data` and `tags` are returned ONLY when
 *          they are authenticated. A format-1 transaction signs its data
 *          itself and commits to no Merkle root, so `data` is the bytes and
 *          `dataRoot` is null; its `data_size` field is not signed and is
 *          never read — the size returned is the signed data's own length.
 */
export function verifyTransactionHeader (header, txid) {
  try {
    // 1. Identity. The id IS the signature's hash, whatever signs it.
    if (!header || typeof header !== 'object' || !isCanonicalTxid(txid) || header.id !== txid) throw mismatch('transaction id mismatch')
    const signature = decoded(header.signature, 2048)
    if (createHash('sha256').update(signature).digest('base64url') !== txid) throw mismatch('signature does not hash to the id')

    // 2. Can this module check it at all? Everything here is a capability
    // limit, not a finding: an unrecognised claim is never ignored, but it is
    // never treated as evidence of a lie either.
    const format = header.format === undefined ? 1 : header.format
    if (format !== 1 && format !== 2) throw unsupported('unsupported transaction format (only formats 1 and 2 are verified)')
    // The node JSON format infers the account type from owner/signature
    // lengths. Reject any explicit unrecognised type rather than ignore it.
    if (header.signature_type !== undefined && header.signature_type !== 1) throw unsupported('unsupported signature type')
    const owner = decoded(header.owner, MODULUS_BYTES)
    if (owner.length !== MODULUS_BYTES || signature.length !== MODULUS_BYTES) throw unsupported('unsupported owner/signature format (RSA 4096 required)')

    // 3. The fields, strictly: a supported transaction cannot be shaped
    // otherwise, so anything here is a document that is not a transaction.
    const target = decoded(header.target, 32)
    if (target.length !== 0 && target.length !== 32) throw mismatch('unsupported target address')
    const anchor = decoded(header.last_tx, 48)
    if (![0, 32, 48].includes(anchor.length)) throw mismatch('invalid transaction anchor')
    const quantity = decimal(header.quantity)
    const reward = decimal(header.reward)
    const tags = tagPairs(header)

    let payload = null
    let dataSize = null
    let dataRoot = null
    let data = null
    if (format === 2) {
      const size = decimal(header.data_size)
      const root = decoded(header.data_root, 32)
      if (root.length !== (size === '0' ? 0 : 32)) throw mismatch('invalid data size/root combination')
      const fields = [Buffer.from('2'), owner, target, Buffer.from(quantity), Buffer.from(reward), anchor, tags, Buffer.from(size), root]
      // An optional positive denomination is prepended (ar_tx.erl).
      if (header.denomination !== undefined) {
        if (typeof header.denomination !== 'string' || !/^[1-9][0-9]{0,2}$/.test(header.denomination)) throw mismatch('unsupported denomination')
        fields.unshift(Buffer.from(header.denomination))
      }
      payload = deepHash(fields)
      dataSize = BigInt(size)
      dataRoot = header.data_root
    } else {
      // Format 1 signs the DATA, not a Merkle root, so the header must carry
      // it: without it there is nothing to hash, which is a limit of this
      // implementation (and of the header budget) rather than a finding.
      if (typeof header.data !== 'string') throw unsupported('format 1 header without the data it signed')
      if (header.data.length > b64Limit(MAX_FORMAT_1_DATA)) throw unsupported('format 1 data is larger than this implementation authenticates')
      data = decoded(header.data, MAX_FORMAT_1_DATA)
      if (header.denomination !== undefined) throw unsupported('denomination is not a format-1 field')
      payload = Buffer.concat([owner, target, data, Buffer.from(quantity), Buffer.from(reward), anchor, ...tags.flat()])
      dataSize = BigInt(data.length)
    }

    const key = createPublicKey({ key: { kty: 'RSA', e: 'AQAB', n: header.owner }, format: 'jwk' })
    if (key.asymmetricKeyDetails?.modulusLength !== 4096) throw unsupported('unsupported RSA modulus size')
    // The salt length is left AUTOMATIC on purpose: the SDKs sign with the
    // digest length and with the maximum, and both are the same signature to
    // the network.
    if (!verify('sha256', payload, { key, padding: constants.RSA_PKCS1_PSS_PADDING }, signature)) throw mismatch('owner signature does not authenticate transaction fields')
    return { ok: true, verdict: 'verified', dataSize, dataRoot, data, tags }
  } catch (err) {
    return { ok: false, verdict: err.verdict || 'mismatch', reason: err.message || 'invalid transaction header' }
  }
}

/** Compatibility export: true means PROVEN — never "not checkable". */
export function headerMatchesId (header, txid) {
  return verifyTransactionHeader(header, txid).ok
}
