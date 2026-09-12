/*
 * A REAL signed transaction for the tests that need one.
 *
 * Since the header check verifies the signature over the transaction's fields
 * (src/ar-tx.js), a made-up `{ signature }` no longer stands in for a
 * transaction: a test that wants the handler to reach its byte check needs a
 * header that is genuinely signed. One RSA-4096 key is generated per test
 * process (Arweave's key size, the one this implementation accepts) and every
 * transaction below is signed with it.
 *
 * The payload comes from the implementation's own `signatureData`, so these
 * fixtures prove the handler's PLUMBING, not the signature construction —
 * that is proven in ar-tx.test.js against real transactions fetched from
 * arweave.net and against arweave-js's own deep-hash vectors.
 */

import { generateKeyPairSync, createHash, sign, constants } from 'node:crypto'
import { signatureData } from '../src/ar-tx.js'

const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 4096, publicExponent: 0x10001 })

/** The wallet's modulus, base64url — an Arweave header's `owner`. */
export const OWNER = publicKey.export({ format: 'jwk' }).n

/** A second wallet, for the case where the owner is swapped for another real key. */
export const OTHER_OWNER = generateKeyPairSync('rsa', { modulusLength: 4096, publicExponent: 0x10001 })
  .publicKey.export({ format: 'jwk' }).n

/**
 * A signed format-2 transaction: `{ id, header }`, where `id` really is
 * SHA-256 of the signature and the signature really is over these fields.
 * @param {object} [fields] anything to set or override on the header
 */
export function signedTransaction (fields = {}) {
  const header = {
    format: 2,
    owner: OWNER,
    target: '',
    quantity: '0',
    reward: '0',
    last_tx: '',
    tags: [],
    data_size: '0',
    data_root: '',
    ...fields
  }
  const payload = signatureData(header)
  if (!payload) throw new Error('signed-tx: these fields have no signature payload')
  const signature = sign('sha256', payload, {
    key: privateKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_MAX_SIGN
  })
  header.signature = signature.toString('base64url')
  header.id = createHash('sha256').update(signature).digest().toString('base64url')
  return { id: header.id, header }
}
