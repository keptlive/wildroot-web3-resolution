/*
 * DID methods that resolve with NO network and NO trust decision: the
 * identifier IS the key (did:key, did:jwk) or IS the account (did:pkh). The
 * document is derived from the identifier by rules the method specification
 * fixes, so nobody is asked and nobody can answer wrongly — the one class of
 * DID a browser can resolve and call verified.
 *
 *   did:key  — a multibase (base58btc) multicodec public key.
 *              https://w3c-ccg.github.io/did-key-spec/
 *   did:jwk  — a base64url JSON Web Key.
 *              https://github.com/quartzjer/did-jwk/blob/main/spec.md
 *   did:pkh  — a CAIP-10 blockchain account id.
 *              https://github.com/w3c-ccg/did-pkh/blob/main/did-pkh-method-draft.md
 *
 * Every other method (did:plc, did:web) fetches its document from someone and
 * is handled in did-protocol.js, on that someone's word.
 */

import { base58btc } from 'multiformats/bases/base58'

/** Multicodec public-key prefixes did:key admits, with the key length each fixes. */
const KEY_CODECS = {
  0xed: { name: 'Ed25519', length: 32 },
  0xec: { name: 'X25519', length: 32, agreementOnly: true },
  0xe7: { name: 'secp256k1', length: 33 },
  0x1200: { name: 'P-256', length: 33 },
  0x1201: { name: 'P-384', length: 49 },
  0x1202: { name: 'P-521', length: 67 },
  0x1205: { name: 'RSA', length: null }
}

const DID_V1 = 'https://www.w3.org/ns/did/v1'

/**
 * The DID document for a locally resolvable identifier, or null when the
 * method is not one of these three. Throws with a readable message for an
 * identifier that names the method but is malformed.
 * @param {string} did
 * @returns {object|null}
 */
export function localDidDocument (did) {
  const m = /^did:([a-z0-9]+):(.+)$/s.exec(String(did || ''))
  if (!m) return null
  const [, method, rest] = m
  if (method === 'key') return didKeyDocument(did, rest)
  if (method === 'jwk') return didJwkDocument(did, rest)
  if (method === 'pkh') return didPkhDocument(did, rest)
  return null
}

/** True when did-local.js answers for this DID's method. */
export function isLocalDidMethod (did) {
  return /^did:(key|jwk|pkh):/.test(String(did || ''))
}

/** Unsigned varint at the head of `bytes`: [value, bytesRead]. */
function readVarint (bytes) {
  let value = 0
  let shift = 0
  for (let i = 0; i < bytes.length && i < 5; i++) {
    value |= (bytes[i] & 0x7f) << shift
    if ((bytes[i] & 0x80) === 0) return [value >>> 0, i + 1]
    shift += 7
  }
  throw new Error('did:key: the multicodec prefix is not a valid varint')
}

function didKeyDocument (did, id) {
  if (!id.startsWith('z')) throw new Error('did:key: the identifier must be base58btc multibase (a leading "z")')
  if (/[^1-9A-HJ-NP-Za-km-z]/.test(id.slice(1))) throw new Error('did:key: not base58btc')
  let bytes
  try { bytes = base58btc.decode(id) } catch { throw new Error('did:key: not base58btc') }
  const [codec, prefixLength] = readVarint(bytes)
  const spec = KEY_CODECS[codec]
  if (!spec) throw new Error(`did:key: unsupported key type (multicodec 0x${codec.toString(16)})`)
  const key = bytes.subarray(prefixLength)
  if (spec.length !== null && key.length !== spec.length) {
    throw new Error(`did:key: a ${spec.name} key is ${spec.length} bytes, this one is ${key.length}`)
  }
  const vmId = `${did}#${id}`
  const vm = { id: vmId, type: 'Multikey', controller: did, publicKeyMultibase: id }
  const doc = {
    '@context': [DID_V1, 'https://w3id.org/security/multikey/v1'],
    id: did,
    verificationMethod: [vm]
  }
  if (spec.agreementOnly) {
    doc.keyAgreement = [vmId]
  } else {
    doc.authentication = [vmId]
    doc.assertionMethod = [vmId]
    doc.capabilityInvocation = [vmId]
    doc.capabilityDelegation = [vmId]
  }
  return doc
}

function didJwkDocument (did, id) {
  let jwk
  try {
    jwk = JSON.parse(Buffer.from(id, 'base64url').toString('utf8'))
  } catch {
    throw new Error('did:jwk: the identifier is not a base64url JSON Web Key')
  }
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk) || !jwk.kty) {
    throw new Error('did:jwk: the identifier is not a base64url JSON Web Key')
  }
  // A private key in an identifier is a leak, not a DID.
  for (const secret of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k']) {
    if (secret in jwk) throw new Error('did:jwk: the key carries private material and is refused')
  }
  const vmId = `${did}#0`
  const doc = {
    '@context': [DID_V1, 'https://w3id.org/security/suites/jws-2020/v1'],
    id: did,
    verificationMethod: [{ id: vmId, type: 'JsonWebKey2020', controller: did, publicKeyJwk: jwk }]
  }
  // The spec: `use: "enc"` lists only keyAgreement; `use: "sig"` everything
  // but keyAgreement; no `use` lists every relationship.
  if (jwk.use !== 'sig') doc.keyAgreement = [vmId]
  if (jwk.use !== 'enc') {
    doc.authentication = [vmId]
    doc.assertionMethod = [vmId]
    doc.capabilityInvocation = [vmId]
    doc.capabilityDelegation = [vmId]
  }
  return doc
}

/** CAIP-2 namespaces did:pkh admits, with the verification-method type each fixes. */
const PKH = {
  eip155: { type: 'EcdsaSecp256k1RecoveryMethod2020', context: 'https://w3id.org/security#EcdsaSecp256k1RecoveryMethod2020', address: /^0x[0-9a-fA-F]{40}$/ },
  bip122: { type: 'EcdsaSecp256k1RecoveryMethod2020', context: 'https://w3id.org/security#EcdsaSecp256k1RecoveryMethod2020', address: /^[1-9A-HJ-NP-Za-km-z]{25,62}$/ },
  solana: { type: 'Ed25519VerificationKey2018', context: 'https://w3id.org/security/suites/ed25519-2018/v1', address: /^[1-9A-HJ-NP-Za-km-z]{32,48}$/ },
  tezos: { type: 'Ed25519VerificationKey2018', context: 'https://w3id.org/security/suites/ed25519-2018/v1', address: /^tz[123][1-9A-HJ-NP-Za-km-z]{33}$/ }
}

function didPkhDocument (did, id) {
  const parts = id.split(':')
  if (parts.length !== 3 || parts.some((p) => !p)) {
    throw new Error('did:pkh: expected did:pkh:<namespace>:<chain reference>:<address> (CAIP-10)')
  }
  const [namespace, reference, address] = parts
  const spec = PKH[namespace]
  if (!spec) throw new Error(`did:pkh: unsupported chain namespace "${namespace}"`)
  if (!/^[-_a-zA-Z0-9]{1,32}$/.test(reference)) throw new Error('did:pkh: malformed chain reference')
  if (!spec.address.test(address)) throw new Error(`did:pkh: malformed ${namespace} address`)
  const vmId = `${did}#blockchainAccountId`
  return {
    '@context': [DID_V1, { blockchainAccountId: 'https://w3id.org/security#blockchainAccountId', [spec.type]: spec.context }],
    id: did,
    verificationMethod: [{ id: vmId, type: spec.type, controller: did, blockchainAccountId: `${namespace}:${reference}:${address}` }],
    authentication: [vmId],
    assertionMethod: [vmId]
  }
}
