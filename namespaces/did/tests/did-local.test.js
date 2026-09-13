/*
 * did:key, did:jwk and did:pkh resolve with no network — the document is
 * derived from the identifier. Vectors are the specifications' own examples.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { base58btc } from 'multiformats/bases/base58'
import { localDidDocument, isLocalDidMethod } from '../src/did-local.js'
import createDidHandler from '../src/did-protocol.js'

// did:key spec §"Example": an Ed25519 key.
const ED = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
// A P-256 key in the did:jwk spec example's exact shape and member order:
// {"crv":"P-256","kty":"EC","x":…,"y":…}, base64url with no padding.
//
// The specification's own printed example is NOT used, because the point it
// prints is not on P-256 (y² ≠ x³ - 3x + b) and the resolver imports the key
// rather than measuring it. This vector is the public point of the fixed
// scalar 0xc0ffee, so the fixture stays deterministic and re-derivable.
const JWK = 'did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IjAyQXpMNjJieURyNl8wcDBEZWlsRnI4Ymo3UDk0MkRfSFFPWG5CLVVQdUkiLCJ5IjoiNktaZ0JfMG5hd0p4Smx4dHNKTEVvTVhyakVYOXhEWlFMSW9KWDExWFJmSSJ9'
// did:pkh spec example: an Ethereum mainnet account.
const PKH = 'did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a'

test('did:key: an Ed25519 key becomes a Multikey document with every relationship', () => {
  const doc = localDidDocument(ED)
  assert.equal(doc.id, ED)
  assert.equal(doc.verificationMethod.length, 1)
  const vm = doc.verificationMethod[0]
  assert.equal(vm.type, 'Multikey')
  assert.equal(vm.controller, ED)
  assert.equal(vm.publicKeyMultibase, 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK')
  assert.equal(vm.id, `${ED}#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`)
  for (const rel of ['authentication', 'assertionMethod', 'capabilityInvocation', 'capabilityDelegation']) {
    assert.deepEqual(doc[rel], [vm.id], rel)
  }
  assert.equal(doc.keyAgreement, undefined, 'no X25519 derivation is claimed')
})

test('did:key: an X25519 key is for key agreement only; wrong lengths and unknown codecs are refused', () => {
  // did:key spec: X25519 example.
  const x = 'did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc'
  const doc = localDidDocument(x)
  assert.deepEqual(doc.keyAgreement, [`${x}#z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc`])
  assert.equal(doc.authentication, undefined)
  const short = 'did:key:' + base58btc.encode(Buffer.from([0xed, 0x01, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]))
  assert.throws(() => localDidDocument(short), /32 bytes, this one is 10/)
  const unknown = 'did:key:' + base58btc.encode(Buffer.from([0x99, 0x01, 1, 2, 3]))
  assert.throws(() => localDidDocument(unknown), /unsupported key type/)
  assert.throws(() => localDidDocument('did:key:abc'), /base58btc/)
  assert.throws(() => localDidDocument('did:key:z0OIl'), /base58btc/)
})

test('did:jwk: a P-256 key, with every relationship; a bent point and a private key are refused', () => {
  const doc = localDidDocument(JWK)
  assert.equal(doc.id, JWK)
  const vm = doc.verificationMethod[0]
  assert.equal(vm.id, `${JWK}#0`)
  assert.equal(vm.type, 'JsonWebKey2020')
  assert.deepEqual(vm.publicKeyJwk, {
    crv: 'P-256',
    kty: 'EC',
    x: '02AzL62byDr6_0p0DeilFr8bj7P942D_HQOXnB-UPuI',
    y: '6KZgB_0nawJxJlxtsJLEoMXrjEX9xDZQLIoJX11XRfI'
  })
  for (const rel of ['authentication', 'assertionMethod', 'capabilityInvocation', 'capabilityDelegation', 'keyAgreement']) {
    assert.deepEqual(doc[rel], [vm.id], rel)
  }
  // `use: enc` on a real X25519 key — the did:key X25519 spec example's own
  // 32 bytes, written as a JWK.
  const X25519 = 'BIiFcQEn3dfvB2pjlhOQQour6jXy9d5s2FKEJNTOJik'
  const enc = 'did:jwk:' + Buffer.from(JSON.stringify({ kty: 'OKP', crv: 'X25519', x: X25519, use: 'enc' })).toString('base64url')
  const encDoc = localDidDocument(enc)
  assert.deepEqual(encDoc.keyAgreement, [`${enc}#0`])
  assert.equal(encDoc.authentication, undefined, 'an encryption key signs nothing')
  assert.equal(encDoc.assertionMethod, undefined)
  // A key that is the right shape and the wrong curve point is refused: the
  // key is imported, not measured.
  const bent = 'did:jwk:' + Buffer.from(JSON.stringify({
    crv: 'P-256',
    kty: 'EC',
    x: 'acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0',
    y: '_KcyLj9vWMptnpKhJpfePeHt6fuY6hQsnUJE7n1u2E4'
  })).toString('base64url')
  assert.throws(() => localDidDocument(bent), /invalid public key/)
  // Private material is refused before the key is ever imported.
  const priv = 'did:jwk:' + Buffer.from(JSON.stringify({ kty: 'OKP', crv: 'Ed25519', x: 'AAAA', d: 'secret' })).toString('base64url')
  assert.throws(() => localDidDocument(priv), /private/)
  assert.throws(() => localDidDocument('did:jwk:not-base64-json'), /JSON Web Key/)
})

test('did:pkh: the spec\'s Ethereum example; a bad address or an unknown chain is refused', () => {
  const doc = localDidDocument(PKH)
  assert.equal(doc.id, PKH)
  const vm = doc.verificationMethod[0]
  assert.equal(vm.type, 'EcdsaSecp256k1RecoveryMethod2020')
  assert.equal(vm.blockchainAccountId, 'eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a')
  assert.deepEqual(doc.authentication, [`${PKH}#blockchainAccountId`])
  assert.equal(localDidDocument('did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev').verificationMethod[0].type, 'Ed25519VerificationKey2018')
  assert.throws(() => localDidDocument('did:pkh:eip155:1:0xnotanaddress'), /malformed eip155/)
  assert.throws(() => localDidDocument('did:pkh:cosmos:cosmoshub-3:cosmos1abc'), /unsupported chain/)
  assert.throws(() => localDidDocument('did:pkh:eip155:0xb9c5714089478a327f09197987f16f9e5d936e8a'), /CAIP-10/)
})

test('other methods are not local, and the handler answers the local ones without fetching', async () => {
  assert.equal(localDidDocument('did:web:example.com'), null)
  assert.equal(localDidDocument('did:plc:abc'), null)
  assert.equal(isLocalDidMethod('did:key:z6'), true)
  assert.equal(isLocalDidMethod('did:web:x'), false)
  const fetched = []
  const handler = await createDidHandler({ fetchImpl: async (url) => { fetched.push(url); throw new Error('no network') } })
  const res = await handler({ url: `did://${ED.slice(4)}` })
  assert.equal(res.status, 200)
  assert.equal(res.headers.get('X-Resolution-Trust'), 'derived')
  assert.equal((await res.json()).id, ED)
  const bad = await handler({ url: 'did:pkh:eip155:1:0xzz' })
  assert.equal(bad.status, 400)
  assert.match(await bad.text(), /malformed/)
  assert.deepEqual(fetched, [], 'nothing was fetched')
})
