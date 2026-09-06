// The identity anchors published under a Handshake name, from the READING
// side: `_hns.<name>` (which key controls this name) and the atproto binding
// receipt that authorises `_atproto.<name>` / the `/.well-known/atproto-did`
// proof.
//
// Deterministic: the key is a fixed 32-byte secret, not fresh randomness, so a
// failure is reproducible.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { controlKeyFromSecret } from '../src/keys.js'
import {
  signClaim, verifyClaim, signAtproto, verifyAtproto, atprotoEvent, claimEvent, CLAIM_KIND
} from '../src/receipt.js'
import {
  recordName, buildRecord, parseRecord, verifyRecord,
  encodeReceipt, decodeReceipt, RECORD_PREFIX, RECORD_VERSION
} from '../src/record.js'

const SECRET = Buffer.from('11'.repeat(32), 'hex')
const KEY = controlKeyFromSecret(SECRET)
const NAME = 'alice.wildroot'
const T0 = 1756000000
const DID = 'did:plc:ewvi7nxzyoun6zhxrhs64oiz'

// ------------------------------------------------------------ `_hns.<name>`

test('the control record lives at _hns.<name>, normalised', () => {
  assert.equal(RECORD_PREFIX, '_hns')
  assert.equal(recordName('Alice.Wildroot'), '_hns.alice.wildroot')
  assert.equal(recordName('alice.wildroot.'), '_hns.alice.wildroot')
})

test('build -> parse -> verify binds exactly this name, key and epoch', () => {
  const { receipt } = signClaim(
    { name: NAME, publicKey: KEY.publicKey, epoch: 2, createdAt: T0 }, SECRET)
  const txt = buildRecord({ publicKey: KEY.publicKey, epoch: 2, receipt })

  assert.equal(txt.length, 1)
  assert.ok(txt[0].length <= 255, 'one RFC 1035 character-string')
  assert.match(txt[0], new RegExp(`^v=${RECORD_VERSION};pubkey=[0-9a-f]{64};epoch=2;receipt=`))

  assert.deepEqual(parseRecord(txt),
    { publicKey: KEY.publicKey, epoch: 2, receipt: { createdAt: T0, sig: receipt.sig } })

  const bound = verifyRecord(NAME, txt)
  assert.deepEqual(bound, { bound: true, publicKey: KEY.publicKey, epoch: 2 })

  // The receipt names the name and the epoch, so neither can be swapped.
  assert.equal(verifyRecord('mallory.wildroot', txt).bound, false)
  assert.equal(verifyRecord(NAME, [txt[0].replace(';epoch=2;', ';epoch=3;')]).bound, false)
})

test('the receipt field is created_at + the raw 64-byte signature, base64url', () => {
  const sig = 'ab'.repeat(64)
  const encoded = encodeReceipt({ createdAt: T0, sig })
  assert.equal(encoded, `${T0}.${Buffer.from(sig, 'hex').toString('base64url')}`)
  assert.deepEqual(decodeReceipt(encoded), { createdAt: T0, sig })
  for (const bad of [null, 42, '', 'x', '0.abc', `${T0}.`, `${T0}.${'A'.repeat(10)}`]) {
    assert.equal(decodeReceipt(bad), null, `rejects ${String(bad)}`)
  }
})

test('unknown fields are ignored; a duplicated field is tampering, not merging', () => {
  const { receipt } = signClaim(
    { name: NAME, publicKey: KEY.publicKey, epoch: 1, createdAt: T0 }, SECRET)
  const [line] = buildRecord({ publicKey: KEY.publicKey, epoch: 1, receipt })
  assert.ok(parseRecord([line + ';future=x']), 'forward compatible')
  assert.equal(parseRecord([line, line]), null, 'a duplicated field is refused')
  for (const bad of [null, [], [123], ['v=hns2;' + line.slice(8)], ['no fields here']]) {
    assert.equal(parseRecord(bad), null)
  }
})

test('a field split across two TXT RECORDS is dropped, not merged', () => {
  // RFC 1035 §3.3.14: the character-strings of ONE record are concatenated
  // into one value (the caller does that, in ../../../src/pointers.js) and
  // separate records are separate values. Merging a field across two records
  // would let an attacker who can add a record complete somebody else's.
  const { receipt } = signClaim(
    { name: NAME, publicKey: KEY.publicKey, epoch: 1, createdAt: T0 }, SECRET)
  const [line] = buildRecord({ publicKey: KEY.publicKey, epoch: 1, receipt })
  const cut = line.indexOf('pubkey=') + 10
  assert.equal(parseRecord([line.slice(0, cut), line.slice(cut)]), null)
})

test('a string longer than a TXT character-string may be is refused', () => {
  // RFC 1035 §3.3.14 caps a <character-string> at 255 bytes; input longer
  // than that is input no nameserver could have served, and the parser will
  // not consider it.
  const { receipt } = signClaim(
    { name: NAME, publicKey: KEY.publicKey, epoch: 1, createdAt: T0 }, SECRET)
  const [line] = buildRecord({ publicKey: KEY.publicKey, epoch: 1, receipt })
  const pad = (n) => line + ';pad=' + 'x'.repeat(n - line.length - 5)

  assert.ok(parseRecord([pad(255)]), 'accepted at the wire maximum')
  assert.equal(parseRecord([pad(256)]), null, 'refused one byte past it')
  assert.equal(parseRecord([pad(1024)]), null)
})

test('the built record has no variable-length field, so its length is a fact', () => {
  // `pubkey` is 64 hex, `receipt` is a fixed-width base64url signature after
  // a decimal timestamp, and the NAME is not in the record at all. The
  // longest string any accepted (epoch, createdAt) pair can produce is well
  // inside one 255-byte character-string, which is why record.js states the
  // length rather than guarding a value that cannot vary.
  const { receipt } = signClaim(
    { name: NAME, publicKey: KEY.publicKey, epoch: 1, createdAt: T0 }, SECRET)
  const longest = buildRecord({
    publicKey: KEY.publicKey,
    epoch: Number.MAX_SAFE_INTEGER,
    receipt: { createdAt: Number.MAX_SAFE_INTEGER, sig: receipt.sig }
  })
  assert.ok(longest[0].length < 255, `worst case is ${longest[0].length} bytes`)
  assert.ok(parseRecord(longest), 'and it round-trips through the parser')
})

test('DI-10: nothing here refuses an OLDER epoch — replay is the caller\'s problem', () => {
  // A receipt for epoch 1 stays valid forever. If a previous holder's record
  // is ever served again it verifies; only DNSSEC-over-the-chain and a
  // caller-side monotonic memory (which does not exist) stop it being used.
  const old = signClaim(
    { name: NAME, publicKey: KEY.publicKey, epoch: 1, createdAt: T0 }, SECRET).receipt
  const txt = buildRecord({ publicKey: KEY.publicKey, epoch: 1, receipt: old })
  assert.equal(verifyRecord(NAME, txt).bound, true)
  assert.equal(verifyRecord(NAME, txt).epoch, 1)
})

// ------------------------------------------------ the atproto binding receipt

test('an atproto binding is a kind-30078 event over (name, key, epoch, did)', () => {
  const event = atprotoEvent(
    { name: NAME, publicKey: KEY.publicKey, did: DID, epoch: 1, createdAt: T0 })
  assert.equal(event.kind, CLAIM_KIND)
  assert.deepEqual(event.tags, [
    ['v', 'hns1'], ['d', `hns:atproto:${NAME}`], ['epoch', '1'], ['did', DID]
  ])
  const { receipt } = signAtproto(
    { name: NAME, publicKey: KEY.publicKey, did: DID, epoch: 1, createdAt: T0 }, SECRET)
  assert.ok(verifyAtproto(
    { name: NAME, publicKey: KEY.publicKey, did: DID, epoch: 1, createdAt: T0, sig: receipt.sig }))
})

test('the binding names the exact account: another DID does not verify', () => {
  const { receipt } = signAtproto(
    { name: NAME, publicKey: KEY.publicKey, did: DID, epoch: 1, createdAt: T0 }, SECRET)
  for (const field of [
    { did: 'did:plc:someoneelse' },
    { name: 'mallory.wildroot' },
    { epoch: 2 },
    { createdAt: T0 + 1 }
  ]) {
    assert.equal(verifyAtproto({
      name: NAME,
      publicKey: KEY.publicKey,
      did: DID,
      epoch: 1,
      createdAt: T0,
      sig: receipt.sig,
      ...field
    }), false, `changing ${Object.keys(field)[0]} breaks the signature`)
  }
})

test('the DID is lowercased before signing, so the preimage is canonical', () => {
  const { receipt } = signAtproto(
    { name: NAME, publicKey: KEY.publicKey, did: '  DID:PLC:ABC ', epoch: 1, createdAt: T0 }, SECRET)
  assert.ok(verifyAtproto({
    name: NAME, publicKey: KEY.publicKey, did: 'did:plc:abc', epoch: 1, createdAt: T0, sig: receipt.sig
  }))
})

test('a claim receipt and an atproto binding cannot be replayed as each other', () => {
  // The whole point of the `hns:atproto:` d-tag prefix.
  const claim = signClaim(
    { name: NAME, publicKey: KEY.publicKey, epoch: 1, createdAt: T0 }, SECRET).receipt
  const bind = signAtproto(
    { name: NAME, publicKey: KEY.publicKey, did: DID, epoch: 1, createdAt: T0 }, SECRET).receipt

  assert.notEqual(claim.sig, bind.sig)
  assert.equal(verifyAtproto({
    name: NAME, publicKey: KEY.publicKey, did: DID, epoch: 1, createdAt: T0, sig: claim.sig
  }), false, 'a claim receipt is not a handle grant')
  assert.equal(verifyClaim({
    name: NAME, publicKey: KEY.publicKey, epoch: 1, createdAt: T0, sig: bind.sig
  }), false, 'a handle grant is not a claim')

  // ...and the version tag is first in both preimages.
  assert.deepEqual(claimEvent(
    { name: NAME, publicKey: KEY.publicKey, epoch: 1, createdAt: T0 }).tags[0], ['v', 'hns1'])
})

test('malformed input is false, never a throw — this runs on untrusted zone data', () => {
  for (const sig of [null, undefined, 42, '', 'zz', 'a'.repeat(127)]) {
    assert.equal(verifyAtproto(
      { name: NAME, publicKey: KEY.publicKey, did: DID, epoch: 1, createdAt: T0, sig }), false)
    assert.equal(verifyClaim(
      { name: NAME, publicKey: KEY.publicKey, epoch: 1, createdAt: T0, sig }), false)
  }
  assert.equal(verifyAtproto(
    { name: 'not-an-sld', publicKey: KEY.publicKey, did: DID, epoch: 1, createdAt: T0, sig: 'a'.repeat(128) }), false)
  assert.deepEqual(verifyRecord(NAME, ['garbage']), { bound: false, reason: 'malformed record' })
})
