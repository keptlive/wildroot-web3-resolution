/*
 * src/hns/ar-tx.js against REAL transactions, and the three verdicts.
 *
 * The id is SHA-256 of the signature, and hashing the signature alone leaves
 * `owner`, `data_root`, `data_size`, `tags`, `target`, `quantity`, `reward`
 * and `last_tx` free for a gateway to swap — with the byte check then hashing
 * against a root of the gateway's choosing. These vectors hold the signature
 * to those fields, on transactions nobody here made:
 *
 *   EDGVy6AAKFNKEA3LsjZJ5OXv82eRvJPsomCA4AWC7y8  format 2, 5,725 bytes, two
 *     tags (an ANS-104 bundle) — the transaction whose BYTES are the
 *     ar-merkle.js fixture, so the two checks meet: the root that one hashes
 *     against is the root this one proves the id commits to.
 *   9TbUmxOrrRpdCh5UfDWO27ogWVLtf_udheVravCyAVY  format 1, 3,694 bytes, three
 *     tags, data inline — the legacy signature, a plain concatenation.
 *
 * Both were fetched from https://arweave.net/tx/<id> on 2026-09-12 and are
 * stored verbatim under tests/fixtures/arweave. The deep-hash vectors are
 * arweave-js's own function's output (arweave@1.15.7 node/lib/deepHash.js).
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'

import { deepHash, headerMatchesId, verifyTransactionHeader } from '../src/ar-tx.js'
import { bytesMatchRoot } from '../src/ar-merkle.js'

const fixture = (name) => new URL(`./fixtures/arweave/${name}`, import.meta.url)
const json = (name) => JSON.parse(readFileSync(fixture(name), 'utf8'))
const FORMAT_2 = json('EDGVy6AAKFNKEA3LsjZJ5OXv82eRvJPsomCA4AWC7y8.tx.json')
const FORMAT_1 = json('9TbUmxOrrRpdCh5UfDWO27ogWVLtf_udheVravCyAVY.tx.json')

/** The same header with one base64url field's first byte flipped. */
function flip (header, field) {
  const bytes = Buffer.from(String(header[field]), 'base64url')
  bytes[0] ^= 1
  return { ...header, [field]: bytes.toString('base64url') }
}

const B = (s) => Buffer.from(s, 'utf8')
const verdict = (header, txid) => verifyTransactionHeader(header, txid).verdict

test('deep hash: arweave-js\'s vectors, and the blob/list tags that keep shapes apart', () => {
  assert.equal(deepHash(B('')).toString('base64url'),
    '-_AMxET1_qncO-32KhP7qK6H50RfyRBWeiO-xOuC-tsRQ8QzBpMU2DYpg9w8Lko4')
  assert.equal(deepHash(B('arweave')).toString('base64url'),
    'QjOAloifwjwO5oJo36Y2H_88xi0ld_B3l5vv6e4Vu4IAvvCk0mMxt9LGRg7OpDaX')
  assert.equal(deepHash([]).toString('base64url'),
    'pp59N_3H8ECp7Baq6E3iT6tKZT2sTeC9JH42urn-RdkonFoEqJPJUoWBL1zvyXB6')
  assert.equal(deepHash([B('a'), [B('b'), B('c')]]).toString('base64url'),
    'MLzgp1PBcPIU9X3QJEvCnHZSaupAXNi_-K-DAafRBCThxX9jq01VBwuZ9I9yqMLn')
  assert.equal(deepHash(B('')).length, 48, 'SHA-384')
  assert.notEqual(deepHash([B('ab')]).toString('hex'), deepHash([B('a'), B('b')]).toString('hex'))
  assert.notEqual(deepHash(B('a')).toString('hex'), deepHash([B('a')]).toString('hex'))
})

test('a real format-2 transaction verifies against its id, fields and all', () => {
  assert.equal(FORMAT_2.format, 2)
  const result = verifyTransactionHeader(FORMAT_2, FORMAT_2.id)
  assert.equal(result.verdict, 'verified')
  assert.equal(result.dataSize, 5725n)
  assert.equal(result.dataRoot, FORMAT_2.data_root)
  assert.equal(result.data, null, 'format 2 commits to a root, not to inline data')
  assert.equal(headerMatchesId(FORMAT_2, FORMAT_2.id), true)
  // The two checks meet: the bytes ar-merkle.js hashes are this transaction's,
  // under a root the signature now binds to the id.
  const bytes = readFileSync(fixture('EDGVy6AAKFNKEA3LsjZJ5OXv82eRvJPsomCA4AWC7y8.bin'))
  assert.equal(Number(result.dataSize), bytes.length)
  assert.equal(bytesMatchRoot(bytes, result.dataRoot), true)
})

test('a swapped data_root or data_size is a mismatch — the lie the byte check would inherit', () => {
  const swapped = flip(FORMAT_2, 'data_root')
  assert.notEqual(swapped.data_root, FORMAT_2.data_root)
  assert.equal(verdict(swapped, FORMAT_2.id), 'mismatch')
  const bytes = readFileSync(fixture('EDGVy6AAKFNKEA3LsjZJ5OXv82eRvJPsomCA4AWC7y8.bin'))
  assert.equal(bytesMatchRoot(bytes, swapped.data_root), false)
  assert.equal(verdict({ ...FORMAT_2, data_size: '5726' }, FORMAT_2.id), 'mismatch')
})

test('a tag added, removed or edited on a real transaction is a mismatch', () => {
  const added = { ...FORMAT_2, tags: [...FORMAT_2.tags, { name: B('x').toString('base64url'), value: B('y').toString('base64url') }] }
  assert.equal(verdict(added, FORMAT_2.id), 'mismatch')
  assert.equal(verdict({ ...FORMAT_2, tags: FORMAT_2.tags.slice(1) }, FORMAT_2.id), 'mismatch')
  assert.equal(verdict({ ...FORMAT_2, tags: [] }, FORMAT_2.id), 'mismatch')
  assert.equal(verdict({ ...FORMAT_2, tags: [flip(FORMAT_2.tags[0], 'value'), FORMAT_2.tags[1]] }, FORMAT_2.id), 'mismatch')
})

test('a swapped owner is caught; a key that is not RSA-4096 is simply not checkable', () => {
  assert.equal(verdict({ ...FORMAT_2, owner: FORMAT_1.owner }, FORMAT_2.id), 'mismatch',
    'another real 4096-bit wallet does not sign this transaction')
  assert.equal(verdict(flip(FORMAT_2, 'owner'), FORMAT_2.id), 'mismatch')
  assert.equal(verdict({ ...FORMAT_2, owner: Buffer.alloc(256, 129).toString('base64url') }, FORMAT_2.id), 'unsupported',
    'a 2048-bit modulus is not an Arweave wallet, so it is not checked as one')
  assert.equal(verdict({ ...FORMAT_2, owner: '' }, FORMAT_2.id), 'unsupported')
})

test('the other signed fields are bound too: target, quantity, reward, last_tx', () => {
  assert.equal(verdict({ ...FORMAT_2, target: FORMAT_2.last_tx.slice(0, 43) }, FORMAT_2.id), 'mismatch')
  assert.equal(verdict({ ...FORMAT_2, quantity: '1' }, FORMAT_2.id), 'mismatch')
  assert.equal(verdict({ ...FORMAT_2, reward: '1' }, FORMAT_2.id), 'mismatch')
  assert.equal(verdict(flip(FORMAT_2, 'last_tx'), FORMAT_2.id), 'mismatch')
})

test('a signature that does not hash to the id is a mismatch, and so is no signature at all', () => {
  assert.equal(createHash('sha256').update(Buffer.from(FORMAT_2.signature, 'base64url')).digest('base64url'),
    FORMAT_2.id, 'the id IS SHA-256 of the signature')
  assert.equal(verdict(flip(FORMAT_2, 'signature'), FORMAT_2.id), 'mismatch')
  assert.equal(verdict(FORMAT_2, FORMAT_1.id), 'mismatch', 'a real header, served for another id')
  assert.equal(verdict({ ...FORMAT_2, signature: '' }, FORMAT_2.id), 'mismatch')
  assert.equal(verdict({ ...FORMAT_2, id: FORMAT_1.id }, FORMAT_2.id), 'mismatch')
  assert.equal(verdict({}, FORMAT_2.id), 'mismatch')
  assert.equal(verdict(null, FORMAT_2.id), 'mismatch')
  assert.equal(verdict(FORMAT_2, 'not a txid'), 'mismatch')
})

test('a real format-1 transaction verifies by the legacy concatenation, its data included', () => {
  assert.equal(FORMAT_1.format, 1)
  assert.equal(FORMAT_1.data_root, '', 'format 1 commits to no Merkle root')
  const result = verifyTransactionHeader(FORMAT_1, FORMAT_1.id)
  assert.equal(result.verdict, 'verified')
  assert.equal(result.dataRoot, null)
  assert.equal(result.dataSize, 3694n)
  assert.deepEqual(result.data, Buffer.from(FORMAT_1.data, 'base64url'))
  // The DATA is inside a format-1 signature, so editing it is a mismatch.
  assert.equal(verdict(flip(FORMAT_1, 'data'), FORMAT_1.id), 'mismatch')
  assert.equal(verdict({ ...FORMAT_1, tags: FORMAT_1.tags.slice(1) }, FORMAT_1.id), 'mismatch')
  assert.equal(verdict({ ...FORMAT_1, reward: '1' }, FORMAT_1.id), 'mismatch')
  // `data_size` is NOT part of a format-1 signature, so it is never read: the
  // size that comes back is the signed data's own length.
  assert.equal(verifyTransactionHeader({ ...FORMAT_1, data_size: '999999' }, FORMAT_1.id).dataSize, 3694n)
  // An absent `format` field is format 1 — the field arrived with format 2.
  const { format, ...noFormat } = FORMAT_1
  assert.equal(format, 1)
  assert.equal(verdict(noFormat, FORMAT_1.id), 'verified')
})

test('a header this implementation cannot check is UNSUPPORTED, never verified', () => {
  for (const fields of [
    { format: 3 },
    { format: '2' },
    { signature_type: 'secp256k1' },
    { signature_type: 3 },
    { denomination: '2' } // format 1 has no denomination field
  ]) {
    const header = { ...FORMAT_1, ...fields }
    assert.equal(verdict(header, FORMAT_1.id), 'unsupported', JSON.stringify(fields))
    assert.equal(headerMatchesId(header, FORMAT_1.id), false, 'unsupported is not verified')
  }
  // Format 1 without the data it signed, or with more of it than this
  // implementation will hold: not checkable, and not a lie either.
  const { data, ...stripped } = FORMAT_1
  assert.ok(data)
  assert.equal(verdict(stripped, FORMAT_1.id), 'unsupported')
  assert.equal(verdict({ ...FORMAT_1, data: 'A'.repeat(400_000) }, FORMAT_1.id), 'unsupported')
  // ... but a format-3 header whose signature is not the id's is still a lie.
  assert.equal(verdict({ ...FORMAT_2, format: 3, signature: flip(FORMAT_2, 'signature').signature }, FORMAT_2.id), 'mismatch')
})
