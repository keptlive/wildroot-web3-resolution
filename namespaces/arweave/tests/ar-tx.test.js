/*
 * The transaction header, bound to the identifier END TO END (src/ar-tx.js).
 *
 * The id is SHA-256 of the signature, and hashing the signature is all the
 * check used to be — which left `owner`, `data_root`, `data_size`, `tags`,
 * `target`, `quantity`, `reward` and `last_tx` free for a gateway to swap,
 * with the byte check then hashing against a root of the gateway's choosing.
 * These tests hold the signature to those fields.
 *
 * THE VECTORS ARE REAL. Both headers were fetched from
 * `https://arweave.net/tx/<id>` on 2026-09-12 and are stored verbatim under
 * tests/fixtures/arweave:
 *
 *   EDGVy6AAKFNKEA3LsjZJ5OXv82eRvJPsomCA4AWC7y8  format 2, 5,725 bytes, two
 *     tags (an ANS-104 bundle) — the same transaction whose BYTES are the
 *     ar-merkle.js fixture, so the two tests meet: the root that check hashes
 *     against is the root this one proves the id commits to.
 *   9TbUmxOrrRpdCh5UfDWO27ogWVLtf_udheVravCyAVY  format 1, 3,694 bytes, three
 *     tags, data inline — the legacy signature, a plain concatenation.
 *
 * The deep-hash vectors are arweave-js's own function's output
 * (`arweave@1.15.7 node/lib/deepHash.js`), computed and pinned here.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'

import { deepHash, headerVerdict, signatureData, MAX_FORMAT_1_DATA } from '../src/ar-tx.js'
import { headerMatchesId } from '../src/ar.js'
import { bytesMatchRoot } from '../src/ar-merkle.js'

const fixture = (name) => JSON.parse(readFileSync(new URL(`./fixtures/arweave/${name}`, import.meta.url), 'utf8'))
const FORMAT_2 = fixture('EDGVy6AAKFNKEA3LsjZJ5OXv82eRvJPsomCA4AWC7y8.tx.json')
const FORMAT_1 = fixture('9TbUmxOrrRpdCh5UfDWO27ogWVLtf_udheVravCyAVY.tx.json')

/** The same header with one base64url field's first byte flipped. */
function flip (header, field) {
  const bytes = Buffer.from(String(header[field]), 'base64url')
  bytes[0] ^= 1
  return { ...header, [field]: bytes.toString('base64url') }
}

const B = (s) => Buffer.from(s, 'utf8')

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
  // The tags are what stop a re-grouping from hashing alike.
  assert.notEqual(deepHash([B('ab')]).toString('hex'), deepHash([B('a'), B('b')]).toString('hex'))
  assert.notEqual(deepHash(B('a')).toString('hex'), deepHash([B('a')]).toString('hex'))
})

test('a real format-2 transaction header verifies against its id, fields and all', () => {
  assert.equal(FORMAT_2.format, 2)
  assert.equal(headerVerdict(FORMAT_2, FORMAT_2.id), 'verified')
  assert.equal(headerMatchesId(FORMAT_2, FORMAT_2.id), true)
  // The two checks meet: the bytes ar-merkle.js hashes are this proven
  // header's, under a data root the signature now binds to the id.
  const bytes = readFileSync(new URL('./fixtures/arweave/EDGVy6AAKFNKEA3LsjZJ5OXv82eRvJPsomCA4AWC7y8.bin', import.meta.url))
  assert.equal(Number(FORMAT_2.data_size), bytes.length)
  assert.equal(bytesMatchRoot(bytes, FORMAT_2.data_root), true)
})

test('a swapped data_root is a mismatch — the lie the byte check would otherwise inherit', () => {
  const swapped = flip(FORMAT_2, 'data_root')
  assert.notEqual(swapped.data_root, FORMAT_2.data_root)
  assert.equal(headerVerdict(swapped, FORMAT_2.id), 'mismatch')
  assert.equal(headerMatchesId(swapped, FORMAT_2.id), false)
  // ... and the swapped root is a root the served bytes would never hash to.
  const bytes = readFileSync(new URL('./fixtures/arweave/EDGVy6AAKFNKEA3LsjZJ5OXv82eRvJPsomCA4AWC7y8.bin', import.meta.url))
  assert.equal(bytesMatchRoot(bytes, swapped.data_root), false)
})

test('a swapped data_size is a mismatch', () => {
  assert.equal(headerVerdict({ ...FORMAT_2, data_size: String(Number(FORMAT_2.data_size) + 1) }, FORMAT_2.id), 'mismatch')
  assert.equal(headerVerdict({ ...FORMAT_2, data_size: '0' }, FORMAT_2.id), 'mismatch')
})

test('a tag added, removed or edited is a mismatch', () => {
  const added = { ...FORMAT_2, tags: [...FORMAT_2.tags, { name: B('x').toString('base64url'), value: B('y').toString('base64url') }] }
  assert.equal(headerVerdict(added, FORMAT_2.id), 'mismatch')
  assert.equal(headerVerdict({ ...FORMAT_2, tags: FORMAT_2.tags.slice(1) }, FORMAT_2.id), 'mismatch')
  assert.equal(headerVerdict({ ...FORMAT_2, tags: [] }, FORMAT_2.id), 'mismatch')
  const edited = { ...FORMAT_2, tags: [flip(FORMAT_2.tags[0], 'value'), FORMAT_2.tags[1]] }
  assert.equal(headerVerdict(edited, FORMAT_2.id), 'mismatch')
})

test('a swapped owner is a mismatch, whether it is another real wallet or a bent one', () => {
  assert.equal(headerVerdict({ ...FORMAT_2, owner: FORMAT_1.owner }, FORMAT_2.id), 'mismatch',
    'another real 4096-bit wallet does not sign this transaction')
  assert.equal(headerVerdict(flip(FORMAT_2, 'owner'), FORMAT_2.id), 'mismatch')
  // A key that is not RSA-4096 is not a key this implementation can check —
  // nothing is proven and nothing is claimed, which is not the same as a lie.
  assert.equal(headerVerdict({ ...FORMAT_2, owner: FORMAT_2.owner.slice(0, 100) }, FORMAT_2.id), 'unsupported')
  assert.equal(headerVerdict({ ...FORMAT_2, owner: '' }, FORMAT_2.id), 'unsupported')
})

test('the other signed fields are bound too: target, quantity, reward, last_tx', () => {
  assert.equal(headerVerdict({ ...FORMAT_2, target: FORMAT_2.owner.slice(0, 43) }, FORMAT_2.id), 'mismatch')
  assert.equal(headerVerdict({ ...FORMAT_2, quantity: '1' }, FORMAT_2.id), 'mismatch')
  assert.equal(headerVerdict({ ...FORMAT_2, reward: '1' }, FORMAT_2.id), 'mismatch')
  assert.equal(headerVerdict(flip(FORMAT_2, 'last_tx'), FORMAT_2.id), 'mismatch')
})

test('a signature that does not hash to the id is a mismatch, and so is no signature at all', () => {
  assert.equal(createHash('sha256').update(Buffer.from(FORMAT_2.signature, 'base64url')).digest().toString('base64url'),
    FORMAT_2.id, 'the id IS SHA-256 of the signature')
  assert.equal(headerVerdict(flip(FORMAT_2, 'signature'), FORMAT_2.id), 'mismatch')
  assert.equal(headerVerdict(FORMAT_2, FORMAT_1.id), 'mismatch', 'a real header, served for another id')
  assert.equal(headerVerdict({ ...FORMAT_2, signature: '' }, FORMAT_2.id), 'mismatch')
  assert.equal(headerVerdict({ ...FORMAT_2, signature: undefined }, FORMAT_2.id), 'mismatch')
  assert.equal(headerVerdict({}, FORMAT_2.id), 'mismatch')
  assert.equal(headerVerdict(null, FORMAT_2.id), 'mismatch')
})

test('a real format-1 transaction verifies by the legacy concatenation, data included', () => {
  assert.equal(FORMAT_1.format, 1)
  assert.equal(FORMAT_1.data_root, '', 'format 1 commits to no Merkle root')
  assert.equal(headerVerdict(FORMAT_1, FORMAT_1.id), 'verified')
  assert.equal(Buffer.from(FORMAT_1.data, 'base64url').length, Number(FORMAT_1.data_size))
  // The DATA is inside a format-1 signature, so editing it is a mismatch.
  assert.equal(headerVerdict(flip(FORMAT_1, 'data'), FORMAT_1.id), 'mismatch')
  assert.equal(headerVerdict({ ...FORMAT_1, tags: FORMAT_1.tags.slice(1) }, FORMAT_1.id), 'mismatch')
  assert.equal(headerVerdict({ ...FORMAT_1, reward: '1' }, FORMAT_1.id), 'mismatch')
  // An absent `format` field is format 1 — the field was added with format 2.
  const { format, ...noFormat } = FORMAT_1
  assert.equal(format, 1)
  assert.equal(headerVerdict(noFormat, FORMAT_1.id), 'verified')
})

test('a header this implementation cannot check is UNSUPPORTED: nothing proven, never passed as proven', () => {
  // A format nobody here constructs a payload for. The id check still ran.
  const future = { ...FORMAT_2, format: 3 }
  assert.equal(headerVerdict(future, FORMAT_2.id), 'unsupported')
  assert.equal(headerMatchesId(future, FORMAT_2.id), false, 'unsupported is not verified')
  assert.equal(signatureData(future), null)
  // ... and a format 3 header whose signature is not the id's is still a lie.
  assert.equal(headerVerdict({ ...future, signature: flip(FORMAT_2, 'signature').signature }, FORMAT_2.id), 'mismatch')
  // Format 1 without the data it signed: not checkable, not a lie.
  const { data, ...stripped } = FORMAT_1
  assert.ok(data)
  assert.equal(headerVerdict(stripped, FORMAT_1.id), 'unsupported')
  assert.equal(headerVerdict({ ...FORMAT_1, data_size: '999999' }, FORMAT_1.id), 'unsupported',
    'data that is not the length the header declares is not the data to hash')
  // Fields of the wrong shape are unsupported, not silently coerced.
  assert.equal(signatureData({ ...FORMAT_2, tags: 'nope' }), null)
  assert.equal(signatureData({ ...FORMAT_2, tags: [{ name: 5, value: 'x' }] }), null)
  assert.equal(signatureData({ ...FORMAT_2, quantity: '1e9' }), null, 'a decimal string, not a number literal')
  assert.equal(signatureData({ ...FORMAT_2, reward: -1 }), null)
  assert.ok(MAX_FORMAT_1_DATA >= 8 * 1024 * 1024)
})
