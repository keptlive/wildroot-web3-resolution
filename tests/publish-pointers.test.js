// The content-pointer convention shared by every resolution path.
//
// A name says where its content lives with a TXT record, and until this change
// that convention was implemented twice — once in the SPV/authoritative path
// (src/hns/resolver.js) and once in the DoH/ODoH path (src/hns/doh.js), each
// with its own regexes and its own ordering. They DISAGREED, which is pinned
// below: doh.js returned on the first ANSWER that matched, so a name carrying
// `ar=` before `ipfs=` resolved to Arweave over DoH and to IPFS over SPV.
//
// What is pinned here:
//   1. every pointer kind parses, and a malformed address is NOT a pointer
//   2. precedence is decided by the table, never by record order
//   3. writing and reading are inverses (a record round-trips unchanged)
//   4. both resolution paths really do use this one parser

import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import {
  POINTER_PRECEDENCE, dnslinkValue, parsePointer, pointerFrom, pointerRecord,
  txtStringsFrom
} from '../src/pointers.js'

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', 'src')
const read = (rel) => readFileSync(join(SRC, rel), 'utf8')

const CID = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi'
const CIDV0 = 'QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG'
const IPNS = 'k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8'
const INFOHASH = 'e84213a794f3ccd890382a54a64ca68b7e925433'
const BTPK = 'a'.repeat(64)
const HYPER = 'ybndrfg8ejkmcpqxot1uwisza345h769ybndrfg8ejkmcpqxot1u'
const ARTX = 'A'.repeat(43)

test('every pointer kind parses to its address', () => {
  assert.deepEqual(parsePointer(`ipfs=${CID}`), { kind: 'ipfs', cid: CID })
  assert.deepEqual(parsePointer(`ipfs=${CIDV0}`), { kind: 'ipfs', cid: CIDV0 })
  assert.deepEqual(parsePointer(`ipns=${IPNS}`), { kind: 'ipns', key: IPNS })
  assert.deepEqual(parsePointer(`ar=${ARTX}`), { kind: 'arweave', txid: ARTX })
  assert.deepEqual(parsePointer(`hyper=${HYPER}`), { kind: 'hyper', key: HYPER })
})

test('a torrent pointer is dispatched by KEY LENGTH, like bittorrent:// itself', () => {
  // 40 hex = an infohash: this exact snapshot, and it can never change.
  assert.deepEqual(parsePointer(`bt=${INFOHASH}`),
    { kind: 'bittorrent', key: INFOHASH, mutable: false })
  // 64 hex = a BEP-46 public key: the same address, updated in place.
  assert.deepEqual(parsePointer(`bt=${BTPK}`),
    { kind: 'bittorrent', key: BTPK, mutable: true })
  // 48 hex is neither, and half-trusting it would point a name at nothing.
  assert.equal(parsePointer(`bt=${'a'.repeat(48)}`), null)
})

test('a malformed address is not a pointer at all', () => {
  for (const bad of [
    'ipfs=', 'ipfs=notacid', `ipns=${'z'.repeat(4)}`, 'ar=too-short',
    `hyper=${'!'.repeat(52)}`, 'bt=', 'nonsense', '=x', '', null, undefined,
    // A CID under a tag we do not serve is still not ours to follow.
    `swarm=${CID}`
  ]) {
    assert.equal(parsePointer(bad), null, `should not parse: ${String(bad)}`)
  }
})

test('precedence comes from the table, NOT from the order of the records', () => {
  const records = [
    `ar=${ARTX}`, `hyper=${HYPER}`, `bt=${BTPK}`, `ipns=${IPNS}`, `ipfs=${CID}`
  ]
  assert.equal(pointerFrom(records).kind, 'ipfs')
  // Reversed input, identical verdict — this is the exact bug the two old
  // parsers had between them.
  assert.equal(pointerFrom([...records].reverse()).kind, 'ipfs')
  // And the full order, checked one drop at a time.
  const want = ['ipfs', 'ipns', 'bittorrent', 'hyper', 'arweave']
  assert.deepEqual(POINTER_PRECEDENCE, want)
  const left = [...records].reverse()
  for (const kind of want) {
    assert.equal(pointerFrom(left).kind, kind)
    left.splice(left.findIndex((r) => parsePointer(r).kind === kind), 1)
  }
  assert.equal(pointerFrom(left), null)
  assert.equal(pointerFrom([]), null)
})

test('a record written is a record read: writing and parsing are inverses', () => {
  for (const [kind, id] of [
    ['ipfs', CID], ['ipns', IPNS], ['bittorrent', BTPK],
    ['bittorrent', INFOHASH], ['hyper', HYPER], ['arweave', ARTX]
  ]) {
    const value = pointerRecord(kind, id)
    const back = parsePointer(value)
    assert.equal(back.kind, kind, value)
    // Byte-identical. CIDs (base32/base58) and Arweave txids (base64url) are
    // CASE-SENSITIVE: normalizing them would corrupt the address, so only the
    // hex keys below are touched.
    assert.equal(back.cid || back.key || back.txid, id, value)
  }
  // Hex IS normalized on the way out, so a re-publish of the same address is
  // not a spurious change in a zone diff.
  assert.equal(pointerRecord('bittorrent', BTPK.toUpperCase()), `bt=${BTPK}`)
  // An address that could never be read back is refused at WRITE time, where
  // the error still means something.
  assert.throws(() => pointerRecord('bittorrent', 'nope'), /not a valid/)
  assert.throws(() => pointerRecord('nonsense', CID), /unknown pointer kind/)
})

test('DNSLink prefers IPNS, because that record then never changes again', () => {
  assert.equal(dnslinkValue({ ipns: IPNS, cid: CID }), `dnslink=/ipns/${IPNS}`)
  assert.equal(dnslinkValue({ cid: CID }), `dnslink=/ipfs/${CID}`)
  assert.equal(dnslinkValue({ ipns: 'garbage', cid: CID }), `dnslink=/ipfs/${CID}`)
  assert.equal(dnslinkValue({}), null)
})

test('both resolution paths use the ONE parser, not their own copies', () => {
  for (const file of ['resolver.js', 'doh.js']) {
    const js = read(file)
    assert.match(js, /pointers\.js/, `${file} imports the shared parser`)
    assert.match(js, /pointerFrom/, `${file} calls it`)
    // The old private copies are gone: no local CID/ar regex, no inline
    // `ipfs=` match. If one comes back the two paths can disagree again.
    assert.doesNotMatch(js, /const CID_RE/, `${file} has no private CID regex`)
    assert.doesNotMatch(js, /const ARTX_RE/, `${file} has no private txid regex`)
    assert.doesNotMatch(js, /\^ipfs=/, `${file} does not re-parse ipfs= itself`)
  }
})

// EXTRACTION NOTE (hns-resolution): the browser's fourth copy of the CID
// shape lived in src/sia/restore.js and src/hns/ipfs.js, neither of which is
// part of the resolution stack. That test stays in the browser tree.

test('...and the ONE assembler, which is where they still disagreed', () => {
  // Sharing the parser was not enough: its INPUT was built three different
  // ways. resolver.js and hip5-op.js SPREAD a record's character-strings,
  // doh.js JOINED them, so the same TXT record read as a different pointer
  // depending on which path a user happened to be on.
  for (const file of ['resolver.js', 'doh.js', 'hip5-op.js']) {
    const js = read(file)
    assert.match(js, /txtStringsFrom/, `${file} uses the shared assembler`)
    assert.doesNotMatch(js, /\.txt\.join\(/, `${file} joins strings itself`)
    assert.doesNotMatch(js, /push\(\.\.\.\(rec\.txt/, `${file} spreads strings itself`)
    assert.doesNotMatch(js, /function txtStringsFrom/, `${file} has its own copy`)
  }
})

test('a record\'s character-strings are ONE value, per RFC 1035', () => {
  // A value over 255 bytes arrives split. Concatenating is what SPF, DKIM and
  // DNSLink all do, and what our own publisher's records assume.
  const long = [`ipfs=${CID}`.slice(0, 20), `ipfs=${CID}`.slice(20)]
  assert.deepEqual(txtStringsFrom([{ type: 16, txt: long }]), [`ipfs=${CID}`])
  assert.deepEqual(pointerFrom(txtStringsFrom([{ type: 16, txt: long }])),
    { kind: 'ipfs', cid: CID })
})

test('separate values are separate records, and order is preserved', () => {
  const out = txtStringsFrom([
    { type: 16, txt: ['ar=' + ARTX] },
    { type: 16, txt: [`ipfs=${CID}`] }
  ])
  assert.deepEqual(out, [`ar=${ARTX}`, `ipfs=${CID}`])
  // Precedence is the parser's job, and it still prefers the CID.
  assert.deepEqual(pointerFrom(out), { kind: 'ipfs', cid: CID })
})

test('the assembler reads raw rdata too, and ignores non-TXT answers', () => {
  const rdata = Buffer.concat([Buffer.from([9]), Buffer.from('ipfs=abc')])
  assert.deepEqual(txtStringsFrom([{ type: 16, rdata }], 16), ['ipfs=abc'])
  assert.deepEqual(txtStringsFrom([{ type: 1, txt: ['ipfs=nope'] }], 16), [])
  assert.deepEqual(txtStringsFrom([], 16), [])
  assert.deepEqual(txtStringsFrom(null, 16), [])
})

// The stated origin (`car=`) — decision D-P2 in STORAGE-PUBLISH-SHARE.md: where
// a published archive can be fetched from as a CAR and verified against
// `ipfs=`. A hint, never an address a name resolves to.
test('car= is an origin hint: https only, bounded, parsed and written round-trip — and never a pointer', async () => {
  const { parseOrigin, originFrom, originRecord, parsePointer, pointerFrom, ORIGIN_MAX_BYTES } = await import('../src/pointers.js')
  const url = 'https://indexer.pinthis.cloud/share/abc123?sig=def'
  assert.equal(parseOrigin(`car=${url}`), url)
  assert.equal(parseOrigin(`CAR= ${url} `), url, 'tag is case-insensitive, url is trimmed')
  assert.equal(parseOrigin('car=http://plain.example/x'), null, 'a bearer capability never travels in plaintext')
  assert.equal(parseOrigin('car=not a url'), null)
  assert.equal(parseOrigin('car='), null)
  assert.equal(parseOrigin(`car=https://x.example/${'a'.repeat(ORIGIN_MAX_BYTES)}`), null, 'bounded like a TXT string should be')
  assert.equal(originRecord(url), `car=${url}`)
  assert.throws(() => originRecord('ftp://x'), /not a usable origin/)
  assert.equal(originFrom(['ipfs=bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi', `car=${url}`]), url)
  assert.equal(originFrom(['ipfs=bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi']), null)
  // Not a pointer: resolution can never be handed a URL.
  assert.equal(parsePointer(`car=${url}`), null)
  assert.equal(pointerFrom([`car=${url}`, 'ipfs=bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi']).kind, 'ipfs')
  assert.equal(pointerFrom([`car=${url}`]), null)
})
