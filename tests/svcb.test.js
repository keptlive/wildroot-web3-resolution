/*
 * SVCB / HTTPS records (type 65, RFC 9460).
 *
 * WHY THE PARSER EXISTS. An ICANN domain can say "reach me on this port, with
 * these protocols, and here is my ECH config" in one record. A Handshake zone
 * could say none of it, because nothing in this browser could read type 65 —
 * so the capability was missing from our side of the boundary rather than from
 * the namespace. It is also the record RFC 9848 requires a client to resolve
 * *before* the ClientHello, so ECH is unreachable without it.
 *
 * WHAT IT DOES NOT YET DO, stated plainly because the alternative is a comment
 * that overclaims: nothing QUERIES type 65 during resolution. Doing so would
 * cost a round trip on every A-record site, and no Handshake zone publishes one
 * yet — including ours. The parser is the half that has to exist first; wiring
 * the query is a small change (and the DANE consequence of honouring a `port`
 * hint is that the pin moves to `_<port>._tcp.<host>`, RFC 6698 §3, which the
 * TLSA lookup would have to follow).
 *
 * The fixtures are REAL rdata, captured from Cloudflare on 2026-09-04 —
 * including `crypto.cloudflare.com`, their ECH test host, whose record carries
 * an actual 71-byte ECH config list. Hand-built bytes would have proved only
 * that the test agrees with the parser.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { parseAnswers, TYPES } from '../src/dns-query.js'

/** Wrap rdata in a minimal DNS response so the real parser can be driven. */
function responseWith (owner, type, rdataHex) {
  const name = Buffer.concat([
    ...owner.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])),
    Buffer.from([0])
  ])
  const rdata = Buffer.from(rdataHex, 'hex')
  const header = Buffer.alloc(12)
  header.writeUInt16BE(0x1234, 0)
  header.writeUInt16BE(0x8180, 2)
  header.writeUInt16BE(1, 4) // qdcount
  header.writeUInt16BE(1, 6) // ancount
  const question = Buffer.concat([name, Buffer.from([0, type, 0, 1])])
  const rr = Buffer.concat([
    name,
    Buffer.from([0, type, 0, 1, 0, 0, 1, 44]),
    Buffer.from([(rdata.length >> 8) & 0xff, rdata.length & 0xff]),
    rdata
  ])
  return parseAnswers(Buffer.concat([header, question, rr]))
}

/** crypto.cloudflare.com, 2026-09-04 — the one with a live ECH config. */
const CRYPTO_CF = '0001000001000302683200040008a29f874fa29f884f000500470045fe0d0041cc0020' +
  '00205d8d147f0e8cb208f94d85d92f7d285bcb14ad619010e1ff66b26d3c319c0825000400010001' +
  '0012636c6f7564666c6172652d6563682e636f6d000000060020260647000007000000000000a29f' +
  '874f260647000007000000000000a29f884f'

/** cloudflare.com, same capture — h3 and h2, no ECH. */
const CF = '0001000001000602683302683200040008681084e5681085e50006002026064700000000' +
  '0000000000681084e5260647000000000000000000681085e5'

const httpsOf = (hex) => {
  const r = responseWith('example.test', TYPES.HTTPS, hex)
  return r.answers.find((a) => a.type === TYPES.HTTPS)
}

test('priority and an empty target parse (the ". means this name" form)', () => {
  const rr = httpsOf(CF)
  assert.equal(rr.priority, 1)
  assert.equal(rr.target, '', 'the root target means "the owner name itself"')
})

test('the ALPN list parses in order', () => {
  assert.deepEqual(httpsOf(CF).params.alpn, ['h3', 'h2'])
  assert.deepEqual(httpsOf(CRYPTO_CF).params.alpn, ['h2'])
})

test('IPv4 hints parse as addresses', () => {
  assert.deepEqual(httpsOf(CF).params.ipv4hint, ['104.16.132.229', '104.16.133.229'])
  assert.deepEqual(httpsOf(CRYPTO_CF).params.ipv4hint, ['162.159.135.79', '162.159.136.79'])
})

test('a real ECH config list is kept as bytes, not dropped', () => {
  // The whole point of the record for RFC 9848. Discarding it here would mean
  // re-parsing the record later, which is how two implementations of one field
  // start.
  const ech = httpsOf(CRYPTO_CF).params.ech
  assert.ok(Buffer.isBuffer(ech))
  assert.equal(ech.length, 71)
  assert.equal(ech.readUInt16BE(0), 69, 'an ECHConfigList is length-prefixed')
  assert.equal(httpsOf(CF).params.ech, undefined, 'and absent when the zone publishes none')
})

test('unknown parameter keys are preserved rather than silently dropped', () => {
  // `key6` is ipv6hint, which we do not special-case; it must still survive so
  // a future consumer is not looking at a lossy parse.
  assert.ok(Buffer.isBuffer(httpsOf(CF).params.key6))
})

test('a truncated parameter stops the parse instead of reading past the record', () => {
  // priority 1, root target, then an alpn key claiming 0xffff bytes.
  const rr = httpsOf('000100' + '0001ffff' + '6832')
  assert.equal(rr.priority, 1)
  assert.deepEqual(rr.params, {}, 'a lying length must yield nothing, not garbage')
})

test('a truncated ALPN list stops at the bad entry, keeping what parsed', () => {
  // A well-formed 4-byte alpn value whose CONTENTS lie: [2]'h2', then a length
  // byte of 9 with nothing behind it. The outer parameter is intact, so the
  // inner list must stop rather than the whole record being discarded.
  const rr = httpsOf('000100' + '00010004' + '02683209')
  assert.deepEqual(rr.params.alpn, ['h2'])
})

test('an empty record parses to no parameters rather than throwing', () => {
  const rr = httpsOf('000100')
  assert.equal(rr.priority, 1)
  assert.deepEqual(rr.params, {})
})

test('the port hint parses — the one parameter a Handshake zone could use today', () => {
  // priority 1, root target, key 3 (port) length 2, value 8443.
  const rr = httpsOf('000100' + '00030002' + '20fb')
  assert.equal(rr.params.port, 8443)
})
