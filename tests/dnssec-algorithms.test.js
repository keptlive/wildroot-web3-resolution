/*
 * The RFC 8624 algorithm set, and the DNSKEY flags a validator must honour.
 *
 * Until 2026-09-05 dnssec.js verified ECDSAP256SHA256 (13) alone and anchored
 * to SHA-256 DS digests alone. RFC 8624 §3.1 makes RSASHA256 (8) a MUST for
 * validators, recommends ED25519 (15) and permits ECDSAP384SHA384 (14); §3.3
 * makes SHA-256 a MUST and SHA-384 a MAY for DS. A zone that chose any of the
 * three was told "this browser cannot verify" and refused — correct, and
 * unnecessary.
 *
 * Every key here is generated in the test and every signature made with it,
 * so what is exercised is the verifier's reading of RFC 3110 / 6605 / 8080
 * key formats and of the DS digest types — not the arithmetic, which
 * dnssec.test.js pins against the Python signer's real output.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'

import {
  validateChainAt, anchorZoneKeysAt, dnskeyRdata, dsDigest, keyTag, wireName,
  isSupportedDs, isWildcardExpanded, wildcardOwner, publicKeyFromDnskey,
  SUPPORTED_ALGORITHMS
} from '../src/dnssec.js'

const AT = 1800000000
const TYPE_A = 1
const TYPE_DNSKEY = 48

/** A zone key of the given DNSSEC algorithm, with its RFC wire form. */
function makeKey (algorithm) {
  if (algorithm === 8) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    const jwk = publicKey.export({ format: 'jwk' })
    const e = Buffer.from(jwk.e, 'base64url')
    const n = Buffer.from(jwk.n, 'base64url')
    // RFC 3110 §2: exponent length, exponent, modulus.
    const raw = Buffer.concat([Buffer.from([e.length]), e, n])
    return { publicKey, privateKey, raw, hash: 'sha256', opts: {} }
  }
  if (algorithm === 13 || algorithm === 14) {
    const curve = algorithm === 13 ? 'P-256' : 'P-384'
    const size = algorithm === 13 ? 64 : 96
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: curve })
    const spki = publicKey.export({ type: 'spki', format: 'der' })
    return {
      publicKey,
      privateKey,
      raw: spki.subarray(spki.length - size),
      hash: algorithm === 13 ? 'sha256' : 'sha384',
      opts: { dsaEncoding: 'ieee-p1363' }
    }
  }
  if (algorithm === 15) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
    const spki = publicKey.export({ type: 'spki', format: 'der' })
    return { publicKey, privateKey, raw: spki.subarray(spki.length - 32), hash: null, opts: {} }
  }
  throw new Error(`no generator for algorithm ${algorithm}`)
}

/** Sign an RRset the way a zone signer does (RFC 4034 §3.1.8.1). */
function signRRset ({ algorithm, key, signedName, type, rdatas, signer, labels, flags = 257 }) {
  const rrsig = {
    algorithm,
    labels,
    originalTtl: 300,
    inception: 1700000000,
    expiration: 2000000000,
    keyTag: keyTag(dnskeyRdata(key.raw, flags, algorithm)),
    signer
  }
  const pre = Buffer.alloc(18)
  pre.writeUInt16BE(type, 0)
  pre.writeUInt8(algorithm, 2)
  pre.writeUInt8(labels, 3)
  pre.writeUInt32BE(rrsig.originalTtl, 4)
  pre.writeUInt32BE(rrsig.expiration, 8)
  pre.writeUInt32BE(rrsig.inception, 12)
  pre.writeUInt16BE(rrsig.keyTag, 16)
  const parts = [pre, wireName(signer)]
  for (const rd of [...rdatas].sort(Buffer.compare)) {
    const hdr = Buffer.alloc(10)
    hdr.writeUInt16BE(type, 0)
    hdr.writeUInt16BE(1, 2)
    hdr.writeUInt32BE(rrsig.originalTtl, 4)
    hdr.writeUInt16BE(rd.length, 8)
    parts.push(wireName(signedName), hdr, rd)
  }
  rrsig.signature = crypto.sign(key.hash, Buffer.concat(parts), { key: key.privateKey, ...key.opts })
  return rrsig
}

/** A signed zone: DNSKEY RRset, its RRSIG, an A RRset at `host.<zone>`, and the DS. */
function signedZone (algorithm, { digestType = 2, flags = 257 } = {}) {
  const zone = 'example'
  const key = makeKey(algorithm)
  const rdata = dnskeyRdata(key.raw, flags, algorithm)
  const dnskeys = [{ flags, protocol: 3, algorithm, rawPubKey: key.raw }]
  const dnskeyRRSIG = signRRset({
    algorithm, key, signedName: zone, type: TYPE_DNSKEY, rdatas: [rdata], signer: zone, labels: 1, flags
  })
  const leafRdatas = [Buffer.from([203, 0, 113, 9])]
  const leafRRSIG = signRRset({
    algorithm, key, signedName: `host.${zone}`, type: TYPE_A, rdatas: leafRdatas, signer: zone, labels: 2, flags
  })
  const ds = [{ keyTag: keyTag(rdata), algorithm, digestType, digest: dsDigest(zone, rdata, digestType) }]
  return { zone, key, dnskeys, dnskeyRRSIG, leafRdatas, leafRRSIG, ds }
}

function validate (z, overrides = {}) {
  return validateChainAt(AT, {
    dsRecords: z.ds,
    dnskeys: z.dnskeys,
    dnskeyRRSIG: z.dnskeyRRSIG,
    leafOwner: `host.${z.zone}`,
    leafType: TYPE_A,
    leafRdatas: z.leafRdatas,
    leafRRSIG: z.leafRRSIG,
    ...overrides
  })
}

for (const algorithm of [8, 13, 14, 15]) {
  test(`algorithm ${algorithm}: a chain validates up to a SHA-256 DS`, () => {
    const z = signedZone(algorithm)
    assert.deepEqual(validate(z), { ok: true })
  })

  test(`algorithm ${algorithm}: a chain validates up to a SHA-384 DS`, () => {
    const z = signedZone(algorithm, { digestType: 4 })
    assert.deepEqual(validate(z), { ok: true })
  })

  test(`algorithm ${algorithm}: one flipped signature byte fails`, () => {
    const z = signedZone(algorithm)
    const sig = Buffer.from(z.leafRRSIG.signature)
    sig[sig.length - 1] ^= 0x01
    const out = validate(z, { leafRRSIG: { ...z.leafRRSIG, signature: sig } })
    assert.equal(out.ok, false)
  })

  test(`algorithm ${algorithm}: a DS naming another algorithm anchors nothing`, () => {
    const z = signedZone(algorithm)
    const other = algorithm === 13 ? 15 : 13
    const out = validate(z, { dsRecords: [{ ...z.ds[0], algorithm: other }] })
    assert.equal(out.ok, false)
    assert.match(out.reason, /DS/)
  })
}

test('the supported set is exactly RFC 8624\'s MUST + RECOMMENDED + ECDSAP384', () => {
  assert.deepEqual([...SUPPORTED_ALGORITHMS].sort((a, b) => a - b), [8, 13, 14, 15])
  assert.equal(isSupportedDs({ algorithm: 8, digestType: 2 }), true)
  assert.equal(isSupportedDs({ algorithm: 15, digestType: 4 }), true)
  assert.equal(isSupportedDs({ algorithm: 13, digestType: 1 }), false, 'SHA-1 DS is MUST NOT')
  assert.equal(isSupportedDs({ algorithm: 16, digestType: 2 }), false, 'ED448 is not implemented')
  assert.equal(isSupportedDs({ algorithm: 5, digestType: 2 }), false, 'RSASHA1 is MUST NOT')
})

test('an RSA key with an oversized or undersized modulus is refused', () => {
  const tiny = Buffer.concat([Buffer.from([1, 3]), Buffer.alloc(64, 1)])
  assert.equal(publicKeyFromDnskey(8, tiny), null)
  const huge = Buffer.concat([Buffer.from([1, 3]), Buffer.alloc(1024, 1)])
  assert.equal(publicKeyFromDnskey(8, huge), null)
  const twoByteExponent = Buffer.concat([Buffer.from([0, 0, 3]), Buffer.from([1, 0, 1]), Buffer.alloc(256, 1)])
  assert.ok(publicKeyFromDnskey(8, twoByteExponent), 'the 0x00 + two-byte exponent length form is legal')
})

test('EC and Ed25519 keys of the wrong length are refused', () => {
  assert.equal(publicKeyFromDnskey(13, Buffer.alloc(65)), null)
  assert.equal(publicKeyFromDnskey(14, Buffer.alloc(64)), null)
  assert.equal(publicKeyFromDnskey(15, Buffer.alloc(31)), null)
  assert.equal(publicKeyFromDnskey(16, Buffer.alloc(57)), null, 'ED448: not implemented, not guessed at')
})

// ---------------------------------------------------------------------------
// DNSKEY flags
// ---------------------------------------------------------------------------

test('a key with the Zone Key bit CLEAR may not verify anything (RFC 4034 §2.1.1)', () => {
  const z = signedZone(13, { flags: 1 })
  const out = validate(z)
  assert.equal(out.ok, false)
  assert.match(out.reason, /DS/)
})

test('a REVOKED key may not verify anything (RFC 5011 §2.1)', () => {
  const z = signedZone(13, { flags: 257 | 0x80 })
  assert.equal(validate(z).ok, false)
})

test('a protocol other than 3 is not a DNSSEC key', () => {
  const z = signedZone(13)
  const out = anchorZoneKeysAt(AT, {
    dsRecords: z.ds,
    dnskeyRRSIG: z.dnskeyRRSIG,
    zone: z.zone,
    dnskeys: [{ ...z.dnskeys[0], protocol: 4 }]
  })
  assert.equal(out.ok, false)
})

test('a bare {flags, rawPubKey} key still means 13/3 — the shape older callers pass', () => {
  const z = signedZone(13)
  const out = anchorZoneKeysAt(AT, {
    dsRecords: z.ds,
    dnskeyRRSIG: z.dnskeyRRSIG,
    zone: z.zone,
    dnskeys: [{ flags: 257, rawPubKey: z.key.raw }]
  })
  assert.equal(out.ok, true)
})

// ---------------------------------------------------------------------------
// RFC 4034 §3.1.3: the Labels field does not count a leading `*`
// ---------------------------------------------------------------------------

test('an RRset OWNED by a wildcard name is not wildcard-EXPANDED', () => {
  // The RFC's own example: `*.example.com.` has a Labels field of 2. Counting
  // the `*` made the NSEC owned by `*.zone` look expanded, so it demanded a
  // §5.3.4 proof that cannot exist and was dropped from every denial.
  assert.equal(isWildcardExpanded({ labels: 2 }, '*.example.com'), false)
  assert.equal(wildcardOwner({ labels: 2 }, '*.example.com'), null)
  assert.equal(isWildcardExpanded({ labels: 1 }, '*.example'), false)
  // ...while a genuinely expanded answer still is.
  assert.equal(isWildcardExpanded({ labels: 2 }, 'a.example.com'), true)
  assert.equal(wildcardOwner({ labels: 2 }, 'a.b.example.com'), '*.example.com')
  // And a wildcard signed one level deeper than its owner is a bad signature, not a wildcard.
  assert.equal(isWildcardExpanded({ labels: 1 }, '*.example.com'), true)
})

test('an RRset at a wildcard owner VERIFIES without a denial proof', () => {
  const zone = 'example'
  const key = makeKey(13)
  const rdata = dnskeyRdata(key.raw, 257, 13)
  const dnskeys = [{ flags: 257, protocol: 3, algorithm: 13, rawPubKey: key.raw }]
  const dnskeyRRSIG = signRRset({ algorithm: 13, key, signedName: zone, type: TYPE_DNSKEY, rdatas: [rdata], signer: zone, labels: 1 })
  const rdatas = [Buffer.from([203, 0, 113, 1])]
  const leafRRSIG = signRRset({ algorithm: 13, key, signedName: `*.${zone}`, type: TYPE_A, rdatas, signer: zone, labels: 1 })
  const out = validateChainAt(AT, {
    dsRecords: [{ keyTag: keyTag(rdata), algorithm: 13, digestType: 2, digest: dsDigest(zone, rdata) }],
    dnskeys,
    dnskeyRRSIG,
    leafOwner: `*.${zone}`,
    leafType: TYPE_A,
    leafRdatas: rdatas,
    leafRRSIG
  })
  assert.deepEqual(out, { ok: true })
})
