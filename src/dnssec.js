/*
 * DNSSEC validation anchored to the Handshake chain.
 *
 * This closes the browser's one real trust gap. Resolution proves *which*
 * nameserver owns a TLD (Urkel proof from the SPV node), but the TXT/A/TLSA
 * answers that server returns travel over unauthenticated DNS — an on-path
 * attacker could forge a "no pin" reply and strip DANE. DNSSEC fixes that:
 *
 *     Handshake chain   DS = hash of the zone's KSK   <- trust root, on-chain
 *            │
 *     zone apex         DNSKEY, self-signed by the KSK's RRSIG
 *            │
 *     _443._tcp.name    TLSA, signed by an RRSIG under that DNSKEY
 *            │
 *     browser           verifies the chain; a forged/stripped answer has no
 *                       valid RRSIG under a DNSKEY that hashes to the DS
 *
 * Because only the name's owner can set the on-chain DS (it is in the name's
 * Handshake resource), the chain replaces the ICANN root of trust entirely.
 *
 * Algorithms: the RFC 8624 set a validator MUST or SHOULD implement —
 * 8 (RSASHA256), 13 (ECDSAP256SHA256, what our own signer dnssec.py and the
 * Handshake ecosystem use), 14 (ECDSAP384SHA384) and 15 (ED25519) — with DS
 * digest types 2 (SHA-256) and 4 (SHA-384). Until 2026-09-05 this file did
 * 13/2 alone, which meant an RSA-signed zone was refused outright; RFC 8624
 * §3.1 makes RSASHA256 a MUST for validators. Everything else (SHA-1 based
 * algorithms, GOST, ED448, DS digest type 1) is treated as unvalidatable and
 * fails closed when the chain says the zone is signed.
 */

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto'

import { provesNoExactMatch } from './denial.js'

const ALG_RSASHA256 = 8
const ALG_ECDSAP256 = 13
const ALG_ECDSAP384 = 14
const ALG_ED25519 = 15
const DIGEST_SHA256 = 2
const DIGEST_SHA384 = 4

/**
 * The signature algorithms this browser can verify (RFC 8624 §3.1: 8 and 13
 * are MUST, 15 is RECOMMENDED, 14 is MAY), and the DS digest types it can
 * anchor to (§3.3: 2 MUST, 4 MAY). Exported so a caller can tell "this zone
 * is signed with something we cannot check" apart from "this zone's signature
 * is wrong" — two very different things to say to a user.
 */
export const SUPPORTED_ALGORITHMS = Object.freeze([
  ALG_RSASHA256, ALG_ECDSAP256, ALG_ECDSAP384, ALG_ED25519])
export const SUPPORTED_DIGESTS = Object.freeze([DIGEST_SHA256, DIGEST_SHA384])

/** Kept for callers that named the old single profile; 13/2 is still the common case. */
export const SUPPORTED_DS = Object.freeze({
  algorithm: ALG_ECDSAP256,
  digestType: DIGEST_SHA256
})

/** Is this DS one we could actually anchor to? */
export function isSupportedDs (ds) {
  return !!ds && SUPPORTED_ALGORITHMS.includes(ds.algorithm) &&
    SUPPORTED_DIGESTS.includes(ds.digestType)
}

// SPKI DER prefixes, so a bare DNSKEY public key becomes a KeyObject without
// hand-rolling ASN.1. Each ends at the BIT STRING's unused-bits byte; the raw
// key (for EC, 0x04||X||Y) follows.
const P256_SPKI_PREFIX = Buffer.from(
  '3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex')
const P384_SPKI_PREFIX = Buffer.from(
  '3076301006072a8648ce3d020106052b81040022036200', 'hex')
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

/** The hash a DS digest type names, in node:crypto's spelling, or null. */
function digestHash (digestType) {
  if (digestType === DIGEST_SHA256) return 'sha256'
  if (digestType === DIGEST_SHA384) return 'sha384'
  return null
}

export function wireName (name) {
  const out = []
  for (const label of name.replace(/\.$/, '').toLowerCase().split('.')) {
    if (!label) continue
    const b = Buffer.from(label, 'ascii')
    out.push(Buffer.from([b.length]), b)
  }
  out.push(Buffer.from([0]))
  return Buffer.concat(out)
}

/** RFC 4034 App. B key tag over DNSKEY rdata. */
export function keyTag (rdata) {
  let total = 0
  for (let i = 0; i < rdata.length; i++) {
    total += (i & 1) ? rdata[i] : rdata[i] << 8
  }
  total += (total >> 16) & 0xffff
  return total & 0xffff
}

/**
 * DNSKEY rdata (flags||proto||alg||pubkey) for a raw public key. The
 * algorithm defaults to 13 because every caller that predates the wider set
 * meant exactly that; a parsed DNSKEY passes its own (`rec.algorithm`).
 */
export function dnskeyRdata (rawPubKey, flags = 257, algorithm = ALG_ECDSAP256, protocol = 3) {
  const head = Buffer.alloc(4)
  head.writeUInt16BE(flags, 0)
  head.writeUInt8(protocol, 2)
  head.writeUInt8(algorithm, 3)
  return Buffer.concat([head, rawPubKey])
}

/** DS digest of a DNSKEY, per RFC 4034 §5.1.4 — SHA-256 unless told otherwise. */
export function dsDigest (ownerName, dnskeyRdataBuf, digestType = DIGEST_SHA256) {
  const hash = digestHash(digestType)
  if (!hash) throw new Error(`unsupported DS digest type ${digestType}`)
  return createHash(hash)
    .update(Buffer.concat([wireName(ownerName), dnskeyRdataBuf]))
    .digest('hex')
}

/**
 * A DNSKEY's public key field -> a KeyObject, by algorithm. Returns null for
 * an algorithm we do not do or a key of the wrong shape, and the caller
 * treats that as "did not verify".
 *
 *   8   RFC 3110 §2: exponent length (one byte, or 0x00 + two bytes), the
 *       exponent, then the modulus. Node takes it as a JWK.
 *   13  RFC 6605 §4: 64 bytes, X||Y, uncompressed.
 *   14  RFC 6605 §4: 96 bytes, X||Y.
 *   15  RFC 8080 §3: the 32-byte Ed25519 public key as-is.
 */
export function publicKeyFromDnskey (algorithm, rawPubKey) {
  const raw = Buffer.isBuffer(rawPubKey) ? rawPubKey : Buffer.from(rawPubKey || [])
  try {
    if (algorithm === ALG_ECDSAP256) {
      if (raw.length !== 64) return null
      return createPublicKey({ key: Buffer.concat([P256_SPKI_PREFIX, Buffer.from([0x04]), raw]), format: 'der', type: 'spki' })
    }
    if (algorithm === ALG_ECDSAP384) {
      if (raw.length !== 96) return null
      return createPublicKey({ key: Buffer.concat([P384_SPKI_PREFIX, Buffer.from([0x04]), raw]), format: 'der', type: 'spki' })
    }
    if (algorithm === ALG_ED25519) {
      if (raw.length !== 32) return null
      return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: 'der', type: 'spki' })
    }
    if (algorithm === ALG_RSASHA256) {
      if (raw.length < 3) return null
      let expLen = raw[0]
      let at = 1
      if (expLen === 0) {
        if (raw.length < 3) return null
        expLen = raw.readUInt16BE(1)
        at = 3
      }
      if (expLen === 0 || at + expLen >= raw.length) return null
      const e = raw.subarray(at, at + expLen)
      const n = raw.subarray(at + expLen)
      // 1024..4096-bit moduli (128..512 bytes). RFC 8624 §3.1 keeps RSA
      // below 1024 bits out (breakable); above 4096 is a cost a hostile
      // zone imposes on us for no security gain.
      if (n.length < 128 || n.length > 512) return null
      return createPublicKey({
        key: { kty: 'RSA', n: n.toString('base64url'), e: e.toString('base64url') },
        format: 'jwk'
      })
    }
  } catch {
    return null
  }
  return null
}

/** Verify one signature under one DNSSEC algorithm, or false. */
function verifySignature (algorithm, key, data, signature) {
  try {
    if (algorithm === ALG_ECDSAP256) {
      return cryptoVerify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, signature)
    }
    if (algorithm === ALG_ECDSAP384) {
      return cryptoVerify('sha384', data, { key, dsaEncoding: 'ieee-p1363' }, signature)
    }
    if (algorithm === ALG_ED25519) {
      return cryptoVerify(null, data, key, signature)
    }
    if (algorithm === ALG_RSASHA256) {
      return cryptoVerify('sha256', data, key, signature)
    }
  } catch {
    return false
  }
  return false
}

/**
 * Verify one RRSIG over an RRset with a raw alg-13 public key.
 * @param {object} rrsig  {typeCovered(number), algorithm, labels, originalTtl,
 *                          expiration, inception, keyTag, signer, signature(Buffer)}
 * @param {string} owner  RRset owner name
 * @param {Buffer[]} rdatas  canonical rdata buffers
 * @param {Buffer} rawPubKey 64-byte X||Y
 */
export function verifyRRSIG (rrsig, owner, rdatas, rawPubKey) {
  return verifyRRSIGAt(Math.floor(Date.now() / 1000), rrsig, owner, rdatas, rawPubKey)
}

/**
 * The same verification, judged against an EXPLICIT clock.
 *
 * ------------------------------------------------------------------------
 * SECURITY. The RRSIG validity window is a gate, not a formality: a caller
 * that controls `now` can make an expired -- or revoked -- signature verify
 * forever. So this is built to be unreachable by accident:
 *
 *   - `now` is the FIRST POSITIONAL argument, never a property of an options
 *     object. That is deliberate. If it were a field, any caller that ever
 *     spread resolver output or config into the options ({ ...untrusted })
 *     could set it, and signature replay would be a data-shape bug away.
 *     Positional-first means an attacker-controlled object literally cannot
 *     become the clock.
 *   - `verifyRRSIG` / `validateChain` -- the ONLY functions production uses --
 *     take no clock at all and always read the real one.
 *   - `now` must be a finite, non-negative integer or verification FAILS
 *     CLOSED. NaN, undefined, Infinity and strings do not sail through the
 *     comparison as they otherwise would (NaN makes both `<` and `>` false,
 *     which would have skipped the window check entirely).
 *   - tests/hns/dnssec-clock-guard.test.js fails the build if anything under
 *     src/ calls this. The boundary is enforced, not remembered.
 *
 * It exists only so the suite can verify the FROZEN signed-zone fixture at
 * tests/fixtures/dir.dnssec.json, whose RRSIGs carry a fixed 30-day window,
 * and so the expiry check itself can be tested -- which nothing covered before.
 * ------------------------------------------------------------------------
 *
 * @param {number} now UNIX seconds to judge the validity window against
 * @param {object} rrsig
 * @param {string} owner
 * @param {Buffer[]} rdatas
 * @param {Buffer} rawPubKey
 */
/** The reason string validateChain uses for a wildcard-expanded RRset. */
export const WILDCARD_REASON =
  'the answer was expanded from a wildcard and the zone did not prove there is ' +
  'no closer match (RFC 4035 §5.3.4)'

/**
 * Wildcards, both halves of RFC 4035. An RRSIG's `labels` counts the labels of
 * the name it was SIGNED under, excluding the root and any leading `*`
 * (RFC 4034 §3.1.3), so a signature made over `*.example` and served at
 * `a.b.example` carries labels=1 against an owner of 2. §5.3.2 rebuilds the
 * wildcard name to verify the signature (wildcardOwner, below); §5.3.4 then
 * requires an authenticated denial that the queried name has no records of
 * its own (validateChainAt's `denial`), or a zone's wildcard signature could be
 * replayed at a name that DOES have its own records. Until 2026-09-04 neither
 * half was implemented and a wildcard answer failed closed with a sentence
 * that accused the zone of tampering.
 */

/**
 * The name a wildcard-expanded RRset was actually SIGNED under, or null when
 * the RRset is not wildcard-expanded.
 *
 * RFC 4035 §5.3.2: `*.` followed by the rightmost `labels` labels of the owner.
 * @param {{labels?: number}} rrsig
 * @param {string} owner
 */
export function wildcardOwner (rrsig, owner) {
  if (!isWildcardExpanded(rrsig, owner)) return null
  const labels = ownerLabels(owner)
  return `*.${labels.slice(labels.length - Number(rrsig.labels)).join('.')}`
}

/**
 * The labels of an owner name AS RFC 4034 §3.1.3 COUNTS THEM: without the
 * root, and without a leading `*`. The RFC's own example is that
 * `*.example.com.` has a Labels field of 2. Counting the `*` — which this file
 * did until 2026-09-05 — made every RRset owned by a wildcard name itself look
 * wildcard-EXPANDED, so it demanded a §5.3.4 proof that could not exist and
 * refused it. The NSEC owned by `*.zone` is exactly such an RRset, and it is
 * the record an NXDOMAIN proof in a zone with a wildcard has to read.
 */
function ownerLabels (owner) {
  const labels = String(owner || '').replace(/\.$/, '').split('.').filter(Boolean)
  if (labels[0] === '*') labels.shift()
  return labels
}

export function isWildcardExpanded (rrsig, owner) {
  const labels = rrsig && Number(rrsig.labels)
  if (!Number.isFinite(labels)) return false
  return labels < ownerLabels(owner).length
}

export function verifyRRSIGAt (now, rrsig, owner, rdatas, rawPubKey) {
  if (!Number.isSafeInteger(now) || now < 0) return false
  if (!SUPPORTED_ALGORITHMS.includes(rrsig.algorithm)) return false
  if (now < rrsig.inception || now > rrsig.expiration) return false

  const pre = Buffer.alloc(18)
  pre.writeUInt16BE(rrsig.typeCovered, 0)
  pre.writeUInt8(rrsig.algorithm, 2)
  pre.writeUInt8(rrsig.labels, 3)
  pre.writeUInt32BE(rrsig.originalTtl, 4)
  pre.writeUInt32BE(rrsig.expiration, 8)
  pre.writeUInt32BE(rrsig.inception, 12)
  pre.writeUInt16BE(rrsig.keyTag, 16)

  // RFC 4035 §5.3.2: the name in the signed data is the RRset's owner —
  // EXCEPT for a wildcard-expanded RRset, where it is the name the zone
  // actually signed, `*.` followed by the rightmost `labels` labels. Using the
  // expanded owner there produces a signature that cannot verify, which is why
  // this used to look like "wildcards are unsupported".
  const signedName = wildcardOwner(rrsig, owner) || owner

  // RRs in canonical order: sort by raw rdata (RFC 4034 §6.3).
  const sorted = [...rdatas].sort(Buffer.compare)
  const parts = [pre, wireName(rrsig.signer)]
  for (const rd of sorted) {
    const hdr = Buffer.alloc(10)
    hdr.writeUInt16BE(rrsig.typeCovered, 0)
    hdr.writeUInt16BE(1, 2) // class IN
    hdr.writeUInt32BE(rrsig.originalTtl, 4)
    hdr.writeUInt16BE(rd.length, 8)
    parts.push(wireName(signedName), hdr, rd)
  }
  const data = Buffer.concat(parts)

  const key = publicKeyFromDnskey(rrsig.algorithm, rawPubKey)
  if (!key) return false
  return verifySignature(rrsig.algorithm, key, data, rrsig.signature)
}

/**
 * May this served DNSKEY verify this RRSIG? The key must be a zone key
 * (RFC 4034 §2.1.1), not revoked (RFC 5011), protocol 3, and of the RRSIG's
 * own algorithm — a DNSKEY RRset anchored as a whole can still carry keys
 * that are not for signing.
 */
function zoneKeyUsable (k, rrsig) {
  if (!k || !rrsig) return false
  if ((k.flags & 0x0100) === 0 || (k.flags & 0x0080) !== 0) return false
  if (Number.isInteger(k.protocol) && k.protocol !== 3) return false
  const alg = Number.isInteger(k.algorithm) ? k.algorithm : ALG_ECDSAP256
  return alg === rrsig.algorithm
}

/**
 * Full chain validation for a leaf RRset.
 * @param {object} args
 *   dsRecords: on-chain DS [{keyTag, algorithm, digestType, digest}]
 *   dnskeys:   [{flags, rawPubKey}] apex DNSKEYs served by the zone
 *   dnskeyRRSIG: RRSIG over the DNSKEY RRset
 *   leafOwner, leafType(number), leafRdatas: the RRset being trusted
 *   leafRRSIG: RRSIG over the leaf RRset
 * @returns {{ok:boolean, reason?:string}}
 */
export function validateChain (opts) {
  return validateChainAt(Math.floor(Date.now() / 1000), opts)
}

/**
 * validateChain against an EXPLICIT clock. Same rules as verifyRRSIGAt: `now`
 * is positional-first so it can never arrive inside `opts`, and any `now`
 * field on `opts` is ignored outright rather than trusted. Test-only; the
 * clock guard test enforces that src/ never calls it.
 *
 * @param {number} now UNIX seconds
 * @param {object} opts see validateChain
 */
export function validateChainAt (now, {
  dsRecords, dnskeys, dnskeyRRSIG, leafOwner,
  leafType, leafRdatas, leafRRSIG, denial = null
}) {
  if (!Number.isSafeInteger(now) || now < 0) {
    return { ok: false, reason: 'invalid verification clock' }
  }
  const signer = leafRRSIG && leafRRSIG.signer
  if (!signer) return { ok: false, reason: 'leaf RRset unsigned' }

  // Steps 1-2: anchor the zone's DNSKEY set to the DS we were handed.
  const anchored = anchorZoneKeysAt(now, {
    dsRecords, dnskeys, dnskeyRRSIG, zone: signer
  })
  if (!anchored.ok) return anchored

  // 3. The leaf RRset must be signed under a validated zone key. (Our zones
  //    use one combined signing key; accept any served DNSKEY, since the
  //    DNSKEY set as a whole is now anchored.)
  for (const k of dnskeys) {
    if (!zoneKeyUsable(k, leafRRSIG)) continue
    if (verifyRRSIGAt(now, { ...leafRRSIG, typeCovered: leafType }, leafOwner,
      leafRdatas, k.rawPubKey)) {
      // 4. BOTH HALVES OF THE WILDCARD RULE. The signature verifying against
      //    the reconstructed `*.` name (§5.3.2) is not the end of it: §5.3.4
      //    says the validator "must take additional steps to verify the
      //    non-existence of an exact match or closer wildcard match for the
      //    query". Without that, a zone's wildcard signature can be lifted and
      //    replayed at a name that has its OWN records, with the real ones
      //    simply withheld — so a verified signature alone would be an answer
      //    for a name the zone never meant to answer for.
      if (isWildcardExpanded(leafRRSIG, leafOwner)) {
        if (!denial || !denial.records || !denial.records.length) {
          return { ok: false, reason: WILDCARD_REASON }
        }
        if (!provesNoExactMatch(denial.records, leafOwner, denial.zone || signer)) {
          return { ok: false, reason: WILDCARD_REASON }
        }
      }
      return { ok: true }
    }
  }
  return { ok: false, reason: 'leaf RRSIG did not verify under any anchored DNSKEY' }
}

/**
 * Anchor a zone's served DNSKEY set to a DS RRset: some served key must hash
 * to a DS, and the DNSKEY RRset must be self-signed by that key.
 *
 * Split out of validateChain because a DELEGATION needs exactly this and
 * nothing else: to trust `pinner.hns`'s keys the browser first anchors
 * `hns`'s keys to the on-chain DS, then verifies the DS RRset `hns` publishes
 * FOR `pinner.hns` under them (validateDs), and that DS becomes the anchor one
 * level down. Duplicating the logic per level is how a chain walk grows a hole.
 *
 * @param {number} now UNIX seconds
 * @param {object} opts dsRecords, dnskeys, dnskeyRRSIG, zone (the apex owner)
 * @returns {{ok:boolean, reason?:string, dnskeyRdatas?:Buffer[]}}
 */
export function anchorZoneKeysAt (now, { dsRecords, dnskeys, dnskeyRRSIG, zone }) {
  if (!Number.isSafeInteger(now) || now < 0) {
    return { ok: false, reason: 'invalid verification clock' }
  }
  const ds = (dsRecords || []).filter(isSupportedDs)
  if (!ds.length) return { ok: false, reason: 'no usable DS on-chain' }
  if (!dnskeys || !dnskeys.length) return { ok: false, reason: 'zone served no DNSKEY' }
  if (!zone) return { ok: false, reason: 'no zone to anchor' }

  // The served key's own algorithm and protocol go into its rdata — a parsed
  // DNSKEY carries both; a test's bare {flags, rawPubKey} means 13/3.
  const algOf = (k) => (Number.isInteger(k.algorithm) ? k.algorithm : ALG_ECDSAP256)
  const dnskeyRdatas = dnskeys.map((k) => dnskeyRdata(
    k.rawPubKey, k.flags, algOf(k), Number.isInteger(k.protocol) ? k.protocol : 3))

  // RFC 4034 §2.1.1-2.1.2: a key with the Zone Key bit clear, or a protocol
  // other than 3, MUST NOT be used to verify RRSIGs. RFC 5011 §2.1: a key
  // with the REVOKE bit set is out too. Kept out of the anchor search rather
  // than merely out of the signature loop, so a DS that names such a key
  // anchors nothing.
  const usable = (k) => ((k.flags & 0x0100) !== 0) && ((k.flags & 0x0080) === 0) &&
    (!Number.isInteger(k.protocol) || k.protocol === 3)

  let anchor = null
  for (let i = 0; i < dnskeys.length && !anchor; i++) {
    const k = dnskeys[i]
    if (!usable(k)) continue
    const rd = dnskeyRdatas[i]
    const tag = keyTag(rd)
    for (const d of ds) {
      if (d.keyTag !== tag || d.algorithm !== algOf(k)) continue
      let digest
      try {
        digest = dsDigest(zone, rd, d.digestType)
      } catch {
        continue
      }
      if (String(d.digest || '').toLowerCase() === digest) {
        anchor = { key: k, rdata: rd, tag, algorithm: algOf(k) }
        break
      }
    }
  }
  if (!anchor) return { ok: false, reason: 'no DNSKEY matches the on-chain DS' }

  // The DNSKEY RRset is signed by the anchored key (RFC 4035 §5.2), and the
  // RRSIG's algorithm must be that key's — a signature under some other
  // algorithm was made by some other key.
  if (!dnskeyRRSIG || dnskeyRRSIG.algorithm !== anchor.algorithm ||
    !verifyRRSIGAt(now, { ...dnskeyRRSIG, typeCovered: 48 }, zone, dnskeyRdatas,
      anchor.key.rawPubKey)) {
    return { ok: false, reason: 'DNSKEY RRSIG did not verify against the DS-anchored key' }
  }
  return { ok: true, dnskeyRdatas }
}

/**
 * The DS RRset a PARENT zone publishes for a child, verified under the
 * parent's own anchored keys. This is the one link that makes a delegation
 * secure rather than a place where an on-path answer takes over: without it,
 * following `hns`'s referral to `ns1.lumeweb` would mean trusting whatever
 * that server says about `pinner.hns` on nobody's authority.
 *
 * An EMPTY, correctly-signed answer is not handled here — an insecure
 * delegation is the caller's decision to make (src/hns/resolver.js), and it
 * carries the same NSEC caveat that file already documents.
 *
 * @param {number} now UNIX seconds
 * @param {object} opts
 *   dsRecords/dnskeys/dnskeyRRSIG: the PARENT's anchor and served keys
 *   parentZone: the parent apex owner name
 *   childOwner:  the delegated name the DS RRset is about
 *   childDs:     the DS records read from the parent [{...,rdataRaw}]
 *   childDsRRSIG: RRSIG covering that DS RRset
 * @returns {{ok:boolean, reason?:string, ds?:Array}}
 */
export function validateDsAt (now, {
  dsRecords, dnskeys, dnskeyRRSIG, parentZone, childOwner, childDs, childDsRRSIG
}) {
  const anchored = anchorZoneKeysAt(now, {
    dsRecords, dnskeys, dnskeyRRSIG, zone: parentZone
  })
  if (!anchored.ok) return anchored

  const rdatas = (childDs || []).filter((d) => d && d.rdataRaw).map((d) => d.rdataRaw)
  if (!rdatas.length) return { ok: false, reason: 'no DS rdata to verify' }
  if (!childDsRRSIG) return { ok: false, reason: 'DS RRset at the delegation is unsigned' }

  for (const k of dnskeys) {
    if (!zoneKeyUsable(k, childDsRRSIG)) continue
    if (verifyRRSIGAt(now, { ...childDsRRSIG, typeCovered: 43 }, childOwner,
      rdatas, k.rawPubKey)) {
      return { ok: true, ds: childDs }
    }
  }
  return { ok: false, reason: 'DS RRSIG did not verify under any anchored DNSKEY' }
}

/** validateDsAt against the real clock — the only form src/ may call. */
export function validateDs (opts) {
  return validateDsAt(Math.floor(Date.now() / 1000), opts)
}

/** anchorZoneKeysAt against the real clock. */
export function anchorZoneKeys (opts) {
  return anchorZoneKeysAt(Math.floor(Date.now() / 1000), opts)
}
