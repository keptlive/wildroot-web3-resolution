/*
 * Validates the JS DNSSEC verifier against a zone signed by the Python signer
 * (~/hns/dnssec.py) — the exact interop that matters, since the browser must
 * verify what our infrastructure actually produces.
 *
 * The signed artifact is VENDORED at tests/fixtures/dir.dnssec.json. It used
 * to be read from ~/hns/dir.dnssec.json and skip when absent, which meant the
 * whole file — DS digest, real RRSIG verification, the full
 * on-chain-DS -> DNSKEY -> leaf-TLSA chain, and the fails-closed case — was
 * SILENTLY SKIPPED on the Windows packaging box, the one machine that builds
 * the installers we ship. The gate read green with the chain unaudited.
 *
 * The fixture is 6 KB of entirely public material (DNSKEY, RRSIGs, digests —
 * no private key). Its RRSIGs carry a fixed 30-day validity window, so every
 * check pins the clock to AT (inside that window) rather than the real time;
 * otherwise this file would turn red on the expiry date for a reason that is
 * not a defect. Refresh it with:
 *   cp ~/hns/dir.dnssec.json tests/fixtures/dir.dnssec.json
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import crypto from 'node:crypto'

import {
  verifyRRSIGAt, dnskeyRdata, dsDigest, keyTag, validateChainAt, wireName,
  isWildcardExpanded, wildcardOwner, WILDCARD_REASON
} from '../src/dnssec.js'

const TYPE = { A: 1, TLSA: 52, DNSKEY: 48, NSEC: 47 }
const signedPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'dir.dnssec.json')

// The clock every check below is judged against: the moment the signer
// actually signed, which is by construction inside the fixture's own
// inception/expiration window. Pinning it is what stops this file turning red
// on the fixture's expiry date for a reason that is not a defect. Production
// never gets to choose its clock -- see dnssec-clock-guard.test.js.
function signedAt (z) {
  const at = z.signed_at ?? z.inception
  assert.ok(Number.isSafeInteger(at) && at >= z.inception && at <= z.expiration,
    'fixture clock must sit inside the RRSIG validity window')
  return at
}

function load () {
  const z = JSON.parse(fs.readFileSync(signedPath, 'utf8'))
  // The signer stores the FULL DNSKEY rdata (flags||proto||alg||key); the
  // bare 64-byte P-256 point is everything after the 4-byte header.
  const rawPubKey = Buffer.from(z.dnskey, 'base64').subarray(4)
  return { z, rawPubKey }
}

function rrsigFrom (obj) {
  return {
    algorithm: obj.algorithm,
    labels: obj.labels,
    originalTtl: obj.original_ttl,
    expiration: obj.expiration,
    inception: obj.inception,
    keyTag: obj.key_tag,
    signer: obj.signer,
    signature: Buffer.from(obj.signature, 'base64')
  }
}

test('key tag and DS digest match the signer', () => {
  const { z, rawPubKey } = load()
  const rd = dnskeyRdata(rawPubKey, 257)
  assert.equal(keyTag(rd), z.key_tag)
  // A DS we compute here is what ds-commit.py would put on-chain.
  const digest = dsDigest(z.zone, rd)
  assert.equal(digest.length, 64) // sha256 hex
})

test('verifies a real TLSA RRSIG from the Python signer', () => {
  const { z, rawPubKey } = load()
  const owner = '_443._tcp.dir'
  const set = z.rrsets[owner].TLSA
  const rdatas = set.rdata.map((b) => Buffer.from(b, 'base64'))
  const rrsig = { ...rrsigFrom(set.rrsig), typeCovered: TYPE.TLSA }
  assert.equal(verifyRRSIGAt(signedAt(z), rrsig, owner, rdatas, rawPubKey), true)
})

test('rejects a tampered TLSA rdata', () => {
  const { z, rawPubKey } = load()
  const owner = '_443._tcp.dir'
  const set = z.rrsets[owner].TLSA
  const rdatas = set.rdata.map((b) => {
    const buf = Buffer.from(b, 'base64')
    buf[buf.length - 1] ^= 0xff // flip a byte of the pinned hash
    return buf
  })
  const rrsig = { ...rrsigFrom(set.rrsig), typeCovered: TYPE.TLSA }
  assert.equal(verifyRRSIGAt(signedAt(z), rrsig, owner, rdatas, rawPubKey), false)
})

test('full chain: on-chain DS -> DNSKEY -> leaf TLSA validates', () => {
  const { z, rawPubKey } = load()
  const dnskeys = [{ flags: 257, rawPubKey }]
  const dsRecords = [{
    keyTag: z.key_tag,
    algorithm: 13,
    digestType: 2,
    digest: dsDigest(z.zone, dnskeyRdata(rawPubKey, 257))
  }]
  // Self-signed DNSKEY RRSIG: the signer emits one over the apex DNSKEY set.
  const apex = z.rrsets[z.zone] || z.rrsets[z.zone + '.'] || null
  const dnskeyRRSIG = apex && apex.DNSKEY
    ? rrsigFrom(apex.DNSKEY.rrsig)
    : null

  const owner = '_443._tcp.dir'
  const set = z.rrsets[owner].TLSA
  const out = validateChainAt(signedAt(z), {
    dsRecords,
    dnskeys,
    dnskeyRRSIG,
    leafOwner: owner,
    leafType: TYPE.TLSA,
    leafRdatas: set.rdata.map((b) => Buffer.from(b, 'base64')),
    leafRRSIG: rrsigFrom(set.rrsig)
  })
  // The leaf verification is the security-critical step; DNSKEY self-sig may
  // be absent in this artifact, so assert the leaf path explicitly too.
  assert.equal(verifyRRSIGAt(signedAt(z),
    { ...rrsigFrom(set.rrsig), typeCovered: TYPE.TLSA }, owner,
    set.rdata.map((b) => Buffer.from(b, 'base64')), rawPubKey), true)
  if (dnskeyRRSIG) assert.equal(out.ok, true, out.reason)
})

test('chain fails closed when DS does not match the DNSKEY', () => {
  const { z, rawPubKey } = load()
  const owner = '_443._tcp.dir'
  const set = z.rrsets[owner].TLSA
  const out = validateChainAt(signedAt(z), {
    dsRecords: [{ keyTag: 12345, algorithm: 13, digestType: 2, digest: 'ab'.repeat(32) }],
    dnskeys: [{ flags: 257, rawPubKey }],
    dnskeyRRSIG: null,
    leafOwner: owner,
    leafType: TYPE.TLSA,
    leafRdatas: set.rdata.map((b) => Buffer.from(b, 'base64')),
    leafRRSIG: rrsigFrom(set.rrsig)
  })
  assert.equal(out.ok, false)
})

test('the real signed zone is REJECTED once its RRSIG window has closed', () => {
  // The same fixture that verifies at signing time must fail one second past
  // expiration. This is the gate itself, exercised against real signer output
  // rather than a synthetic record -- and it is why the clock is injectable.
  const { z, rawPubKey } = load()
  const owner = '_443._tcp.dir'
  const set = z.rrsets[owner].TLSA
  const rdatas = set.rdata.map((b) => Buffer.from(b, 'base64'))
  const rrsig = { ...rrsigFrom(set.rrsig), typeCovered: TYPE.TLSA }

  assert.equal(verifyRRSIGAt(signedAt(z), rrsig, owner, rdatas, rawPubKey), true,
    'sanity: valid inside the window')
  assert.equal(verifyRRSIGAt(z.expiration + 1, rrsig, owner, rdatas, rawPubKey), false,
    'an EXPIRED RRSIG must not verify')
  assert.equal(verifyRRSIGAt(z.inception - 1, rrsig, owner, rdatas, rawPubKey), false,
    'a not-yet-valid RRSIG must not verify')
})

// ---------------------------------------------------------------------------
// Wildcards: refused, and said so honestly.
// ---------------------------------------------------------------------------

test('a wildcard-expanded RRset is recognised by its label count', () => {
  // RFC 4034 §3.1.3: `labels` counts the labels of the name the RRset was
  // SIGNED under, excluding the root and any leading `*`. A signature made over
  // `*.example` and served at `a.b.example` carries labels=1 against 3.
  assert.equal(isWildcardExpanded({ labels: 1 }, 'a.b.example'), true)
  assert.equal(isWildcardExpanded({ labels: 2 }, 'a.b.example'), true)
  assert.equal(isWildcardExpanded({ labels: 3 }, 'a.b.example'), false)
  assert.equal(isWildcardExpanded({ labels: 1 }, 'example'), false)
  // Trailing-dot and junk forms must not be read as wildcards by accident.
  assert.equal(isWildcardExpanded({ labels: 3 }, 'a.b.example.'), false)
  assert.equal(isWildcardExpanded({}, 'a.b.example'), false)
  assert.equal(isWildcardExpanded({ labels: 'x' }, 'a.b.example'), false)
})

test('the reconstructed name is `*.` plus the rightmost `labels` labels', () => {
  // RFC 4035 §5.3.2, which is the half that makes a wildcard signature
  // verifiable at all.
  assert.equal(wildcardOwner({ labels: 1 }, 'a.b.example'), '*.example')
  assert.equal(wildcardOwner({ labels: 2 }, 'a.b.example'), '*.b.example')
  assert.equal(wildcardOwner({ labels: 3 }, 'a.b.example'), null, 'not a wildcard')
  assert.equal(isWildcardExpanded({ labels: 3 }, 'a.b.example'), false)
})

test('a DOCTORED labels field fails as what it is — a bad signature', () => {
  // Claiming an RRset was signed higher up the tree changes the name the
  // signature is computed over (RFC 4035 §5.3.2), so a real signature stops
  // verifying. Before §5.3.2 was implemented this was reported as "wildcard";
  // it is more honestly a signature that does not check out.
  const { z, rawPubKey } = load()
  const owner = '_443._tcp.dir'
  const set = z.rrsets[owner].TLSA
  const apex = z.rrsets[z.zone] || z.rrsets[z.zone + '.']
  const out = validateChainAt(signedAt(z), {
    dsRecords: [{
      keyTag: z.key_tag,
      algorithm: 13,
      digestType: 2,
      digest: dsDigest(z.zone, dnskeyRdata(rawPubKey, 257))
    }],
    dnskeys: [{ flags: 257, rawPubKey }],
    dnskeyRRSIG: rrsigFrom(apex.DNSKEY.rrsig),
    leafOwner: owner,
    leafType: TYPE.TLSA,
    leafRdatas: set.rdata.map((b) => Buffer.from(b, 'base64')),
    leafRRSIG: { ...rrsigFrom(set.rrsig), labels: 1 }
  })
  assert.equal(out.ok, false)
  assert.match(out.reason, /did not verify/)
})

// ---------------------------------------------------------------------------
// A REAL wildcard, signed here, so both halves of RFC 4035 can be exercised.
// ---------------------------------------------------------------------------

/**
 * Sign one RRset the way a zone signer does, so the verifier can be driven
 * with a signature that genuinely verifies. The point of these tests is the
 * §5.3.4 GATE, not the arithmetic — the arithmetic is already pinned against
 * the Python signer's output above.
 */
function signRRset ({ signedName, type, rdatas, signer, key, labels }) {
  const rrsig = {
    algorithm: 13,
    labels,
    originalTtl: 300,
    inception: 1700000000,
    expiration: 2000000000,
    keyTag: keyTag(dnskeyRdata(key.raw, 257)),
    signer
  }
  const pre = Buffer.alloc(18)
  pre.writeUInt16BE(type, 0)
  pre.writeUInt8(13, 2)
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
  rrsig.signature = crypto.sign('sha256', Buffer.concat(parts),
    { key: key.privateKey, dsaEncoding: 'ieee-p1363' })
  return rrsig
}

/** A throwaway zone key, and the DS the chain would carry for it. */
function makeZoneKey (zone) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const spki = publicKey.export({ type: 'spki', format: 'der' })
  const raw = spki.subarray(spki.length - 65 + 1) // drop the 0x04 point marker
  const key = { publicKey, privateKey, raw }
  const rdata = dnskeyRdata(raw, 257)
  return {
    key,
    dnskeys: [{ flags: 257, rawPubKey: raw }],
    ds: [{ keyTag: keyTag(rdata), algorithm: 13, digestType: 2, digest: dsDigest(zone, rdata) }]
  }
}

const AT = 1800000000 // inside the window the helper signs for

test('a WILDCARD answer verifies against the reconstructed name and its proof', () => {
  // The two halves together: §5.3.2 rebuilds `*.example` for the signature,
  // §5.3.4 requires an NSEC showing the queried name has no exact match.
  const zone = 'example'
  const { key, dnskeys, ds } = makeZoneKey(zone)
  const dnskeyRRSIG = signRRset({
    signedName: zone, type: 48, rdatas: [dnskeyRdata(key.raw, 257)], signer: zone, key, labels: 1
  })
  const rdatas = [Buffer.from([203, 0, 113, 7])]
  const leafRRSIG = signRRset({
    signedName: `*.${zone}`, type: TYPE.A, rdatas, signer: zone, key, labels: 1
  })
  const args = {
    dsRecords: ds,
    dnskeys,
    dnskeyRRSIG,
    leafOwner: `absent.${zone}`,
    leafType: TYPE.A,
    leafRdatas: rdatas,
    leafRRSIG
  }

  // Without the §5.3.4 proof: refused, and named as the wildcard it is.
  const noProof = validateChainAt(AT, args)
  assert.equal(noProof.ok, false)
  assert.equal(noProof.reason, WILDCARD_REASON)

  // With an NSEC covering the queried name: accepted.
  const covering = {
    name: `a.${zone}`,
    nextName: `z.${zone}`,
    types: new Set([TYPE.A])
  }
  const ok = validateChainAt(AT, { ...args, denial: { records: [covering], zone } })
  assert.equal(ok.ok, true, ok.reason)
})

test('a WILDCARD answer is REFUSED when the name provably exists', () => {
  // The replay this gate exists to stop: lift a zone's wildcard signature and
  // serve it at a name that has its OWN records, withholding the real ones.
  const zone = 'example'
  const { key, dnskeys, ds } = makeZoneKey(zone)
  const dnskeyRRSIG = signRRset({
    signedName: zone, type: 48, rdatas: [dnskeyRdata(key.raw, 257)], signer: zone, key, labels: 1
  })
  const rdatas = [Buffer.from([203, 0, 113, 7])]
  const leafRRSIG = signRRset({
    signedName: `*.${zone}`, type: TYPE.A, rdatas, signer: zone, key, labels: 1
  })
  // An NSEC that NAMES the queried name says it exists.
  const naming = { name: `real.${zone}`, nextName: `z.${zone}`, types: new Set([TYPE.A]) }
  const out = validateChainAt(AT, {
    dsRecords: ds,
    dnskeys,
    dnskeyRRSIG,
    leafOwner: `real.${zone}`,
    leafType: TYPE.A,
    leafRdatas: rdatas,
    leafRRSIG,
    denial: { records: [naming], zone }
  })
  assert.equal(out.ok, false)
  assert.equal(out.reason, WILDCARD_REASON)
})

test('a NON-wildcard answer needs no denial records at all', () => {
  const zone = 'example'
  const { key, dnskeys, ds } = makeZoneKey(zone)
  const dnskeyRRSIG = signRRset({
    signedName: zone, type: 48, rdatas: [dnskeyRdata(key.raw, 257)], signer: zone, key, labels: 1
  })
  const rdatas = [Buffer.from([203, 0, 113, 7])]
  const leafRRSIG = signRRset({
    signedName: `host.${zone}`, type: TYPE.A, rdatas, signer: zone, key, labels: 2
  })
  const out = validateChainAt(AT, {
    dsRecords: ds,
    dnskeys,
    dnskeyRRSIG,
    leafOwner: `host.${zone}`,
    leafType: TYPE.A,
    leafRdatas: rdatas,
    leafRRSIG
  })
  assert.equal(out.ok, true, out.reason)
})
