// A self-signed certificate for 127.0.0.1, built with no dependencies.
//
// WHY NOT A LIBRARY. The obvious candidates shell out to the `openssl` CLI
// (`pem`, which is already in the tree transitively) — and today proved what
// that costs: six DANE tests silently never ran on Windows for want of that
// binary. A browser that ships to machines without a toolchain cannot depend
// on one at runtime either. Node's crypto can generate the key and produce
// the SubjectPublicKeyInfo and the signature; the only thing missing is ~150
// lines of DER, which is what this file is.
//
// WHY THE KEY NEVER TOUCHES DISK. This certificate exists so Chromium will
// talk to a DoH endpoint on loopback (odoh-bridge.js), and it is trusted via
// `--ignore-certificate-errors-spki-list`, which makes Chromium accept that
// public key FOR ANY HOST. A key with that power sitting in the profile
// directory would be a standing MITM key for the whole browser. So it is
// generated fresh in memory at every launch and is gone when the process
// exits: nothing to steal later, and the pin is only valid for the run that
// created it.

import { createHash, createSign, generateKeyPairSync, randomBytes } from 'node:crypto'

// --------------------------------------------------------------- DER bits

const tag = (byte, body) => Buffer.concat([Buffer.from([byte]), len(body), body])

function len (body) {
  const n = body.length
  if (n < 0x80) return Buffer.from([n])
  const bytes = []
  let v = n
  while (v > 0) { bytes.unshift(v & 0xff); v >>= 8 }
  return Buffer.from([0x80 | bytes.length, ...bytes])
}

const seq = (...parts) => tag(0x30, Buffer.concat(parts))
const set = (...parts) => tag(0x31, Buffer.concat(parts))
const ctx = (n, body, constructed = true) => tag((constructed ? 0xa0 : 0x80) | n, body)
const bitString = (body) => tag(0x03, Buffer.concat([Buffer.from([0]), body]))
const octet = (body) => tag(0x04, body)
const bool = (v) => tag(0x01, Buffer.from([v ? 0xff : 0x00]))
const printable = (s) => tag(0x13, Buffer.from(s, 'ascii'))

function integer (buf) {
  let b = Buffer.isBuffer(buf) ? buf : Buffer.from([buf])
  while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.subarray(1)
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b])
  return tag(0x02, b)
}

function oid (dotted) {
  const parts = dotted.split('.').map(Number)
  const out = [parts[0] * 40 + parts[1]]
  for (const part of parts.slice(2)) {
    const chunk = []
    let v = part
    do { chunk.unshift(v & 0x7f); v >>= 7 } while (v > 0)
    for (let i = 0; i < chunk.length - 1; i++) chunk[i] |= 0x80
    out.push(...chunk)
  }
  return tag(0x06, Buffer.from(out))
}

function utcTime (date) {
  const p = (n) => String(n).padStart(2, '0')
  const s = p(date.getUTCFullYear() % 100) + p(date.getUTCMonth() + 1) +
    p(date.getUTCDate()) + p(date.getUTCHours()) + p(date.getUTCMinutes()) +
    p(date.getUTCSeconds()) + 'Z'
  return tag(0x17, Buffer.from(s, 'ascii'))
}

const OID = {
  commonName: '2.5.4.3',
  ecdsaWithSHA256: '1.2.840.10045.4.3.2',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  extKeyUsage: '2.5.29.37',
  serverAuth: '1.3.6.1.5.5.7.3.1',
  subjectAltName: '2.5.29.17'
}

/** SAN: DNS:localhost + IP:127.0.0.1 (the only names this is ever for). */
function subjectAltName () {
  const dns = tag(0x82, Buffer.from('localhost', 'ascii')) // [2] dNSName
  const ip = tag(0x87, Buffer.from([127, 0, 0, 1])) // [7] iPAddress
  return seq(oid(OID.subjectAltName), octet(seq(dns, ip)))
}

function extensions () {
  return ctx(3, seq(
    seq(oid(OID.basicConstraints), bool(true), octet(seq())), // CA:FALSE, critical
    seq(oid(OID.keyUsage), bool(true),
      octet(tag(0x03, Buffer.from([5, 0xa0])))), // digitalSignature|keyEncipherment
    seq(oid(OID.extKeyUsage), octet(seq(oid(OID.serverAuth)))),
    subjectAltName()
  ))
}

/**
 * A fresh P-256 key and a self-signed certificate for loopback.
 * @param {object} [opts]
 * @param {number} [opts.days] validity window (short by design — it is
 *   regenerated every launch, so a long life would only widen the window in
 *   which a leaked key is useful)
 * @returns {{cert: string, key: string, spkiPin: string}} PEMs plus the
 *   base64 SHA-256 of the SPKI, which is what Chromium's
 *   --ignore-certificate-errors-spki-list expects.
 */
export function generateLoopbackCert ({ days = 2 } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const spki = publicKey.export({ type: 'spki', format: 'der' })

  const name = seq(set(seq(oid(OID.commonName), printable('HNS.ONE ODoH bridge'))))
  const algo = seq(oid(OID.ecdsaWithSHA256))
  const now = new Date(Date.now() - 60_000) // a minute of clock slack
  const until = new Date(now.getTime() + days * 86400_000)

  const tbs = seq(
    ctx(0, integer(Buffer.from([2]))), // v3
    integer(randomBytes(16)), // serial
    algo,
    name, // issuer == subject
    seq(utcTime(now), utcTime(until)),
    name,
    spki,
    extensions()
  )

  const signature = createSign('sha256').update(tbs).sign({ key: privateKey, dsaEncoding: 'der' })
  const der = seq(tbs, algo, bitString(signature))

  return {
    cert: pem('CERTIFICATE', der),
    key: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    spkiPin: createHash('sha256').update(spki).digest('base64')
  }
}

function pem (label, der) {
  const b64 = der.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n$/, '')
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`
}
