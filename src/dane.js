/*
 * DANE certificate validation for Handshake hosts.
 *
 * No CA can issue for a Handshake name, so trust is pinned in DNS instead:
 * the zone publishes `_443._tcp.<host> TLSA 3 1 1 <sha256(SPKI)>` and the
 * TLS certificate must hash to exactly that. We support the one profile
 * the Handshake ecosystem standardised on (DANE-EE / SPKI / SHA-256) and
 * fail CLOSED on everything else: an unsupported TLSA parameter combination
 * is a mismatch, not a shrug — downgrading on confusion is how a pinning
 * scheme quietly stops pinning.
 */

import { createHash, X509Certificate } from 'node:crypto'

export const SUPPORTED = { usage: 3, selector: 1, matchingType: 1 }

/**
 * @param {Buffer|string} certDer raw DER certificate (or PEM string)
 * @param {Array<{usage:number,selector:number,matchingType:number,certificate:string}>} tlsaRecords
 * @returns {{state: 'verified'|'tlsa_mismatch'|'no_tlsa'|'cert_invalid', detail?: string}}
 */
export function verifyDane (certDer, tlsaRecords) {
  const records = (tlsaRecords || []).filter((r) => r && r.certificate)
  if (!records.length) return { state: 'no_tlsa' }

  let x509
  try {
    x509 = new X509Certificate(certDer)
  } catch (err) {
    return { state: 'cert_invalid', detail: String(err.message || err) }
  }

  // NB: no PKIX validity-date check. For DANE-EE (usage 3) RFC 7671 §5.1
  // says the TLSA pin replaces the CA trust chain entirely, expiry
  // included — the zone owner's live control of the DS/TLSA records IS the
  // freshness signal. Rejecting on notAfter would break a correctly-pinned
  // self-signed site the day its arbitrary expiry passes, for no security
  // gain (the operator, not a CA, controls the pin).

  // A key type Node cannot export (an exotic or malformed SPKI) is a bad
  // certificate, not an exception for the caller — whose error path was
  // the DoH fallback.
  let spki
  try {
    spki = x509.publicKey.export({ type: 'spki', format: 'der' })
  } catch (err) {
    return { state: 'cert_invalid', detail: `unsupported public key: ${String(err.message || err)}` }
  }
  const spkiHash = createHash('sha256').update(spki).digest('hex')

  const supported = records.filter((r) =>
    r.usage === SUPPORTED.usage &&
    r.selector === SUPPORTED.selector &&
    r.matchingType === SUPPORTED.matchingType)

  if (!supported.length) {
    // TLSA records exist but in a profile we do not implement. Treating
    // that as "no pinning" would let a zone's stated policy be ignored.
    return { state: 'tlsa_mismatch', detail: 'no supported (3 1 1) TLSA record' }
  }
  for (const r of supported) {
    if (r.certificate.toLowerCase() === spkiHash) {
      return { state: 'verified' }
    }
  }
  return { state: 'tlsa_mismatch', detail: `SPKI ${spkiHash.slice(0, 16)}… matches none of ${supported.length} record(s)` }
}
