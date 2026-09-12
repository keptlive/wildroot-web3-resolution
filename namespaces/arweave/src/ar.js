/* global Response */

/*
 * ar:// — native Arweave fetching.
 *
 *   ar://<txid>              the transaction's data
 *   ar://<txid>/path?query   path within a manifest, query carried through
 *
 * HONESTY NOTE: what a gateway serves is checked in two steps and neither is
 * taken on trust. The transaction HEADER is fetched from a second gateway and
 * its signature verified over its own fields (ar-tx.js), which binds
 * `data_root`, `data_size`, `tags` and the rest to the id; the BYTES are then
 * hashed against that proven `data_root` (ar-merkle.js) when the whole body
 * is in hand and under MAX_VERIFY_BYTES. Where either step cannot be made —
 * one gateway, a manifest path, a Range, a body too big, a header this
 * implementation cannot check — the response says so in `X-Arweave-Verified`
 * and claims nothing. Contrast with ipfs://, where the local node verifies
 * every block whatever its size.
 */

import { isCanonicalTxid } from '../../../src/pointers.js'
import { bytesMatchRoot } from './ar-merkle.js'
import { headerVerdict } from './ar-tx.js'

export { headerVerdict }

/** The largest body checked against its data root in memory (8 MiB). */
export const MAX_VERIFY_BYTES = 8 * 1024 * 1024

/**
 * THE HEADER CHECK. An Arweave transaction id IS the SHA-256 of the
 * transaction's signature (the protocol's definition of the id) — and that
 * hash alone says nothing about the FIELDS served beside the signature, which
 * a gateway could swap while keeping the signature. So the signature is
 * verified over those fields as well (`headerVerdict`, ar-tx.js: RSA-PSS
 * under the owner's key, over the deep hash of the transaction), which binds
 * `owner`, `data_root`, `data_size`, `tags`, `target`, `quantity`, `reward`
 * and `last_tx` to the id — and makes the data root the byte check hashes
 * against the transaction's own, not the gateway's choice.
 *
 * True here means PROVEN: a header this implementation cannot check (see
 * ar-tx.js) is false, and so is a caught lie — the caller distinguishes them
 * with `headerVerdict`, refusing one and claiming nothing for the other.
 * Applied to the transaction's own data (no manifest path), and only when a
 * second gateway exists to ask.
 */
export function headerMatchesId (header, txid) {
  return headerVerdict(header, txid) === 'verified'
}

/**
 * The gateways an `ar://` fetch may try, in order.
 *
 * A single host is a single point of failure for a scheme whose entire
 * promise is that the content outlives everyone — and `arweave.net` is the
 * project's own gateway, not a member of the ar.io gateway network (it does
 * not answer `/ar-io/info`). The two below it are independent ar.io nodes
 * with their own operators and wallets, so an outage at one is not an outage
 * of `ar://`. Criterion for a row: an independent operator answering
 * `/ar-io/info`, reachable on the review date; a host that stops answering is
 * removed rather than kept for sentiment. Reviewed 2026-09-06.
 *
 * A txid names IMMUTABLE content, which is what makes failover safe here in a
 * way it would not be for a mutable name: any gateway that answers can only
 * answer with the bytes that hash to that id, or be caught doing otherwise.
 * (Catching it is the unfinished half — see the header.)
 */
export const AR_GATEWAYS = Object.freeze([
  'https://arweave.net',
  'https://permagate.io',
  'https://ar-io.dev'
])

/** The request headers forwarded to a gateway: a FIXED set, so nothing the caller chose beyond it reaches the gateway. */
const FORWARDED = ['range', 'if-none-match', 'if-modified-since', 'accept']

/** The response headers returned to the caller. */
const RETURNED = ['content-type', 'content-length', 'etag', 'cache-control', 'content-range', 'accept-ranges', 'last-modified', 'vary']

/**
 * A transport failure, as opposed to the gateway answering with a status.
 * Structure first (the error code, or the cause's), then the message —
 * a runtime that rewords its errors must not turn failover off silently.
 */
function isReachFailure (err) {
  const code = String((err && (err.code || (err.cause && err.cause.code))) || '')
  if (/^(ENOTFOUND|ECONNREFUSED|ECONNRESET|ETIMEDOUT|EAI_AGAIN|EHOSTUNREACH|ENETUNREACH|UND_ERR_)/.test(code)) return true
  if (err && (err.name === 'AbortError' || err.name === 'TimeoutError')) return true
  const m = String((err && err.message) || err || '')
  return /abort|timeout|timed out|fetch failed|ENOTFOUND|ECONN|EAI_AGAIN|network/i.test(m)
}

/** A path segment as the URL parser delivered it: already percent-encoded, and must not decode to a separator. */
function isSafeSegment (segment) {
  if (segment === '.' || segment === '..') return false
  try {
    const decoded = decodeURIComponent(segment)
    return !decoded.includes('/') && !decoded.includes('\\') && decoded !== '.' && decoded !== '..'
  } catch {
    return false
  }
}

/**
 * The sandbox label a gateway serves a transaction under: arweave.net (and
 * every ar.io gateway) answers `GET /<txid>` with a 302 to
 * `https://<base32(txid bytes)>.<gateway>/<txid>[/path]`, so that each
 * transaction gets its own origin in the renderer. Base32 per RFC 4648 §6,
 * lowercase, unpadded — 52 characters for a 32-byte id.
 * @param {string} txid the canonical base64url id
 */
export function sandboxLabel (txid) {
  const bytes = Buffer.from(String(txid), 'base64url')
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567'
  let bits = 0
  let acc = 0
  let out = ''
  for (const b of bytes) {
    acc = (acc << 8) | b
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += alphabet[(acc >> bits) & 31]
    }
  }
  if (bits > 0) out += alphabet[(acc << (5 - bits)) & 31]
  return out
}

/**
 * Where a gateway redirect may go: the SAME gateway — its own host, or a
 * subdomain of it, which is how a gateway sandboxes a transaction into its
 * own origin (sandboxLabel) — the SAME transaction (the txid stays the first
 * path segment), https, one hop. Anything else is refused — a `location`
 * handed back to the renderer would restore the open redirect that
 * `redirect: 'manual'` closes. (The fetch handed in must really RETURN the
 * 3xx on a manual redirect; Electron's net.fetch rejects instead, so the
 * browser hands in src/protocols/manual-redirect-fetch.js.)
 */
export function sameScopeRedirect (location, base, txid) {
  let target
  try { target = new URL(String(location), base) } catch { return null }
  const from = new URL(base)
  if (target.protocol !== 'https:') return null
  const sameGateway = target.host === from.host || target.hostname.endsWith('.' + from.hostname)
  if (!sameGateway) return null
  const first = target.pathname.split('/').filter(Boolean)[0]
  if (first !== txid) return null
  return target.href
}

/**
 * @param {object} options
 * @param {string} [options.gateway] pin ONE gateway (tests, callers that must)
 * @param {string[]} [options.gateways] the failover list; defaults to AR_GATEWAYS
 * @param {boolean} [options.verifyHeader] fetch the transaction header from a
 *        SECOND gateway and require it to hash to the id (headerMatchesId);
 *        the browser turns this on, the library default is off because it is
 *        one more request per transaction.
 * @param {Function} options.fetchImpl REQUIRED. The session-bound fetch
 *        (net.fetch riding the active proxy). Node's global fetch ignores
 *        session.setProxy, so defaulting to it would leak the real IP to the
 *        gateway with anonymization on — and `ar` is deliberately left
 *        ungated on the strength of this injection. No default, so a caller
 *        that forgets fails at construction, not in a user's traffic.
 */
export default function createArHandler ({ gateway = null, gateways = null, fetchImpl, verifyHeader = false } = {}) {
  if (typeof fetchImpl !== 'function') {
    throw new Error('createArHandler needs fetchImpl: the session-bound fetch (the global fetch is not proxied)')
  }
  // `gateway` (singular) is kept for callers and tests that pin one host.
  const hosts = gateways && gateways.length
    ? gateways
    : (gateway ? [gateway] : AR_GATEWAYS)
  async function handler (request) {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      // There is nothing under a transaction id to write to.
      return new Response('Method Not Allowed', {
        status: 405, headers: { 'content-type': 'text/plain', allow: 'GET, HEAD' }
      })
    }
    // Parse from the RAW url: txids are case-sensitive base64url and
    // URL.hostname would lowercase them into a different (wrong) id.
    const raw = String(request.url).replace(/^ar:\/\//, '').split('#')[0]
    const qIndex = raw.indexOf('?')
    const before = qIndex === -1 ? raw : raw.slice(0, qIndex)
    const query = qIndex === -1 ? '' : raw.slice(qIndex)
    const segments = before.split('/').filter(Boolean)
    const txid = segments[0] || ''
    // Reject any dot-segments or a segment that decodes to a separator:
    // ar://<txid>/../x would normalize to gateway/x, escaping the txid's
    // scope. The path stays strictly under it. Segments arrive percent-encoded
    // from the URL parser and are passed on AS THEY ARE — re-encoding turns
    // `%20` into `%2520` and makes the file unreachable.
    const rest = segments.slice(1)
    if (!rest.every(isSafeSegment)) {
      return new Response('Invalid path', {
        status: 400, headers: { 'content-type': 'text/plain' }
      })
    }
    const path = rest.length ? '/' + rest.join('/') : ''
    if (!isCanonicalTxid(txid)) {
      return new Response(`Not an Arweave transaction id: ${txid}`, {
        status: 400, headers: { 'content-type': 'text/plain' }
      })
    }

    const headers = { 'user-agent': 'hns.one-browser' }
    for (const h of FORWARDED) {
      const v = request.headers && request.headers.get(h)
      if (v) headers[h] = v
    }

    // Try each gateway until one ANSWERS. A 404 is an answer — the txid is
    // not there and another gateway saying so again helps nobody — so only a
    // failure to reach the host, or a 5xx, moves on. Anything else is
    // returned as it came, statuses included.
    let res = null
    let lastErr = null
    let headerVerified = false
    let servedBy = null
    for (let i = 0; i < hosts.length; i++) {
      let target = `${hosts[i]}/${txid}${path}${query}`
      try {
        for (let hop = 0; ; hop++) {
          res = await doFetch(target, request.method, headers)
          const location = res.status >= 300 && res.status < 400 && res.headers.get('location')
          if (!location) break
          const next = hop === 0 ? sameScopeRedirect(location, target, txid) : null
          if (!next) {
            return new Response(`The gateway ${new URL(target).host} redirected outside this transaction, which was refused.`, {
              status: 502, headers: { 'content-type': 'text/plain' }
            })
          }
          target = next
        }
      } catch (err) {
        lastErr = err
        res = null
        if (isReachFailure(err) && i < hosts.length - 1) continue
        throw err
      }
      if (res.status >= 500 && i < hosts.length - 1) continue
      servedBy = hosts[i]
      break
    }
    if (!res) throw (lastErr || new Error('no Arweave gateway answered'))
    // The header check, against a gateway OTHER than the one that served the
    // bytes: a lying gateway would supply a matching header too.
    let header = null
    if (res.status === 200 && !path && hosts.length > 1 && verifyHeader) {
      const other = hosts.find((h) => h !== servedBy) || hosts[1]
      try {
        const h = await doFetch(`${other}/tx/${txid}`, 'GET', { 'user-agent': 'hns.one-browser', accept: 'application/json' })
        if (h.status === 200) header = await h.json()
      } catch {
        header = null // the second gateway is unreachable: nothing was checked, and the response says so
      }
      const verdict = header ? headerVerdict(header, txid) : null
      if (verdict === 'mismatch') {
        return new Response(`The transaction header ${other} serves for ${txid} is not the transaction that id names (its signature does not hash to the id, or does not sign the fields served with it). Refused.`, {
          status: 502, headers: { 'content-type': 'text/plain' }
        })
      }
      // 'unsupported': the id check passed and the signature could not be
      // checked over the fields (ar-tx.js). Nothing was proven, so nothing is
      // claimed and the data root is not used — the standing of no header.
      if (verdict === 'verified') headerVerified = true
    }
    // THE BYTES, against the header's data root (src/hns/ar-merkle.js). A
    // proven header names the Merkle root the transaction committed to; the
    // body either hashes to it or is not this transaction's. Only a whole
    // body can be checked — not a Range — and only up to MAX_VERIFY_BYTES,
    // because the check needs the bytes in memory before the first one is
    // handed on; above that the header check stands alone and the response
    // says so. A bundled data item has no top-level header and is never here.
    //
    // ONLY THE TRANSACTION'S OWN BYTES CAN BE CHECKED. A gateway renders some
    // transactions rather than serving them: a bundle id or a path manifest
    // answers with an HTML index (arweave.net, 2026-09-06: a 10,386-byte
    // bundle came back as a 2,285-byte page), which is the gateway's page
    // and not the data `data_root` commits to. The body is checked when its
    // length is the header's `data_size` — the gateway served the data —
    // and reported `header` when it is not; a body of the RIGHT length that
    // does not hash to the root is the one case that is refused.
    let body = res.body
    let bytesVerified = false
    if (headerVerified && header && header.data_root && res.status === 200 &&
        !(request.headers && request.headers.get('range'))) {
      const declared = Number(header.data_size)
      if (Number.isFinite(declared) && declared >= 0 && declared <= MAX_VERIFY_BYTES) {
        const bytes = Buffer.from(await res.arrayBuffer())
        if (bytes.length === declared) {
          if (!bytesMatchRoot(bytes, header.data_root)) {
            return new Response(`The bytes ${servedBy} served for ${txid} do not hash to the transaction's data root. Refused.`, {
              status: 502, headers: { 'content-type': 'text/plain' }
            })
          }
          bytesVerified = true
        }
        body = bytes
      }
    }
    const out = new Headers()
    for (const k of RETURNED) {
      const v = res.headers.get(k)
      if (v) out.set(k, v)
    }
    // What was and was not checked, machine-readable for the trust panel:
    // `bytes` when the body hashed to the proven header's data root,
    // `header` when only the transaction header was proven to be this id's,
    // `none` otherwise.
    out.set('X-Arweave-Verified', bytesVerified ? 'bytes' : headerVerified ? 'header' : 'none')
    return new Response(body, { status: res.status, headers: out })
  }

  function doFetch (target, method, headers) {
    return fetchImpl(target, {
      method, // GET or HEAD — anything else was refused above
      // manual: never let the gateway bounce the fetch to an arbitrary host.
      redirect: 'manual',
      headers
    })
  }

  return { handler, close: () => {} }
}
