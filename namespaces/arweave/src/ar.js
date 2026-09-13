/* global Response, Headers, ReadableStream */

/*
 * ar:// — native Arweave fetching.
 *
 *   ar://<txid>              the transaction's data
 *   ar://<txid>/path?query   path within a manifest, query carried through
 *
 * With verification enabled, supported transaction headers are authenticated
 * by both signature-id binding and the owner's signature (ar-tx.js). Small raw
 * bodies must also match the signed size and Merkle root — or, for a format-1
 * transaction, the signed data itself — before any bytes are served. Other
 * responses explicitly retain gateway trust: a header this implementation
 * cannot check is reported as nothing checked, exactly like a header gateway
 * that did not answer, and never refused as though something had been caught.
 * Neither check proves mining, confirmations, or permanence.
 */

import { isCanonicalTxid } from '../../../src/pointers.js'
import { bytesMatchRoot } from './ar-merkle.js'
import { headerMatchesId, verifyTransactionHeader } from './ar-tx.js'

export { headerMatchesId, verifyTransactionHeader }

/** The largest body checked against its data root in memory (8 MiB). */
export const MAX_VERIFY_BYTES = 8 * 1024 * 1024
export const MAX_HEADER_BYTES = 256 * 1024

function tagValue (verified, name) {
  const values = verified.tags.filter(([key]) => key.equals(Buffer.from(name))).map(([, value]) => value.toString('utf8'))
  return values.length === 1 ? values[0] : null
}

function renderedTransaction (verified) {
  // Only authenticated type tags select a gateway representation. A mismatch
  // in body size, Content-Type, or a redirect cannot grant this exception.
  return tagValue(verified, 'Content-Type') === 'application/x.arweave-manifest+json' ||
    (tagValue(verified, 'Bundle-Format') === 'binary' && tagValue(verified, 'Bundle-Version') === '2.0.0')
}

function rawContentType (verified) {
  const type = tagValue(verified, 'Content-Type')
  return type && type.length <= 256 && /^[\x20-\x7e]+$/.test(type) ? type : 'application/octet-stream'
}

function cancelBody (response) {
  try { response?.body?.cancel().catch(() => {}) } catch {}
}

/** Never trust Content-Length or signed data_size as a limit on allocation. */
async function readBounded (response, maxBytes, signal, expected = null) {
  if (signal?.aborted) {
    cancelBody(response)
    throw new Error('request aborted')
  }
  const reader = response.body?.getReader()
  if (!reader) {
    if (expected !== null && expected !== 0) throw new Error('raw body size does not match signed data_size')
    return Buffer.alloc(0)
  }
  const abort = () => { reader.cancel().catch(() => {}) }
  signal?.addEventListener('abort', abort, { once: true })
  const chunks = []
  let size = 0
  try {
    while (true) {
      const { value, done } = await reader.read()
      if (signal?.aborted) throw new Error('request aborted')
      if (done) break
      size += value.byteLength
      if (size > maxBytes) throw new Error('response exceeds verification byte limit')
      if (expected !== null && size > expected) throw new Error('raw body size exceeds signed data_size')
      chunks.push(Buffer.from(value))
    }
    if (expected !== null && size !== expected) throw new Error('raw body size does not match signed data_size')
    return Buffer.concat(chunks, size)
  } catch (err) {
    reader.cancel().catch(() => {})
    throw err
  } finally {
    signal?.removeEventListener('abort', abort)
    reader.releaseLock()
  }
}

/** Large raw transactions stream with backpressure, without a Merkle claim. */
function sizeCheckedStream (body, expected) {
  if (!body) throw new Error('missing raw transaction body')
  const reader = body.getReader()
  let size = 0n
  return new ReadableStream({
    async pull (controller) {
      try {
        const { value, done } = await reader.read()
        if (done) {
          if (size !== expected) throw new Error('raw body size does not match signed data_size')
          reader.releaseLock()
          controller.close()
          return
        }
        size += BigInt(value.byteLength)
        if (size > expected) throw new Error('raw body size exceeds signed data_size')
        controller.enqueue(value)
      } catch (err) {
        reader.cancel().catch(() => {})
        controller.error(err)
      }
    },
    cancel (reason) { return reader.cancel(reason) }
  })
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
 * Gateway failover alone is not an integrity check. Only the authenticated
 * raw-body branch below can report verified bytes.
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
 *        SECOND gateway and authenticate its id, fields and owner signature;
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
    let servedBy = null
    for (let i = 0; i < hosts.length; i++) {
      let target = `${hosts[i]}/${txid}${path}${query}`
      try {
        for (let hop = 0; ; hop++) {
          res = await doFetch(target, request.method, headers, request.signal)
          const location = res.status >= 300 && res.status < 400 && res.headers.get('location')
          if (!location) break
          const next = hop === 0 ? sameScopeRedirect(location, target, txid) : null
          cancelBody(res)
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
      if (res.status >= 500 && i < hosts.length - 1) {
        cancelBody(res)
        continue
      }
      servedBy = hosts[i]
      break
    }
    if (!res) throw (lastErr || new Error('no Arweave gateway answered'))
    // A second gateway remains useful for availability/cross-checking. The
    // cryptographic claim comes from the signature, not gateway independence.
    let verified = null
    if (res.status === 200 && !path && hosts.length > 1 && verifyHeader) {
      const other = hosts.find((h) => h !== servedBy) || hosts[1]
      let headerResponse = null
      try {
        headerResponse = await doFetch(`${other}/tx/${txid}`, 'GET', { 'user-agent': 'hns.one-browser', accept: 'application/json' }, request.signal)
      } catch {
        // Unavailable header: retain the explicit unchecked gateway contract.
      }
      if (headerResponse?.status === 200) {
        let result = null
        try {
          const bytes = await readBounded(headerResponse, MAX_HEADER_BYTES, request.signal)
          result = verifyTransactionHeader(JSON.parse(bytes.toString('utf8')), txid)
        } catch (err) {
          cancelBody(res)
          return refused(`The transaction header from ${other} could not be authenticated: ${err.message}.`)
        }
        // A caught lie is refused. A header this implementation cannot check
        // (ar-tx.js: an unknown format or account type, an owner that is not
        // RSA-4096, a format-1 header without its data) proves nothing, so it
        // claims nothing — `none`, the standing of a header we never got. A
        // refusal there would stop no attack, because a header gateway can
        // reach that standing by not answering, and would break honest
        // content this implementation simply cannot verify.
        if (!result.ok && result.verdict !== 'unsupported') {
          cancelBody(res)
          return refused(`The transaction header from ${other} could not be authenticated: ${result.reason}.`)
        }
        verified = result.ok ? result : null
      } else {
        cancelBody(headerResponse)
      }
    }
    // Raw and rendered content have separate contracts chosen BEFORE reading
    // data. Signed manifest/bundle types allow a gateway-rendered page, which
    // remains unverified even if its length happens to match the transaction.
    const representation = path ? 'manifest-path' : verified ? renderedTransaction(verified) ? 'gateway-rendered' : 'raw' : 'gateway'
    let body = res.body
    let bytesVerified = false
    if (verified && representation === 'raw' && request.method === 'GET' && !headers.range) {
      try {
        if (verified.data) {
          // Format 1 signs the data itself, so the served bytes are compared
          // with the signed bytes: no Merkle root exists to hash against, and
          // the header's own `data_size` is not part of that signature.
          body = await readBounded(res, MAX_VERIFY_BYTES, request.signal, Number(verified.dataSize))
          if (!body.equals(verified.data)) {
            return refused(`The bytes ${servedBy} served for ${txid} are not the data this transaction signed.`)
          }
          bytesVerified = true
        } else if (verified.dataSize <= BigInt(MAX_VERIFY_BYTES)) {
          body = await readBounded(res, MAX_VERIFY_BYTES, request.signal, Number(verified.dataSize))
          // Zero-length format-2 data has an empty root, not an empty-chunk
          // Merkle leaf. The signature already authenticated that pairing.
          if (body.length && !bytesMatchRoot(body, verified.dataRoot)) {
            return refused(`The bytes ${servedBy} served for ${txid} do not hash to the transaction's data root.`)
          }
          bytesVerified = true
        } else {
          body = sizeCheckedStream(body, verified.dataSize)
        }
      } catch (err) {
        cancelBody(res)
        return refused(`The raw transaction body was refused: ${err.message}.`)
      }
    }
    const out = new Headers()
    for (const k of RETURNED) {
      const v = res.headers.get(k)
      if (v) out.set(k, v)
    }
    if (verified && representation === 'raw') out.set('content-type', rawContentType(verified))
    if (bytesVerified) out.set('content-length', String(body.length))
    // `header` authenticates the transaction only, never a rendered page or
    // streamed large/range body. These headers are produced here, not copied
    // from the gateway. A verified raw response's MIME type is signed too.
    out.set('X-Arweave-Verified', bytesVerified ? 'bytes' : verified ? 'header' : 'none')
    out.set('X-Arweave-Representation', representation)
    return new Response(body, { status: res.status, headers: out })
  }

  function doFetch (target, method, headers, signal) {
    return fetchImpl(target, {
      method, // GET or HEAD — anything else was refused above
      // manual: never let the gateway bounce the fetch to an arbitrary host.
      redirect: 'manual',
      headers,
      signal
    })
  }

  return { handler, close: () => {} }
}

function refused (message) {
  return new Response(`${message} Refused.`, {
    status: 502,
    headers: { 'content-type': 'text/plain', 'X-Arweave-Verified': 'none', 'X-Arweave-Representation': 'refused' }
  })
}
