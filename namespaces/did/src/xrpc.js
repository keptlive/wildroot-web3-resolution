// Minimal XRPC transport for the AT Protocol (Bluesky), Electron-free.
//
// WHY A HAND-ROLLED CLIENT AND NOT @atproto/api. The official SDK drags in a
// lexicon code-generation layer and a session manager designed around browser
// storage; this browser needs exactly eight endpoints, an injectable fetch so
// `node --test` covers every path without a network, and session tokens that
// live in the VAULT, not in a library's idea of persistence. Eight endpoints
// is fewer lines than the integration would be.
//
// POLITENESS IS A CONTRACT HERE. Reads go to Bluesky's PUBLIC AppView, which
// is a free service run for the whole network. So: GETs are cached briefly,
// a 429 is retried ONCE after a short honest wait, and anything beyond that
// is surfaced to the user as "Bluesky is rate-limiting us" rather than being
// hammered in a loop.

/** Public, unauthenticated AppView. Reads only; writes go to the user's PDS. */
export const PUBLIC_APPVIEW = 'https://public.api.bsky.app'

export class XrpcError extends Error {
  constructor (message, { status = 0, code = '' } = {}) {
    super(message)
    this.name = 'XrpcError'
    this.status = status
    this.code = code
  }
}

/** Does this error mean "your access token expired, refresh and retry"? */
export function isExpiredToken (err) {
  return Boolean(err && err.name === 'XrpcError' &&
    (err.code === 'ExpiredToken' || err.status === 401))
}

const DEFAULT_TIMEOUT = 10000

/**
 * Build a transport. Everything is injectable for tests; the defaults are the
 * real network.
 *
 * @param {object} [options]
 * @param {Function} [options.fetchFn] fetch-compatible function
 * @param {number} [options.cacheTtlMs] how long an unauthenticated GET is fresh
 * @param {Function} [options.now] clock, for tests
 * @param {Function} [options.sleep] wait, for tests
 */
export function makeXrpc ({
  fetchFn = globalThis.fetch,
  cacheTtlMs = 120000,
  now = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
} = {}) {
  /** url -> {at, value}. Unauthenticated GETs only; authed responses differ per user. */
  const cache = new Map()

  function remember (url, value) {
    // Bounded: this is a courtesy cache, not a database.
    if (cache.size > 200) cache.clear()
    cache.set(url, { at: now(), value })
  }

  async function parse (res) {
    let body = null
    try { body = await res.json() } catch { /* some errors have no body */ }
    if (res.ok) return body
    const code = (body && body.error) || ''
    const message = (body && body.message) || `${res.status}`
    if (res.status === 429) {
      throw new XrpcError('Bluesky is rate-limiting us — try again in a minute', {
        status: 429, code: code || 'RateLimitExceeded'
      })
    }
    throw new XrpcError(`Bluesky answered ${res.status}: ${code ? code + ' — ' : ''}${message}`, {
      status: res.status, code
    })
  }

  async function request (url, init) {
    const res = await fetchFn(url, {
      ...init, redirect: 'error', signal: AbortSignal.timeout(DEFAULT_TIMEOUT)
    })
    if (res.status === 429) {
      // ONE polite retry, after a short wait. `ratelimit-reset` is epoch
      // seconds; anything further away than a few seconds is the user's
      // problem to hear about, not ours to spin on.
      const reset = Number(res.headers && res.headers.get && res.headers.get('ratelimit-reset'))
      const waitMs = Number.isFinite(reset)
        ? Math.max(0, reset * 1000 - now())
        : 1000
      if (waitMs <= 5000) {
        await sleep(waitMs || 1000)
        return parse(await fetchFn(url, {
          ...init, redirect: 'error', signal: AbortSignal.timeout(DEFAULT_TIMEOUT)
        }))
      }
    }
    return parse(res)
  }

  function query (service, nsid, params) {
    const url = new URL(`/xrpc/${nsid}`, service)
    for (const [key, value] of Object.entries(params || {})) {
      if (value === undefined || value === null || value === '') continue
      url.searchParams.set(key, String(value))
    }
    return url.toString()
  }

  return {
    /** GET a query endpoint. Cached briefly unless authed or ttl:0. */
    async get (service, nsid, params, { accessJwt = null, ttl = cacheTtlMs } = {}) {
      const url = query(service, nsid, params)
      if (!accessJwt && ttl > 0) {
        const hit = cache.get(url)
        if (hit && now() - hit.at < ttl) return hit.value
      }
      const headers = accessJwt ? { Authorization: `Bearer ${accessJwt}` } : {}
      const value = await request(url, { method: 'GET', headers })
      if (!accessJwt && ttl > 0) remember(url, value)
      return value
    },

    /** POST a procedure endpoint. Never cached. */
    async proc (service, nsid, body, { accessJwt = null } = {}) {
      const headers = { 'Content-Type': 'application/json' }
      if (accessJwt) headers.Authorization = `Bearer ${accessJwt}`
      return request(query(service, nsid, null), {
        method: 'POST', headers, body: body === undefined ? undefined : JSON.stringify(body)
      })
    }
  }
}
