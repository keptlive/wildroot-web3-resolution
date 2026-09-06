/* globals Response */

/*
 * onion:// — reach a Tor onion service, and ONLY ever through the Tor client
 * running on THIS device.
 *
 * THE HARD RULE.
 *   Wildroot will not route your traffic through a hosted relay and call it
 *   privacy. An onion service is reached exclusively through the device-local
 *   Tor circuit that "IP Protection" turns on (src/hns/tor.js + anonymize.js).
 *   When IP Protection is on, the whole browsing session's proxy IS that Tor
 *   SOCKS port, with proxy-side (remote) DNS — so the .onion name is resolved
 *   inside the Tor network and never leaks to a system resolver. This handler
 *   therefore fetches over the session-bound `fetchImpl`, which rides that
 *   proxy; it opens no relay of its own and knows no fallback path.
 *
 * WHEN IT IS OFF.
 *   If IP Protection is not on, we do NOT silently fetch (a direct fetch could
 *   not resolve a .onion anyway, and trying would leak the attempt). Instead we
 *   serve a plain interstitial that explains the user must turn IP Protection
 *   on, and carries the honest fingerprinting caveat: reaching .onion works,
 *   but this browser does not resist fingerprinting the way Tor Browser does,
 *   so onion browsing here hides your IP — it is not full anonymity.
 */

import { escapeHtml } from './html.js'
import { isValidV3Onion, isOnionHost } from '../../../src/router.js'
import { safeStatus } from '../../../src/safe-status.js'

/** The most same-service redirects followed inside one request. */
const MAX_REDIRECTS = 5

/**
 * The gate decision, factored out so it is unit-testable without a real Tor.
 * @param {{ ipProtectionOn: boolean }} state
 * @returns {{ action: 'route' } | { action: 'interstitial' }}
 */
export function decideOnionRoute ({ ipProtectionOn } = {}) {
  // Route ONLY when IP Protection is on — that is the only configuration in
  // which the session proxy points at the device-local Tor with proxy-side
  // DNS. Routing while Tor is still bootstrapping is safe: the request waits
  // for the circuit rather than escaping direct (see anonymize.js), so no
  // .onion address and no traffic ever leaves the tunnel.
  return ipProtectionOn ? { action: 'route' } : { action: 'interstitial' }
}

/**
 * Parse `onion://<host>[:port][/path][?query]` (fragment dropped, host
 * lower-cased, port kept apart). `onion:` is a standard scheme, so the URL
 * parser is the right tool; a string it refuses falls back to a hand split
 * that keeps the same shape, so a malformed address still fails closed
 * inside the handler rather than throwing out of it.
 */
export function parseOnionUrl (url) {
  try {
    const u = new URL(String(url))
    if (u.protocol === 'onion:' && u.hostname) {
      return { host: u.hostname.toLowerCase(), port: u.port || '', path: `${u.pathname}${u.search}` || '/' }
    }
  } catch { /* fall through */ }
  const raw = String(url).replace(/^onion:\/\//i, '').split('#')[0]
  const slash = raw.indexOf('/')
  let host, path
  if (slash === -1) {
    const q = raw.indexOf('?')
    host = q === -1 ? raw : raw.slice(0, q)
    path = q === -1 ? '/' : raw.slice(q)
  } else {
    host = raw.slice(0, slash)
    path = raw.slice(slash)
  }
  const m = /^(.*):(\d+)$/.exec(host)
  return { host: (m ? m[1] : host).toLowerCase(), port: m ? m[2] : '', path: path || '/' }
}

/**
 * Where an onion service tried to send us. Three cases, decided here so the
 * handler never hands a stranger's Location to the page under this origin:
 *   same service  -> followed internally (bounded);
 *   another onion -> a real navigation to onion://<other>/…, so the origin
 *                    changes as it should;
 *   off Tor       -> not fetched; the page is told where it was sent.
 * @param {string} location the Location header, possibly relative
 * @param {string} base the http://<host>[:port]/… URL just fetched
 */
export function classifyOnionRedirect (location, base) {
  let target
  try { target = new URL(String(location), base) } catch { return { kind: 'invalid' } }
  const from = new URL(base)
  if (target.protocol !== 'http:' && target.protocol !== 'https:') return { kind: 'off-tor', url: target.href }
  if (!isOnionHost(target.hostname)) return { kind: 'off-tor', url: target.href }
  const same = target.hostname.toLowerCase() === from.hostname.toLowerCase() && target.port === from.port
  const onionUrl = `onion://${target.hostname.toLowerCase()}${target.port ? ':' + target.port : ''}${target.pathname}${target.search}`
  return same
    ? { kind: 'same-service', url: `http://${target.host}${target.pathname}${target.search}`, onionUrl }
    : { kind: 'other-onion', onionUrl }
}

/**
 * @param {object} options
 * @param {Function} options.fetchImpl  session-bound fetch (net.fetch with
 *        bypassCustomProtocolHandlers) — rides the active Tor proxy when IP
 *        Protection is on. REQUIRED: without it there is no Tor-only path.
 * @param {() => boolean} options.ipProtectionOn  is IP Protection (Tor) on?
 */
export default function createOnionHandler ({ fetchImpl, ipProtectionOn } = {}) {
  const isOn = typeof ipProtectionOn === 'function' ? ipProtectionOn : () => false

  async function handler (request) {
    const { host, port, path } = parseOnionUrl(request.url)
    if (!/\.onion$/i.test(host)) {
      return htmlResponse(400, 'Not an onion address',
        '<p>This is not a <code>.onion</code> service address.</p>')
    }
    // Refuse an address that cannot exist BEFORE asking for a circuit. Its
    // checksum does not match, so it was mistyped or truncated; Tor would
    // spend a circuit finding that out. Not a security check (see
    // isValidV3Onion) — a fast, local, honest failure inside this namespace.
    if (!isValidV3Onion(host)) {
      return htmlResponse(400, 'Not a valid onion address',
        `<p><code>${escapeHtml(host)}</code> is not a valid version-3 onion address — its ` +
        'checksum does not match, so it was mistyped or truncated somewhere. Nothing was sent.</p>')
    }

    if (decideOnionRoute({ ipProtectionOn: isOn() }).action !== 'route') {
      return interstitial(host)
    }

    if (!fetchImpl) {
      return htmlResponse(500, 'Onion routing is not wired',
        '<p>No Tor-routed fetch is available in this build.</p>')
    }

    // Reached only through the device Tor circuit. The onion service speaks
    // HTTP; the SOCKS proxy carries the .onion hostname to Tor for resolution.
    let target = `http://${host}${port ? ':' + port : ''}${path}`
    try {
      let method = request.method
      let body = (method === 'GET' || method === 'HEAD')
        ? undefined
        : Buffer.from(await request.arrayBuffer())
      let res
      for (let hop = 0; ; hop++) {
        res = await fetchImpl(target, {
          method,
          // manual: a redirect is DECIDED here (classifyOnionRedirect), never
          // followed to wherever the service pointed. Followed blindly, an
          // onion service could serve clearnet bytes — or another service's —
          // under its own origin, with this origin's storage.
          redirect: 'manual',
          body,
          headers: forwardHeaders(request)
        })
        const location = res.headers.get('location')
        if (!(res.status >= 300 && res.status < 400) || !location) break
        const redirect = classifyOnionRedirect(location, target)
        if (redirect.kind === 'same-service' && hop < MAX_REDIRECTS) {
          target = redirect.url
          // RFC 9110 §15.4: a 301/302/303 answer to a request with a body is
          // followed with a GET and no body; 307/308 keep the method.
          if (res.status !== 307 && res.status !== 308 && method !== 'GET' && method !== 'HEAD') {
            method = 'GET'
            body = undefined
          }
          continue
        }
        if (redirect.kind === 'same-service') {
          return htmlResponse(502, 'Too many redirects',
            `<p>The onion service redirected more than ${MAX_REDIRECTS} times without serving a page.</p>`)
        }
        if (redirect.kind === 'other-onion') {
          // A real navigation: the address bar and the origin change.
          return new Response('', {
            status: safeStatus(res.status),
            headers: { location: redirect.onionUrl, 'X-Resolution-Namespace': 'tor' }
          })
        }
        return htmlResponse(200, 'This onion service sent you off Tor',
          `<p><code>${escapeHtml(host)}</code> answered with a redirect to ` +
          `<code>${escapeHtml(redirect.url || location)}</code>, which is not an onion service. ` +
          'It was not followed: the page would have loaded under this onion address with its storage.</p>' +
          (redirect.url ? `<p>You can open it deliberately: <a href="${escapeHtml(redirect.url)}">${escapeHtml(redirect.url)}</a></p>` : ''))
      }
      const headers = new Headers()
      // The body may have been transparently decompressed by the fetch layer,
      // in which case the upstream length is wrong for the bytes served.
      const encoded = !!res.headers.get('content-encoding')
      for (const k of [
        'content-type', 'content-length', 'etag', 'cache-control', 'content-disposition', 'last-modified',
        'content-range', 'accept-ranges', 'vary',
        // The service's OWN instructions about its own content. Dropping
        // these would leave an onion page less defended here than in a
        // browser that does nothing. Strict-Transport-Security is left out
        // deliberately: there is no TLS in the tunnel, and forwarding it
        // would poison HSTS state for the origin.
        'content-security-policy', 'content-security-policy-report-only',
        'x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy'
      ]) {
        if (k === 'content-length' && encoded) continue
        const v = res.headers.get(k)
        if (v) headers.set(k, v)
      }
      // The verdict stays TRUSTED, never green: onion pages are HTTP inside Tor.
      headers.set('X-Resolution-Namespace', 'tor')
      return new Response(res.body, { status: safeStatus(res.status), headers })
    } catch (err) {
      return htmlResponse(502, 'Could not reach the onion service',
        `<p>The request over Tor failed: <code>${escapeHtml(String((err && err.message) || err))}</code>.</p>` +
        '<p>The circuit may still be building — the first connection can take up to a minute. Try again in a moment.</p>')
    }
  }

  return { handler }
}

function forwardHeaders (request) {
  // Both PINNED, not forwarded. Accept-Language is one of the highest-entropy
  // passive fingerprinting headers there is; the value is the one Tor Browser
  // sends, because matching the largest crowd is what a fingerprint-resistant
  // value is for. This does not make the browser fingerprint-resistant (the
  // page still has canvas, fonts, screen metrics) — it removes the one
  // header this handler would otherwise add by itself.
  const out = { 'user-agent': 'hns.one-browser', 'accept-language': 'en-US,en;q=0.5' }
  for (const h of ['content-type', 'range', 'accept', 'if-none-match', 'if-modified-since']) {
    const v = request.headers.get(h)
    if (v) out[h] = v
  }
  return out
}

/**
 * The "turn on IP Protection" interstitial, with the fingerprinting caveat.
 * @param {string} host
 */
function interstitial (host) {
  return htmlResponse(200, 'Turn on IP Protection to reach this .onion service',
    `<p>This browser reaches <code>${escapeHtml(host)}</code> <b>only</b> through the Tor client
        running on your own device — never through a hosted relay. That path is off right now.</p>
     <p><b>To open it:</b> use the <b>Privacy</b> menu and choose
        <b>IP&nbsp;Protection: On (via&nbsp;Tor)</b>, then reload this page. The first
        connection can take up to a minute while the circuit is built.</p>
     <p class="warn"><b>One honest caveat:</b> reaching .onion here hides your IP, but this browser does
        not resist fingerprinting the way Tor Browser does — so this is not full anonymity.</p>`)
}

function htmlResponse (status, title, innerHtml) {
  const body = `<!doctype html>
<html><head><meta charset="utf-8">
<title>${escapeHtml(title)}</title>
<meta name="color-scheme" content="light dark">
<style>
  body { font: 16px/1.6 system-ui, sans-serif; margin: 0; padding: 3rem 1.5rem;
         max-width: 40rem; margin-inline: auto; }
  code { background: color-mix(in srgb, currentColor 10%, transparent);
         padding: .15em .4em; border-radius: 4px; word-break: break-all; }
  .warn { border-left: 3px solid currentColor; padding-left: 1rem; opacity: .85; }
</style></head><body>
<h1>${escapeHtml(title)}</h1>
${innerHtml}
</body></html>`
  return new Response(body, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'X-Resolution-Namespace': 'tor',
      'Access-Control-Allow-Origin': 'null'
    }
  })
}
