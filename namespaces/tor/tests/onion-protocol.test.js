/*
 * onion:// gating and routing — no real Tor anywhere. The device Tor is
 * represented by the ipProtectionOn() flag (exactly what the anonymize
 * controller exposes) and a fetchImpl stub standing in for the session-bound,
 * Tor-proxied net.fetch.
 *
 * The product rule under test:
 *   - Tor OFF -> a "turn on IP Protection" interstitial, ZERO network requests,
 *                carrying the honest fingerprinting caveat.
 *   - Tor ON  -> the request rides the Tor-proxied fetch as an http:// URL for
 *                the .onion host, so the name is resolved inside Tor (SOCKS5
 *                DOMAINNAME, RFC 1928 §5) and never by a system resolver.
 *
 * The cases below the first divider pin the behaviour the Tor chapter of the
 * specification describes, so the documents cannot drift from the code.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import createOnionHandler, { decideOnionRoute, parseOnionUrl, classifyOnionRedirect } from '../src/onion-protocol.js'

const ONION = 'p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion'
const OTHER = 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion'

/** A handler with the gate open, which is the state most cases below need. */
const routed = (fetchImpl) => createOnionHandler({ fetchImpl, ipProtectionOn: () => true }).handler

test('decideOnionRoute: routes only when IP Protection is on', () => {
  assert.equal(decideOnionRoute({ ipProtectionOn: true }).action, 'route')
  assert.equal(decideOnionRoute({ ipProtectionOn: false }).action, 'interstitial')
  assert.equal(decideOnionRoute({}).action, 'interstitial')
  assert.equal(decideOnionRoute().action, 'interstitial')
})

test('parseOnionUrl keeps host, port and path apart and lower-cases the host', () => {
  assert.deepEqual(parseOnionUrl(`onion://${ONION}/`), { host: ONION, port: '', path: '/' })
  assert.deepEqual(parseOnionUrl(`onion://${ONION}/a/b?x=1#f`), { host: ONION, port: '', path: '/a/b?x=1' })
  assert.deepEqual(parseOnionUrl(`onion://${ONION}`), { host: ONION, port: '', path: '/' })
  // `onion:` is not a WHATWG *special* scheme, so a query-only URL has an
  // empty path; the query alone is the path handed to the request builder,
  // which is what `http://<host>?q=1` means anyway.
  assert.deepEqual(parseOnionUrl(`onion://${ONION}?q=1`), { host: ONION, port: '', path: '?q=1' })
  assert.deepEqual(parseOnionUrl(`ONION://${ONION.toUpperCase()}/`), { host: ONION, port: '', path: '/' })
  // A port is carried beside the host, never inside it, so the .onion suffix
  // test still sees an address.
  assert.deepEqual(parseOnionUrl(`onion://${ONION}:8080/x?y=1`), { host: ONION, port: '8080', path: '/x?y=1' })
  // The fragment is dropped before the request is built: it is the client's,
  // and an onion service has no business receiving it.
  assert.equal(parseOnionUrl(`onion://${ONION}/p#secret`).path, '/p')
  // A string the URL parser refuses still comes back in the same shape, so a
  // malformed address fails closed inside the handler rather than throwing.
  assert.deepEqual(parseOnionUrl('onion://typod.onion:99/a'), { host: 'typod.onion', port: '99', path: '/a' })
})

test('Tor OFF: interstitial, no fetch, with the fingerprinting caveat', async () => {
  let fetched = 0
  const { handler } = createOnionHandler({
    fetchImpl: async () => { fetched++; return new Response('should not happen') },
    ipProtectionOn: () => false
  })
  const res = await handler(new Request(`onion://${ONION}/`))
  assert.equal(fetched, 0, 'nothing hit the network while Tor was off')
  const body = await res.text()
  assert.match(body, /IP Protection/i)
  assert.match(body, /Privacy/i) // tells the user how to turn it on
  assert.match(body, /hosted relay/i) // device-local only
  assert.match(body, /fingerprint/i)
  assert.match(body, /not full anonymity/i)
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'tor')
})

test('the interstitial escapes the host it echoes back', async () => {
  const { handler } = createOnionHandler({ fetchImpl: async () => new Response(''), ipProtectionOn: () => false })
  const res = await handler(new Request('onion://%3Cimg%20src=x%20onerror=alert(1)%3E.onion/'))
  const body = await res.text()
  assert.doesNotMatch(body, /<img/i)
  assert.match(body, /&lt;img|%3cimg/i)
})

test('Tor ON: routes through the Tor-proxied fetch to an http:// onion URL', async () => {
  const seen = []
  const { handler } = createOnionHandler({
    fetchImpl: async (url, opts) => { seen.push({ url, opts }); return new Response('ONIONBODY', { status: 200, headers: { 'content-type': 'text/html' } }) },
    ipProtectionOn: () => true
  })
  const res = await handler(new Request(`onion://${ONION}/path?q=1`))
  assert.equal(res.status, 200)
  assert.equal(await res.text(), 'ONIONBODY')
  // Resolution stays proxy-side: the .onion host is handed to the Tor SOCKS
  // proxy inside an http URL, never to a system resolver.
  assert.equal(seen.length, 1)
  assert.equal(seen[0].url, `http://${ONION}/path?q=1`)
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'tor')
})

test('Tor ON routes even while the circuit is still building (no leak window)', async () => {
  // ipProtectionOn() is the controller's mode, not its readiness. The session
  // proxy already points at the (bootstrapping) SOCKS port, so a request WAITS
  // for the circuit instead of escaping direct. Turning the gate on readiness
  // instead would open exactly that leak.
  let fetched = 0
  const { handler } = createOnionHandler({
    fetchImpl: async () => { fetched++; return new Response('late but inside the tunnel') },
    ipProtectionOn: () => true // mode = tor, bootstrap not finished
  })
  const res = await handler(new Request(`onion://${ONION}/`))
  assert.equal(res.status, 200)
  assert.equal(fetched, 1)
})

test('a non-.onion host is refused as an onion address (never routed)', async () => {
  let fetched = 0
  const { handler } = createOnionHandler({
    fetchImpl: async () => { fetched++; return new Response('') },
    ipProtectionOn: () => true
  })
  const res = await handler(new Request('onion://example.com/'))
  assert.equal(res.status, 400)
  assert.equal(fetched, 0)
})

test('no fetchImpl wired: 500, and still no network path', async () => {
  const { handler } = createOnionHandler({ ipProtectionOn: () => true })
  const res = await handler(new Request(`onion://${ONION}/`))
  assert.equal(res.status, 500)
  assert.match(await res.text(), /not wired|No Tor-routed fetch/i)
})

test('Tor ON but the circuit errors: honest 502, not a leak or a fallback', async () => {
  const { handler } = createOnionHandler({
    fetchImpl: async () => { throw new Error('SOCKS connection failed') },
    ipProtectionOn: () => true
  })
  const res = await handler(new Request(`onion://${ONION}/`))
  assert.equal(res.status, 502)
  const body = await res.text()
  assert.match(body, /over Tor failed|circuit may still be building/i)
  // L2: the failure is answered as a Tor failure. No second namespace is tried.
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'tor')
})

// --- headers: what is sent INTO the service, and what comes back -----------

test('User-Agent and Accept-Language are pinned; five headers are forwarded', async () => {
  let sent = null
  const handler = routed(async (_url, opts) => { sent = opts.headers; return new Response('') })
  await handler(new Request(`onion://${ONION}/`, {
    headers: {
      accept: 'text/html',
      'accept-language': 'de-CH,de;q=0.9',
      range: 'bytes=0-1',
      cookie: 'session=secret',
      referer: 'https://tracker.example/'
    }
  }))
  assert.equal(sent['user-agent'], 'hns.one-browser')
  assert.equal(sent.accept, 'text/html')
  assert.equal(sent.range, 'bytes=0-1')
  // Neither Cookie nor Referer is forwarded by this handler.
  assert.equal(sent.cookie, undefined)
  assert.equal(sent.referer, undefined)
  // Accept-Language is PINNED to Tor Browser's value, not forwarded: it is the
  // one high-entropy passive fingerprinting header this handler would
  // otherwise create by itself.
  assert.equal(sent['accept-language'], 'en-US,en;q=0.5')
  assert.deepEqual(Object.keys(sent).sort(), ['accept', 'accept-language', 'range', 'user-agent'])
})

test('the response header allow-list carries the service\'s own instructions', async () => {
  const handler = routed(async () => new Response('x', {
    headers: {
      'content-type': 'text/html',
      etag: '"abc"',
      'cache-control': 'no-store',
      'content-disposition': 'inline',
      'last-modified': 'Wed, 21 Oct 2026 07:28:00 GMT',
      'accept-ranges': 'bytes',
      vary: 'accept-encoding',
      // The service's own instructions about its own content.
      'content-security-policy': "default-src 'self'",
      'content-security-policy-report-only': "default-src 'none'",
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
      'permissions-policy': 'geolocation=()',
      // …and the things that must not cross.
      'set-cookie': 'a=b',
      'strict-transport-security': 'max-age=31536000',
      'x-tracking': 'yes'
    }
  }))
  const res = await handler(new Request(`onion://${ONION}/`))
  assert.equal(res.headers.get('content-type'), 'text/html')
  assert.equal(res.headers.get('etag'), '"abc"')
  assert.equal(res.headers.get('cache-control'), 'no-store')
  assert.equal(res.headers.get('content-disposition'), 'inline')
  assert.equal(res.headers.get('last-modified'), 'Wed, 21 Oct 2026 07:28:00 GMT')
  assert.equal(res.headers.get('accept-ranges'), 'bytes')
  assert.equal(res.headers.get('vary'), 'accept-encoding')
  assert.equal(res.headers.get('content-security-policy'), "default-src 'self'")
  assert.equal(res.headers.get('content-security-policy-report-only'), "default-src 'none'")
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff')
  assert.equal(res.headers.get('x-frame-options'), 'DENY')
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer')
  assert.equal(res.headers.get('permissions-policy'), 'geolocation=()')
  // Strict-Transport-Security is left out deliberately: there is no TLS in the
  // tunnel, and forwarding it would poison HSTS state for the origin.
  assert.equal(res.headers.get('strict-transport-security'), null)
  assert.equal(res.headers.get('set-cookie'), null)
  assert.equal(res.headers.get('x-tracking'), null)
})

test('a decompressed body does not carry the upstream length', async () => {
  const handler = routed(async () => new Response('x', {
    headers: { 'content-type': 'text/plain', 'content-encoding': 'gzip', 'content-length': '9999' }
  }))
  const res = await handler(new Request(`onion://${ONION}/`))
  assert.equal(res.headers.get('content-length'), null)
  // With no content-encoding the length is the body's own and is passed on.
  const plain = routed(async () => new Response('x', { headers: { 'content-length': '1' } }))
  assert.equal((await plain(new Request(`onion://${ONION}/`))).headers.get('content-length'), '1')
})

test('a range request is served with its content-range', async () => {
  const handler = routed(async () => new Response('x', {
    status: 206,
    headers: { 'content-range': 'bytes 0-0/10', 'accept-ranges': 'bytes' }
  }))
  const res = await handler(new Request(`onion://${ONION}/big.bin`, { headers: { range: 'bytes=0-0' } }))
  assert.equal(res.status, 206)
  assert.equal(res.headers.get('content-range'), 'bytes 0-0/10')
})

test('an upstream status Chromium cannot carry is clamped to 502', async () => {
  // A status is chosen by the far end, so it is a variable, not a literal:
  // Chromium NOTREACHEDs on a code it has no reason phrase for.
  const handler = routed(async () => new Response('', { status: 523 }))
  assert.equal((await handler(new Request(`onion://${ONION}/`))).status, 502)
  const ok = routed(async () => new Response('', { status: 404 }))
  assert.equal((await ok(new Request(`onion://${ONION}/`))).status, 404)
})

// --- the address check: local, instant, before any circuit -----------------

test('an address whose checksum does not match is refused before any circuit', async () => {
  let fetched = 0
  const handler = routed(async () => { fetched++; return new Response('') })
  const res = await handler(new Request(`onion://${'a'.repeat(56)}.onion/`))
  assert.equal(res.status, 400)
  assert.match(await res.text(), /checksum does not match/)
  assert.equal(fetched, 0, 'no circuit is spent finding out what a checksum says')
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'tor')
})

test('the refusal page escapes the address it echoes back', async () => {
  const handler = routed(async () => new Response(''))
  const res = await handler(new Request('onion://%3Cimg%20src=x%20onerror=alert(1)%3E.onion/'))
  assert.equal(res.status, 400)
  const body = await res.text()
  assert.doesNotMatch(body, /<img/i)
})

// --- ports -----------------------------------------------------------------

test('an onion service on a non-default port is reachable', async () => {
  const seen = []
  const handler = routed(async (url) => { seen.push(url); return new Response('ok', { status: 200 }) })
  const res = await handler(new Request(`onion://${ONION}:8080/x?y=1`))
  assert.equal(res.status, 200)
  assert.deepEqual(seen, [`http://${ONION}:8080/x?y=1`])
})

// --- redirects: decided here, never followed to wherever the service points -

test('classifyOnionRedirect sorts a Location into exactly one kind', () => {
  const base = `http://${ONION}/a/b`
  assert.equal(classifyOnionRedirect('/welcome', base).kind, 'same-service')
  assert.equal(classifyOnionRedirect(`http://${ONION}/welcome`, base).kind, 'same-service')
  assert.equal(classifyOnionRedirect(`http://${OTHER}/there`, base).kind, 'other-onion')
  // A different port on the same host is a different service.
  assert.equal(classifyOnionRedirect(`http://${ONION}:9/a`, base).kind, 'other-onion')
  assert.equal(classifyOnionRedirect('https://example.com/', base).kind, 'off-tor')
  // A non-http(s) target is off Tor too — it is certainly not this service.
  assert.equal(classifyOnionRedirect('ftp://x/', base).kind, 'off-tor')
  assert.equal(classifyOnionRedirect('http://', base).kind, 'invalid')
  // The onion:// form a navigation would use carries the port.
  assert.equal(classifyOnionRedirect(`http://${OTHER}:8080/there?x=1`, base).onionUrl,
    `onion://${OTHER}:8080/there?x=1`)
})

test('a same-service redirect is followed internally, bounded at five hops', async () => {
  const seen = []
  const handler = routed(async (url) => {
    seen.push(url)
    if (seen.length === 1) return new Response('', { status: 302, headers: { location: '/welcome' } })
    return new Response('WELCOME', { status: 200 })
  })
  const res = await handler(new Request(`onion://${ONION}/`))
  assert.equal(res.status, 200)
  assert.equal(await res.text(), 'WELCOME')
  assert.deepEqual(seen, [`http://${ONION}/`, `http://${ONION}/welcome`])

  let hops = 0
  const loop = routed(async () => { hops++; return new Response('', { status: 302, headers: { location: '/again' } }) })
  const looped = await loop(new Request(`onion://${ONION}/`))
  assert.equal(looped.status, 502)
  assert.match(await looped.text(), /Too many redirects|redirected more than/i)
  assert.equal(hops, 6, 'five followed hops, and the sixth answer ends it')
})

test('a redirect to ANOTHER onion service becomes a real navigation', async () => {
  // The origin has to change, so the browser performs the navigation — this
  // handler does not fetch a stranger and serve it under this address.
  const seen = []
  const handler = routed(async (url) => {
    seen.push(url)
    return new Response('', { status: 301, headers: { location: `http://${OTHER}/there?x=1` } })
  })
  const res = await handler(new Request(`onion://${ONION}/`))
  assert.equal(res.status, 301)
  assert.equal(res.headers.get('location'), `onion://${OTHER}/there?x=1`)
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'tor')
  assert.deepEqual(seen, [`http://${ONION}/`], 'the other service was not fetched here')
})

test('a redirect off Tor is not followed: the page names the destination', async () => {
  const seen = []
  const handler = routed(async (url) => {
    seen.push(url)
    return new Response('', { status: 302, headers: { location: 'https://example.com/track' } })
  })
  const res = await handler(new Request(`onion://${ONION}/`))
  assert.equal(res.status, 200)
  const body = await res.text()
  assert.match(body, /sent you off Tor/)
  assert.match(body, /example\.com\/track/)
  assert.match(body, /<a href="https:\/\/example\.com\/track">/, 'offered as a link the user can take')
  assert.deepEqual(seen, [`http://${ONION}/`], 'the clearnet URL was never fetched')
  assert.equal(res.headers.get('X-Resolution-Namespace'), 'tor')
})

test('a 304 answer to a conditional request is passed through, not treated as a redirect', async () => {
  // if-none-match and if-modified-since are forwarded, so this is the ordinary
  // case, not an exotic one: a 3xx without a Location is not a redirect.
  const handler = routed(async () => new Response(null, { status: 304, headers: { etag: '"v1"' } }))
  const res = await handler(new Request(`onion://${ONION}/`))
  assert.equal(res.status, 304)
  assert.equal(res.headers.get('etag'), '"v1"')
})

test('a same-service 303 after a POST is followed with a GET and no body; a 307 keeps the method', async () => {
  // RFC 9110 §15.4.4: a user agent retrieves a 303 target with GET. 307 and
  // 308 (§15.4.8, §15.4.9) preserve the method and body.
  for (const [status, expectMethod] of [[303, 'GET'], [302, 'GET'], [307, 'POST'], [308, 'POST']]) {
    const seen = []
    const handler = routed(async (url, opts) => {
      seen.push({ url, method: opts.method, body: opts.body && Buffer.from(opts.body).toString() })
      if (seen.length === 1) return new Response('', { status, headers: { location: '/done' } })
      return new Response('OK', { status: 200 })
    })
    const res = await handler(new Request(`onion://${ONION}/submit`, { method: 'POST', body: 'a=1' }))
    assert.equal(res.status, 200, String(status))
    assert.deepEqual(seen.map((s) => s.method), ['POST', expectMethod], String(status))
    assert.deepEqual(seen.map((s) => s.body), ['a=1', expectMethod === 'POST' ? 'a=1' : undefined], String(status))
  }
})
