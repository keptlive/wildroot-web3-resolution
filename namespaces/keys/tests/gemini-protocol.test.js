// `gemini://` — the redirect rule, the input form, and the status mapping.
//
// `src/gemini-protocol.js` is byte-identical to `src/protocols/gemini-protocol.js`
// in the Wildroot tree modulo its import paths, and it is the browser's own
// handler over the `@derhuerst/gemini` client rather than a library's fetch
// wrapper. The reason it exists is the redirect: a Gemini 30/31 is a
// RESOLUTION decision — which host's bytes end up under which origin — and
// `gemini:` is registered standard and secure, so an origin carries storage.
//
// Adapted from tests/hns/gemini-protocol.test.js in the Wildroot tree. The
// client is injected (`requestImpl`), so nothing here opens a socket: a
// scripted client answers each request and applies the caller's redirect
// predicate exactly as the real one does. Its bodies are Buffer chunks,
// because that is what the real client's stream yields and what
// `Readable.toWeb()` is handed downstream.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Readable } from 'node:stream'

import createHandler, { sameHostGeminiRedirect, MAX_REDIRECTS } from '../src/gemini-protocol.js'

/** A scripted Gemini client: `script(url, n)` answers the nth request. */
function client (script) {
  const asked = []
  const requestImpl = (url, opts, cb) => {
    asked.push(url)
    const answer = script(url, asked.length)
    // Apply the caller's redirect predicate the way the real client does.
    if ((answer.statusCode === 30 || answer.statusCode === 31) && opts.followRedirects(asked.length, answer)) {
      return requestImpl(new URL(answer.meta, url).href, opts, cb)
    }
    const res = answer.body === undefined ? answer : Object.assign(Readable.from([Buffer.from(answer.body)]), answer)
    setTimeout(() => cb(null, res), 0)
  }
  requestImpl.asked = asked
  return requestImpl
}

const handlerFor = async (requestImpl) => (await createHandler({ requestImpl })).handler

// --- the redirect rule ------------------------------------------------------

test('a same-host redirect is followed, bounded', async () => {
  const same = client((url, n) => n === 1
    ? { statusCode: 30, meta: '/welcome' }
    : { statusCode: 20, meta: 'text/gemini', body: '# hi' })
  const handler = await handlerFor(same)
  const res = await handler(new Request('gemini://a.example/'))
  assert.equal(res.status, 200)
  assert.equal(await res.text(), '# hi')
  assert.deepEqual(same.asked, ['gemini://a.example/', 'gemini://a.example/welcome'])

  // A loop is bounded: past MAX_REDIRECTS the redirect is RETURNED, not
  // followed, so the browser decides rather than the client spinning.
  const loop = client(() => ({ statusCode: 30, meta: '/again' }))
  const looped = await (await handlerFor(loop))(new Request('gemini://a.example/'))
  assert.equal(looped.status, 302)
  assert.equal(loop.asked.length, MAX_REDIRECTS + 1)
})

test('a redirect to another host is a real navigation, not a silent fetch', async () => {
  // The whole point: host B's bytes must never be served under `gemini://A`'s
  // origin. The response carries a `gemini:` Location, so the address bar and
  // the origin move with the content.
  const other = client(() => ({ statusCode: 31, meta: 'gemini://b.example/there' }))
  const nav = await (await handlerFor(other))(new Request('gemini://a.example/'))
  assert.equal(nav.status, 301, '31 is permanent, 30 is temporary')
  assert.equal(nav.headers.get('Location'), 'gemini://b.example/there')
  assert.deepEqual(other.asked, ['gemini://a.example/'], 'the other host was never fetched here')

  const temp = client(() => ({ statusCode: 30, meta: 'gemini://b.example/there' }))
  assert.equal((await (await handlerFor(temp))(new Request('gemini://a.example/'))).status, 302)
})

test('a redirect out of the namespace is refused and named, never followed', async () => {
  // L2: a gemini:// failure stays a gemini:// failure. Following this would
  // let a capsule launch an https:// fetch from the main process.
  const off = client(() => ({ statusCode: 30, meta: 'https://example.com/' }))
  const refused = await (await handlerFor(off))(new Request('gemini://a.example/'))
  assert.equal(refused.status, 502)
  assert.equal(refused.headers.get('Location'), null)
  assert.match(await refused.text(), /not a gemini:\/\/ address/)
})

test('sameHostGeminiRedirect compares scheme, host and port — the default port included', () => {
  assert.equal(sameHostGeminiRedirect('gemini://a.example/', '/relative'), true)
  assert.equal(sameHostGeminiRedirect('gemini://a.example/', 'gemini://A.EXAMPLE:1965/x'), true,
    'DNS is case-insensitive and 1965 is the default port')
  assert.equal(sameHostGeminiRedirect('gemini://a.example/', 'gemini://a.example:1966/x'), false)
  assert.equal(sameHostGeminiRedirect('gemini://a.example/', 'gemini://b.example/x'), false)
  assert.equal(sameHostGeminiRedirect('gemini://a.example/', 'https://a.example/x'), false)
  assert.equal(sameHostGeminiRedirect('gemini://a.example/', 'not a url at all'), true,
    'a bare relative target resolves against the request URL')
  assert.equal(sameHostGeminiRedirect('not a url', '/x'), false)
})

// --- input ------------------------------------------------------------------

test('input requests render a form, and its submission goes into the query string', async () => {
  const handler = await handlerFor(client(() => ({ statusCode: 10, meta: 'Search terms' })))
  const res = await handler(new Request('gemini://a.example/search'))
  assert.equal(res.status, 200)
  assert.match(res.headers.get('Content-Type'), /text\/html/)
  assert.match(await res.text(), /<form method="post"/)

  // 11 is a sensitive input: the field is a password field, and the prompt is
  // escaped — a capsule chooses that string.
  const pw = await handlerFor(client(() => ({ statusCode: 11, meta: '<script>alert(1)</script>' })))
  const body = await (await pw(new Request('gemini://a.example/'))).text()
  assert.match(body, /type="password"/)
  assert.doesNotMatch(body, /<script>/)

  const form = new FormData()
  form.set('input', 'hello world')
  const posted = await handler(new Request('gemini://a.example/search', { method: 'POST', body: form }))
  assert.equal(posted.status, 302)
  assert.equal(posted.headers.get('Location'), 'gemini://a.example/search?hello%20world')
})

test('only GET, HEAD and the form POST are accepted', async () => {
  const handler = await handlerFor(client(() => ({ statusCode: 20, meta: 'text/gemini', body: 'x' })))
  const res = await handler(new Request('gemini://a.example/', { method: 'DELETE' }))
  assert.equal(res.status, 405)
})

// --- status mapping ---------------------------------------------------------

test('a Gemini status becomes an HTTP status Chromium can carry', async () => {
  // Gemini's two-digit codes are multiplied by ten. A product Chromium does
  // not define is 502 instead: a handler's status goes straight into
  // net::GetHttpReasonPhrase(), which NOTREACHEDs on a code it does not know.
  const missing = await handlerFor(client(() => ({ statusCode: 51, meta: 'Not found' })))
  const res = await missing(new Request('gemini://a.example/missing'))
  assert.equal(res.status, 510)
  assert.equal(await res.text(), 'Not found', 'the META line is the body of a failure')
  assert.match(res.headers.get('Content-Type'), /text\/plain/)

  const odd = await handlerFor(client(() => ({ statusCode: 62, meta: 'cert' })))
  assert.equal((await odd(new Request('gemini://a.example/'))).status, 502,
    '620 is not a status Chromium can carry')
})

test('a success serves the body with the META line as its content type', async () => {
  const handler = await handlerFor(client(() => ({ statusCode: 20, meta: 'text/gemini; lang=en', body: '# hi' })))
  const res = await handler(new Request('gemini://a.example/'))
  assert.equal(res.status, 200)
  assert.equal(res.headers.get('Content-Type'), 'text/gemini; lang=en')
  assert.equal(await res.text(), '# hi')
})
