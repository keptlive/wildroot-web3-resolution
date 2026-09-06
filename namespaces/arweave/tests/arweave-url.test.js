/*
 * The `ar://` URL form: what an identifier may be, what a path may be, what
 * reaches a gateway, and what comes back.
 *
 * Everything here is asserted on the URL and the init the handler actually
 * asked its injected fetch for, rather than on a status code, because the
 * property that matters is *what left the process*. A test that only checks
 * a 200 cannot tell a correct request from a confined one.
 *
 * SPEC.md §3 (the identifier), §4 (the URL form), §6.3 (redirects),
 * §6.4 (headers), §6.5 (method), §6.6 (the injected fetch).
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import createArHandler from '../src/ar.js'

/** A real 43-character Arweave transaction id (Wildroot release 1). */
const TX = 'W-9rj7LCX-1kRs8Edf4UmJvzCHYBCnZN_13dh0Y7xq8'

/** A handler that records the URL and init it was asked for. */
function recorder (reply = () => new Response('ok', { status: 200 })) {
  const calls = []
  const { handler } = createArHandler({
    fetchImpl: async (url, init) => { calls.push({ url, init }); return reply(url, init) }
  })
  return { handler, calls }
}

/** The same, pinned to one gateway so an absolute target is predictable. */
function pinned (reply = () => new Response('ok', { status: 200 })) {
  const calls = []
  const { handler } = createArHandler({
    gateway: 'https://g.example',
    fetchImpl: async (url, init) => { calls.push({ url, init }); return reply(url, init) }
  })
  return { handler, calls }
}

// --- §3: the identifier -----------------------------------------------------

test('an identifier is 43 characters of the RFC 4648 §5 base64url alphabet', async () => {
  const { handler, calls } = recorder()
  assert.equal((await handler(new Request(`ar://${TX}/`))).status, 200)
  assert.equal(calls.length, 1)

  // Everything outside the alphabet, and every other length, is refused
  // BEFORE a gateway is chosen (SPEC §11.3 — this is a confinement boundary).
  for (const bad of [
    'A'.repeat(42), 'A'.repeat(44), '', 'not-a-txid',
    'A'.repeat(42) + '+', // base64 standard alphabet, not base64url
    'A'.repeat(42) + '/', // ditto, and a separator besides
    'A'.repeat(42) + '=' // padding: 43 chars are unpadded by construction
  ]) {
    const r = recorder()
    const res = await r.handler(new Request(`ar://${bad}/`))
    assert.equal(res.status, 400, `${JSON.stringify(bad)} should be refused`)
    assert.equal(r.calls.length, 0, 'a refused id must never reach a gateway')
  }
})

test('an identifier is case-sensitive and is NOT folded', async () => {
  // SPEC §3.4/§4.2: parsing is done on the raw URL precisely so that a
  // case-sensitive base64url id is not lowercased into a different id. The
  // handler forwards what it was given; it does not "helpfully" repair it.
  const { handler, calls } = recorder()
  await handler(new Request(`ar://${TX.toLowerCase()}/`))
  assert.ok(calls[0].url.endsWith(TX.toLowerCase()),
    'a lowercased id is forwarded as the different id it is, not folded back')
})

test('only the CANONICAL spelling of an identifier is accepted', async () => {
  // SPEC §3.3. 43 base64url chars carry 258 bits for a 256-bit id, so the last
  // character has two must-be-zero bits (RFC 4648 §3.5) and only 16 of the 64
  // alphabet characters have them. Without this check sixteen distinct URLs
  // would name every transaction.
  const twin = TX.slice(0, 42) + '9'
  assert.notEqual(TX, twin)
  assert.deepEqual(
    Buffer.from(TX, 'base64url'), Buffer.from(twin, 'base64url'),
    'the premise: both decode to the same 32 bytes')
  assert.notEqual(Buffer.from(twin, 'base64url').toString('base64url'), twin,
    'and the twin is not what a canonical re-encode produces')

  const { handler, calls } = recorder()
  assert.equal((await handler(new Request(`ar://${twin}/`))).status, 400)
  assert.equal(calls.length, 0, 'a non-canonical id reaches no gateway')
  assert.equal((await handler(new Request(`ar://${TX}/`))).status, 200)
  assert.equal(calls.length, 1, 'and the canonical one is unaffected')
})

// --- §4.3: the path ---------------------------------------------------------

test('a path stays strictly under the identifier', async () => {
  const { handler, calls } = recorder()
  await handler(new Request(`ar://${TX}/../secret`))
  assert.ok(calls[0].url.startsWith(`https://arweave.net/${TX}/`), calls[0].url)
  assert.ok(!calls[0].url.includes('..'), calls[0].url)
})

test('a raw dot-segment string is refused with 400 and reaches no gateway', async () => {
  // Through a WHATWG Request, `..` is already collapsed and the explicit guard
  // is unreachable. It is real defence for a raw string, which is what a
  // non-Request caller (or another runtime's URL handling) can present.
  const { handler, calls } = recorder()
  const res = await handler({
    url: `ar://${TX}/a/../../etc/passwd`,
    method: 'GET',
    arrayBuffer: async () => new ArrayBuffer(0)
  })
  assert.equal(res.status, 400)
  assert.equal(calls.length, 0)
})

test('a segment that DECODES to a separator or a dot-segment is refused', async () => {
  // SPEC §4.3. Segments are forwarded as received, so the encoding is no
  // longer what confines them — this check is. `a%2F..%2Fb` survives WHATWG
  // normalization intact and would escape the identifier at the gateway.
  for (const path of ['a%2F..%2Fb', 'a%5C..%5Cb', 'a%2Fb']) {
    const { handler, calls } = recorder()
    const res = await handler(new Request(`ar://${TX}/${path}`))
    assert.equal(res.status, 400, path)
    assert.equal(calls.length, 0, `${path} must reach no gateway`)
  }

  // An encoded DOT-segment is collapsed by WHATWG URL normalization before a
  // Request reaches the handler (`/a/%2E%2E/b` is already `/b`), so the guard
  // is exercised here the way it is exercised in production by a non-Request
  // caller: on a raw string.
  for (const path of ['%2E%2E', 'a/%2e%2e/b', '.', 'a/../b']) {
    const { handler, calls } = recorder()
    const res = await handler({ url: `ar://${TX}/${path}`, method: 'GET' })
    assert.equal(res.status, 400, path)
    assert.equal(calls.length, 0, `${path} must reach no gateway`)
  }
})

test('an identifier with no path is fetched without a trailing slash', async () => {
  const { handler, calls } = recorder()
  await handler(new Request(`ar://${TX}`))
  assert.equal(calls[0].url, `https://arweave.net/${TX}`)
  const b = recorder()
  await b.handler(new Request(`ar://${TX}/`))
  assert.equal(b.calls[0].url, `https://arweave.net/${TX}`,
    'a bare trailing slash is the same request')
  // Empty segments are dropped, so a trailing slash deeper in the path does
  // not reach the gateway either. A gateway that normalizes such a path
  // answers with a redirect, which §6.3 follows.
  const c = recorder()
  await c.handler(new Request(`ar://${TX}/dir//sub/`))
  assert.equal(c.calls[0].url, `https://arweave.net/${TX}/dir/sub`)
})

test('an already-encoded path segment is passed on AS RECEIVED', async () => {
  // SPEC §4.3. Segments arrive percent-encoded from the URL parser;
  // re-encoding them would turn `%20` into `%2520` and address a manifest
  // path that does not exist.
  const { handler, calls } = pinned()
  await handler(new Request(`ar://${TX}/my%20file.html`))
  assert.equal(calls[0].url, `https://g.example/${TX}/my%20file.html`)
  await handler(new Request(`ar://${TX}/caf%C3%A9.txt`))
  assert.equal(calls[1].url, `https://g.example/${TX}/caf%C3%A9.txt`)
})

test('the query string is carried; the fragment is not', async () => {
  // SPEC §4.4. A manifest-hosted application reading `location.search` needs
  // the query. The fragment is never sent on the wire and is dropped first,
  // so a `#` cannot smuggle itself into the query.
  const { handler, calls } = pinned()
  await handler(new Request(`ar://${TX}/app?route=x&token=y`))
  assert.equal(calls[0].url, `https://g.example/${TX}/app?route=x&token=y`)

  await handler(new Request(`ar://${TX}?dl=1`))
  assert.equal(calls[1].url, `https://g.example/${TX}?dl=1`,
    'a query with no path is carried too')

  await handler(new Request(`ar://${TX}/app?q=1#section`))
  assert.equal(calls[2].url, `https://g.example/${TX}/app?q=1`)

  await handler(new Request(`ar://${TX}/app#section`))
  assert.equal(calls[3].url, `https://g.example/${TX}/app`)
})

// --- §6.4: headers ----------------------------------------------------------

test('Range and the answers it implies pass through a FIXED safelist', async () => {
  const { handler, calls } = recorder(() => new Response('partial', {
    status: 206,
    headers: {
      'content-type': 'video/mp4',
      'content-range': 'bytes 0-9/100',
      'accept-ranges': 'bytes',
      'last-modified': 'Wed, 21 Oct 2026 07:28:00 GMT',
      vary: 'accept-encoding',
      'set-cookie': 'a=b',
      'x-powered-by': 'a gateway'
    }
  }))
  const res = await handler(new Request(`ar://${TX}/v.mp4`, {
    headers: {
      range: 'bytes=0-9',
      'if-none-match': 'W/"x"',
      'if-modified-since': 'Wed, 21 Oct 2026 07:28:00 GMT',
      accept: 'video/mp4',
      cookie: 'secret=1',
      'x-custom': 'no'
    }
  }))

  assert.deepEqual(calls[0].init.headers, {
    'user-agent': 'hns.one-browser',
    range: 'bytes=0-9',
    'if-none-match': 'W/"x"',
    'if-modified-since': 'Wed, 21 Oct 2026 07:28:00 GMT',
    accept: 'video/mp4'
  }, 'the safelist, and nothing else the caller chose, leaves this process')

  assert.equal(res.status, 206)
  assert.equal(res.headers.get('content-range'), 'bytes 0-9/100',
    'a 206 without Content-Range is malformed; media served from ar:// seeks')
  assert.equal(res.headers.get('accept-ranges'), 'bytes')
  assert.equal(res.headers.get('last-modified'), 'Wed, 21 Oct 2026 07:28:00 GMT')
  assert.equal(res.headers.get('vary'), 'accept-encoding')
  assert.equal(res.headers.get('content-type'), 'video/mp4')
  assert.equal(res.headers.get('set-cookie'), null, 'the gateway sets no cookie here')
  assert.equal(res.headers.get('x-powered-by'), null)
})

// --- §6.3: redirects --------------------------------------------------------

test('the gateway is never permitted to redirect the fetch itself', async () => {
  const { handler, calls } = recorder()
  await handler(new Request(`ar://${TX}/`))
  assert.equal(calls[0].init.redirect, 'manual',
    'an ar:// fetch must not be bounceable to an arbitrary host')
})

test('a redirect is followed within the same gateway and the same transaction, once', async () => {
  const seen = []
  const { handler } = createArHandler({
    gateway: 'https://g.example',
    fetchImpl: async (url) => {
      seen.push(url)
      if (seen.length === 1) {
        return new Response('', { status: 302, headers: { location: `/${TX}/index.html` } })
      }
      return new Response('INDEX', { status: 200 })
    }
  })
  const res = await handler(new Request(`ar://${TX}/`))
  assert.equal(res.status, 200)
  assert.equal(await res.text(), 'INDEX')
  assert.deepEqual(seen, [`https://g.example/${TX}`, `https://g.example/${TX}/index.html`])
})

test('a redirect out of scope is refused with 502 and no Location', async () => {
  // Handing `location` back to the renderer would restore the open redirect
  // that `redirect: 'manual'` exists to close, so the refusal carries none.
  for (const location of [
    'https://evil.example/', // another host
    `https://g.example/OTHER${TX.slice(5)}/x`, // another transaction
    `http://g.example/${TX}/x` // downgraded to plaintext
  ]) {
    const asked = []
    const { handler } = createArHandler({
      gateway: 'https://g.example',
      fetchImpl: async (url) => {
        asked.push(url)
        return new Response('', { status: 302, headers: { location } })
      }
    })
    const res = await handler(new Request(`ar://${TX}/`))
    assert.equal(res.status, 502, location)
    assert.equal(res.headers.get('location'), null,
      'the redirect is never handed to the renderer')
    assert.equal(asked.length, 1, `${location}: the target was never fetched`)
  }
})

test('a SECOND redirect is refused rather than followed', async () => {
  // One hop, so a gateway cannot walk a client around its own namespace.
  const asked = []
  let n = 0
  const { handler } = createArHandler({
    gateway: 'https://g.example',
    fetchImpl: async (url) => {
      asked.push(url)
      return new Response('', { status: 302, headers: { location: `/${TX}/step${++n}` } })
    }
  })
  const res = await handler(new Request(`ar://${TX}/`))
  assert.equal(res.status, 502)
  assert.equal(res.headers.get('location'), null)
  assert.equal(asked.length, 2, 'the first redirect was followed, the second was not')
})

test('a 3xx with no Location is returned as it came', async () => {
  // A 304 answering an If-None-Match is not a redirect and must survive.
  const { handler } = recorder(() => new Response(null, {
    status: 304, headers: { etag: 'W/"x"', 'cache-control': 'max-age=60' }
  }))
  const res = await handler(new Request(`ar://${TX}/x`, {
    headers: { 'if-none-match': 'W/"x"' }
  }))
  assert.equal(res.status, 304)
  assert.equal(res.headers.get('etag'), 'W/"x"')
})

// --- §6.5: method -----------------------------------------------------------

test('GET and HEAD reach a gateway, each as itself', async () => {
  // The upstream request carries the method it was given: a HEAD is a HEAD
  // of the gateway, and transfers no body.
  for (const method of ['GET', 'HEAD']) {
    const asked = []
    const fetchImpl = async (url, init) => { asked.push(init.method); return new Response(method === 'HEAD' ? null : 'ok', { status: 200, headers: { 'content-type': 'text/plain' } }) }
    const { handler } = createArHandler({ gateway: 'https://g.example', fetchImpl })
    const res = await handler(new Request(`ar://${TX}/`, { method }))
    assert.equal(res.status, 200, method)
    assert.deepEqual(asked, [method])
  }
})

test('any other method is refused with 405 and reaches no gateway', async () => {
  // There is nothing under a transaction id to write to.
  for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
    const { handler, calls } = recorder()
    const res = await handler(new Request(`ar://${TX}/x`, {
      method, ...(method === 'DELETE' ? {} : { body: 'hello' })
    }))
    assert.equal(res.status, 405, method)
    assert.equal(res.headers.get('allow'), 'GET, HEAD')
    assert.equal(calls.length, 0, `${method} must reach no gateway`)
  }
})

// --- §6.6: the injected fetch -----------------------------------------------

test('fetchImpl is REQUIRED — the runtime global fetch is not proxied', () => {
  // `ar://` is deliberately left ungated while anonymization is on, on the
  // strength of the caller injecting the session-bound (proxied) fetch. A
  // handler that fell back to the global fetch would disclose the real client
  // address to the gateway with anonymization visibly on, so there is no
  // fallback: a caller that forgets fails at construction.
  assert.throws(() => createArHandler({}), /fetchImpl/)
  assert.throws(() => createArHandler(), /fetchImpl/)
  assert.throws(() => createArHandler({ gateway: 'https://g.example' }), /fetchImpl/)
})
