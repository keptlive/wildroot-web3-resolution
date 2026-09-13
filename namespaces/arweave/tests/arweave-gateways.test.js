/*
 * `ar://` must not have one point of failure.
 *
 * The handler took a single hardcoded `https://arweave.net`. That is the
 * Arweave project's own gateway — not a member of the ar.io gateway network,
 * and not something we operate — so the scheme whose entire promise is that
 * content outlives everyone was one outage away from serving nothing.
 *
 * Failover is safe HERE in a way it would not be for a mutable name: a txid
 * addresses immutable content, so a second gateway can only answer with bytes
 * that hash to the same id, or be caught. (Catching it is the unfinished half
 * — see the header of src/hns/ar.js.)
 *
 * The rule the tests below pin is *when* to move on. A 404 is an ANSWER: the
 * transaction is not there, and asking three more gateways to say so again
 * costs three round trips and tells the user nothing new. Only a failure to
 * REACH a host, or a 5xx, is worth another attempt.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import createArHandler, { AR_GATEWAYS, sandboxLabel, sameScopeRedirect } from '../src/ar.js'
import { tag, transaction } from './ar-transaction-fixture.js'

const TX = 'W-9rj7LCX-1kRs8Edf4UmJvzCHYBCnZN_13dh0Y7xq8'

/** A fetch that records what it was asked for and replies from a script. */
function scripted (replies) {
  const tried = []
  const fetchImpl = async (url) => {
    const reply = replies[tried.length] || (() => new Response('ok', { status: 200 }))
    tried.push(new URL(url).host)
    const out = reply()
    if (out instanceof Error) throw out
    return out
  }
  return { tried, fetchImpl }
}

const ok = () => new Response('ok', { status: 200, headers: { 'content-type': 'text/plain' } })

test('the default list is more than one operator', () => {
  assert.ok(AR_GATEWAYS.length > 1)
  const hosts = AR_GATEWAYS.map((u) => new URL(u).host)
  assert.equal(new Set(hosts).size, hosts.length, 'the same host listed twice is not failover')
})

test('every default gateway is https', () => {
  // An http: gateway would put the whole fetch in plaintext, and nothing
  // downstream re-checks the scheme.
  for (const g of AR_GATEWAYS) assert.equal(new URL(g).protocol, 'https:', g)
})

test('a transport failure is recognised by its error CODE, not only its wording', async () => {
  // The whole "try the next gateway" decision used to be a match on
  // human-readable error text, which a runtime that rewords or localizes its
  // errors turns off silently. Structure is checked first: this error has an
  // EMPTY message and only `cause.code`.
  const silent = new Error('')
  silent.cause = { code: 'ECONNREFUSED' }
  const { tried, fetchImpl } = scripted([() => silent])
  const { handler } = createArHandler({ fetchImpl })
  const res = await handler(new Request(`ar://${TX}/`))
  assert.equal(res.status, 200)
  assert.equal(tried.length, 2, 'moved on to the next gateway')

  const aborted = new Error('')
  aborted.name = 'AbortError'
  const b = scripted([() => aborted])
  const { handler: h2 } = createArHandler({ fetchImpl: b.fetchImpl })
  assert.equal((await h2(new Request(`ar://${TX}/`))).status, 200)
  assert.equal(b.tried.length, 2)
})

test('a gateway that cannot be reached is skipped', async () => {
  const { tried, fetchImpl } = scripted([() => new Error('fetch failed')])
  const { handler } = createArHandler({ fetchImpl })
  const res = await handler(new Request(`ar://${TX}/`))
  assert.equal(res.status, 200)
  assert.equal(tried.length, 2, 'it gave up instead of trying the next gateway')
})

test('a 5xx is retried on the next gateway', async () => {
  const { tried, fetchImpl } = scripted([() => new Response('down', { status: 503 })])
  const { handler } = createArHandler({ fetchImpl })
  const res = await handler(new Request(`ar://${TX}/`))
  assert.equal(res.status, 200)
  assert.equal(tried.length, 2)
})

test('a 404 is an ANSWER and is not retried', async () => {
  // The transaction is not there. Three more gateways saying so is three more
  // round trips and the same page.
  const { tried, fetchImpl } = scripted([() => new Response('no', { status: 404 })])
  const { handler } = createArHandler({ fetchImpl })
  const res = await handler(new Request(`ar://${TX}/`))
  assert.equal(res.status, 404)
  assert.equal(tried.length, 1)
})

test('the first gateway answering ends it', async () => {
  const { tried, fetchImpl } = scripted([ok])
  const { handler } = createArHandler({ fetchImpl })
  assert.equal((await handler(new Request(`ar://${TX}/`))).status, 200)
  assert.equal(tried.length, 1)
})

test('every gateway failing surfaces the error rather than a blank success', async () => {
  const fail = () => new Error('fetch failed')
  const { fetchImpl } = scripted([fail, fail, fail, fail])
  const { handler } = createArHandler({ fetchImpl })
  await assert.rejects(() => handler(new Request(`ar://${TX}/`)), /fetch failed/)
})

test('a caller may still pin ONE gateway, and then there is no failover', async () => {
  // Tests and the anonymized path pin a host on purpose; silently reaching for
  // two more would defeat the point of pinning it.
  const { tried, fetchImpl } = scripted([() => new Error('fetch failed')])
  const { handler } = createArHandler({ gateway: 'https://only.example', fetchImpl })
  await assert.rejects(() => handler(new Request(`ar://${TX}/`)))
  assert.deepEqual(tried, ['only.example'])
})

test('failover does not weaken the txid rule', async () => {
  // The txid check runs before any gateway is chosen, so adding gateways
  // cannot have widened what a URL may address.
  const { tried, fetchImpl } = scripted([ok])
  const { handler } = createArHandler({ fetchImpl })
  assert.equal((await handler(new Request('ar://not-a-txid/'))).status, 400)
  assert.equal(tried.length, 0, 'a rejected URL must never reach a gateway')
})

test('a path cannot escape the txid, whichever gateway answers', async () => {
  // Worth being precise about WHY this holds, because the handler's explicit
  // dot-segment guard is not what does it here: `new Request()` applies WHATWG
  // URL normalization, so `ar://<txid>/../secret` has already collapsed to
  // `ar://<txid>/secret` before the handler ever runs. The guard is real
  // defence for a raw string, and unreachable through a Request. Either way,
  // what reaches a gateway stays under the txid — asserted on the URL actually
  // requested rather than on a status code.
  const { fetchImpl } = scripted([ok])
  let asked = null
  const { handler } = createArHandler({
    fetchImpl: async (url, init) => { asked = url; return fetchImpl(url, init) }
  })
  await handler(new Request(`ar://${TX}/../secret`))
  assert.ok(asked.startsWith(`https://arweave.net/${TX}/`), asked)
  assert.ok(!asked.includes('..'), asked)
})

// ---------------------------------------------------------------------------
// What reaches the gateway, and what comes back.
// ---------------------------------------------------------------------------

/** A fetch that records the URL and init it was asked for and answers `reply`. */
function recording (reply = ok) {
  const asked = []
  const fetchImpl = async (url, init) => { asked.push({ url, init }); return reply(url, init) }
  fetchImpl.asked = asked
  return fetchImpl
}

test('the query string is kept and an encoded path segment is not encoded twice', async () => {
  const fetchImpl = recording()
  const { handler } = createArHandler({ gateway: 'https://g.example', fetchImpl })
  await handler(new Request(`ar://${TX}/my%20file.html?x=1&y=2`))
  assert.equal(fetchImpl.asked[0].url, `https://g.example/${TX}/my%20file.html?x=1&y=2`)
  await handler(new Request(`ar://${TX}?dl=1`))
  assert.equal(fetchImpl.asked[1].url, `https://g.example/${TX}?dl=1`)
  // A segment that DECODES to a separator is refused: it would escape the txid.
  const res = await handler(new Request(`ar://${TX}/a%2F..%2Fb`))
  assert.equal(res.status, 400)
  assert.equal(fetchImpl.asked.length, 2)
})

test('only the canonical spelling of a transaction id is accepted', async () => {
  // The final base64url character carries two must-be-zero bits; the
  // non-canonical twin of a real id names the same bytes and is refused.
  const fetchImpl = recording()
  const { handler } = createArHandler({ fetchImpl })
  const twin = TX.slice(0, -1) + '9'
  assert.equal((await handler(new Request(`ar://${twin}/`))).status, 400)
  assert.equal((await handler(new Request(`ar://${TX}/`))).status, 200)
  assert.equal(fetchImpl.asked.length, 1)
})

test('only GET and HEAD reach a gateway', async () => {
  const fetchImpl = recording()
  const { handler } = createArHandler({ fetchImpl })
  const res = await handler(new Request(`ar://${TX}/`, { method: 'POST', body: 'x' }))
  assert.equal(res.status, 405)
  assert.equal(fetchImpl.asked.length, 0)
})

test('fetchImpl is required — the global fetch is not proxied', () => {
  assert.throws(() => createArHandler({}), /fetchImpl/)
})

test('a transport failure is recognised by its error CODE, not only its wording', async () => {
  const silent = new Error('')
  silent.cause = { code: 'ECONNREFUSED' }
  const { tried, fetchImpl } = scripted([() => silent])
  const { handler } = createArHandler({ fetchImpl })
  const res = await handler(new Request(`ar://${TX}/`))
  assert.equal(res.status, 200)
  assert.equal(tried.length, 2, 'moved on to the next gateway')
})

test('Range and its answers pass through, and nothing else the caller chose', async () => {
  const fetchImpl = recording(() => new Response('partial', {
    status: 206,
    headers: { 'content-type': 'video/mp4', 'content-range': 'bytes 0-9/100', 'accept-ranges': 'bytes', 'set-cookie': 'a=b', 'x-powered-by': 'x' }
  }))
  const { handler } = createArHandler({ fetchImpl })
  const res = await handler(new Request(`ar://${TX}/v.mp4`, { headers: { range: 'bytes=0-9', cookie: 'secret=1', 'x-custom': 'no' } }))
  assert.equal(fetchImpl.asked[0].init.headers.range, 'bytes=0-9')
  assert.equal(fetchImpl.asked[0].init.headers.cookie, undefined)
  assert.equal(fetchImpl.asked[0].init.headers['x-custom'], undefined)
  assert.equal(res.status, 206)
  assert.equal(res.headers.get('content-range'), 'bytes 0-9/100')
  assert.equal(res.headers.get('accept-ranges'), 'bytes')
  assert.equal(res.headers.get('set-cookie'), null)
  assert.equal(res.headers.get('x-powered-by'), null)
})

test('a gateway redirect is followed only within the same gateway and the same transaction, one hop', async () => {
  const seen = []
  const same = async (url) => {
    seen.push(url)
    if (seen.length === 1) return new Response('', { status: 302, headers: { location: `/${TX}/index.html` } })
    return new Response('INDEX', { status: 200 })
  }
  const { handler } = createArHandler({ gateway: 'https://g.example', fetchImpl: same })
  const res = await handler(new Request(`ar://${TX}/`))
  assert.equal(res.status, 200)
  assert.equal(await res.text(), 'INDEX')
  assert.deepEqual(seen, [`https://g.example/${TX}`, `https://g.example/${TX}/index.html`])

  // arweave.net's real shape: a 302 into a per-transaction SANDBOX subdomain,
  // `https://<base32(txid)>.arweave.net/<txid>[/path]`, so each transaction is
  // its own origin. Same gateway, same transaction — followed, and with the
  // header check on the response says what was checked.
  const label = sandboxLabel(TX)
  assert.match(label, /^[a-z2-7]{52}$/, 'a 32-byte id sandboxes to 52 base32 characters')
  const { id, header } = transaction(Buffer.from('PNG'), { tags: [tag('Content-Type', 'image/png')] })
  const sandbox = []
  const sandboxed = async (url) => {
    sandbox.push(url)
    if (/\/tx\//.test(url)) return new Response(JSON.stringify(header), { status: 200, headers: { 'content-type': 'application/json' } })
    if (url === `https://g.example/${id}`) return new Response('', { status: 302, headers: { location: `https://${sandboxLabel(id)}.g.example/${id}` } })
    return new Response('PNG', { status: 200, headers: { 'content-type': 'image/png' } })
  }
  const viaSandbox = createArHandler({ gateways: ['https://g.example', 'https://h.example'], fetchImpl: sandboxed, verifyHeader: true })
  const png = await viaSandbox.handler(new Request(`ar://${id}`))
  assert.equal(png.status, 200)
  assert.equal(await png.text(), 'PNG')
  assert.equal(png.headers.get('content-type'), 'image/png')
  assert.equal(png.headers.get('X-Arweave-Verified'), 'bytes', 'the signature and bytes checks ran after the sandbox hop')
  assert.deepEqual(sandbox.slice(0, 2), [`https://g.example/${id}`, `https://${sandboxLabel(id)}.g.example/${id}`])
  assert.ok(sandbox[2].startsWith('https://h.example/tx/'), 'the header came from the other gateway')
  // A subdomain of ANOTHER host, or the same gateway with another txid, is still refused.
  assert.equal(sameScopeRedirect(`https://${label}.evil.example/${TX}`, `https://g.example/${TX}`, TX), null)
  assert.equal(sameScopeRedirect(`https://${label}.g.example/OTHER${TX.slice(5)}`, `https://g.example/${TX}`, TX), null)
  assert.equal(sameScopeRedirect(`https://notg.example/${TX}`, `https://g.example/${TX}`, TX), null, 'a host that merely ends with the gateway name is not a subdomain')
  assert.equal(sameScopeRedirect(`https://${label}.g.example/${TX}/a/b`, `https://g.example/${TX}`, TX), `https://${label}.g.example/${TX}/a/b`)

  for (const location of ['https://evil.example/', `https://g.example/OTHER${TX.slice(5)}/x`, `http://g.example/${TX}/x`, `http://${label}.g.example/${TX}/x`]) {
    const asked = []
    const bounce = async (url) => { asked.push(url); return new Response('', { status: 302, headers: { location } }) }
    const { handler } = createArHandler({ gateway: 'https://g.example', fetchImpl: bounce })
    const res = await handler(new Request(`ar://${TX}/`))
    assert.equal(res.status, 502, location)
    assert.equal(res.headers.get('location'), null, 'the redirect is never handed to the renderer')
    assert.equal(asked.length, 1, `${location}: the target was never fetched`)
  }
})

test('a HEAD is issued upstream as a HEAD, not a GET', async () => {
  const fetchImpl = recording(() => new Response(null, { status: 200, headers: { 'content-type': 'text/html', 'content-length': '1234' } }))
  const { handler } = createArHandler({ fetchImpl })
  const res = await handler(new Request(`ar://${TX}/`, { method: 'HEAD' }))
  assert.equal(fetchImpl.asked[0].init.method, 'HEAD')
  assert.equal(res.status, 200)
  assert.equal(res.headers.get('content-length'), '1234')
})

test('with the header check on, a second gateway\'s transaction must authenticate its fields and id', async () => {
  const { headerMatchesId } = await import('../src/ar.js')
  const { id, header } = transaction(Buffer.from('bytes'))
  assert.equal(headerMatchesId(header, id), true)
  assert.equal(headerMatchesId({ ...header, signature: Buffer.alloc(256, 8).toString('base64url') }, id), false)
  assert.equal(headerMatchesId({}, id), false)

  const answers = (header) => async (url) => {
    if (/\/tx\//.test(url)) return new Response(JSON.stringify(header), { status: 200, headers: { 'content-type': 'application/json' } })
    return new Response('bytes', { status: 200, headers: { 'content-type': 'text/plain' } })
  }
  const good = createArHandler({ gateways: ['https://a.example', 'https://b.example'], fetchImpl: recording(answers(header)), verifyHeader: true })
  const ok = await good.handler(new Request(`ar://${id}/`))
  assert.equal(ok.status, 200)
  assert.equal(ok.headers.get('X-Arweave-Verified'), 'bytes')

  const asked = []
  const liar = createArHandler({ gateways: ['https://a.example', 'https://b.example'], fetchImpl: async (url, init) => { asked.push(url); return answers({ ...header, signature: Buffer.alloc(256, 9).toString('base64url') })(url, init) }, verifyHeader: true })
  const bad = await liar.handler(new Request(`ar://${id}/`))
  assert.equal(bad.status, 502)
  assert.match(await bad.text(), /does not hash to the id/)
  assert.ok(asked.some((u) => u.startsWith('https://b.example/tx/')), 'the header came from the OTHER gateway')

  // A path inside a manifest is another transaction's bytes: not checked, and said so.
  const manifest = await good.handler(new Request(`ar://${id}/index.html`))
  assert.equal(manifest.headers.get('X-Arweave-Verified'), 'none')
  // One gateway only: nothing to check against.
  const single = createArHandler({ gateway: 'https://a.example', fetchImpl: recording(answers({})), verifyHeader: true })
  assert.equal((await single.handler(new Request(`ar://${id}/`))).headers.get('X-Arweave-Verified'), 'none')
})
