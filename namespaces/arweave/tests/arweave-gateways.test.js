/*
 * `ar://` must not have one point of failure.
 *
 * `arweave.net` is the Arweave project's own gateway — not a member of the
 * ar.io gateway network, and not something we operate — so a scheme whose
 * entire promise is that content outlives everyone cannot rest on it alone.
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

import createArHandler, { AR_GATEWAYS } from '../src/ar.js'

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

test('every default gateway is https', () => {
  // An http: gateway would put the whole fetch in plaintext, and nothing
  // downstream re-checks the scheme.
  for (const g of AR_GATEWAYS) assert.equal(new URL(g).protocol, 'https:', g)
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
