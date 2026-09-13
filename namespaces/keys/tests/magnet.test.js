// `magnet:` — the identifier, its two URNs, and the two places that read it.
//
// Adapted from tests/hns/torrent-magnet.test.js and tests/hns/magnet-consent.test.js
// in the Wildroot tree. What was dropped: the assertions that read
// src/window.js and src/pages/torrents/torrents.js off disk to prove the
// consent rewrite is wired at every navigation entry point. That is browser
// wiring, not resolution, and those files are not in this package.
//
// What was ADDED here (and is not in the browser tests) are the negative cases
// that make the grammar's edges explicit: the BEP-9 base32 infohash form and
// the BEP-52 `urn:btmh:` v2 form, each REFUSED BY NAME rather than with a
// message about a different magnet; a hybrid v1+v2 magnet, which resolves in
// either parameter order; and a magnet carrying both `xs` and `xt`, on which
// the handler and the navigation rewrite must agree. DEVIATIONS.md KY-2 and
// KY-3 say which forms this browser still does not read.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import createMagnetHandler, {
  INFO_HASH_MATCH, PUBLIC_KEY_MATCH, magnetToTorrentsPage
} from '../src/magnet-protocol.js'

const INFOHASH = 'c0ffee0123456789abcdef0123456789abcdef01'
const PUBKEY = 'd'.repeat(64)
// A v2 (BEP-52) infohash is SHA-256, so its multihash is 1220 + 64 hex.
const V2_MULTIHASH = '1220' + 'a'.repeat(64)

// --- the grammar ------------------------------------------------------------

test('the exported regexes ARE the canonical key shapes', () => {
  assert.equal(INFO_HASH_MATCH.exec(`urn:btih:${INFOHASH}`)[1], INFOHASH)
  assert.equal(PUBLIC_KEY_MATCH.exec(`urn:btpk:${PUBKEY}`)[1], PUBKEY)
  assert.equal(INFO_HASH_MATCH.exec(`urn:btih:${PUBKEY}`), null, '64 hex is not an infohash')
  assert.equal(PUBLIC_KEY_MATCH.exec(`urn:btpk:${INFOHASH}`), null, '40 hex is not a pubkey')
  // And stateless: the same regex answers the same input twice. (They used to
  // carry /g at module scope, so a successful .exec left lastIndex at the end
  // of the match and every SECOND identical magnet silently missed.)
  assert.ok(INFO_HASH_MATCH.test(`urn:btih:${INFOHASH}`))
  assert.ok(INFO_HASH_MATCH.test(`urn:btih:${INFOHASH}`))
})

test('the infohash form is 40 HEX only — BEP-9 base32 is not accepted', () => {
  // BEP-9 states the magnet info-hash may be given as 40 hex OR 32 base32
  // characters. Only the hex form is recognised (DEVIATIONS.md KY-2).
  const base32 = 'YNCKHTQCWBTRNJIV4WNAE52SJUQCZO5C' // 32 chars, legal base32
  assert.equal(INFO_HASH_MATCH.exec(`urn:btih:${base32}`), null)
})

test('a form this browser does not read is refused BY NAME', async () => {
  // "Magnet has no bittorrent infohash" is untrue of both of these: they carry
  // one, written in a form this browser does not read. A refusal that
  // describes a different magnet sends the reader looking for the wrong bug.
  const handler = await createMagnetHandler()
  const base32 = 'YNCKHTQCWBTRNJIV4WNAE52SJUQCZO5C'

  const v2 = handler(new Request(`magnet:?xt=urn:btmh:${V2_MULTIHASH}`))
  assert.equal(v2.status, 400)
  assert.match(await v2.text(), /BitTorrent v2 infohash \(urn:btmh\)/)

  const b32 = handler(new Request(`magnet:?xt=urn:btih:${base32}`))
  assert.equal(b32.status, 400)
  assert.match(await b32.text(), /base32 form/)

  // And the generic message survives for a magnet that really carries nothing.
  const nothing = handler(new Request('magnet:?xt=urn:sha1:whatever'))
  assert.equal(nothing.status, 400)
  assert.match(await nothing.text(), /no bittorrent infohash/)
})

// --- the handler: magnet: -> the consent page -------------------------------

test('btih (40 hex) redirects into the infohash branch', async () => {
  const handler = await createMagnetHandler()
  const res = handler(new Request(`magnet:?xt=urn:btih:${INFOHASH}&dn=bunny`))
  assert.equal(res.status, 308)
  // The infohash branch of the consent page — not bittorrent://, which would
  // add the torrent and start peer traffic for a link that was merely
  // dispatched here.
  assert.equal(res.headers.get('Location'), `wildroot://torrents?add=${INFOHASH}&dn=bunny`)
})

test('btpk (64 hex) redirects into the mutable branch', async () => {
  const handler = await createMagnetHandler()
  const res = handler(new Request(`magnet:?xs=urn:btpk:${PUBKEY}`))
  assert.equal(res.status, 308)
  // The mutable branch of the same consent page. A BEP-46 address opens a
  // site through bt-fetch rather than adding a managed torrent, so the page
  // is told which of the two it is being asked to confirm — but the answer is
  // still an inert page, never bittorrent://<key>.
  assert.equal(res.headers.get('Location'), `wildroot://torrents?mutable=${PUBKEY}`)
})

test('no magnet reaches a peer-backed URL through the handler', async () => {
  // Defence in depth: the handler calls the same rewrite the navigation entry
  // points do, so a redirect or a subresource that arrives here WITHOUT the
  // main-frame rewrite still lands at consent. No `Location` this handler can
  // emit carries network authority.
  const handler = await createMagnetHandler()
  for (const url of [
    `magnet:?xt=urn:btih:${INFOHASH}`,
    `magnet:?xs=urn:btpk:${PUBKEY}`,
    `magnet:?xs=urn:btpk:${PUBKEY}&xt=urn:btih:${INFOHASH}`,
    `magnet:?xt=urn:btmh:${V2_MULTIHASH}`,
    'magnet:?xt=urn:sha1:whatever',
    'magnet:?dn=nothing'
  ]) {
    const location = handler(new Request(url)).headers.get('Location')
    assert.ok(location === null || location.startsWith('wildroot://torrents?'), url)
  }
})

test('the same magnet parses correctly EVERY time (the /g lastIndex trap)', async () => {
  const handler = await createMagnetHandler()
  for (let i = 0; i < 3; i++) {
    assert.equal(handler(new Request(`magnet:?xt=urn:btih:${INFOHASH}`)).status, 308, `btih attempt ${i}`)
    assert.equal(handler(new Request(`magnet:?xs=urn:btpk:${PUBKEY}`)).status, 308, `btpk attempt ${i}`)
  }
})

test('a malformed magnet is an in-namespace 400, never a redirect', async () => {
  const handler = await createMagnetHandler()
  for (const bad of [
    'magnet:?xt=urn:btih:tooshort',
    `magnet:?xt=urn:btih:${'g'.repeat(40)}`, // not hex
    'magnet:?dn=nothing-else'
  ]) {
    const res = handler(new Request(bad))
    assert.equal(res.status, 400, bad)
    assert.equal(res.headers.get('Location'), null)
  }
})

test('a v2-only magnet (BEP-52 urn:btmh) is refused, not misrouted', async () => {
  // Refusing is correct: nothing downstream speaks v2, and a v2 infohash is
  // byte-for-byte the shape of a BEP-46 public key, so guessing would hand it
  // to the wrong engine (KY-3).
  const handler = await createMagnetHandler()
  const res = handler(new Request(`magnet:?xt=urn:btmh:${V2_MULTIHASH}`))
  assert.equal(res.status, 400)
  assert.equal(res.headers.get('Location'), null)
})

test('a HYBRID v1+v2 magnet resolves in EITHER xt order', async () => {
  const handler = await createMagnetHandler()
  // Hybrid torrents carry both URNs, in whichever order the publisher wrote
  // them. Every `xt` is read, so the usable v1 infohash is found wherever it
  // sits: one magnet, one outcome.
  for (const url of [
    `magnet:?xt=urn:btih:${INFOHASH}&xt=urn:btmh:${V2_MULTIHASH}`,
    `magnet:?xt=urn:btmh:${V2_MULTIHASH}&xt=urn:btih:${INFOHASH}`
  ]) {
    const res = handler(new Request(url))
    assert.equal(res.status, 308, url)
    assert.equal(res.headers.get('Location'), `wildroot://torrents?add=${INFOHASH}`, url)
  }
})

// --- the navigation rewrite (consent) --------------------------------------

test('an infohash magnet becomes a confirmation URL, not a bittorrent one', () => {
  assert.equal(magnetToTorrentsPage(`magnet:?xt=urn:btih:${INFOHASH}`),
    `wildroot://torrents?add=${INFOHASH}`)
  // Uppercase hashes normalize; the display name rides along so the prompt can
  // name the torrent before any metadata exists.
  assert.equal(magnetToTorrentsPage(`magnet:?xt=urn:btih:${INFOHASH.toUpperCase()}&dn=Big+Buck+Bunny`),
    `wildroot://torrents?add=${INFOHASH}&dn=Big%20Buck%20Bunny`)
})

test('a mutable magnet becomes a confirmation URL too', () => {
  // The consent rule has no exception: a BEP-46 address opens a site through
  // bt-fetch, which is still peer traffic the user did not ask for.
  assert.equal(magnetToTorrentsPage(`magnet:?xs=urn:btpk:${PUBKEY}`),
    `wildroot://torrents?mutable=${PUBKEY}`)
  assert.equal(magnetToTorrentsPage(`magnet:?xs=urn:btpk:${PUBKEY.toUpperCase()}&dn=My+Site`),
    `wildroot://torrents?mutable=${PUBKEY}&dn=My%20Site`)
})

test('a hostile display name cannot break out of the URL', () => {
  const nasty = magnetToTorrentsPage(`magnet:?xt=urn:btih:${INFOHASH}&dn=${encodeURIComponent('" onload=alert(1) &add=evil')}`)
  assert.match(nasty, new RegExp(`^wildroot://torrents\\?add=${INFOHASH}&dn=`))
  // One `add` parameter only — the name cannot smuggle a second.
  assert.equal(new URL(nasty).searchParams.getAll('add').length, 1)
  assert.equal(new URL(nasty).searchParams.get('add'), INFOHASH)
})

test('a magnet with no address this browser reads is declined', () => {
  assert.equal(magnetToTorrentsPage('magnet:?dn=nothing'), null)
  assert.equal(magnetToTorrentsPage(`magnet:?xt=urn:btmh:${V2_MULTIHASH}`), null)
  assert.equal(magnetToTorrentsPage('https://example.com/'), null)
  assert.equal(magnetToTorrentsPage(''), null)
  assert.equal(magnetToTorrentsPage(null), null)
  assert.equal(magnetToTorrentsPage(undefined), null)
})

test('handler and rewrite AGREE about a magnet carrying both xs and xt', async () => {
  // The mutable key wins in both readers, and both readers answer with the
  // SAME consent URL — the handler because it calls the rewrite. Which reader
  // sees a magnet depends on whether the user clicked it (rewrite, via
  // src/window.js) or it was dispatched (handler), so a disagreement here is
  // one magnet with two meanings.
  const both = `magnet:?xs=urn:btpk:${PUBKEY}&xt=urn:btih:${INFOHASH}`
  const consent = `wildroot://torrents?mutable=${PUBKEY}`
  const handler = await createMagnetHandler()
  assert.equal(handler(new Request(both)).headers.get('Location'), consent)
  assert.equal(magnetToTorrentsPage(both), consent)
  // The precedence is `xs` wherever it sits, not "the first parameter".
  const reversed = `magnet:?xt=urn:btih:${INFOHASH}&xs=urn:btpk:${PUBKEY}`
  assert.equal(handler(new Request(reversed)).headers.get('Location'), consent)
  assert.equal(magnetToTorrentsPage(reversed), consent)
})
