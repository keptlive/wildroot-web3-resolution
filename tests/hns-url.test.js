// A numeric Handshake TLD survives the URL parser (src/hns/hns-url.cjs).
//
// Chromium treats a host whose last label is all digits as an IPv4 address,
// so `hns://hello.14898/` was an invalid URL in the shipped browser — found by
// the 2.78.0 release smoke. The fix is a marker no Handshake name can carry.

import test from 'node:test'
import assert from 'node:assert/strict'

import { encodeHnsHost, decodeHnsHost, displayHnsUrl, isEncodedNumericTld, fixHnsHref } from '../src/hns-url.cjs'

test('a numeric TLD gains a leading underscore in a URL host, and only then', () => {
  assert.equal(encodeHnsHost('hello.14898'), 'hello._14898')
  assert.equal(encodeHnsHost('14898'), '_14898')
  assert.equal(encodeHnsHost('a.b.14898'), 'a.b._14898')
  assert.equal(encodeHnsHost('hello.14898:8080'), 'hello._14898:8080', 'a port rides along')
  for (const plain of ['alice.w3', 'pxls', 'pinner.hns', 'x1.abc123', 'xn--ls8h', 'hello.14898x', '']) {
    assert.equal(encodeHnsHost(plain), plain, `${plain} is not numeric and is left alone`)
  }
  // A trailing dot does not hide the numeric TLD: the URL Standard's
  // "ends in a number" check strips one empty label first, so the unmarked
  // form threw in `new URL` and the link stayed dead.
  assert.equal(encodeHnsHost('hello.14898.'), 'hello._14898.')
  assert.equal(encodeHnsHost('14898.'), '_14898.')
  assert.equal(decodeHnsHost('hello._14898.'), 'hello.14898.')
  assert.doesNotThrow(() => new URL(`hns://${encodeHnsHost('hello.14898.')}/x`))
})

test('decoding is the exact inverse, and touches nothing that was not encoded', () => {
  for (const name of ['hello.14898', '14898', 'a.b.14898', 'hello.14898:8080', 'alice.w3', 'pxls']) {
    assert.equal(decodeHnsHost(encodeHnsHost(name)), name)
  }
  assert.equal(decodeHnsHost('hello._14898'), 'hello.14898')
  assert.equal(decodeHnsHost('_14898'), '14898')
  assert.equal(decodeHnsHost('hello.14898'), 'hello.14898', 'an unencoded host is unchanged')
  assert.equal(decodeHnsHost('_dmarc.example'), '_dmarc.example', 'an underscore that is not a numeric marker is not ours')
  assert.equal(decodeHnsHost('a_b.w3'), 'a_b.w3')
})

test('encoding is idempotent — a URL rebuilt from a URL does not grow markers', () => {
  assert.equal(encodeHnsHost(encodeHnsHost('hello.14898')), 'hello._14898')
  assert.equal(isEncodedNumericTld('hello._14898'), true)
  assert.equal(isEncodedNumericTld('hello.14898'), false)
  assert.equal(isEncodedNumericTld('hello.w3'), false)
})

test('the address bar shows the name, not the marker', () => {
  assert.equal(displayHnsUrl('hns://hello._14898/path?q=1#f'), 'hns://hello.14898/path?q=1#f')
  assert.equal(displayHnsUrl('hns://_14898/'), 'hns://14898/')
  assert.equal(displayHnsUrl('hns://alice.w3/'), 'hns://alice.w3/')
  assert.equal(displayHnsUrl('https://example.com/_14898'), 'https://example.com/_14898', 'not an hns URL: untouched')
  assert.equal(displayHnsUrl('hns://a_b.w3/'), 'hns://a_b.w3/')
})

test('a third-party link written in the plain form is rewritten on the way out, and nothing else is', () => {
  assert.equal(fixHnsHref('hns://hello.14898/'), 'hns://hello._14898/')
  assert.equal(fixHnsHref('hns://hello.14898'), 'hns://hello._14898/', 'a bare host gains its slash')
  assert.equal(fixHnsHref('HNS://Hello.14898/a/b?x=1#f'), 'hns://Hello._14898/a/b?x=1#f')
  assert.equal(fixHnsHref('  hns://14898/x '), 'hns://_14898/x')
  assert.equal(fixHnsHref('hns://hello._14898/'), null, 'already the internal form')
  assert.equal(fixHnsHref('hns://alice.w3/'), null)
  assert.equal(fixHnsHref('https://hello.14898/'), null, 'not our scheme')
  assert.equal(fixHnsHref('hns://hello.14898.hns.one/'), null, 'an ICANN suffix is not numeric')
  assert.equal(fixHnsHref(''), null)
})
