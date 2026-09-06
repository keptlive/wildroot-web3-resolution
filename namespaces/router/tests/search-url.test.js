// search:// URLs have ONE spelling and one builder (`src/search-url.js`), and
// a typed query is where classification ends (Part II §9).
//
// The bug class this pins: `search` is a standard scheme, so a hostless
// `search://?q=x` is an invalid URL — it loads nowhere, and a restored history
// entry holding one trips an internal invariant in the URL library on every
// session save. Restore filters such entries; this file makes sure nothing
// MINTS one again, and that every legacy spelling still reads as the same
// search rather than 404ing.
//
// EXTRACTION NOTE (hns-resolution): the browser's copy ends with two tests that
// walk `src/` looking for a hostless `search://` literal in any source file.
// They are about the Wildroot tree's contents, not about the grammar, and stay
// there.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  SEARCH_CATEGORIES, searchCategory, searchTemplate, searchHome, searchURL,
  parseSearchURL, canonicalSearchURL, canonicalSearchTemplate
} from '../../../src/search-url.js'
import { classify, NAMESPACES } from '../../../src/router.js'

/** What Chromium commits for a standard-scheme URL: lowercased host, '/' path. */
function chromiumCanonical (raw) {
  const u = new URL(raw)
  return `${u.protocol}//${u.hostname.toLowerCase()}${u.pathname || '/'}${u.search}${u.hash}`
}

test('the builder always produces a host, and Chromium would commit it unchanged', () => {
  for (const cat of SEARCH_CATEGORIES) {
    const url = searchURL('hello world', cat)
    assert.equal(url, `search://${cat}/?q=hello%20world`)
    assert.equal(new URL(url).hostname, cat, 'the host is the category')
    assert.equal(chromiumCanonical(url), url, 'already in the form Chromium commits')
    assert.equal(searchHome(cat), `search://${cat}/`)
    assert.equal(searchTemplate(cat), `search://${cat}/?q=%s`)
  }
  assert.equal(searchURL('a&b=c?d#e'), 'search://web/?q=a%26b%3Dc%3Fd%23e', 'the query is encoded')
  assert.equal(searchURL(''), 'search://web/?q=', 'an empty query still has a host')
  assert.equal(searchURL(undefined), 'search://web/?q=')
})

test('unknown or legacy category names fall back to web', () => {
  assert.equal(searchCategory('academic'), 'academic')
  assert.equal(searchCategory('Academic'), 'academic')
  assert.equal(searchCategory('all'), 'web')
  assert.equal(searchCategory('nope'), 'web')
  assert.equal(searchCategory(''), 'web')
  assert.equal(searchCategory(null), 'web')
  assert.equal(searchURL('x', 'bogus'), 'search://web/?q=x')
})

test('the parser reads the canonical form: host = category, q = query', () => {
  assert.deepEqual(parseSearchURL('search://web/?q=hello%20world'), { query: 'hello world', cat: 'web' })
  assert.deepEqual(parseSearchURL('search://academic/?q=quantum'), { query: 'quantum', cat: 'academic' })
  assert.deepEqual(parseSearchURL('search://Code/?q=x'), { query: 'x', cat: 'code' }, 'host case is Chromium\'s business')
  assert.deepEqual(parseSearchURL('search://web/'), { query: '', cat: 'web' }, 'the home page')
  assert.deepEqual(parseSearchURL('search://web'), { query: '', cat: 'web' })
  assert.deepEqual(parseSearchURL('search://web/kittens'), { query: 'kittens', cat: 'web' }, 'a hand-typed path searches')
  assert.deepEqual(parseSearchURL('search://web/?q=x&cat=academic'), { query: 'x', cat: 'web' }, 'on a canonical URL the host wins')
  // Bangs stay in the query for the handler's parseBang.
  assert.deepEqual(parseSearchURL('search://web/?q=!a%20quantum'), { query: '!a quantum', cat: 'web' })
})

test('every legacy spelling reads as the same search', () => {
  // The four minters commit 6584613 named: DEFAULT_SEARCH_PROVIDER, the
  // omnibox fallback, the context menu, the results page's own links.
  assert.deepEqual(parseSearchURL('search://?q=magnet%20link'), { query: 'magnet link', cat: 'web' })
  assert.deepEqual(parseSearchURL('search://?q=torrent%20list&cat=academic'), { query: 'torrent list', cat: 'academic' })
  assert.deepEqual(parseSearchURL('search://?q=x&cat=all'), { query: 'x', cat: 'web' })
  assert.deepEqual(parseSearchURL('search://?q=x&cat=custom'), { query: 'x', cat: 'custom' })
  assert.deepEqual(parseSearchURL('search://'), { query: '', cat: 'web' }, 'the old hostless home')
  // The router's old default put the query in the host.
  assert.deepEqual(parseSearchURL('search://hello'), { query: 'hello', cat: 'web' })
  assert.deepEqual(parseSearchURL('search://hello%20world'), { query: 'hello world', cat: 'web' })
  assert.deepEqual(parseSearchURL('search://q/magnet%20link'), { query: 'q/magnet link', cat: 'web' }, 'exactly what the old handler searched')
})

test('non-search input is null; a broken search: string is the web home, never a throw', () => {
  for (const other of ['https://a.example/?q=x', 'wildroot://welcome', '', null, undefined, 42, 'searchx://?q=1']) {
    assert.equal(parseSearchURL(other), null, String(other))
    assert.equal(canonicalSearchURL(other), null, String(other))
  }
  assert.deepEqual(parseSearchURL('search:'), { query: '', cat: 'web' })
  assert.deepEqual(parseSearchURL('search://%zz'), { query: '%zz', cat: 'web' })
})

test('canonicalSearchURL: rewrite on the rewriteToWildroot contract', () => {
  // Null for a URL that is already canonical, so a restored entry keeps its
  // history; the canonical string for any alias.
  assert.equal(canonicalSearchURL('search://web/?q=hello%20world'), null)
  assert.equal(canonicalSearchURL('search://academic/?q=x'), null)
  assert.equal(canonicalSearchURL('search://web/'), null)
  assert.equal(canonicalSearchURL('search://?q=hello%20world'), 'search://web/?q=hello%20world')
  assert.equal(canonicalSearchURL('search://?q=x&cat=academic'), 'search://academic/?q=x')
  assert.equal(canonicalSearchURL('search://'), 'search://web/')
  assert.equal(canonicalSearchURL('search://hello%20world'), 'search://web/?q=hello%20world')
  assert.equal(canonicalSearchURL('search://Web/?q=x'), 'search://web/?q=x', 'host case normalised the way Chromium does')
  assert.equal(canonicalSearchURL('search://web/kittens'), 'search://web/?q=kittens')
  // Idempotent: the rewrite of a rewrite is nothing.
  for (const alias of ['search://?q=a%20b&cat=code', 'search://', 'search://x']) {
    const once = canonicalSearchURL(alias)
    assert.equal(canonicalSearchURL(once), null, alias)
    assert.deepEqual(parseSearchURL(once), parseSearchURL(alias), `${alias} means the same search`)
  }
})

test('canonicalSearchTemplate: a legacy provider template becomes the host form; others pass through', () => {
  assert.equal(canonicalSearchTemplate('search://?q=%s'), 'search://web/?q=%s')
  assert.equal(canonicalSearchTemplate('search://?q=%s&cat=academic'), 'search://academic/?q=%s')
  assert.equal(canonicalSearchTemplate('search://?q=%s&cat=custom'), 'search://custom/?q=%s')
  assert.equal(canonicalSearchTemplate('search://code/?q=%s'), 'search://code/?q=%s')
  assert.equal(canonicalSearchTemplate('https://duckduckgo.com/?q=%s'), 'https://duckduckgo.com/?q=%s')
  assert.equal(canonicalSearchTemplate(undefined), '')
})

// ---- what a search means for resolution ----------------------------------

test('a search is a terminal, not a fallback: it is only ever reached without a namespace', () => {
  // classify() reaches the search branch from exactly two places — an empty
  // input, and an input that named no protocol and was not a name. It is never
  // reached from a resolution FAILURE, which is what would make it an L2 breach.
  for (const [input, reason] of [['', 'empty'], ['  ', 'empty'],
    ['com', 'search'], ['how to publish a site', 'search']]) {
    const c = classify(input)
    assert.equal(c.namespace, NAMESPACES.SEARCH, JSON.stringify(input))
    assert.equal(c.reason, reason, JSON.stringify(input))
    assert.equal(c.explicit, false, JSON.stringify(input))
    assert.deepEqual(parseSearchURL(c.url), { query: input.trim(), cat: 'web' },
      'and the URL it produces reads back as the query that was typed')
  }
})

test('a typed search:// URL is an explicit scheme like any other (L1)', () => {
  const c = classify('search://academic/?q=quantum')
  assert.equal(c.explicit, true)
  assert.equal(c.scheme, 'search')
  assert.equal(c.namespace, NAMESPACES.SEARCH)
  assert.equal(c.url, 'search://academic/?q=quantum', 'not re-encoded as a query about itself')
})

test('the classifier can be given a different search backend without changing the rule', () => {
  // The searchURL injection point exists so a caller can substitute a provider.
  // It must not be able to change WHICH inputs are searches.
  const c = classify('how to publish a site', { searchURL: (q) => `https://example.test/?q=${encodeURIComponent(q)}` })
  assert.equal(c.namespace, NAMESPACES.SEARCH)
  assert.equal(c.url, 'https://example.test/?q=how%20to%20publish%20a%20site')
  assert.equal(classify('pinner', { searchURL: () => 'https://example.test/' }).namespace, NAMESPACES.HNS,
    'a name is still a name')
})
