/*
 * The classification ORDER (Part II §6.1).
 *
 * The top-level tests/router.test.js proves each branch in isolation. This file
 * proves the thing that cannot be seen one branch at a time: that the branches
 * are consulted in a fixed order, that the order is the one the specification
 * states, and that reordering any of the first four would be a security
 * regression rather than a refactor.
 *
 * The worked table at the bottom is the normative corpus of §6.1. Every row is
 * produced by running the classifier, not by reading it.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { classify, classifyHost, isValidV3Onion, NAMESPACES } from '../../../src/router.js'
import { isReservedHost, isHnsHost } from '../../../src/hns-host.js'

const V3 = 'p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion'

// --- the order itself -------------------------------------------------------

test('an explicit scheme is consulted before anything else (L1)', () => {
  // Each of these inputs would classify differently on every LATER rule. The
  // scheme wins over all of them, which is the whole of L1.
  const cases = [
    ['ipfs://vitalik.eth/', 'ipfs'], // would be .eth -> ens
    ['ipfs://' + V3 + '/', 'ipfs'], // would be .onion -> tor
    ['https://hello.14898/', 'https'], // would be numeric TLD -> hns
    ['hns://example.com/', 'hns'], // would be ICANN -> icann
    ['ens://pinner/', 'ens'] // would be a bare label -> hns
  ]
  for (const [input, scheme] of cases) {
    const c = classify(input)
    assert.equal(c.explicit, true, input)
    assert.equal(c.scheme, scheme, input)
    assert.equal(c.url, input, 'the URL is returned untouched')
    assert.equal(c.reason, 'explicit-scheme', input)
  }
})

test('an UNKNOWN scheme is still preserved as itself, with a null namespace', () => {
  // It must not be reinterpreted as a bare host, an ICANN name, or a search;
  // dispatch fails it closed in its own name instead.
  for (const input of ['foobar://whatever', 'mailto:a@b.example', 'javascript:alert(1)']) {
    const c = classify(input)
    assert.equal(c.explicit, true, input)
    assert.equal(c.namespace, null, input)
    assert.equal(c.url, input, input)
    assert.equal(c.known, false, `${input}: the decision SAYS the table does not know it`)
  }
  // ...and the same field is true for a scheme the table does know, so a
  // caller that navigates can require it instead of inheriting a rule from a
  // comment (§11.4).
  for (const input of ['ipfs://bafyfoo/', 'hns://pinner/', 'search://web/?q=x']) {
    assert.equal(classify(input).known, true, input)
  }
  // `known` is a property of an EXPLICIT decision only.
  assert.equal(classify('pinner').known, undefined)
})

test('.onion is matched FIRST, before every other host rule', () => {
  // A host that satisfies a later rule as well must still go to Tor. If .onion
  // moved below the ICANN test, an onion under a name that happened to parse as
  // something else would reach a resolver — which is the disclosure the rule
  // exists to prevent.
  for (const host of [V3, 'tooshort.onion', 'x.y.onion', 'UPPER.ONION', 'a.b.c.onion']) {
    assert.equal(classifyHost(host), NAMESPACES.TOR, host)
    assert.equal(classify(host).scheme, 'onion', host)
  }
  // ...and validity is REPORTED, never used to route.
  assert.equal(classify(V3).validV3, true)
  assert.equal(classify('tooshort.onion').validV3, false)
  assert.equal(classify('tooshort.onion').namespace, NAMESPACES.TOR,
    'a malformed onion must NOT be released to a resolver')
})

test('v3 validity is the whole address: version byte and SHA3-256 checksum', () => {
  // Not a length test. The 56 base32 characters decode to
  // PUBKEY[32] ‖ CHECKSUM[2] ‖ VERSION[1], and both trailing fields are
  // checked, so a single mistyped character is caught locally instead of
  // spending a circuit.
  assert.equal(isValidV3Onion(V3), true)
  assert.equal(isValidV3Onion(V3.toUpperCase()), true, 'base32 is case-insensitive')
  assert.equal(isValidV3Onion('facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion'), true)
  // Same length, same alphabet, one character different: the checksum fails.
  assert.equal(isValidV3Onion('q' + V3.slice(1)), false, 'a flipped key byte')
  assert.equal(isValidV3Onion(V3.slice(0, 55) + 'a.onion'), false, 'a flipped version/checksum byte')
  assert.equal(isValidV3Onion('expyuzz4wqqyqhjn.onion'), false, 'a v2 address is not v3')
  assert.equal(isValidV3Onion(''), false)
  // And none of it moves the routing decision.
  assert.equal(classifyHost('q' + V3.slice(1)), NAMESPACES.TOR)
})

test('.eth is matched second, and has no Handshake or ICANN backstop', () => {
  for (const host of ['vitalik.eth', 'a.b.eth', 'UPPER.ETH', 'x.eth']) {
    assert.equal(classifyHost(host), NAMESPACES.ENS, host)
  }
  // A Handshake name whose LABEL is eth/onion is still Handshake: the rule is a
  // suffix rule, not a substring rule.
  assert.equal(classifyHost('eth.14898'), NAMESPACES.HNS)
  assert.equal(classifyHost('onion.14898'), NAMESPACES.HNS)
  assert.equal(classifyHost('ethereum.com'), NAMESPACES.ICANN)
  assert.equal(classifyHost('my-eth-wallet.com'), NAMESPACES.ICANN)
})

test('the gateway-path and localhost rules run before host classification', () => {
  // /ipfs/… would otherwise be read as a path on an empty host, and a bare
  // `localhost` would fall into the single-label branch and become Handshake.
  assert.equal(classify('/ipfs/bafyfoo').namespace, NAMESPACES.IPFS)
  assert.equal(classify('/ipns/k51foo').scheme, 'ipns')
  for (const input of ['localhost', 'localhost/', 'localhost:3000']) {
    const c = classify(input)
    assert.equal(c.namespace, NAMESPACES.WEB, input)
    assert.equal(c.scheme, 'http', input)
    assert.equal(c.reason, 'localhost', input)
  }
})

test('a pasted CID is IPFS, and a CIDv0 is written in the form a host survives', () => {
  // Chromium lowercases a standard scheme's host, and CIDv0 is case-sensitive
  // base58 — so the v0 spelling cannot survive as a host and is written as the
  // CIDv1 base32 form, which names the same bytes.
  const v1 = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi'
  const c1 = classify(v1)
  assert.equal(c1.namespace, NAMESPACES.IPFS)
  assert.equal(c1.reason, 'bare-cid')
  assert.equal(c1.url, `ipfs://${v1}/`)

  const v0 = classify('QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG')
  assert.equal(v0.namespace, NAMESPACES.IPFS)
  assert.equal(v0.url, 'ipfs://bafybeie5nqv6kd3qnfjupgvz34woh3oksc3iau6abmyajn7qvtf6d2ho34/')
  assert.equal(new URL(v0.url).hostname, new URL(v0.url).hostname.toLowerCase(),
    'the URL Chromium commits is the URL that was built')

  // Only a bare CID: anything with a separator in it is a host or a path.
  assert.equal(classify(`${v1}/dir`).namespace, NAMESPACES.HNS,
    'a CID with a path is not this rule — it is a host')
  assert.equal(classify('QmNotACidAtAll').namespace, NAMESPACES.HNS)
})

test('`@user@host` is an ActivityPub address, not a host with a credential', () => {
  // The URL parser reads the second `@` as a userinfo separator, so treating
  // this as a host navigates to the instance carrying a stray credential.
  for (const handle of ['@alice@example.com', '@bob@mastodon.social']) {
    const c = classify(handle)
    assert.equal(c.namespace, NAMESPACES.ACTIVITYPUB, handle)
    assert.equal(c.scheme, 'activitypub', handle)
    assert.equal(c.reason, 'fedi-handle', handle)
    assert.equal(c.url, `activitypub:${handle}`, handle)
  }
  // One `@`, or an instance with no dot, is not the canonical form — and it is
  // not a name either: the URL constructor would read everything before the
  // last `@` as userinfo and DROP it. A stray `@` is a search.
  for (const odd of ['@alice', '@alice@localhostish', 'alice@example']) {
    assert.equal(classify(odd).namespace, NAMESPACES.SEARCH, odd)
  }
})

test('the ICANN decision is a set membership test against the full root list', () => {
  // A short hand-written allowlist silently hijacks real sites. These are the
  // ones that catch a short list out.
  for (const host of ['shop.blog', 'foo.link', 'bbc.co.uk', 'a.app', 'x.dev', 'y.xyz']) {
    assert.equal(classifyHost(host), NAMESPACES.ICANN, host)
  }
  // ...and a Unicode TLD must be punycoded BEFORE the lookup or a real ccTLD is
  // hijacked to Handshake.
  assert.equal(classifyHost('пример.рф'), NAMESPACES.ICANN)
  assert.equal(classifyHost('xn--e1afmkfd.xn--p1ai'), NAMESPACES.ICANN)
  // ...while an emoji label is genuinely not ICANN, and is Handshake.
  assert.equal(classifyHost('a.\u{1F91D}'), NAMESPACES.HNS)
})

test('an all-numeric final label is Handshake, and is carried with the `_` marker', () => {
  // ICANN has no all-numeric top-level domains, so the rule is unambiguous. The
  // marker is applied BEFORE the punycode pass, because the URL constructor
  // throws on the unmarked form (SPEC §8.2).
  assert.equal(classifyHost('hello.14898'), NAMESPACES.HNS)
  assert.equal(classify('hello.14898').url, 'hns://hello._14898/')
  assert.equal(classify('14898').url, 'hns://_14898/')
  assert.equal(classify('14898/').url, 'hns://_14898/')
  // A non-final numeric label is NOT marked.
  assert.equal(classify('14898.woodburn').url, 'hns://14898.woodburn/')
})

// --- the single bare label --------------------------------------------------

test('a single bare label is Handshake unless the label is an ICANN TLD', () => {
  for (const word of ['pinner', 'hnshosting', 'bananas', '14898', '\u{1F91D}', 'w3']) {
    const c = classify(word)
    assert.equal(c.namespace, NAMESPACES.HNS, word)
    assert.equal(c.reason, 'hns-bare-label', word)
  }
  for (const word of ['com', 'org', 'app', 'blog', 'link']) {
    const c = classify(word)
    assert.equal(c.namespace, NAMESPACES.SEARCH, word)
    assert.equal(c.reason, 'search', word)
  }
})

test('whitespace excludes an input from the bare-label rule, deliberately', () => {
  // classifyHost returns null for a whitespace-bearing host as well as for a
  // single label, so the bare-label branch has to exclude whitespace by hand.
  // Without that, every multi-word search becomes a Handshake lookup.
  for (const q of ['how to publish a site', 'pinner hns', 'two words', 'a  b']) {
    assert.equal(classify(q).namespace, NAMESPACES.SEARCH, JSON.stringify(q))
  }
  // ' pinner ' is trimmed first, so it IS a name — the trim happens before the
  // whitespace test and that ordering is load-bearing.
  assert.equal(classify(' pinner ').reason, 'hns-bare-label')
})

test('empty input is the search home, not a name', () => {
  for (const q of ['', '   ', '\t']) {
    const c = classify(q)
    assert.equal(c.namespace, NAMESPACES.SEARCH, JSON.stringify(q))
    assert.equal(c.reason, 'empty', JSON.stringify(q))
  }
})

// --- the http -> hns rewrite path ------------------------------------------

test('a URL host settles navigation intent that typed input leaves open', () => {
  // The one deliberate asymmetry between the two classification paths: a single
  // bare label is undecided when TYPED (it might be a word) and decided when it
  // arrives as a host (http://hnshosting/ is already a navigation).
  assert.equal(classifyHost('hnshosting'), null, 'undecided as a host classification')
  assert.equal(isHnsHost('hnshosting'), true, 'decided as a URL host')
  assert.equal(classify('hnshosting').namespace, NAMESPACES.HNS, 'and typed, by the ICANN rule')
})

// --- special-use names ------------------------------------------------------

test('the special-use list covers each RFC-reserved label and its whole subtree', () => {
  for (const label of ['localhost', 'local', 'invalid', 'test', 'example', 'onion', 'arpa']) {
    assert.equal(isReservedHost(label), true, label)
    assert.equal(isReservedHost(`nas.${label}`), true, `nas.${label}`)
    assert.equal(isReservedHost(`a.b.${label}.`), true, `trailing dot: ${label}`)
    assert.equal(isHnsHost(`nas.${label}`), false, `nas.${label} is never Handshake`)
  }
})

test('the special-use list also covers labels no RFC reserves (RT-1)', () => {
  // Deliberately broader than the RFCs: these are what home routers and
  // corporate networks actually use, and the carve-out exists for exactly them.
  for (const label of ['internal', 'home', 'lan', 'corp', 'intranet', 'private']) {
    assert.equal(isReservedHost(`printer.${label}`), true, label)
    assert.equal(isHnsHost(`printer.${label}`), false, label)
  }
})

test('the special-use list is consulted on BOTH paths, and Tor still runs first', () => {
  // One list, one answer, whether the name was typed or arrived as a URL host.
  // A reserved name is a device on the user's own network, so it is reached the
  // way `localhost` is — plain http, the platform resolver — and never sent to
  // a Handshake resolver, where whoever registers `local` could answer for it.
  for (const host of ['nas.local', 'app.localhost', 'printer.lan', 'foo.test', 'x.invalid']) {
    assert.equal(isReservedHost(host), true, `${host} is reserved`)
    const c = classify(host)
    assert.equal(c.namespace, NAMESPACES.WEB, host)
    assert.equal(c.reason, 'reserved-host', host)
    assert.equal(c.url, `http://${host}`, host)
    assert.equal(isHnsHost(host), false, host)
  }
  // `onion` is in the reserved list too, and the Tor branch is tested BEFORE
  // it — otherwise every onion address would be diverted to the web namespace.
  assert.equal(classifyHost(V3), NAMESPACES.TOR)
  assert.equal(classifyHost('anything.onion'), NAMESPACES.TOR)
})

test('an IP literal is classified before the label count, bracketed or not', () => {
  // An IPv6 literal has no dot, so a label count tested first would hand it to
  // the bare-label branch and make it a Handshake name.
  for (const ip of ['127.0.0.1', '8.8.8.8', '203.0.113.9', '127.0.0.1:8080']) {
    const c = classify(ip)
    assert.equal(c.namespace, NAMESPACES.WEB, ip)
    assert.equal(c.reason, 'ip-literal', ip)
  }
  for (const ip of ['::1', '[::1]', '2001:db8::1', '[2001:db8::1]:8080', '::ffff:127.0.0.1']) {
    assert.equal(classifyHost(ip), NAMESPACES.WEB, ip)
    const c = classify(ip)
    assert.equal(c.namespace, NAMESPACES.WEB, ip)
    assert.equal(c.reason, 'ip-literal', ip)
  }
  // `::1` is an address, not a host with a port of 1: the host reducer must
  // not strip a "port" from a bracketed or colon-dense host.
  assert.equal(classifyHost('::1'), NAMESPACES.WEB)
  assert.equal(classifyHost('[::1]'), NAMESPACES.WEB)
})

test('an unbracketed IPv6 literal is bracketed in the URL built for it, and its first group is not a scheme', () => {
  assert.equal(classify('::1').url, 'https://[::1]')
  assert.equal(new URL(classify('::1').url).hostname, '[::1]')
  assert.equal(classify('[::1]').url, 'https://[::1]')
  assert.equal(classify('[::1]:8080').url, 'https://[::1]:8080')
  // A literal whose first hextet is letter-leading matches the scheme grammar
  // by shape; the second colon says it is an address.
  const c = classify('fe80::1')
  assert.equal(c.explicit, false)
  assert.equal(c.namespace, NAMESPACES.WEB)
  assert.equal(c.url, 'https://[fe80::1]')
  assert.ok(new URL(classify('2001:db8::1').url))
})

test('RT-4: a registered scheme name followed by a bare port reads as a scheme', () => {
  // example.com:8080 is a host; hns:8080 is not, because `hns` is a scheme the
  // registry knows. Recorded so a reader does not take it for an oversight.
  assert.equal(classify('example.com:8080').namespace, NAMESPACES.ICANN)
  assert.equal(classify('example.com:8080').url, 'https://example.com:8080')
  const c = classify('hns:8080')
  assert.equal(c.explicit, true, 'RT-4')
  assert.equal(c.scheme, 'hns', 'RT-4')
})

// --- the worked corpus of SPEC §6.1 ----------------------------------------

test('the worked classification table (Part II §6.1)', () => {
  /** [input, namespace, url, reason] — every row measured, not assumed. */
  const TABLE = [
    ['', 'search', 'search://web/?q=', 'empty'],
    ['ipfs://bafyfoo/', 'ipfs', 'ipfs://bafyfoo/', 'explicit-scheme'],
    ['foobar://x', null, 'foobar://x', 'explicit-scheme'],
    ['/ipfs/bafyfoo', 'ipfs', 'ipfs://bafyfoo', 'ipfs-path'],
    ['/ipns/k51foo', 'ipfs', 'ipns://k51foo', 'ipns-path'],
    ['localhost:3000', 'web', 'http://localhost:3000', 'localhost'],
    [V3, 'tor', `onion://${V3}`, 'onion-host'],
    ['tooshort.onion', 'tor', 'onion://tooshort.onion', 'onion-host'],
    ['vitalik.eth', 'ens', 'ens://vitalik.eth', 'eth-name'],
    ['vitalik.eth/path', 'ens', 'ens://vitalik.eth/path', 'eth-name'],
    ['127.0.0.1', 'web', 'https://127.0.0.1', 'ip-literal'],
    ['hello.14898', 'hns', 'hns://hello._14898/', 'hns-tld'],
    ['nathan.woodburn', 'hns', 'hns://nathan.woodburn/', 'hns-tld'],
    ['proof.w3', 'hns', 'hns://proof.w3/', 'hns-tld'],
    ['nas.local', 'web', 'http://nas.local', 'reserved-host'],
    ['[::1]', 'web', 'https://[::1]', 'ip-literal'],
    ['@alice@example.com', 'activitypub', 'activitypub:@alice@example.com', 'fedi-handle'],
    ['bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi', 'ipfs',
      'ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/', 'bare-cid'],
    ['example.com', 'icann', 'https://example.com', 'icann-tld'],
    ['shop.blog', 'icann', 'https://shop.blog', 'icann-tld'],
    ['pinner', 'hns', 'hns://pinner/', 'hns-bare-label'],
    ['14898', 'hns', 'hns://_14898/', 'hns-bare-label'],
    ['\u{1F91D}', 'hns', 'hns://xn--5p9h/', 'hns-bare-label'],
    ['com', 'search', 'search://web/?q=com', 'search'],
    ['how to publish a site', 'search', 'search://web/?q=how%20to%20publish%20a%20site', 'search']
  ]
  for (const [input, namespace, url, reason] of TABLE) {
    const c = classify(input)
    assert.equal(c.namespace, namespace, `namespace for ${JSON.stringify(input)}`)
    assert.equal(c.url, url, `url for ${JSON.stringify(input)}`)
    assert.equal(c.reason, reason, `reason for ${JSON.stringify(input)}`)
  }
})

test('every decision names exactly one namespace and one reason — there is no second guess', () => {
  const inputs = ['', 'pinner', 'example.com', 'vitalik.eth', V3, '/ipfs/x', 'localhost',
    'hello.14898', 'com', 'a b', 'ipfs://x', '127.0.0.1']
  for (const input of inputs) {
    const c = classify(input)
    assert.equal(typeof c.url, 'string', input)
    assert.equal(typeof c.reason, 'string', input)
    assert.equal(typeof c.explicit, 'boolean', input)
    assert.ok(!Array.isArray(c.namespace), 'a decision is never a list of candidates')
  }
})
