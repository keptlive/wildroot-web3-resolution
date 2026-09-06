// Is this URL host a Handshake host, and how does its http(s) URL map to
// hns://? The desktop's answer to the gap Android never had: Android
// intercepts every http(s) request whose host's final label is not an ICANN
// TLD, but on desktop a literal http://nathan.woodburn/ link fell through to
// SYSTEM DNS (the user's router), which knows nothing about Handshake — a
// blank page with no error. Main-frame loads are therefore rewritten to
// hns:// at every navigation entry point (Window.loadURL, will-navigate,
// addTab, loadTabState) so they ride the chain-proof/DANE resolver instead.
//
// CLASSIFICATION IS NOT DECIDED HERE. It delegates to classifyHost() in
// src/protocols/router.js — the BR-1 single source of truth — because this
// file once carried its own copy of the rules and that copy silently lacked
// the `.eth`/`.onion` guard: a LINK CLICK on http://vitalik.eth became
// hns://vitalik.eth (an ENS hijack) and http://<addr>.onion put the onion
// address in a DNS query (a deanonymising leak) while typed input was safely
// classified two files away. One classifier, consumed everywhere (LAW L2).
//
// Pure module (node:url + the router) — unit-tested in
// tests/hns/hns-host.test.js. Single labels count (http://hnshosting/),
// numeric TLDs count (ICANN has none), IDN hosts are punycoded before the
// lookup so real internationalized ccTLDs are not hijacked.

import { classifyHost, NAMESPACES } from './router.js'

import icannTlds from './icann-tlds.cjs'

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

// The scheme whose fail-closed handler owns each non-HNS, non-DNS namespace
// (src/protocols/unimplemented-protocol.js). A malformed host under these
// TLDs must stay in its namespace too — a typo'd onion in a DNS query leaks
// exactly as effectively as a valid one.
const NAMESPACE_SCHEMES = new Map([
  [NAMESPACES.ENS, 'ens'],
  [NAMESPACES.TOR, 'onion']
])

/**
 * The scheme whose namespace owns this host, when that is NOT Handshake —
 * 'ens' for *.eth, 'onion' for *.onion — else null.
 * @param {string?} rawHost hostname (no scheme, no port)
 * @returns {string?}
 */
export function reservedNamespaceScheme (rawHost) {
  if (!rawHost) return null
  return NAMESPACE_SCHEMES.get(classifyHost(String(rawHost))) || null
}

/**
 * @param {string?} rawHost hostname (no scheme, no port)
 * @param {Set<string>} [tlds] override for tests
 */
/**
 * Names that are NOT Handshake, whatever the ICANN list says.
 *
 * RFC 6761 / RFC 8375 special-use names, plus the two labels every home
 * network actually uses. The classifier calls anything outside the bundled
 * ICANN snapshot a Handshake name, so `nas.local`, `printer.lan`,
 * `gitlab.internal` and `app.localhost` were all rewritten to hns:// — which
 * breaks reaching your own devices AND sends their names to a Handshake
 * resolver, where whoever registers the TLD `local` receives queries for your
 * internal machines and can answer them.
 *
 * `localhost` alone was already exempt; a subdomain of it was not, even
 * though RFC 6761 reserves the whole subtree to loopback.
 */
const NEVER_HNS_TLDS = new Set([
  'localhost', // RFC 6761 — the whole subtree is loopback
  'local', // RFC 6762 — mDNS; every NAS, printer and Home Assistant
  'internal', // RFC 8375 (home.arpa's informal twin), widely used internally
  'home', // common home-router default
  'lan', // common home-router default
  'intranet',
  'corp',
  'private',
  'invalid', // RFC 6761 — guaranteed not to resolve
  'test', // RFC 6761 — reserved for testing
  'example', // RFC 6761
  'onion', // RFC 7686 — Tor, handled by the tor route, never Handshake
  'arpa' // infrastructure; home.arpa lives here
])

/** Is this a name the network reserves, so never a Handshake name? */
export function isReservedHost (rawHost) {
  const host = String(rawHost || '').toLowerCase().replace(/\.$/, '')
  if (!host) return false
  const last = host.slice(host.lastIndexOf('.') + 1)
  return NEVER_HNS_TLDS.has(host) || NEVER_HNS_TLDS.has(last)
}

export function isHnsHost (rawHost, tlds = icannTlds) {
  if (!rawHost) return false
  const host = String(rawHost).toLowerCase().replace(/\.$/, '')
  if (!host || isReservedHost(host)) return false
  if (IPV4.test(host)) return false
  if (host.startsWith('[') || host.includes(':')) return false // IP literals
  const ns = classifyHost(host, tlds)
  if (ns === NAMESPACES.HNS) return true
  // null = a single bare label. In the omnibox that is ambiguous (word vs
  // site) and defaults to search; HERE the input is already a URL with a
  // host, so navigation intent is settled — a single non-ICANN label
  // (http://hnshosting/) is a Handshake host.
  return ns === null
}

/**
 * If this is a main-frame-loadable http(s) URL on a Handshake host, the
 * hns:// URL it should load as; if it is on a namespace-reserved host
 * (*.eth, *.onion), the URL in THAT scheme, whose fail-closed handler
 * answers without touching the network — else null (load unchanged).
 * Everything but the scheme is preserved; the hns:// handler owns
 * https-vs-http, DANE and the trust state from there.
 * @param {string} urlString
 * @param {Set<string>} [tlds] override for tests
 * @returns {string?}
 */
export function rewriteToHns (urlString, tlds = icannTlds) {
  let url
  try {
    url = new URL(String(urlString))
  } catch {
    return null
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null
  const port = url.port ? `:${url.port}` : ''
  const rest = `${url.hostname}${port}${url.pathname}${url.search}${url.hash}`
  const reserved = reservedNamespaceScheme(url.hostname)
  if (reserved) return `${reserved}://${rest}`
  if (!isHnsHost(url.hostname, tlds)) return null
  return `hns://${rest}`
}
