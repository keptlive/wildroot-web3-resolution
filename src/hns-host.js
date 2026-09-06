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

import { classifyHost, NAMESPACES, isReservedHost, NEVER_HNS_TLDS } from './router.js'

import icannTlds from './icann-tlds.cjs'

// The reserved-name list lives in src/hns/reserved-names.cjs and is consulted
// by the router's classifier; it is re-exported here for the callers that
// have always read it from this module.
export { isReservedHost, NEVER_HNS_TLDS }

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

// The scheme whose handler owns each non-HNS, non-DNS namespace: ens:// for
// *.eth (src/protocols/ens-protocol.js) and onion:// for *.onion
// (src/protocols/onion-protocol.js). A malformed host under these TLDs must
// stay in its namespace too — a typo'd onion in a DNS query leaks exactly as
// effectively as a valid one.
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
 * (*.eth, *.onion), the URL in THAT scheme, whose handler resolves it in its
 * own namespace or refuses it there — else null (load unchanged).
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
