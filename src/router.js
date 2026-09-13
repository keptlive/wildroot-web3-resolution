/* global Response */

/*
 * Resolution router & scheme registry (BR-1) — the ONE authoritative place
 * that decides "which protocol owns this input" and dispatches to its handler.
 *
 * Two jobs, one module, and no other place gets to make these decisions:
 *
 *   1. THE REGISTRY (scheme -> handler).  Every per-scheme handler registers
 *      into a ProtocolRouter. Dispatch is by explicit scheme only. This is
 *      where LAW L1 ("explicit scheme selects the protocol, always") and LAW
 *      L2 ("no silent cross-namespace fallback") are enforced in code: a
 *      handler's failure is returned AS THAT SCHEME's failure and the router
 *      never, ever re-dispatches the same request into a second namespace.
 *
 *   2. THE CLASSIFIER (bare input -> namespace).  When the user types something
 *      with no scheme, exactly one namespace is chosen — an HNS TLD, ICANN,
 *      .eth (ENS), .onion (Tor), an IPFS path, localhost, or (only when nothing
 *      names a protocol) web search. The decision is made ONCE. There is no
 *      "try HNS, and if that 404s look it up in ICANN": that would be the
 *      cross-namespace fallback L2 forbids. `classify()` returns a single
 *      target plus the reason it was chosen; callers act on that and nothing
 *      more.
 *
 * This module is deliberately free of Electron/DOM imports so it runs under
 * plain `node --test` and can be shared by the main-process registry
 * (src/protocols/index.js) and, in a later additive step, the renderer
 * omni-box classifier (src/ui/omni-box.js) — which today duplicates the
 * bare-input rules.
 *
 * Design note on the HNS internal transport fallback: the mature hns handler
 * (src/hns/index.js) retries a failed chain lookup over DoH. That is NOT an L2
 * violation — DoH still resolves the SAME Handshake name in the SAME namespace;
 * it is a weaker transport for one protocol, surfaced honestly (X-HNS-Trust).
 * L2 forbids a failure in namespace A becoming a lookup in namespace B. The
 * router models exactly that boundary and nothing finer.
 */

import { createHash } from 'node:crypto'
import { CID } from 'multiformats/cid'

import classifier from './classify-host.cjs'
import { searchURL as makeSearchURL } from './search-url.js'
import { encodeHnsHost } from './hns-url.cjs'
import { CID_RE } from './pointers.js'
import { decodeNip19 } from '../namespaces/nostr/src/nip19.js'

// THE HOST CLASSIFIER LIVES IN src/hns/classify-host.cjs — one implementation
// the omnibox (CommonJS) shares with this module. Everything host-shaped is
// re-exported from here so existing importers keep their names.
const {
  ICANN_TLDS, NEVER_HNS_TLDS, ONION_V3,
  isReservedHost, isOnionHost, isEthName, bareHost, asciiTld, classifyHost, isBareNumberOff
} = classifier

export { ICANN_TLDS, NEVER_HNS_TLDS, isReservedHost, isOnionHost, isEthName, classifyHost }

// --- Namespaces -------------------------------------------------------------
// A namespace is "a distinct address space with its own root of trust." Two
// schemes may share one namespace (ipfs/ipns/ipld/pubsub are all IPFS). A
// failure must never cross a namespace boundary (L2).
export const NAMESPACES = Object.freeze({
  HNS: 'hns', // Handshake names, SPV chain-proof + DANE/CID (L3)
  IPFS: 'ipfs', // content-addressed, verified by CID
  ARWEAVE: 'arweave', // permaweb, verified by immutable txid
  ENS: 'ens', // .eth via Ethereum, contenthash -> ipfs/ar
  WEB3: 'web3', // ERC-4804 web3:// EVM calls (a scheme; the w3:// short
  // form is intentionally NOT offered — it collides with the .w3 HNS TLD)
  NOSTR: 'nostr', // npub / nprofile, key-signed events
  ATPROTO: 'atproto', // at:// + did:plc/web, DID-document authenticated
  DID: 'did', // did: documents (did:plc, did:web)
  ACTIVITYPUB: 'activitypub', // WebFinger/actor, signed
  TOR: 'tor', // .onion v3, onion-key authenticated, NEVER DNS
  ICANN: 'icann', // ICANN DNS names, resolved via the ODoH policy (BR-2/3)
  WEB: 'web', // explicit http(s):// URLs and IP literals
  GEMINI: 'gemini',
  HYPER: 'hyper',
  SSB: 'ssb',
  BITTORRENT: 'bittorrent',
  MAGNET: 'magnet',
  BROWSER: 'browser', // built-in wildroot:// / browser:// UI pages
  SEARCH: 'search' // the terminal for "no protocol was named"
})

// --- The authoritative scheme -> namespace table ----------------------------
// This is the single source of truth. `status` is honest about maturity so the
// other BR tasks know what they register INTO vs build:
//   live    - handler shipped and wired in src/protocols/index.js
//   partial - handler exists, a task is open to bring it to spec
//   planned - greenfield; a stub should register so dispatch fails CLOSED
//             inside the right namespace instead of leaking to another (L2).
// `verify` names the native layer that authenticates the canonical object (L3).
// `trust` is the verdict a page in that scheme can at best reach — trustless
// (every step verified here), trusted (something taken on somebody's word),
// open (no transport protection), refused (a fail-closed stub), builtin (the
// browser's own pages) — and tests/hns/lock-semantics.test.js holds
// src/hns/trust-path.js to it, so the table cannot claim what the panel
// does not deliver.
// The router does not perform verification — it names it so no scheme is wired
// in without a verification story: register() REFUSES a scheme with no row
// (CODE-AUDIT 3.10 found two registered with none). `navigable: false` marks
// a scheme that is an origin for subresources and main-process loads only —
// never a link target — so the will-navigate allowlist (src/window.js) must
// NOT carry it; tests/hns/nav-scheme-coverage.test.js pins both directions.
export const SCHEME_TABLE = Object.freeze([
  { scheme: 'hns', namespace: NAMESPACES.HNS, status: 'live', trust: 'trustless', verify: 'SPV chain proof + DANE (TLSA 3 1 1) or content CID' },
  { scheme: 'ipfs', namespace: NAMESPACES.IPFS, status: 'live', trust: 'trustless', verify: 'CID' },
  { scheme: 'ipns', namespace: NAMESPACES.IPFS, status: 'live', trust: 'trustless', verify: 'IPNS record + CID' },
  { scheme: 'ipld', namespace: NAMESPACES.IPFS, status: 'live', trust: 'trustless', verify: 'CID' },
  // A topic is a free-form string, not a content address: the only thing a
  // message carries is the publishing peer's libp2p signature.
  { scheme: 'pubsub', namespace: NAMESPACES.IPFS, status: 'live', trust: 'trusted', verify: 'libp2p publisher signature — a topic is not a content address' },
  // Honest status: with the header check on, the transaction header is
  // authenticated against the id (its signature verified over the fields, not
  // merely hashed — src/hns/ar-tx.js) and a whole raw body under 8 MiB is
  // checked against the signed data root or, for format 1, the signed data
  // itself. A larger transaction, a Range, a manifest path, a bundled item
  // and a header we cannot check stay gateway-trusted, and this row is the
  // resolution-time claim, written before any fetch — so 'partial', never
  // 'live'. The per-fetch truth is X-Arweave-Verified. BR-6 closes the rest.
  { scheme: 'ar', namespace: NAMESPACES.ARWEAVE, status: 'partial', trust: 'trusted', verify: 'immutable txid; signed header + bytes under 8 MiB checked per fetch, the rest gateway-trusted (BR-6)' },
  // Resolves the name's EIP-1577 contenthash over a PUBLIC Ethereum RPC and
  // hands the ipfs/ar pointer to those handlers. 'partial', not 'live': the
  // content is CID-verified but the name->content binding is RPC-trusted (not
  // chain-proven), so the verdict is TRUSTED (the neutral lock, as for an
  // https:// page) and never the green trustless one. Never falls back to
  // .eth-as-HNS.
  { scheme: 'ens', namespace: NAMESPACES.ENS, status: 'partial', trust: 'trusted', verify: 'ENS contenthash via public Ethereum RPC (RPC-trusted, not chain-proven — lock TRUSTED, never green)' },
  { scheme: 'web3', namespace: NAMESPACES.WEB3, status: 'partial', trust: 'trusted', verify: 'ERC-4804 EVM read (BR-5)' },
  { scheme: 'nostr', namespace: NAMESPACES.NOSTR, status: 'partial', trust: 'trusted', verify: 'schnorr signature + event id recomputed locally; relay completeness NOT proven' },
  { scheme: 'at', namespace: NAMESPACES.ATPROTO, status: 'planned', trust: 'refused', verify: 'DID document (BR-7)' },
  // Fetched, not proven: the document's id is checked against the DID asked
  // for and the host is guarded, but the did:plc operation log is not audited
  // and did:web rests on WebPKI — the lock is TRUSTED, never green.
  { scheme: 'did', namespace: NAMESPACES.DID, status: 'partial', trust: 'trusted', verify: 'DID document fetched from plc.directory / the did:web host (id checked; not proven — lock TRUSTED)' },
  { scheme: 'activitypub', namespace: NAMESPACES.ACTIVITYPUB, status: 'planned', trust: 'refused', verify: 'WebFinger/actor signature (BR-7)' },
  // Reached ONLY through the device-local Tor that IP Protection turns on
  // (never a hosted relay). 'partial': it works and the onion key authenticates
  // the service at the Tor layer, but it is gated on IP Protection and this
  // browser does not resist fingerprinting like Tor Browser. NEVER DNS.
  { scheme: 'onion', namespace: NAMESPACES.TOR, status: 'partial', trust: 'trusted', verify: 'Tor onion-service key via the device-local Tor circuit — NEVER DNS' },
  { scheme: 'https', namespace: NAMESPACES.WEB, status: 'live', trust: 'trusted', verify: 'WebPKI (address via the ODoH policy, BR-3)' },
  { scheme: 'http', namespace: NAMESPACES.WEB, status: 'live', trust: 'open', verify: 'none (plaintext)' },
  { scheme: 'https+raw', namespace: NAMESPACES.WEB, status: 'live', trust: 'trusted', verify: 'WebPKI' },
  // TLS with rejectUnauthorized:false and no certificate store: encrypted,
  // and nothing else. Not TOFU — no fingerprint is remembered or compared.
  { scheme: 'gemini', namespace: NAMESPACES.GEMINI, status: 'live', trust: 'trusted', verify: 'none — TLS with no certificate verification (not TOFU: nothing is pinned)' },
  { scheme: 'hyper', namespace: NAMESPACES.HYPER, status: 'live', trust: 'trustless', verify: 'hypercore key (a DNSLink name→key binding is resolver-trusted)' },
  { scheme: 'ssb', namespace: NAMESPACES.SSB, status: 'live', trust: 'trustless', verify: 'feed signature' },
  { scheme: 'bittorrent', namespace: NAMESPACES.BITTORRENT, status: 'live', trust: 'trustless', verify: 'infohash' },
  { scheme: 'bt', namespace: NAMESPACES.BITTORRENT, status: 'live', trust: 'trustless', verify: 'infohash' },
  { scheme: 'magnet', namespace: NAMESPACES.MAGNET, status: 'live', trust: 'trusted', verify: 'infohash' },
  { scheme: 'wildroot', namespace: NAMESPACES.BROWSER, status: 'live', trust: 'builtin', verify: 'built-in' },
  // Permanent SILENT aliases of wildroot:// (D2): still served (old sessions,
  // links in the wild) but rewritten to wildroot:// on navigation
  // (src/scheme-alias.js) and never advertised in the UI.
  { scheme: 'agregore', namespace: NAMESPACES.BROWSER, status: 'live', trust: 'builtin', verify: 'built-in', aliasOf: 'wildroot' },
  { scheme: 'browser', namespace: NAMESPACES.BROWSER, status: 'live', trust: 'builtin', verify: 'built-in', aliasOf: 'wildroot' },
  { scheme: 'search', namespace: NAMESPACES.SEARCH, status: 'live', trust: 'trusted', verify: 'n/a (private metasearch)' },
  // Its own scheme rather than a wildroot:// page: an isolated secure origin
  // for a page that does its own crypto; see src/protocols/paste-protocol.js.
  { scheme: 'paste', namespace: NAMESPACES.BROWSER, status: 'live', trust: 'builtin', verify: 'built-in; content verified against its CID in the page' },
  // Also its own scheme, and for the same reason as paste://: the editor
  // keeps an autosaved draft in localStorage of its own.
  { scheme: 'editor', namespace: NAMESPACES.BROWSER, status: 'live', trust: 'builtin', verify: 'built-in; published document addressed by CID' },
  // The embedded Bluesky client (vendored impro, src/bluesky-app) — its own
  // scheme for its localStorage sessions, same reason as editor/paste. The
  // CONTENT it shows is Bluesky's network over WebPKI HTTPS, not chain-
  // verified — 'live' here means the app itself is built in and local.
  { scheme: 'bluesky', namespace: NAMESPACES.BROWSER, status: 'live', trust: 'trusted', verify: 'built-in app; network content via WebPKI (Bluesky PDS/appview)' },
  { scheme: 'mastodon', namespace: NAMESPACES.BROWSER, status: 'live', trust: 'trusted', verify: 'built-in app; network content via WebPKI (the Fediverse server)' },
  // Converted media (src/media/media-protocol.js): a <video src> the player
  // sets, addressed by the source it was converted from. Not a link target.
  { scheme: 'media', namespace: NAMESPACES.BROWSER, status: 'live', trust: 'builtin', verify: 'built-in; bytes derived locally from a source the browser already verified', navigable: false },
  // The document render sandbox (src/documents/docview-protocol.js): an
  // isolated origin main loads into a view. A page navigating a tab into it
  // is refused (documentToViewerPage), so it is not a link target either.
  { scheme: 'docview', namespace: NAMESPACES.BROWSER, status: 'live', trust: 'builtin', verify: 'built-in sandbox; the document it renders was opened by the user', navigable: false }
])

// Fast scheme -> table-row lookup.
const SCHEME_INDEX = new Map(SCHEME_TABLE.map((row) => [row.scheme, row]))

/** The namespace a scheme belongs to, or null if the scheme is unknown. */
export function namespaceForScheme (scheme) {
  const row = SCHEME_INDEX.get(String(scheme || '').toLowerCase())
  return row ? row.namespace : null
}

/** The full table row for a scheme, or null. */
export function schemeInfo (scheme) {
  return SCHEME_INDEX.get(String(scheme || '').toLowerCase()) || null
}

// --- Classifier primitives --------------------------------------------------

const IPFS_PREFIX = '/ipfs/'
const IPNS_PREFIX = '/ipns/'

// A scheme token followed by ':'. Per L1, once a scheme is present the
// classifier does NOT get a vote — the scheme wins.
const EXPLICIT_SCHEME = /^([a-z][a-z0-9+.-]*):/i

/**
 * Does this input already name a protocol explicitly? (the L1 gate)
 * Careful about the "example.com:8080" host:port shape, which superficially
 * matches scheme syntax but is not a scheme.
 */
export function hasExplicitScheme (input) {
  const s = String(input || '').trim()
  if (!EXPLICIT_SCHEME.test(s)) return false
  const scheme = s.slice(0, s.indexOf(':')).toLowerCase()
  const rest = s.slice(scheme.length + 1)
  // "host:8080" / "host:8080/path": a real registered scheme is never followed
  // by a bare port number. An UNKNOWN token followed by digits is host:port.
  if (/^\d+(\/|$|\?|#)/.test(rest) && !SCHEME_INDEX.has(scheme)) return false
  // "fe80::1": a scheme is never followed by a second colon — that is an
  // IPv6 literal whose first group happens to spell a scheme token.
  if (rest.startsWith(':') && !SCHEME_INDEX.has(scheme)) return false
  return true
}

/** The scheme token of an explicit input (lowercased), or null. */
export function schemeOf (input) {
  const s = String(input || '').trim()
  if (!hasExplicitScheme(s)) return null
  return s.slice(0, s.indexOf(':')).toLowerCase()
}

const B32 = 'abcdefghijklmnopqrstuvwxyz234567' // RFC 4648 §6

/**
 * A well-formed v3 onion address — rend-spec-v3 §6:
 *   base32(PUBKEY[32] ‖ CHECKSUM[2] ‖ VERSION[1]) + ".onion"
 *   CHECKSUM = SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)[:2], VERSION = 3
 * 56 base32 characters are exactly 35 bytes, so there is no padding to worry
 * about. This is a SYNTAX check, not a security one: Tor derives the service
 * lookup from the key bytes, so a corrupt address cannot reach a WRONG
 * service — it just fails after a circuit is spent. Checking here lets a
 * mistyped or truncated address fail instantly and locally. Routing does not
 * consult it: an invalid .onion still belongs to the Tor namespace
 * (classifyHost), because a typo leaks to a resolver as well as a real one.
 */
export function isValidV3Onion (host) {
  const s = String(host || '').toLowerCase()
  if (!ONION_V3.test(s)) return false
  const raw = Buffer.alloc(35)
  let acc = 0
  let bits = 0
  let at = 0
  for (const c of s.slice(0, 56)) {
    acc = (acc << 5) | B32.indexOf(c)
    bits += 5
    if (bits >= 8) {
      bits -= 8
      raw[at++] = (acc >> bits) & 0xff
    }
  }
  if (raw[34] !== 3) return false
  const want = createHash('sha3-256')
    .update(Buffer.concat([Buffer.from('.onion checksum'), raw.subarray(0, 32), raw.subarray(34)]))
    .digest()
  return raw[32] === want[0] && raw[33] === want[1]
}

// --- The classifier ---------------------------------------------------------

/**
 * Decide what a typed omni-box string means. Returns a single decision:
 *   { url, scheme, namespace, explicit, reason }
 *
 * `explicit` is true when the input already named a scheme (L1: the scheme
 * wins, we do not sniff). Otherwise exactly one namespace is chosen and there
 * is no second guess (L2).
 *
 * @param {string} input
 * @param {object} [opts]
 * @param {(q:string)=>string} [opts.searchURL] map a query to a search URL;
 *        defaults to the internal private metasearch (search://).
 */
export function classify (input, opts = {}) {
  const raw = String(input || '').trim()
  const searchURL = opts.searchURL || makeSearchURL

  if (!raw) {
    return { url: searchURL(''), scheme: 'search', namespace: NAMESPACES.SEARCH, explicit: false, reason: 'empty' }
  }

  // L1: an explicit scheme is authoritative. We do not reclassify it, we do not
  // "improve" it — we route it to whatever it named, known or not. An unknown
  // scheme is still returned as itself (dispatch will fail closed in-namespace).
  if (hasExplicitScheme(raw)) {
    const scheme = schemeOf(raw)
    return {
      url: raw,
      scheme,
      namespace: namespaceForScheme(scheme),
      explicit: true,
      reason: 'explicit-scheme',
      // Whether the table knows the scheme. `javascript:`, `data:` and
      // `file:` come back here untouched with `namespace: null`; a caller
      // that navigates must not treat every decision as a link target.
      known: SCHEME_INDEX.has(scheme)
    }
  }

  // `@user@host` is the canonical Fediverse address and is NOT a host: the URL
  // parser reads the second `@` as a userinfo separator and would navigate to
  // the instance with a stray credential. It belongs to activitypub, whose
  // handler refuses it visibly and names what is missing.
  if (/^@[^@\s/]+@[^@\s/]+\.[^@\s/]+$/.test(raw)) {
    return { url: `activitypub:${raw}`, scheme: 'activitypub', namespace: NAMESPACES.ACTIVITYPUB, explicit: false, reason: 'fedi-handle' }
  }
  // Any other `@` in a scheme-less input is not a name: no namespace here has
  // one in an address, and the URL constructor would read what precedes it as
  // userinfo and silently drop it (`@alice@host` -> `hns://host/`). A search.
  if (raw.includes('@')) {
    return { url: searchURL(raw), scheme: 'search', namespace: NAMESPACES.SEARCH, explicit: false, reason: 'search' }
  }

  // A NIP-19 identifier is self-describing: the human-readable part IS the
  // type and a 30-bit checksum makes a false positive a one-in-a-billion
  // event — so it is DECODED before it is claimed, and a Handshake name that
  // merely starts with `npub` stays a name. `nsec` is routed on purpose: the
  // nostr handler answers with the "that is a PRIVATE KEY" page, whereas the
  // bare-label rule would have sent the secret to a resolver as a name.
  // A trailing slash — the address bar adds one — is not part of the identifier.
  const nip19 = raw.replace(/\/+$/, '')
  if (/^(npub|note|nprofile|nevent|naddr|nsec)1[02-9ac-hj-np-z]{6,}$/i.test(nip19)) {
    const decoded = decodeNip19(nip19.toLowerCase())
    if (!decoded.error || /^nsec1/i.test(nip19)) {
      return { url: `nostr:${nip19.toLowerCase()}`, scheme: 'nostr', namespace: NAMESPACES.NOSTR, explicit: false, reason: 'nip19-identifier' }
    }
  }

  // A pasted CID is the most natural thing anybody does with one, and it is
  // self-describing. A CIDv0 (`Qm…`, base58, case-sensitive) cannot survive
  // as a URL host — Chromium lowercases it — so it is written as its CIDv1
  // base32 form, which names the same bytes. An IPNS key is deliberately NOT
  // recognised here: `Qm…` is both a legacy IPNS key and a CIDv0, and
  // guessing between them is exactly the sniffing the router exists to avoid.
  if (!/[\s./:?#]/.test(raw) && CID_RE.test(raw)) {
    const cid = bareCid(raw)
    if (cid) return { url: `ipfs://${cid}/`, scheme: 'ipfs', namespace: NAMESPACES.IPFS, explicit: false, reason: 'bare-cid' }
  }

  // Scheme-less. IPFS/IPNS gateway-style paths.
  if (raw.startsWith(IPFS_PREFIX)) {
    return { url: `ipfs://${raw.slice(IPFS_PREFIX.length)}`, scheme: 'ipfs', namespace: NAMESPACES.IPFS, explicit: false, reason: 'ipfs-path' }
  }
  if (raw.startsWith(IPNS_PREFIX)) {
    return { url: `ipns://${raw.slice(IPNS_PREFIX.length)}`, scheme: 'ipns', namespace: NAMESPACES.IPFS, explicit: false, reason: 'ipns-path' }
  }

  // Bare localhost is developer HTTP, never a Handshake name or a search.
  if (/^localhost(:\d+)?\/?$/.test(raw)) {
    return { url: `http://${raw}`, scheme: 'http', namespace: NAMESPACES.WEB, explicit: false, reason: 'localhost' }
  }

  const host = bareHost(raw)
  const ns = classifyHost(host)

  if (ns === NAMESPACES.TOR) {
    // Bare onion -> onion:// so it dispatches to the Tor handler and NEVER a
    // resolver. (onion:// is the browser's internal carrier scheme for BR-8.)
    return { url: `onion://${raw}`, scheme: 'onion', namespace: NAMESPACES.TOR, explicit: false, reason: 'onion-host', validV3: isValidV3Onion(host) }
  }
  if (ns === NAMESPACES.ENS) {
    return { url: `ens://${raw}`, scheme: 'ens', namespace: NAMESPACES.ENS, explicit: false, reason: 'eth-name' }
  }
  if (ns === NAMESPACES.HNS) {
    return { url: makeHnsURL(raw), scheme: 'hns', namespace: NAMESPACES.HNS, explicit: false, reason: 'hns-tld' }
  }
  if (ns === NAMESPACES.ICANN) {
    return { url: `https://${raw}`, scheme: 'https', namespace: NAMESPACES.ICANN, explicit: false, reason: 'icann-tld' }
  }
  if (ns === NAMESPACES.WEB) {
    // A reserved name is a device on the user's own network, which is reached
    // the way `localhost` is (plain http, the platform resolver); an IP literal
    // gets https like any other explicit host.
    if (isReservedHost(host)) {
      return { url: `http://${raw}`, scheme: 'http', namespace: NAMESPACES.WEB, explicit: false, reason: 'reserved-host' }
    }
    // An unbracketed IPv6 literal is not a URL host until it is bracketed.
    const literal = host.includes(':') && !host.startsWith('[') ? raw.replace(host, `[${host}]`) : raw
    return { url: `https://${literal}`, scheme: 'https', namespace: NAMESPACES.WEB, explicit: false, reason: 'ip-literal' }
  }

  // ns === null: A SINGLE BARE LABEL, AND IT IS A NAME.
  //
  // `pinner` is a Handshake name; so are hnshosting, varo, 14898 and 🤝. Most
  // Handshake sites ARE bare TLDs, and a browser whose subject is names does
  // not answer one by asking a search engine (Matt, 2026-09-04). This used to
  // require a signal of navigation intent — a trailing `/` or `.`, or a
  // non-ASCII label — and search everything else.
  //
  // The ICANN list still decides, exactly as it does for a dotted host: a bare
  // `com`, `org` or `app` is a TLD somebody might be about to type more of, so
  // it stays a search. Anything with whitespace never reached here at all.
  //
  // A search is NOT a cross-namespace fallback: no protocol was ever named, so
  // there is nothing to fall back FROM (L2 is about a NAMED protocol failing).
  // The omnibox offers the search as a second suggestion row for exactly this
  // input (src/ui/omni-box.js isBareWord), which is where "I meant to look
  // that up" is answered — not here, by guessing.
  // `null` is not only "one bare label" — classifyHost also returns it for a
  // host with WHITESPACE in it, which is what a real search query looks like
  // ("how to publish a site"). The old nav-intent test rejected those by
  // accident, because a sentence rarely ends in a slash. Now that a bare label
  // navigates, the exclusion has to be deliberate, or every multi-word search
  // becomes a Handshake lookup. Caught by its own test on the way in.
  // A bare number is a name only with numeric names on (classify-host.cjs).
  const label = /\s/.test(raw) ? '' : asciiTld(host)
  if (label && !ICANN_TLDS.has(label) && !isBareNumberOff(label)) {
    return { url: makeHnsURL(raw), scheme: 'hns', namespace: NAMESPACES.HNS, explicit: false, reason: 'hns-bare-label' }
  }
  return { url: searchURL(raw), scheme: 'search', namespace: NAMESPACES.SEARCH, explicit: false, reason: 'search' }
}

/** A CID string in the form that survives as a URL host, or null. */
function bareCid (raw) {
  try {
    const parsed = CID.parse(raw)
    return parsed.version === 0 ? parsed.toV1().toString() : raw
  } catch {
    return null
  }
}

// Unicode input (🤝) is punycoded here or the resolver gets a name the chain
// has never heard of — and a NUMERIC TLD (hello.14898, our own free names)
// is written with the `_` marker (src/hns/hns-url.cjs), because Chromium
// reads a host whose last label is all digits as an IPv4 address and refuses
// the URL outright. `new URL('http://hello.14898')` throws for the same
// reason, so the numeric case is handled BEFORE the punycode pass instead of
// falling back to the raw name as it used to. Mirrors omni-box.makeHNS.
function makeHnsURL (query) {
  const [rawHostPart, ...rest] = query.split('/')
  const hostPart = encodeHnsHost(rawHostPart)
  try {
    const u = new URL('http://' + hostPart)
    const host = u.port ? `${u.hostname}:${u.port}` : u.hostname
    return `hns://${host}/${rest.join('/')}`
  } catch {
    return `hns://${encodeHnsHost(query)}`
  }
}

// --- The registry / dispatcher ---------------------------------------------

/**
 * The registry every per-scheme handler registers into. Dispatch is by scheme
 * only (L1); a handler failure is returned in-namespace and never re-dispatched
 * across a namespace boundary (L2).
 */
export class ProtocolRouter {
  constructor () {
    /** @type {Map<string, {handler: Function, info: object}>} */
    this.handlers = new Map()
  }

  /**
   * Register a handler for one or more schemes. A double-registration is a
   * wiring bug, so it throws unless `meta.override` is set.
   * @param {string|string[]} schemes
   * @param {(request: Request) => Promise<Response>|Response} handler
   * @param {object} [meta]
   */
  register (schemes, handler, meta = {}) {
    if (typeof handler !== 'function') {
      throw new Error('router: handler must be a function')
    }
    const list = Array.isArray(schemes) ? schemes : [schemes]
    for (const raw of list) {
      const scheme = String(raw).toLowerCase()
      if (this.handlers.has(scheme) && !meta.override) {
        throw new Error(`router: scheme "${scheme}" already registered`)
      }
      // No row, no handler: the table is the one place a scheme's namespace
      // and verification story live. A test may name both explicitly.
      const info = schemeInfo(scheme) || (meta.namespace && meta.status ? { scheme, namespace: meta.namespace, status: meta.status } : null)
      if (!info) throw new Error(`router: scheme "${scheme}" has no SCHEME_TABLE row — add it there first, with its verification story`)
      this.handlers.set(scheme, { handler, info })
    }
    return this
  }

  has (scheme) {
    return this.handlers.has(String(scheme || '').toLowerCase())
  }

  handlerFor (scheme) {
    const entry = this.handlers.get(String(scheme || '').toLowerCase())
    return entry ? entry.handler : null
  }

  registeredSchemes () {
    return [...this.handlers.keys()].sort()
  }

  /**
   * Route a Request to the handler its scheme names. This is the L1/L2 choke
   * point:
   *   - the scheme is read from the URL and nothing else (no sniffing);
   *   - if no handler is registered, we return a 501 tagged with THAT scheme —
   *     we do NOT reinterpret the URL in another namespace;
   *   - if the handler throws, we return a 502 tagged with THAT scheme — the
   *     failure surfaces as this protocol's failure, never a second lookup.
   * @param {Request} request
   */
  async dispatch (request) {
    const raw = String((request && request.url) || '')
    let scheme
    try {
      scheme = new URL(raw).protocol.replace(/:$/, '').toLowerCase()
    } catch {
      // Not a URL the WHATWG parser accepts — but a NAMED scheme's failure is
      // still that scheme's. `at://did:plc:abc/…` is the canonical AT-URI and
      // is not a WHATWG URL (a host may not carry a colon that is not a
      // port), so the scheme is read by prefix and the handler gets the
      // request, tagged with its namespace. With no scheme at all it stays a
      // bare 400.
      scheme = schemeOf(raw)
      if (!scheme) return routerError(400, 'router', 'The address is not a valid URL.', null)
    }
    const entry = this.handlers.get(scheme)
    if (!entry) {
      // NO FALLBACK. An unregistered scheme fails as itself. It is never
      // reinterpreted as a bare host, an ICANN name, or a search (L1/L2).
      return routerError(501, scheme, `No handler is registered for "${scheme}://". ` +
        'The browser will not guess a different protocol for this address.', scheme)
    }
    try {
      return await entry.handler(request)
    } catch (err) {
      // The handler threw. That is THIS scheme's failure. We surface it as such
      // and do not re-dispatch into any other namespace (L2).
      return routerError(502, scheme, String((err && err.message) || err), scheme)
    }
  }
}

function routerError (status, scheme, detail, schemeTag) {
  const headers = { 'content-type': 'text/plain; charset=utf-8' }
  // A machine-readable marker so the address-bar/trust UI (BR-9) can show that
  // the failure stayed inside the named protocol — proof there was no fallback.
  if (schemeTag) headers['X-Resolution-Namespace'] = namespaceForScheme(schemeTag) || schemeTag
  return new Response(`${scheme || 'router'}: ${detail}`, { status, headers })
}

export default ProtocolRouter
