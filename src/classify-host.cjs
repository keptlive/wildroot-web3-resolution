// The host classifier — ONE implementation of "which namespace does this
// host belong to", shared by the router (src/protocols/router.js, an ES
// module) and the omnibox (src/ui/omni-box.js, CommonJS extending
// HTMLElement, which cannot import an ES module). Written as CommonJS for the
// same reason icann-tlds.cjs, reserved-names.cjs and hns-url.cjs are: both
// sides can load it. Dependency-free apart from the two lists it consults.
//
// The third reader of this rule, the WebSocket PAC script
// (src/hns/ws-proxy-pac.js), runs inside Chromium's PAC sandbox where there
// is no URL parser, so it cannot use this module; it embeds the two lists and
// a reduced, ASCII-only form of the same rule, and
// tests/hns/omnibox-namespaces.test.js holds it to this module's answers.
//
// The order is the crux of LAW L1/L2 for typed input — each host resolves to
// ONE namespace, decided here and nowhere else.

const ICANN_TLDS = require('./icann-tlds.cjs')
const { isReservedHost, NEVER_HNS_TLDS } = require('./reserved-names.cjs')

// NUMERIC HANDSHAKE NAMES (`hello.14898`, `14898`) ARE OFF BY DEFAULT.
// Matt, 2026-09-06 (NT-1 decided): pure-number names are excluded for
// simplicity. ICANN has no all-numeric TLD, so the rule is sound, and
// Handshake sells such names — but the URL Standard reads a host ending in
// digits as an IPv4 address, so writing them needs the `_` marker of
// src/hns/hns-url.cjs, a convention nobody else implements. The resolution
// method stays in the code and the documentation (docs/RESOLUTION-ROUTER.md,
// the public specification's experimental chapter Part B); this switch
// turns it on — Settings › Operator panel › "Names that are only numbers"
// (`hnsOptions.numericNames`). Main sets it from the config; the chrome UI's
// copy of this module is set from the window URL (src/ui/script.js).
let numericNames = false

/** @param {unknown} on */
function setNumericNames (on) { numericNames = !!on }
function numericNamesEnabled () { return numericNames }
const NUMERIC_LABEL = /^\d+$/
/**
 * A bare all-digit label (`14898`) typed on its own: a Handshake name only
 * when numeric names are on. The single-label decision belongs to the
 * callers (classifyHost returns null for it), so both of them ask this.
 * @param {string} label
 */
function isBareNumberOff (label) { return NUMERIC_LABEL.test(String(label || '')) && !numericNames }

/** The namespace names classifyHost returns; the router's NAMESPACES agree. */
const NAMESPACE = Object.freeze({
  TOR: 'tor',
  ENS: 'ens',
  HNS: 'hns',
  ICANN: 'icann',
  WEB: 'web'
})

// v3 onion: exactly 56 base32 chars (a-z, 2-7) + ".onion". v2 (16 chars) is
// dead and unsafe; we recognize the .onion suffix but only mark v3 valid.
const ONION_V3 = /^[a-z2-7]{56}\.onion$/i

function isOnionHost (host) {
  return /\.onion$/i.test(String(host || ''))
}

function isEthName (host) {
  return /\.eth$/i.test(String(host || ''))
}

// An IPv4 dotted quad, or an IPv6 literal with or without its brackets.
function isIpLiteral (host) {
  const h = String(host || '')
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true
  const bare = h.replace(/^\[|\]$/g, '')
  if (bare.includes(':') && /^[0-9a-f:.]+$/i.test(bare)) return true
  return false
}

// Strip a scheme-less path/query/fragment, any :port and a trailing dot to
// get the bare host. The trailing dot (the DNS root form, `vitalik.eth.`)
// must go BEFORE the suffix checks or `.eth`/`.onion` silently miss.
// A `:port` is stripped only from a host with exactly one colon and no
// brackets: `::1` is an address, not a host with a port of 1.
function bareHost (input) {
  let host = String(input || '').trim().split(/[/?#]/)[0]
  if (!host.startsWith('[') && (host.match(/:/g) || []).length === 1) {
    host = host.replace(/:\d+$/, '')
  } else if (host.startsWith('[')) {
    host = host.replace(/^(\[[^\]]*\]):\d+$/, '$1')
  }
  host = host.replace(/\.$/, '')
  return host
}

// Punycode the host so a Unicode TLD (пример.рф) is compared against the
// punycode ICANN list, and an emoji label is recognized as non-ICANN (HNS).
function asciiTld (host) {
  const labels = String(host || '').split('.').filter(Boolean)
  let tld = labels[labels.length - 1]
  try {
    const ascii = new URL('http://' + host).hostname
    tld = ascii.split('.').filter(Boolean).pop()
  } catch { /* keep the raw tld */ }
  return (tld || '').toLowerCase()
}

/**
 * Classify a bare HOST (no scheme) into exactly one namespace.
 *
 * Returns one of: 'tor' | 'ens' | 'hns' | 'icann' | 'web' (an IP literal, or
 * a reserved name such as `nas.local`) | null, where null means "a single
 * bare label" — the caller decides between HNS and search.
 *
 * `tlds` is an override for tests (defaults to the bundled IANA snapshot).
 */
function classifyHost (rawHost, tlds = ICANN_TLDS) {
  const host = bareHost(rawHost)
  if (!host || /\s/.test(host)) return null

  // .onion FIRST and unconditionally: a v3 onion goes to Tor and MUST NEVER be
  // sent to DNS/ODoH (L1). Even a malformed .onion stays in the Tor namespace
  // (it fails as a Tor address, not as a DNS miss) — never leaked to a resolver.
  if (isOnionHost(host)) return NAMESPACE.TOR

  // .eth -> ENS. No fallback into HNS or ICANN if ENS has no record (L2).
  if (isEthName(host)) return NAMESPACE.ENS

  // A name the network reserves (RFC 6761/6762/7686/8375 and the home-network
  // labels, src/hns/reserved-names.cjs) is the user's own device, never a
  // Handshake lookup. `.onion` is in that list too, which is why the Tor test
  // above runs first.
  if (isReservedHost(host)) return NAMESPACE.WEB

  // An IP literal BEFORE the label count: an IPv6 literal has no dots and
  // would otherwise fall to the bare-label rule and become a Handshake name.
  if (isIpLiteral(host)) return NAMESPACE.WEB

  const labels = host.split('.').filter(Boolean)
  if (labels.length < 2) return null // single label: caller decides HNS vs search (isBareNumberOff)

  const tld = asciiTld(host)
  // ICANN has no all-numeric TLDs; a numeric final label (14898) is Handshake
  // — when numeric names are on. Off, it is what the URL parser will make of
  // it anyway: an address, which is to say not a name.
  if (NUMERIC_LABEL.test(tld)) return numericNames ? NAMESPACE.HNS : NAMESPACE.WEB
  return tlds.has(tld) ? NAMESPACE.ICANN : NAMESPACE.HNS
}

module.exports = {
  NAMESPACE,
  ONION_V3,
  ICANN_TLDS,
  NEVER_HNS_TLDS,
  isOnionHost,
  isEthName,
  isIpLiteral,
  isReservedHost,
  bareHost,
  asciiTld,
  classifyHost,
  setNumericNames,
  numericNamesEnabled,
  isBareNumberOff
}
