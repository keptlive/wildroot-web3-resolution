// Names the network reserves, which are therefore never Handshake names —
// whatever the ICANN list says.
//
// RFC 6761 / RFC 6762 / RFC 7686 / RFC 8375 special-use names, plus the
// labels home networks actually use. The classifier calls anything outside
// the bundled ICANN snapshot a Handshake name, so without this carve-out
// `nas.local`, `printer.lan`, `gitlab.internal` and `app.localhost` would all
// become Handshake lookups — which breaks reaching your own devices AND sends
// their names to a Handshake resolver, where whoever registers the TLD
// `local` receives queries for your internal machines and can answer them.
//
// ONE LIST, THREE CONSUMERS. The router's classifier (src/protocols/router.js)
// for typed input and link rewriting, the omnibox (src/ui/omni-box.js, which
// is CommonJS and cannot import the router) for its suggestion rows, and the
// WebSocket PAC script (src/hns/ws-proxy-pac.js, which embeds it) — the same
// arrangement icann-tlds.cjs has, and for the same reason: a list kept in two
// places is a list that disagrees with itself.

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
function isReservedHost (rawHost) {
  const host = String(rawHost || '').toLowerCase().replace(/\.$/, '')
  if (!host) return false
  const last = host.slice(host.lastIndexOf('.') + 1)
  return NEVER_HNS_TLDS.has(host) || NEVER_HNS_TLDS.has(last)
}

module.exports = { NEVER_HNS_TLDS, isReservedHost }
