// A Handshake name as a URL host — and the one case where the two differ.
//
// `hns://` is a STANDARD scheme (src/main.cjs), so Chromium parses its host
// with the URL Standard's rules, and one of those is that a host whose LAST
// label is all digits is an IPv4 address. `hns://14898/` canonicalises to
// `hns://0.0.58.50/`, and `hns://hello.14898/` — every name under our own
// free TLD — is simply an invalid URL: not navigable, not linkable, not
// typeable. The comment in main.cjs said the dotted form was unaffected; it
// was not (found 2026-09-05 by the release smoke, which could not open
// hello.14898 in the installed build).
//
// So in a URL a numeric TLD label carries a leading underscore:
//
//   hello.14898   <->   hns://hello._14898/
//   14898         <->   hns://_14898/
//
// `_` is the right marker because a Handshake name can never contain one
// (names are [a-z0-9-]), so the decoding is unambiguous and can never collide
// with a real name — and Chromium accepts it in a host (`_` is not a forbidden
// host code point; `_dmarc.example.com` is a host every browser has parsed).
// A non-numeric TLD is written exactly as it is; this touches nothing else.
//
// CommonJS, because the omnibox (src/ui/omni-box.js) is CommonJS and must
// build the same URL the router does; ESM callers import it as a named export.

const NUMERIC = /^\d+$/
const MARKED = /^_\d+$/

/** The URL-host form of a Handshake name: a numeric TLD gains its `_`. */
function encodeHnsHost (name) {
  const raw = String(name || '')
  if (!raw) return raw
  const m = /^([^:]*)(:\d+)?$/.exec(raw)
  const host = m ? m[1] : raw
  const port = m && m[2] ? m[2] : ''
  const labels = host.split('.')
  // The last NON-EMPTY label: `hello.14898.` (a trailing dot) is still a
  // numeric TLD to the URL Standard's "ends in a number" check, which strips
  // one empty trailing label first — and an unmarked one made the URL throw.
  let last = labels.length - 1
  if (last > 0 && labels[last] === '') last--
  if (NUMERIC.test(labels[last])) labels[last] = `_${labels[last]}`
  return labels.join('.') + port
}

/** The Handshake name a URL host names: the `_` comes off a numeric TLD. */
function decodeHnsHost (host) {
  const raw = String(host || '')
  if (!raw) return raw
  const m = /^([^:]*)(:\d+)?$/.exec(raw)
  const h = m ? m[1] : raw
  const port = m && m[2] ? m[2] : ''
  const labels = h.split('.')
  let last = labels.length - 1
  if (last > 0 && labels[last] === '') last-- // a trailing dot, as in encodeHnsHost
  if (MARKED.test(labels[last])) labels[last] = labels[last].slice(1)
  return labels.join('.') + port
}

/** Is this URL host the encoded form of a numeric TLD? */
function isEncodedNumericTld (host) {
  const labels = String(host || '').split(':')[0].split('.')
  let last = labels.length - 1
  if (last > 0 && labels[last] === '') last--
  return MARKED.test(labels[last] || '')
}

/**
 * An hns:// URL as a person should read it: the `_` gone from the host. For
 * the address bar and anywhere a URL is shown rather than navigated. Every
 * other URL comes back untouched.
 */
function displayHnsUrl (url) {
  const s = String(url || '')
  const m = /^(hns:\/\/)([^/?#]+)(.*)$/i.exec(s)
  if (!m || !isEncodedNumericTld(m[2])) return s
  return m[1] + decodeHnsHost(m[2]) + m[3]
}

/**
 * A link somebody else wrote as `hns://hello.14898/…` — the plain form, which
 * Chromium refuses as a URL before any handler sees it — rewritten to the form
 * it will navigate. Null for every other href, so a click handler can leave
 * everything else exactly alone. Case-insensitive on the scheme, tolerant of
 * surrounding whitespace, never touches a host that is already encoded.
 */
function fixHnsHref (href) {
  const m = /^hns:\/\/([^/?#]+)([/?#].*)?$/i.exec(String(href || '').trim())
  if (!m) return null
  const host = m[1]
  const encoded = encodeHnsHost(host)
  if (encoded === host) return null
  return `hns://${encoded}${m[2] || '/'}`
}

module.exports = { encodeHnsHost, decodeHnsHost, isEncodedNumericTld, displayHnsUrl, fixHnsHref }
