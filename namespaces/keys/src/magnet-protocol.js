/* global Response */
// The ONE place the two BitTorrent key shapes are defined (docs/TORRENT-DESIGN.md
// §2.1): 40 hex = infohash (rqbit), 64 hex = ed25519 pubkey / BEP-46 (bt-fetch).
// torrent-protocol.js imports these for its dispatch — do not fork them.
// Deliberately NOT /g: a sticky lastIndex on a module-level regex made every
// second .exec() of the same shape silently miss.
export const INFO_HASH_MATCH = /^urn:btih:([a-f0-9]{40})$/i
export const PUBLIC_KEY_MATCH = /^urn:btpk:([a-f0-9]{64})$/i

/**
 * A CLICKED magnet link -> the torrents page, pending confirmation.
 *
 * Every other browser asks before handing a magnet to a torrent client, and
 * until now this one did not: clicking a magnet on any site added the torrent
 * and started peer traffic with no prompt, because the redirect below goes
 * straight to bittorrent://<hash>/ and the protocol handler adds whatever it
 * is asked for. Navigation is therefore rewritten one layer up (src/window.js)
 * to `wildroot://torrents?add=<hash>`, which shows an "Add this torrent?" card
 * and adds NOTHING until the user says so.
 *
 * The display name rides along when the link carries one, so the card can name
 * the torrent before any metadata has been fetched — otherwise the user would
 * be asked to approve a bare 40-hex string.
 *
 * A `xs=urn:btpk:` (BEP-46 mutable) magnet also needs consent, but opens a
 * mutable site through bt-fetch rather than adding a managed torrent. The
 * mutable key wins even when the same magnet also carries an `xt`.
 *
 * @param {unknown} url
 * @returns {string?} the page URL, or null if this magnet is unsupported
 */
export function magnetToTorrentsPage (url) {
  if (typeof url !== 'string' || !/^magnet:/i.test(url)) return null
  let parsed
  try { parsed = new URL(url) } catch { return null }
  const mutable = mutableKey(parsed)
  const match = mutable || infoHash(parsed)
  if (!match) return null
  const name = (parsed.searchParams.get('dn') || '').trim()
  return `wildroot://torrents?${mutable ? 'mutable' : 'add'}=${match[1].toLowerCase()}` +
    (name ? `&dn=${encodeURIComponent(name.slice(0, 200))}` : '')
}

/**
 * The v1 infohash, from WHICHEVER `xt` carries it. A hybrid v1+v2 magnet has
 * two — `urn:btih:` and `urn:btmh:` — in whichever order the publisher wrote
 * them, and reading only the first would refuse a usable magnet by accident.
 */
function infoHash (parsed) {
  for (const xt of parsed.searchParams.getAll('xt')) {
    const m = INFO_HASH_MATCH.exec(xt)
    if (m) return m
  }
  return null
}

/** The BEP-46 mutable key, if any `xs` carries one. */
function mutableKey (parsed) {
  for (const xs of parsed.searchParams.getAll('xs')) {
    const m = PUBLIC_KEY_MATCH.exec(xs)
    if (m) return m
  }
  return null
}

/** Why a magnet with `xt` values but no v1 infohash could not be used. */
function refusalFor (parsed) {
  const xts = parsed.searchParams.getAll('xt')
  if (xts.some((x) => /^urn:btmh:/i.test(x))) {
    return 'This magnet carries only a BitTorrent v2 infohash (urn:btmh), which this browser does not read'
  }
  if (xts.some((x) => /^urn:btih:[a-z2-7]{32}$/i.test(x))) {
    return 'This magnet writes its infohash in the base32 form, which this browser does not read'
  }
  return 'Magnet has no bittorrent infohash'
}

export default async function createHandler () {
  return function magnetHandler (req) {
    try {
      const parsed = new URL(req.url)
      // A redirect or public subresource can reach this handler without the
      // main-frame navigation rewrite. It must still land at inert consent,
      // never a peer-backed bittorrent URL. No network authority is granted
      // merely by asking for a magnet resource.
      const pending = magnetToTorrentsPage(req.url)
      if (pending) return sendFinal(pending)
      if (parsed.searchParams.has('xt')) {
        return sendError(refusalFor(parsed))
      }

      return sendError('Magnet link has no `xt` or `xs` parameter')
    } catch (e) {
      return sendError(String((e && e.message) || e))
    }

    function sendFinal (Location) {
      return new Response('', {
        status: 308,
        headers: {
          Location
        }
      })
    }

    function sendError (message) {
      return new Response(message, {
        status: 400,
        headers: {
          'content-type': 'text/html'
        }
      })
    }
  }
}
