/* global Response */

/*
 * gemini:// — Gemini space, reached with the @derhuerst/gemini client.
 *
 * THE REDIRECT RULE, which is why this handler exists instead of a library's
 * fetch wrapper: a Gemini 30/31 redirect is DECIDED here. A redirect to the
 * same host is followed, at most five times (the Gemini specification's own
 * guidance); a redirect anywhere else is handed to the browser as a real
 * 30x navigation, so the address bar and the origin change with it. Followed
 * blindly, a redirect would return host B's bytes under `gemini://A`'s origin
 * — and `gemini:` is a standard, secure scheme with persistent storage.
 *
 * WHAT IS NOT VERIFIED. The connection is TLS with certificate verification
 * off (`rejectUnauthorized: false`) and no certificate store: nothing is
 * pinned on first use, nothing is compared on the next visit. Encrypted, and
 * that is all; the scheme table and the trust panel say so.
 */

import { Readable } from 'node:stream'
import fetchToHandler from './fetch-to-handler.js'
import { safeStatus } from '../../../src/safe-status.js'
import { socksDialer } from '../../../src/socks-dial.js'
import { privateRefusal } from '../../../src/delivery-mode.js'

const GEMINI_PORT = 1965

/** Same-host redirects followed inside one request (Gemini spec §3.2.2 guidance). */
export const MAX_REDIRECTS = 5

const MIME_TEXT_HTML = 'text/html; charset=utf-8'
const INPUT_FIELD = 'input'

/**
 * May the client follow this redirect on its own? Only to the same host and
 * port, only over gemini:, only a bounded number of times. Anything else
 * returns to the caller as the redirect it is.
 * @param {string} from the URL being fetched
 * @param {string} meta the redirect target from the response
 */
export function sameHostGeminiRedirect (from, meta) {
  let a, b
  try { a = new URL(from); b = new URL(String(meta), from) } catch { return false }
  return b.protocol === 'gemini:' && b.hostname.toLowerCase() === a.hostname.toLowerCase() && (b.port || '1965') === (a.port || '1965')
}

/**
 * @param {object} [options]
 * @param {Function} [options.requestImpl] the client (tests inject one);
 *        defaults to @derhuerst/gemini's, imported lazily.
 * @param {() => boolean} [options.isAnonymized] IP Protection on?
 * @param {() => (string|null)} [options.torSocks] the device-local Tor's
 *        `socks5://…` while protection is on. With it, the TLS connection is
 *        made over a socket dialled THROUGH Tor (the capsule sees the exit,
 *        and the OS resolver never sees the host — Tor resolves the name);
 *        without it, an anonymized request is refused rather than leaked.
 */
export default async function createHandler (options = {}) {
  const isAnonymized = typeof options.isAnonymized === 'function' ? options.isAnonymized : () => false
  const torSocks = typeof options.torSocks === 'function' ? options.torSocks : () => null
  return fetchToHandler(async () => {
    const request = options.requestImpl || (await import('@derhuerst/gemini/client.js')).default

    const send = async (url) => {
      const tlsOpt = { rejectUnauthorized: false }
      if (isAnonymized()) {
        const socks = torSocks()
        const u = new URL(url)
        // Private mode with no Tor to hand: refused in the same words as every
        // other refusal (src/hns/delivery-mode.js) — the mode, nothing sent,
        // the switch.
        if (!socks) {
          const copy = privateRefusal('site', { host: u.hostname })
          throw Object.assign(new Error(`${copy.title}. ${copy.detail}`), { status: 503 })
        }
        // The socket is dialled through Tor by NAME, so the OS resolver is
        // never asked; TLS then runs over it with the hostname for SNI.
        tlsOpt.socket = await socksDialer(socks)(u.hostname, Number(u.port) || GEMINI_PORT)
        tlsOpt.servername = u.hostname
      }
      return new Promise((resolve, reject) => {
        request(url, {
          followRedirects: (n, res) => n <= MAX_REDIRECTS && sameHostGeminiRedirect(url, res.meta),
          verifyAlpnId: () => true,
          tlsOpt
        }, (err, res) => (err ? reject(err) : resolve(res)))
      })
    }

    return async function geminiFetch (req) {
      const url = String(req.url)
      const method = String(req.method || 'GET').toUpperCase()

      if (method === 'POST') {
        // The input form below submits here: the answer goes into the query
        // string of the same URL, which is how Gemini carries input.
        const formData = await req.formData()
        const input = formData.get(INPUT_FIELD)
        if (!input) throw new Error(`Expected ${INPUT_FIELD} field in form submission`)
        const location = new URL(url)
        location.search = String(input)
        return new Response('', { status: 302, headers: { Location: location.href } })
      }
      if (method !== 'GET' && method !== 'HEAD') {
        return new Response('Method Not Allowed', { status: 405, headers: { 'Content-Type': 'text/plain' } })
      }

      let res
      try {
        res = await send(url)
      } catch (err) {
        if (err && err.status === 503) {
          return new Response(err.message, { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } })
        }
        throw err
      }
      const { statusCode, statusMessage: statusText, meta } = res

      if (statusCode === 11) return form(meta, 'password')
      if (statusCode >= 10 && statusCode < 20) return form(meta)

      if (statusCode === 30 || statusCode === 31) {
        // Not followed above, so it is off this host: a real navigation.
        let target
        try { target = new URL(String(meta), url).href } catch { target = '' }
        if (!target.startsWith('gemini:')) {
          return new Response(`This Gemini site redirected to ${meta}, which is not a gemini:// address. It was not followed.`,
            { status: 502, headers: { 'Content-Type': 'text/plain; charset=utf-8' } })
        }
        return new Response('', { status: statusCode === 31 ? 301 : 302, headers: { Location: target } })
      }

      const isOK = statusCode >= 20 && statusCode < 30
      return new Response(
        isOK ? (typeof res.pipe === 'function' ? Readable.toWeb(res) : res) : String(meta || ''),
        {
          status: safeStatus(statusCode * 10),
          statusText,
          headers: isOK ? { 'Content-Type': meta } : { 'Content-Type': 'text/plain; charset=utf-8' }
        })
    }
  })
}

function form (prompt, type = 'text') {
  const safe = String(prompt || '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
  const body = `<!DOCTYPE html>
<title>${safe}</title>
<form method="post" enctype="application/x-www-form-urlencoded">
  <h1>${safe}</h1>
  <input autofocus name="${INPUT_FIELD}" type="${type}">
  <input type="submit">
</form>
`
  return new Response(body, { status: 200, headers: { 'Content-Type': MIME_TEXT_HTML } })
}
