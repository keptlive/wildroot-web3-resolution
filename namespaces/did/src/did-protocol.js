/* global Response */

/*
 * did: — a DID document for a did:plc or did:web identifier.
 *
 * WHAT IS AND IS NOT VERIFIED. The document is FETCHED — from the PLC
 * directory for did:plc, from the domain the identifier names for did:web —
 * and checked to be ABOUT the identifier asked for (its `id` must match).
 * That is the strongest cheap check DID resolution has, and it is the only
 * one made: the did:plc operation log is not audited, and did:web rests on
 * WebPKI. So the trust panel calls a did: page TRUSTED, never green
 * (src/hns/trust-path.js), and the scheme table's row says the same.
 *
 * THE HOST IS A STRANGER'S CHOICE. A did:web names any host on the internet
 * and a link to one is written by whoever wants this browser to fetch it, so
 * the fetch is held to the same rules as any other stranger-directed request
 * in this tree: HTTPS only, a public host (no loopback, private or reserved
 * name, no IP literal that is not public), no redirects, a deadline. The
 * transport is injected so it can ride the proxied session fetch and be
 * faked in tests.
 */

import { isPublicAddress } from '../../../src/safe-address.js'
import { isReservedHost } from '../../../src/hns-host.js'
import { safeStatus } from '../../../src/safe-status.js'

const DEFAULT_PLC_DIRECTORY = 'https://plc.directory'
const FETCH_TIMEOUT_MS = 10000

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

/**
 * did:web method-specific-id -> the DID document URL (did:web §3.2, the
 * read algorithm, in its order):
 *   1. `:` separators become `/` — BEFORE any percent-decoding, or a port's
 *      `%3A` would be turned into one of them;
 *   2. the port, percent-encoded in the identifier, is decoded (RFC 3986 §2.1:
 *      the encoding is case-insensitive);
 *   3. `.well-known` is appended ONLY when there is no path;
 *   4. then `did.json`.
 * Checked against the method specification's published examples in
 * tests/hns/did-protocol.test.js.
 * @param {string} methodSpecificId
 * @returns {string}
 */
export function didWebUrl (methodSpecificId) {
  const parts = String(methodSpecificId || '').split(':')
  const host = parts[0].replace(/%3a/gi, ':')
  const path = parts.slice(1).join('/')
  return `https://${host}/${path ? path + '/' : '.well-known/'}did.json`
}

/**
 * May this did:web host be fetched? Not loopback, not a private or reserved
 * name, not a non-public IP literal. A hostname that RESOLVES to a private
 * address is not caught here (that needs a connect-time check); the
 * limitation is recorded in docs/STANDARDS.md beside the ERC-3668 row that
 * shares it.
 * @param {string} host as it appears in the URL (may carry a port)
 */
export function isSafeDidWebHost (host) {
  const bare = String(host || '').toLowerCase().replace(/:\d+$/, '').replace(/^\[|\]$/g, '')
  if (!bare) return false
  if (isReservedHost(bare)) return false
  if (IPV4.test(bare) || bare.includes(':')) return isPublicAddress(bare)
  return true
}

/**
 * Create a handler for did: protocol URLs
 * Resolves AT Protocol DIDs (did:plc and did:web) to their DID Documents
 * @param {object} options
 * @param {string} [options.plcDirectory] - URL of the PLC directory service
 * @param {Function} [options.fetchImpl] - the transport; the proxied session
 *        fetch in the browser, a fake in tests. Defaults to the global fetch,
 *        which is NOT proxied.
 */
export default async function createHandler (options = {}) {
  const plcDirectory = options.plcDirectory || DEFAULT_PLC_DIRECTORY
  const fetchImpl = options.fetchImpl || ((...args) => globalThis.fetch(...args))

  return function didHandler (/** @type {{ url: string }} */ req) {
    return resolve(req.url)
  }

  /** @param {string} url */
  async function resolve (url) {
    try {
      // did: URLs look like did:plc:abc123 or did:web:example.com
      // Electron may give us did:// format, normalize it
      const did = url.startsWith('did://') ? url.replace('did://', 'did:') : url

      const parts = did.split(':')
      if (parts.length < 3 || parts[0] !== 'did' || parts.some((p) => !p)) {
        return sendError(400, `Invalid DID format: ${did}`)
      }

      const method = parts[1]

      /** @type {string} */
      let resolveURL

      if (method === 'plc') {
        // did:plc identifiers resolve via plc.directory
        resolveURL = `${plcDirectory}/${did}`
      } else if (method === 'web') {
        // did:web identifiers resolve over HTTPS from the host they name.
        resolveURL = didWebUrl(parts.slice(2).join(':'))
        let host
        try { host = new URL(resolveURL).host } catch { host = '' }
        if (!host || !isSafeDidWebHost(host)) {
          return sendError(400, `Refusing to fetch ${did}: its host is not a public web host`)
        }
      } else {
        return sendError(400, `Unsupported DID method: ${method}. Supported methods: plc, web`)
      }

      const response = await fetchImpl(resolveURL, {
        method: 'GET',
        headers: { accept: 'application/did+json, application/json' },
        // A redirect would send the fetch somewhere the identifier did not
        // name; a document that is not where the DID says it is, is not that
        // DID's document.
        redirect: 'error',
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS)
      })

      if (!response.ok) {
        return sendError(
          safeStatus(response.status),
          `Failed to resolve DID: ${did}\nHTTP ${response.status} from ${resolveURL}`
        )
      }

      const json = await response.json()

      // The one check that is always possible: the document must be ABOUT the
      // identifier asked for. A directory or host answering with somebody
      // else's document is a wrong answer, not a resolution.
      if (!json || typeof json !== 'object' || json.id !== did) {
        return sendError(502,
          `DID document mismatch: asked for ${did}, ${resolveURL} answered a document for ${json && json.id ? json.id : '(no id)'}`)
      }

      return new Response(JSON.stringify(json), {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Resolution-Namespace': 'did',
          'Access-Control-Allow-Origin': '*',
          'Allow-CSP-From': '*',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Allow-Methods': '*'
        }
      })
    } catch (/** @type {any} */ e) {
      // The message, never the stack: a stack carries this installation's
      // paths, to whoever caused the navigation.
      return sendError(502, `Error resolving DID: ${e && e.message ? e.message : e}`)
    }
  }

  /** @param {number} status @param {string} message */
  function sendError (status, message) {
    return new Response(message, {
      status,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'X-Resolution-Namespace': 'did'
      }
    })
  }
}
