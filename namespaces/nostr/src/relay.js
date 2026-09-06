// Minimal NIP-01 relay client.
//
// NO WEBSOCKET DEPENDENCY. Electron 38 ships Node 22, where `WebSocket` is a
// global. `ws` exists in node_modules but only as somebody else's transitive
// dependency, and taking one we do not declare breaks the day that tree
// reshuffles. If the global is ever missing we say so plainly rather than
// silently resolving nothing.
//
// A relay is a TRANSPORT here, never an authority: every event it returns is
// signature-checked by the caller, so a hostile relay's options are limited to
// omission and delay. That is why querying several in parallel and taking the
// union is safe — a relay cannot poison the result, only fail to contribute.

import { verifyEvent } from './event.js'
import { isPublicAddress } from '../../../src/safe-address.js'

/** Relays queried when an identifier carries no hints of its own. */
export const DEFAULT_RELAYS = [
  'wss://social.hns.one',
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.nostr.band'
]

/**
 * Does this event actually answer the filter it arrived for? NIP-01 says a
 * relay SHOULD return matching events; nothing makes it. A signature check
 * cannot do this job — an event by a different author is validly signed BY
 * THAT AUTHOR, so it passes verification while answering nobody's question.
 * Without this, a relay answering `{ids:[X]}` with event Y has Y rendered as
 * X, and one answering `{authors:[A]}` with B's notes lists them under A.
 * @param {object} ev a verified event
 * @param {object} filter the NIP-01 filter it was returned for
 */
export function matchesFilter (ev, filter) {
  if (!ev || !filter) return false
  if (Array.isArray(filter.ids) && !filter.ids.includes(ev.id)) return false
  if (Array.isArray(filter.authors) && !filter.authors.includes(ev.pubkey)) return false
  if (Array.isArray(filter.kinds) && !filter.kinds.includes(ev.kind)) return false
  for (const [key, want] of Object.entries(filter)) {
    if (key[0] !== '#' || !Array.isArray(want)) continue
    const name = key.slice(1)
    const have = (Array.isArray(ev.tags) ? ev.tags : [])
      .filter((t) => Array.isArray(t) && t[0] === name).map((t) => t[1])
    if (!want.some((v) => have.includes(v))) return false
  }
  if (Number.isFinite(filter.since) && ev.created_at < filter.since) return false
  if (Number.isFinite(filter.until) && ev.created_at > filter.until) return false
  return true
}

/**
 * May this relay URL be dialled? Relay hints arrive inside identifiers — the
 * TLV bytes of a link somebody else wrote — so they are attacker-chosen. Only
 * `wss://` (never plaintext), never a loopback, private or link-local
 * address, never a reserved name, never an onion (a WebSocket to a `.onion`
 * outside the Tor proxy would put the name in a DNS query).
 * @param {unknown} raw
 * @returns {boolean}
 */
export function isSafeRelayUrl (raw) {
  let u
  try { u = new URL(String(raw)) } catch { return false }
  if (u.protocol !== 'wss:') return false
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '')
  if (!host) return false
  if (host === 'localhost' || /\.(localhost|local|internal|lan|home|onion|arpa)$/.test(host)) return false
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':')) return isPublicAddress(host)
  return true
}

/**
 * One spelling per relay, so `wss://nos.lol` and `wss://nos.lol/` are one
 * socket rather than two and the relay report counts them once (the same
 * canonicalisation nostr-tools applies). A URL that will not parse is
 * returned as it came, for the caller's safety check to refuse.
 * @param {string} raw
 */
export function normalizeRelayUrl (raw) {
  try {
    const u = new URL(String(raw).trim())
    u.hostname = u.hostname.toLowerCase()
    if (u.pathname === '/') u.pathname = ''
    u.hash = ''
    return u.href.replace(/\/$/, '')
  } catch {
    return String(raw)
  }
}

/**
 * Query one relay and return the VERIFIED events matching a filter.
 * Never throws and never rejects: a dead relay is a normal condition, and one
 * bad relay must not take down a query fanned out across several.
 */
export function queryRelay (url, filter, { timeout = 6000, limit = 50, WebSocketImpl } = {}) {
  const WS = WebSocketImpl || globalThis.WebSocket
  return new Promise((resolve) => {
    if (typeof WS !== 'function') {
      resolve({ url, events: [], error: 'no WebSocket implementation available in this runtime' })
      return
    }
    /** @type {any[]} */
    const events = []
    const rejected = []
    let socket
    let done = false

    const finish = (error) => {
      if (done) return
      done = true
      clearTimeout(timer)
      try { socket && socket.close() } catch { /* already gone */ }
      resolve({ url, events, rejected, ...(error ? { error } : {}) })
    }

    const timer = setTimeout(() => finish('timed out'), timeout)

    try {
      socket = new WS(url)
    } catch (err) {
      finish(`could not open: ${err.message}`)
      return
    }

    const subId = 'wr' + Math.random().toString(36).slice(2, 10)

    socket.onopen = () => {
      try {
        socket.send(JSON.stringify(['REQ', subId, { ...filter, limit }]))
      } catch (err) {
        finish(`send failed: ${err.message}`)
      }
    }

    socket.onmessage = (msg) => {
      // Once this query is finished, nothing the relay says can change the
      // result — and processing it anyway is not merely wasteful, it is a
      // LIVELOCK: the EOSE branch below answers with CLOSE, so a relay that
      // replies to our CLOSE gets answered again, and again, forever. That is
      // a hostile relay's cheapest denial-of-service and it cost a hung test
      // process to find.
      if (done) return
      let frame
      try {
        frame = JSON.parse(typeof msg.data === 'string' ? msg.data : String(msg.data))
      } catch {
        return // a relay that speaks nonsense is simply ignored
      }
      if (!Array.isArray(frame)) return
      const [kind, id, payload] = frame
      if (kind === 'EVENT' && id === subId) {
        // The whole security model in four lines: nothing a relay sends is
        // shown to anyone until its signature has been checked here — AND it
        // must be an answer to the question asked. "This relay answered a
        // different question" is reported, not dropped: it is the most
        // useful thing the relay report can say about a relay.
        const check = verifyEvent(payload)
        if (!check.ok) {
          rejected.push({ id: payload && payload.id, reason: check.reason })
        } else if (!matchesFilter(payload, filter)) {
          rejected.push({ id: payload.id, reason: 'does not match the filter it was returned for' })
        } else {
          events.push(payload)
        }
        if (events.length >= limit) finish()
      } else if ((kind === 'EOSE' && id === subId) || (kind === 'CLOSED' && id === subId)) {
        try { socket.send(JSON.stringify(['CLOSE', subId])) } catch { /* closing anyway */ }
        finish()
      } else if (kind === 'NOTICE') {
        // Relay chatter. Not an error, not displayed.
      }
    }

    socket.onerror = () => finish('connection error')
    socket.onclose = () => finish()
  })
}

/**
 * Fan a filter out across relays and return the union of verified events,
 * newest first, de-duplicated by event id.
 */
export async function queryRelays (relays, filter, opts = {}) {
  const settled = await Promise.all(
    (relays && relays.length ? relays : DEFAULT_RELAYS).map((r) => queryRelay(r, filter, opts))
  )
  /** @type {Map<string, any>} */
  const byId = new Map()
  let verifiedCount = 0
  const rejected = []
  for (const result of settled) {
    for (const ev of result.events) {
      verifiedCount++
      if (!byId.has(ev.id)) byId.set(ev.id, ev)
    }
    for (const r of result.rejected || []) rejected.push({ ...r, relay: result.url })
  }
  const events = [...byId.values()].sort((a, b) => b.created_at - a.created_at)
  return {
    events,
    rejected,
    relaysQueried: settled.map(({ url, error, events: e }) => ({
      url, ok: !error, count: e.length, ...(error ? { error } : {})
    })),
    verifiedCount
  }
}
