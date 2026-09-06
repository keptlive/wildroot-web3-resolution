// nostr:// — NIP-21 addresses, resolved and VERIFIED locally.
//
// Trust story, and why the lock stays open. Every event rendered here has had
// its id recomputed from its own contents and its schnorr signature checked
// against the author's pubkey, in this process (src/protocols/nostr/event.js).
// So the AUTHORSHIP of what you see is cryptographically established, and a
// relay cannot alter or forge a note.
//
// What is NOT established is completeness or currency: relays can withhold, a
// profile may have been updated somewhere we did not ask, and we cannot prove
// we were shown everything. That is a real gap, it is not one a padlock should
// paper over, and it is why this ships with the lock OPEN and the page saying
// exactly which relays answered. See docs/Protocols.md, "Decided direction".

/* global Response */

import { parseNostrURI } from './nip19.js'
import { queryRelays, DEFAULT_RELAYS, isSafeRelayUrl, normalizeRelayUrl } from './relay.js'

/**
 * The most relay hints one identifier may add. The hints are the link
 * author's choice, so they are bounded like anything else a stranger chooses.
 */
export const MAX_RELAY_HINTS = 4

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
))

/** Content is untrusted text from a stranger: escape, then linkify. */
function renderContent (text) {
  return esc(text)
    .replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1">$1</a>')
    .replace(/\b(nostr:(?:npub|note|nevent|nprofile|naddr)1[02-9ac-hj-np-z]+)/gi, '<a href="$1">$1</a>')
    .replace(/\n/g, '<br>')
}

const when = (ts) => new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC'

/**
 * @param {object} [options]
 * @param {string[]} [options.relays] the relays queried besides any hints
 * @param {number} [options.timeout] per-relay deadline, ms
 * @param {Function} [options.WebSocketImpl] the WebSocket class (tests)
 */
export default async function createHandler (options = {}) {
  const relays = options.relays || DEFAULT_RELAYS
  const timeout = options.timeout || 6000
  const WebSocketImpl = options.WebSocketImpl

  return async function nostrHandler (request) {
    try {
      const target = parseNostrURI(request.url)
      if (target.error) return page(400, 'Not a nostr address', `<p class="err">${esc(target.error)}</p>`)

      // Relay hints are the LINK AUTHOR's choice — TLV bytes in the
      // identifier — so they are checked before anything is dialled (wss
      // only, no private or reserved host) and bounded. A refused hint is
      // reported on the page: silently dropped, it would look like a relay
      // that had nothing.
      const refused = []
      const accepted = []
      for (const raw of target.relays || []) {
        const url = normalizeRelayUrl(raw)
        if (!isSafeRelayUrl(url)) refused.push({ url: String(raw), reason: 'refused: not a public wss:// relay' })
        else if (accepted.length >= MAX_RELAY_HINTS) refused.push({ url: String(raw), reason: `refused: more than ${MAX_RELAY_HINTS} relay hints` })
        else if (!accepted.includes(url)) accepted.push(url)
      }
      const hinted = [...new Set([...accepted, ...relays.map(normalizeRelayUrl)])]
      const opts = { timeout, WebSocketImpl, refused }

      if (target.type === 'npub' || target.type === 'nprofile') {
        return await renderProfile(target, hinted, opts)
      }
      if (target.type === 'note' || target.type === 'nevent') {
        return await renderNote(target, hinted, opts)
      }
      if (target.type === 'naddr') {
        return await renderAddressable(target, hinted, opts)
      }
      return page(501, 'Unsupported nostr address', `<p class="err">${esc(target.type)} is not handled yet.</p>`)
    } catch (err) {
      return page(502, 'nostr lookup failed', `<p class="err">${esc(err.message)}</p>`)
    }
  }
}

/** Was any relay reached at all? "Nothing found" may only be said if so. */
const anyRelayAnswered = (...results) => results.some((r) => r.relaysQueried.some((q) => q.ok))

/** 404 when at least one relay answered and had nothing; 502 when none was reached. */
function notFound (title, body, ...results) {
  if (anyRelayAnswered(...results)) return page(404, title, body)
  return page(502, 'No relay could be reached',
    '<p class="err">No relay answered, so nothing is known about this address — it was not found to be absent.</p>' + body)
}

async function renderProfile (target, relays, opts) {
  const pubkey = target.pubkey
  const [meta, notes] = await Promise.all([
    queryRelays(relays, { kinds: [0], authors: [pubkey] }, { ...opts, limit: 5 }),
    queryRelays(relays, { kinds: [1], authors: [pubkey] }, { ...opts, limit: 20 })
  ])
  let profile = {}
  if (meta.events[0]) {
    try { profile = JSON.parse(meta.events[0].content) } catch { profile = {} }
  }
  const name = profile.display_name || profile.name || 'Unnamed profile'
  // A `nip05` field is a CLAIM the key makes about a handle. NIP-05 says a
  // client that shows it should verify it; this page does not look it up, so
  // it is shown as a claim, never as a fact.
  const body = `
    <header class="profile">
      <h1>${esc(name)}</h1>
      ${profile.nip05 ? `<p class="nip05">claims <code>${esc(profile.nip05)}</code> <span class="dim">(not verified — the handle was not looked up)</span></p>` : ''}
      ${profile.about ? `<p class="about">${renderContent(profile.about)}</p>` : ''}
      <p class="key"><code>${esc(pubkey)}</code></p>
    </header>
    <h2>${notes.events.length} verified note${notes.events.length === 1 ? '' : 's'}</h2>
    ${notes.events.map((ev) => noteCard(ev, pubkey)).join('') || '<p class="empty">No notes returned by the relays that answered.</p>'}
    ${relayReport(notes, opts.refused)}`
  if (meta.events.length || notes.events.length) return page(200, name, body, pubkey)
  return notFound(name, body, meta, notes)
}

async function renderNote (target, relays, opts) {
  // An nevent may carry the author and kind: both become part of the question,
  // so an answer that is not that author's, or not that kind, is not an answer.
  const filter = {
    ids: [target.id],
    ...(target.author ? { authors: [target.author] } : {}),
    ...(Number.isInteger(target.kind) ? { kinds: [target.kind] } : {})
  }
  const res = await queryRelays(relays, filter, { ...opts, limit: 1 })
  const ev = res.events[0]
  if (!ev) {
    return notFound('Note not found', `
      <p class="err">No relay that answered had this event, or none that did could produce a
      valid signature for it.</p>
      <p class="key"><code>${esc(target.id)}</code></p>
      ${relayReport(res, opts.refused)}`, res)
  }
  return page(200, 'Note', noteCard(ev) + relayReport(res, opts.refused), ev.pubkey)
}

async function renderAddressable (target, relays, opts) {
  const res = await queryRelays(relays, {
    kinds: [target.kind],
    authors: [target.pubkey],
    '#d': [target.identifier]
  }, { ...opts, limit: 1 })
  const ev = res.events[0]
  if (!ev) return notFound('Not found', `<p class="err">No relay returned a verified event for this address.</p>${relayReport(res, opts.refused)}`, res)
  return page(200, target.identifier || 'Article', noteCard(ev, target.pubkey) + relayReport(res, opts.refused), ev.pubkey)
}

/**
 * One event. The AUTHOR is always shown — a card without one gives a careful
 * reader nothing to compare against the key the page is about — and an author
 * other than the page's key is said out loud.
 */
const noteCard = (ev, pagePubkey) => `
  <article class="note">
    <div class="meta">
      <span class="verified" title="id recomputed and schnorr signature checked in this process">✓ signature verified</span>
      <time>${esc(when(ev.created_at))}</time>
    </div>
    <div class="author">by <code title="${esc(ev.pubkey)}">${esc(String(ev.pubkey).slice(0, 16))}…</code>${
      pagePubkey && ev.pubkey !== pagePubkey ? ' <span class="bad">— NOT the key this page is about</span>' : ''}</div>
    <div class="content">${renderContent(ev.content)}</div>
    <div class="ids"><code>${esc(ev.id)}</code></div>
  </article>`

function relayReport (res, refused = []) {
  const rows = res.relaysQueried.map((r) => `
    <li>${r.ok ? '' : '<span class="bad">×</span> '}${esc(r.url)}
      — ${r.ok ? `${r.count} event${r.count === 1 ? '' : 's'}` : esc(r.error)}</li>`).join('')
  const hintRows = refused.map((r) => `
    <li><span class="bad">×</span> ${esc(r.url)} — ${esc(r.reason)}</li>`).join('')
  const dropped = (res.rejected || []).length
  return `
    <details class="relays">
      <summary>Where this came from${dropped ? ` — ${dropped} event${dropped === 1 ? '' : 's'} DISCARDED as unverifiable` : ''}</summary>
      <ul>${rows}${hintRows}</ul>
      ${dropped
        ? `<ul class="dropped">${res.rejected.map((r) => `<li><code>${esc((r.id || '?').slice(0, 16))}</code> from ${esc(r.relay)}: ${esc(r.reason)}</li>`).join('')}</ul>`
        : ''}
      <p class="caveat">Authorship of everything shown above was verified in this
      browser. Completeness was not: relays can withhold events, and there is no
      way to prove you were shown all of them. That is why the padlock is open.</p>
    </details>`
}

function page (status, title, body, pubkey) {
  const html = `<!doctype html><meta charset="utf-8">
<title>${esc(title)}</title>
<meta name="color-scheme" content="light dark">
<style>
  :root { --fg:#111; --dim:#666; --line:#ddd; --bad:#b00; --ok:#0a7; --bg:#fff; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e8e8e8; --dim:#999; --line:#333; --bad:#f66; --ok:#3d9; --bg:#111; }
  }
  body { background:var(--bg); color:var(--fg); font:16px/1.5 system-ui,sans-serif;
         max-width:44rem; margin:2rem auto; padding:0 1rem; }
  h1 { font-size:1.5rem; margin:0 0 .25rem; }
  h2 { font-size:1rem; color:var(--dim); font-weight:600; margin:2rem 0 .5rem; }
  code { font-family:ui-monospace,monospace; font-size:.8em; color:var(--dim); word-break:break-all; }
  .note { border:1px solid var(--line); border-radius:8px; padding:1rem; margin:0 0 1rem; }
  .meta { display:flex; justify-content:space-between; font-size:.8rem; color:var(--dim); margin-bottom:.5rem; }
  .verified { color:var(--ok); }
  .content { white-space:normal; overflow-wrap:break-word; }
  .ids { margin-top:.75rem; }
  .author, .dim { color:var(--dim); font-size:.85rem; }
  .err { color:var(--bad); }
  .bad { color:var(--bad); }
  .empty, .caveat { color:var(--dim); font-size:.9rem; }
  .relays { margin-top:2rem; border-top:1px solid var(--line); padding-top:1rem; font-size:.85rem; color:var(--dim); }
  .relays ul { padding-left:1.2rem; }
  a { color:inherit; }
</style>
${body}`
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      // Honest trust signalling, machine-readable for the lock UI: authorship
      // is proven, completeness is not.
      'X-Nostr-Trust': 'signature-verified; completeness-unverified',
      ...(pubkey ? { 'X-Nostr-Pubkey': pubkey } : {}),
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src https: data:"
    }
  })
}
