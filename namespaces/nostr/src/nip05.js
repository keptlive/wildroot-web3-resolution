// NIP-05: `<local>@<domain>` -> a 32-byte public key.
//
// ─────────────────────────────────────────────────────────────────────────────
// THIS FILE IS **FACTORED**, NOT COPIED. Every other module in this directory
// is byte-identical to its counterpart in the Wildroot tree. This one is not,
// and a reader must not mistake it for the shipping code.
//
// In Wildroot the NIP-05 path is split across two places, neither of which can
// be lifted out whole:
//
//   * `src/nostr/social-core.js` — `nip05For`, `displayName` and
//     `verificationHost`. Pure functions, but they sit in a module that is
//     mostly the social CLIENT (NIP-18 repost unwrapping, NIP-02 follow-list
//     arithmetic, publish-result summarising, relay health) and that imports a
//     second, vendored copy of the NIP-01 verifier. Copying the file would drag
//     the whole social client across the scope line drawn in SPEC.md §1.1.
//     The three functions below are reproduced from it VERBATIM, comments
//     included, so a diff against `social-core.js` is a two-hunk diff.
//
//   * `src/social.js`, the `case 'verify':` arm of the social IPC switch —
//     the actual `.well-known/nostr.json` fetch. It is a branch of a `switch`
//     inside an Electron IPC handler; there is no function to import.
//     `lookupNip05` below is that branch, lifted into a function, with `fetch`
//     made injectable so it can be tested without a network. The request it
//     makes — same URL shape, same `redirect: 'error'`, same 6-second timeout,
//     same "is `names[local]` equal to this pubkey" comparison — is the same
//     request. The Wildroot code hardcodes the local part `_`; this generalises
//     it, because NIP-05 does not.
//
// Everything this module says about trust is in SPEC.md §7 and DEVIATIONS.md
// D-N5/D-N6: a NIP-05 answer is WebPKI-trusted and server-asserted. Nothing
// about it is cryptographic. It maps a name onto a key on the word of whoever
// controls that domain's TLS certificate and web server, which is the ordinary
// trust model of the web and is strictly weaker than the event verification in
// `event.js`.
// ─────────────────────────────────────────────────────────────────────────────

const HEX32 = /^[0-9a-f]{64}$/

/**
 * `_@alice.wildroot.hns.one` — the ONE address form for a Handshake identity.
 *
 * NIP-05 renders a `_` local part as the bare domain, so this appears in any
 * ordinary client as `alice.wildroot.hns.one`: exactly the string the user
 * typed to claim the name. The `alice.wildroot@hns.one` form also resolves and
 * is deliberately NOT used — it reads as a mailbox at a domain the user does
 * not control, which is name confusion at the precise boundary where identity
 * is being asserted.
 */
export function nip05For (name, base = 'hns.one') {
  return `_@${name}.${base}`
}

/** The bare name a client will display, back out of the NIP-05 form. */
export function displayName (nip05) {
  return String(nip05 || '').replace(/^_@/, '')
}

// A hostname and nothing else: LDH labels, at least two of them, no port, no
// path, no credentials, no percent-escapes, no unicode.
const HOSTNAME = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/

/**
 * The host whose zone must answer for a claimed name — or null.
 *
 * THE INPUT IS HOSTILE. It is the `hns` field of a stranger's `kind:0`,
 * fetched from a public relay, and it is about to be interpolated into a URL
 * this browser then fetches. Left unvalidated it is a server-side request
 * forgery primitive pointed at whatever the user's machine can reach:
 *
 *   "127.0.0.1:8080/x?y="            -> fetches loopback
 *   "169.254.169.254/latest/meta-data/?x=" -> fetches cloud metadata
 *   "evil.example/#"                 -> the fragment truncates the path, so
 *                                       the fetch hits the attacker's root
 *                                       and any JSON there is believed
 *   "evil.example\\.hns.one"          -> a backslash is a path separator to
 *                                       the URL parser, so a string that ENDS
 *                                       in .hns.one resolves to a host that
 *                                       does not
 *
 * Appending a suffix does not save you: every example above already contains
 * the character that ends the host. So this validates the SHAPE first and
 * returns null for anything that is not purely a hostname.
 */
export function verificationHost (claim, base = 'hns.one') {
  const name = String(claim || '').trim().toLowerCase().replace(/\.$/, '')
  if (!name || !HOSTNAME.test(name)) return null
  const host = name.endsWith('.' + base) ? name : `${name}.${base}`
  // Re-check after the suffix: the join must not have produced anything new.
  return HOSTNAME.test(host) ? host : null
}

/**
 * Split a NIP-05 identifier into its local part and its domain.
 *
 * NIP-05 §"Identifier" restricts the local part to `a-z0-9-_.` and says a
 * bare `<domain>` means `_@<domain>`. Anything outside that grammar is
 * refused rather than escaped: the local part goes into a query string and
 * the domain goes into an authority, and neither is a place to be lenient.
 *
 * @returns {{local: string, domain: string} | null}
 */
export function parseNip05 (identifier) {
  const s = String(identifier || '').trim().toLowerCase()
  if (!s) return null
  const at = s.lastIndexOf('@')
  const local = at === -1 ? '_' : s.slice(0, at)
  const domain = at === -1 ? s : s.slice(at + 1)
  if (!/^[a-z0-9\-_.]+$/.test(local)) return null
  if (!HOSTNAME.test(domain)) return null
  return { local, domain }
}

/**
 * Resolve a NIP-05 identifier to a pubkey, and to the relays the domain
 * suggests for it.
 *
 * The two properties that make this safe to point at a stranger's string:
 *
 *   1. **The host is derived here**, from the identifier, and is never
 *      accepted from the caller. `parseNip05`/`verificationHost` refuse
 *      anything that is not purely a hostname, so a port, a path, a fragment
 *      or a backslash cannot steer the fetch somewhere else.
 *   2. **Redirects are refused.** NIP-05 says a client MUST NOT follow
 *      redirects on this request. A redirect would move the answer to a host
 *      other than the one being asserted about, which is the whole assertion.
 *
 * The answer is a CLAIM by the domain, not a proof. See SPEC.md §7.3.
 *
 * @param {string} identifier `alice@example.com`, or a bare `example.com`
 * @param {object} [opts]
 * @param {typeof fetch} [opts.fetchImpl] injected for tests; defaults to the
 *        global `fetch` (Node >= 18, Electron main).
 * @param {number} [opts.timeout] milliseconds
 * @returns {Promise<{ok: true, pubkey: string, relays: string[], local: string,
 *                    domain: string} | {ok: false, reason: string}>}
 */
export async function lookupNip05 (identifier, { fetchImpl, timeout = 6000 } = {}) {
  const parts = parseNip05(identifier)
  if (!parts) return { ok: false, reason: 'not a NIP-05 identifier' }
  const doFetch = fetchImpl || globalThis.fetch
  if (typeof doFetch !== 'function') {
    return { ok: false, reason: 'no fetch implementation available in this runtime' }
  }
  const { local, domain } = parts
  const url = `https://${domain}/.well-known/nostr.json?name=${encodeURIComponent(local)}`
  let res
  try {
    res = await doFetch(url, {
      redirect: 'error', // NIP-05 forbids following redirects here
      signal: AbortSignal.timeout(timeout)
    })
  } catch (err) {
    return { ok: false, reason: String(err && err.message ? err.message : err) }
  }
  if (!res || !res.ok) return { ok: false, reason: `lookup returned ${res ? res.status : 'nothing'}` }
  let doc
  try {
    doc = await res.json()
  } catch {
    return { ok: false, reason: 'the well-known document is not JSON' }
  }
  const pubkey = doc && doc.names && doc.names[local]
  if (!HEX32.test(String(pubkey || ''))) {
    return { ok: false, reason: `no 32-byte key for '${local}' at ${domain}` }
  }
  // `relays` is OPTIONAL in NIP-05 and is a HINT. It is filtered to websocket
  // URLs here because it is about to become a socket somebody else chose.
  const hinted = (doc.relays && doc.relays[pubkey]) || []
  const relays = Array.isArray(hinted)
    ? hinted.filter((r) => typeof r === 'string' && /^wss:\/\//i.test(r))
    : []
  return { ok: true, pubkey, relays, local, domain }
}

/**
 * Does a claimed Handshake name resolve, over NIP-05, to this exact key?
 *
 * This is the Wildroot-specific half: a stranger's `kind:0` carries an `hns`
 * field naming a Handshake name, and that field is a CLAIM until the name's
 * OWN zone agrees. `verificationHost` turns the claim into `<name>.hns.one`
 * (or leaves an already-suffixed one alone) and nothing else is ever fetched.
 *
 * @param {string} claim the `hns` field of somebody's profile
 * @param {string} pubkey the 64-hex key that profile was signed with
 */
export async function verifyHandshakeClaim (claim, pubkey, opts = {}) {
  const host = verificationHost(claim, opts.base)
  if (!HEX32.test(String(pubkey || '')) || !host) {
    return { verified: false, reason: 'not a resolvable name' }
  }
  const found = await lookupNip05(`_@${host}`, opts)
  if (!found.ok) return { verified: false, reason: found.reason }
  return { verified: found.pubkey === pubkey, found: found.pubkey, host }
}
