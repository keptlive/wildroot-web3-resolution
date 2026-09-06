// Fail-closed handlers for namespaces we RECOGNISE but do not yet resolve.
//
// WHY THIS EXISTS, and why it is not just a nicety.
//
// The omnibox classifies any host whose TLD is not in the ICANN root into a
// namespace, and some of those namespaces (atproto, activitypub) we can name
// but cannot yet resolve. A namespace we can name but not resolve must fail
// INSIDE ITSELF — visibly, with no lookup in anyone else's address space —
// because the alternative is a cross-namespace hijack that LAW L2 forbids:
// e.g. before `.eth` and `.onion` had real handlers, `vitalik.eth` became
// `hns://vitalik.eth` (traffic meant for ENS handed to whoever owns the
// Handshake TLD "eth"), and `<addr>.onion` left the machine in a DNS query
// (a deanonymising leak for a Tor user). `ens://` and `onion://` now have
// their own real handlers (ens-protocol.js / onion-protocol.js); the schemes
// that remain here are the ones still awaiting verified resolution.
//
// These handlers make no network request of any kind; that is their entire
// security value, and the reason they must stay boring.

const ESCAPE = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }
const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (c) => ESCAPE[c])

/**
 * @param {object} options
 * @param {string} options.scheme     the scheme this handler owns ('ens')
 * @param {string} options.namespace  its namespace ('ens', 'tor')
 * @param {string} options.title      human name ('Ethereum Name Service')
 * @param {string} options.detail     what would be needed to resolve it
 * @param {string} [options.leak]     what we deliberately did NOT do
 */
export function createUnimplementedHandler ({ scheme, namespace, title, detail, leak }) {
  return async function unimplementedHandler (request) {
    // The URL is echoed back so the user can see their input was understood.
    // It is escaped and never resolved, fetched, or logged to the network.
    let shown = ''
    try {
      shown = String((request && request.url) || '')
    } catch { /* a URL we cannot even read is still not a reason to throw */ }

    const body = `<!doctype html>
<html><head><meta charset="utf-8">
<title>${escapeHtml(title)} is not supported yet</title>
<meta name="color-scheme" content="light dark">
<style>
  body { font: 16px/1.6 system-ui, sans-serif; margin: 0; padding: 3rem 1.5rem;
         max-width: 40rem; margin-inline: auto; }
  code { background: color-mix(in srgb, currentColor 10%, transparent);
         padding: .15em .4em; border-radius: 4px; word-break: break-all; }
  .note { border-left: 3px solid currentColor; padding-left: 1rem; opacity: .8; }
</style></head><body>
<h1>${escapeHtml(title)} is not supported yet</h1>
<p>This browser recognised <code>${escapeHtml(shown)}</code> as
a <strong>${escapeHtml(namespace)}</strong> address, but cannot resolve it yet.</p>
<p>${escapeHtml(detail)}</p>
${leak ? `<p class="note">${escapeHtml(leak)}</p>` : ''}
</body></html>`

    return new Response(body, {
      status: 501,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        // The machine-readable proof that this failure stayed in its own
        // namespace — the same header ProtocolRouter.dispatch sets.
        'X-Resolution-Namespace': namespace,
        'Access-Control-Allow-Origin': 'null'
      }
    })
  }
}

/** The namespaces recognised-but-unresolved in this build. */
export const UNIMPLEMENTED = [
  {
    scheme: 'at',
    namespace: 'atproto',
    title: 'atproto',
    detail: 'Resolving it needs the DID document for the repository and a ' +
      'signature check on the record, which this build does not carry.'
  },
  {
    scheme: 'activitypub',
    namespace: 'activitypub',
    title: 'ActivityPub',
    detail: 'Resolving it needs a WebFinger lookup and an actor signature ' +
      'check, which this build does not carry.'
  }
]
