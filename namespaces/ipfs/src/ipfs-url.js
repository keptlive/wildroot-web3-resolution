// The root CID an `ipfs://` URL names.
//
// Lifted out of the Wildroot browser's `src/sia/restore.js`, where it sits
// because the storage restore hook is its only caller. It is pure address
// parsing — `ipfs://<cid>[/path]` → `<cid>` — so it belongs to resolution, not
// to the restore, and it is the one place in the tree that turns a URL in the
// IPFS namespace back into a content address.
//
// The function body is byte-identical to the Wildroot tree; only the import
// path changes (`../publish/pointers.js` → the extracted `../../../src/pointers.js`).

import { CID_RE } from '../../../src/pointers.js'

/**
 * The root CID an `ipfs://` URL asks for, or null for anything else — the
 * only URLs a restore can help. Pure, for the protocol handler.
 * @param {string} url
 */
export function rootCidOf (url) {
  let u
  try { u = new URL(String(url)) } catch { return null }
  if (u.protocol !== 'ipfs:') return null
  const host = u.hostname
  // THE SHARED CID SHAPE, not a fourth copy. This used to carry a hand-rolled
  // one that had already drifted from the real shape three ways: no upper
  // bound, so 200 characters of junk passed; digits base32 never uses accepted;
  // and no multibase prefix required. publish-pointers.test.js guards
  // resolver.js and doh.js against exactly this and did not reach here — it
  // does now.
  //
  // `ipfs:` is a non-special scheme, so URL parsing preserves case and the
  // CIDv0 `Qm…` branch of the shared regex still matches — checked, because a
  // lowercasing hostname would have made this a silent regression for v0.
  //
  // EXTRACTOR'S NOTE, and it is a real caveat rather than a nit: that last
  // paragraph is true of the URL parser *this function runs in* (Node's, and
  // any WHATWG parser that has never heard of `ipfs:`). It is NOT true of the
  // browser that hosts it. Wildroot registers `ipfs:`, `ipns:`, `ipld:` and
  // `pubsub:` as **standard** schemes, and a standard scheme's host is
  // canonicalised — lowercased — by Chromium before a handler ever sees it.
  // See ../../DEVIATIONS.md IP-5.
  return CID_RE.test(host) ? host : null
}
