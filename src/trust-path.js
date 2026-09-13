// The whole verification path for a page, and where every fact came from.
//
// WHY THIS EXISTS. The lock used to be one boolean and one sentence of
// tooltip. That is not enough to be honest with: "chain-verified, DANE
// pinned" hides whether the PIN itself was proven (a TLSA record from an
// unsigned zone is only as good as the DNS hop), and an open lock said
// nothing about which step actually failed. A padlock that cannot explain
// itself is decoration.
//
// So resolution produces a LIST OF STEPS instead. Each step says what was
// checked, what the answer was, and — the part that matters — WHO TOLD US:
//
//   verified    checked cryptographically, here, in this process
//   unverified  taken on someone's word (a resolver, a CA, the network)
//   failed      checked and did not pass
//   none        does not apply, or is absent and known to be absent
//
// This module is pure: URL and resolution facts in, steps out. No I/O, so it
// is unit-testable and cannot itself become a source of surprises.

/** @typedef {{label:string, state:'verified'|'unverified'|'failed'|'none', source:string, detail?:string, applicable?:boolean}} Step */

const step = (label, state, source, detail) => ({ label, state, source, ...(detail ? { detail } : {}) })

/**
 * The path for an hns:// resolution.
 * @param {string} host
 * @param {object} resolution what the resolver returned
 * @param {object} [extra] transport facts known only after connecting
 */
/**
 * The pointer kinds whose bytes authenticate themselves — a CID, an infohash,
 * a signed BEP-46/IPNS record, a hypercore key. For all of them the CONTENT is
 * verified and only the name->content binding depends on the chain, which is
 * why they share one branch and one caveat below.
 *
 * Arweave is NOT in this set. An `ar=` pointer names immutable content, and
 * src/hns/ar.js does check what it can — the transaction header authenticated
 * against the id, and a whole raw body under 8 MiB against the signed data
 * root — but only per fetch, and never for a larger transaction, a Range, a
 * manifest path or a bundled item. This step is written at RESOLUTION time,
 * before any of that is known, so it stays unverified and says which hop is
 * trusted (ARWEAVE_CONTENT below) instead of borrowing the content-addressed
 * sentence. The per-fetch truth is the X-Arweave-Verified response header.
 */
const CONTENT_ADDRESSED = new Set(['ipfs', 'ipns', 'bittorrent', 'hyper'])

const ARWEAVE_CONTENT = 'The transaction id names immutable content. The bytes ' +
  'came from an Arweave gateway; for a top-level transaction under 8 MiB they ' +
  'are checked against the transaction\'s data root (the response header ' +
  'X-Arweave-Verified says "bytes"), otherwise the gateway is trusted the way ' +
  'any HTTPS site is.'

function contentLabel (resolution, id) {
  switch (resolution.kind) {
    case 'ipfs': return `IPFS CID ${id}`
    case 'ipns': return `IPNS name ${id}`
    case 'bittorrent':
      return resolution.mutable
        ? `Torrent, signed by public key ${id}`
        : `Torrent infohash ${id}`
    default: return `Hypercore key ${id}`
  }
}

export function hnsSteps (host, resolution = {}, extra = {}) {
  const steps = []
  const chain = resolution.trust !== 'doh'

  // 1. Name -> records. Either an Urkel proof we verified against the chain
  //    root, or a resolver's word for it.
  if (chain) {
    steps.push(step('Handshake name', 'verified',
      'Local SPV node — Urkel tree proof checked against the chain root',
      `${host} resolved from the chain itself, not from anyone's DNS server.`))
  } else if (resolution.oblivious) {
    // Resolved by asking someone — but obliviously, so no single party saw
    // both who asked and what was asked. Worth saying explicitly: it is the
    // difference between "a resolver knows your browsing" and "nobody does".
    steps.push(step('Handshake name', 'unverified',
      `Oblivious DoH — relay ${resolution.via || '(unnamed)'} → target ${resolution.target || 'odoh.hns.one'}`,
      'The chain proof was unavailable, so this name was resolved by asking a ' +
      'server — but obliviously: the relay saw your address and only ' +
      'ciphertext, the target saw the question and only the relay. Neither ' +
      'alone can link you to this lookup. The ANSWER is still just their word ' +
      'for it, which is what "not verified" means here.'))
  } else {
    steps.push(step('Handshake name', 'unverified',
      resolution.endpoint
        ? `Plain DoH resolver ${resolution.endpoint} — NOT oblivious`
        : 'DoH resolver (SPV unavailable) — NOT oblivious',
      'The chain proof was unavailable AND the oblivious path did not work, ' +
      'so this name was resolved by asking a resolver directly. That resolver ' +
      'saw your address and the name together, and could have sent you ' +
      'somewhere else.'))
  }

  // 2a. The HIP-5 `_op` hop, when the TLD delegated to a registry contract
  //     instead of a nameserver (src/hns/hip5-op.js). The chain PROVED which
  //     contract answers for this name; nothing proved the contract's answer,
  //     which was read from a public Optimism RPC with no light client and no
  //     Merkle proof against a block header. So: unverified, in those words —
  //     the same standing ens:// has, and the reason the verdict is `partial`
  //     (TRUSTED, never green) even when the records carry a DANE pin.
  if (resolution.op) {
    steps.push(step('Name records', 'unverified',
      `Optimism registry ${resolution.op.registry}, read via ${resolution.op.rpc || 'a public RPC'}`,
      'The Handshake chain proves this name\'s records live in that contract, ' +
      'and the contract was asked directly — no nameserver of the domain ' +
      'owner\'s was involved. But the contract\'s answer arrived over an ' +
      'ordinary RPC connection: this browser does not run an Optimism light ' +
      'client, so that last step is taken on the endpoint\'s word.'))
  }

  // 2. The authoritative hop. Whether this counts as verified is decided by
  //    step 3: DNSSEC is what turns "a server said so" into "the zone's own
  //    key signed it". Marking it unverified when the signature DID validate
  //    would under-claim, which is as misleading as over-claiming.
  if (resolution.ns) {
    steps.push(resolution.dnssecValidated
      ? step('Zone records', 'verified',
        `Authoritative nameserver ${resolution.ns}, signatures checked`,
        'The records are signed by the zone’s own key (see DNSSEC below).')
      : step('Zone records', 'unverified',
        `Authoritative nameserver ${resolution.ns}`,
        'Records came from the zone’s nameserver over plain DNS, and this ' +
        'zone publishes no signatures — so this hop is taken on trust.'))
  }

  // 3. DNSSEC — the step that decides whether the PIN can be trusted.
  if (resolution.dnssecValidated) {
    steps.push(step('DNSSEC', 'verified',
      'DS record on the Handshake chain → DNSKEY → RRSIG',
      'The records were signed by a key the chain itself vouches for.'))
  } else if (resolution.kind === 'dnssec-fail') {
    steps.push(step('DNSSEC', 'failed',
      'DS record on the Handshake chain',
      resolution.reason || 'The zone is signed but its records did not validate.'))
  } else if (resolution.dnssecAnchored && !resolution.op) {
    // ANCHORED BUT UNPROVEN — a third state, and the one that was being told
    // as the first. The chain DOES carry a DS for this zone; we simply did not
    // get a validated answer (a forged denial at _443._tcp, an unreachable
    // DNSKEY, a signature we cannot check). Saying "this zone is not signed"
    // there is false, and it understates the situation in precisely the case
    // that matters most — see the NSEC gap in src/hns/README.md.
    steps.push(step('DNSSEC', 'unverified',
      'DS record on the Handshake chain, signatures NOT checked',
      'The chain vouches for this zone’s signing key, but the answers here ' +
      'were not proved against it. Treat them as this nameserver’s word.'))
  } else if ((resolution.tlsa || []).length && !resolution.op && !chain) {
    // A pin that arrived over DoH. Nothing about the chain was consulted, so
    // "no DS on chain" would be a claim about something never looked at; what
    // is true is that the pin is the resolver's word and pins the handshake
    // all the same.
    steps.push(step('DNSSEC', 'none',
      'Not checked — the pin came from the DoH resolver',
      'The chain proof was unavailable, so whether this zone is signed was ' +
      'not established. The TLSA pin below is the resolver\'s word, and the ' +
      'connection is still held to it.'))
  } else if ((resolution.tlsa || []).length && !resolution.op) {
    // Not for an `_op` resolution: there was no DNS answer and no zone to
    // sign one. Step 2a already says where the pin came from and on whose
    // word — repeating it as a missing DS would name the wrong gap.
    steps.push(step('DNSSEC', 'none',
      'No DS record on chain for this zone',
      'This zone is not signed, so its TLSA pin is only as trustworthy as ' +
      'the DNS answer that carried it.'))
  }

  // 4. The pin.
  const pinned = (resolution.tlsa || []).length > 0
  if (pinned) {
    // "…and did" is the CONNECTION step's to report, not this one's. This step
    // runs at resolution time, before any handshake, so on a mismatch the
    // panel showed "the certificate had to match this pin, and did" directly
    // above "Refused before connecting — the certificate did not match the
    // pin". Seen live on hns://lumeweb during a key rotation, 2026-09-04.
    const matched = extra.transport === 'https-dane'
    steps.push(step('DANE pin (TLSA)', matched ? 'verified' : 'unverified',
      resolution.op ? 'TLSA 3 1 1 record in the Optimism registry' : 'TLSA 3 1 1 record in the zone',
      matched
        ? 'The certificate had to match this pin, and did — no certificate ' +
          'authority is involved or trusted.'
        : 'The certificate must match this pin for the page to load. No ' +
          'certificate authority is involved or trusted.'))
  } else if (resolution.allowInsecure) {
    steps.push(step('DANE pin (TLSA)', 'none',
      'Zone answered authoritatively: no TLSA record',
      'The zone states it publishes no pin, so there is nothing to verify ' +
      'the connection against.'))
  } else if (resolution.kind === 'site') {
    steps.push(step('DANE pin (TLSA)', 'failed',
      'Lookup did not return an authoritative answer',
      'Whether this name has a pin could not be determined, so loading it ' +
      'was refused rather than downgraded.'))
  }

  // 4b. THE RESOLUTION ITSELF FAILED. Without this the list is just
  //     [Handshake name: verified] and summarize() reports "Every step was
  //     verified on this computer" — a fully green padlock over an error page
  //     for a name that is unregistered, points at a private address, or whose
  //     zone could not be reached at all.
  if (resolution.kind === 'unregistered') {
    steps.push(step('Records', 'none', 'The chain has no records for this name',
      'There is nothing published here to verify.'))
  } else if (resolution.kind === 'blocked') {
    steps.push(step('Address', 'failed',
      `The name points at ${resolution.address}`,
      'That is a loopback, private or reserved address. A public name aimed ' +
      'at one is either a mistake or an attempt to reach something on your ' +
      'own network, so it was refused.'))
  } else if (resolution.kind === 'unreachable') {
    steps.push(step('Records', 'failed', 'The zone could not be reached',
      resolution.reason || 'Nothing could be established about this name.'))
  }

  // 5. What the bytes actually travelled over.
  if (CONTENT_ADDRESSED.has(resolution.kind)) {
    const id = resolution.cid || resolution.txid || resolution.key
    steps.push(step('Content', 'verified',
      contentLabel(resolution, id) + (resolution.dnslink ? ' (from the DNSLink record)' : ''),
      'Content-addressed: the bytes are checked against the address they ' +
      'were requested by, so they cannot have been altered in transit.'))
    if (!chain) {
      steps.push(step('Pointer', 'unverified', 'DoH resolver',
        'The content is intact, but the record saying THIS name points at ' +
        'that content was not chain-verified.'))
    }
  } else if (resolution.kind === 'arweave') {
    steps.push(step('Content', 'unverified',
      `Arweave tx ${resolution.txid}, fetched from a gateway over HTTPS`, ARWEAVE_CONTENT))
    if (!chain) {
      steps.push(step('Pointer', 'unverified', 'DoH resolver',
        'The record saying THIS name points at that transaction was not ' +
        'chain-verified.'))
    }
  } else if (resolution.kind === 'site') {
    if (extra.transport === 'https-dane') {
      steps.push(step('Connection', 'verified',
        `HTTPS to ${resolution.address}, certificate matched the TLSA pin`,
        'Encrypted, and authenticated by the pin rather than by a CA.'))
    } else if (extra.transport === 'http') {
      steps.push(step('Connection', 'none', `Plain HTTP to ${resolution.address}`,
        'Not encrypted and not authenticated. Anyone on the path can read ' +
        'or change this page.'))
    } else if (extra.transport === 'refused') {
      steps.push(step('Connection', 'failed', 'Refused before connecting',
        extra.detail || 'There was no verifiable way to load this name.'))
    }
  }
  return steps
}

/**
 * The path for everything that is NOT an hns:// page, so the same window can
 * answer for any URL the user is looking at. These are honest about being
 * shallower: for https we are trusting the CA system, and saying so is the
 * whole point of this panel.
 * @param {string} url
 */
export function schemeSteps (url, dns = null, bridge = null, evidence = null) {
  let protocol = ''
  let host = ''
  try {
    const u = new URL(url)
    protocol = u.protocol.replace(':', '')
    host = u.hostname
  } catch {
    // Not a WHATWG URL — but a NAMED scheme still gets its own arm (the
    // canonical AT-URI `at://did:plc:…` is one such address). Only an input
    // with no scheme at all is a parse failure.
    const named = /^([a-z][a-z0-9+.-]*):/i.exec(String(url || '').trim())
    if (!named) return [step('Address', 'failed', 'Not a URL this browser could parse')]
    protocol = named[1].toLowerCase()
  }
  switch (protocol) {
    case 'https':
      return [
        icannNameStep(host, dns, bridge),
        step('Connection', 'unverified', 'HTTPS certificate signed by a public CA',
          'Encrypted, and vouched for by a certificate authority — which ' +
          'means trusting that authority, and every other one your system ' +
          'trusts, not to issue for this name.')
      ]
    case 'http':
      return [
        icannNameStep(host, dns, bridge),
        step('Connection', 'none', 'Plain HTTP',
          'Not encrypted and not authenticated. Anyone on the path can read ' +
          'or change this page.')
      ]
    case 'ipfs':
    case 'ipns':
      return [step('Content', 'verified', `IPFS ${protocol === 'ipns' ? 'IPNS name' : 'CID'} ${host}`,
        protocol === 'ipns'
          ? 'An IPNS name is a signed pointer; the content it names is ' +
            'CID-verified once fetched.'
          : 'Content-addressed: the bytes are verified against the CID.')]
    case 'hyper':
      // A hypercore KEY verifies its own feed. A DOTTED host is a DNSLink name,
      // and the name→key mapping came from a DoH resolver's unsigned answer
      // (hyper-sdk resolves it itself), which is the ens:// shape: the pointer
      // is someone's word, the content it names verifies.
      return host.includes('.')
        ? [
            step('Name records', 'unverified', `DNSLink name ${host}, read via a DoH resolver`,
              'Which hypercore key this name points at was read from a public ' +
              'DNS resolver and taken on its word — no DNSSEC, no chain proof.'),
            step('Content', 'verified', 'Key-addressed once resolved',
              'Whatever key the record named, every block is checked against ' +
              'that key\'s signatures.')
          ]
        : [step('Content', 'verified', `Hypercore key ${host}`,
            'Key-addressed: every block is checked against the signature of ' +
            'the key in the address. That proves who wrote it, not that you ' +
            'were shown the newest version.')]
    case 'ssb':
      return [step('Content', 'verified', `SSB feed ${host}`,
        'Key-addressed: every message is checked against the feed key\'s ' +
        'signature. That proves who wrote it, not that the feed is complete.')]
    case 'bt':
    case 'bittorrent':
      return /^[0-9a-f]{40}$/i.test(host)
        ? [step('Content', 'verified', `Torrent infohash ${host}`,
            'Content-addressed: every piece is checked against the infohash, ' +
            'so the bytes cannot have been altered.')]
        : [step('Content', 'verified', `Torrent, signed by public key ${host}`,
            'Key-addressed (BEP 46): the pointer is signed by the key in the ' +
            'address and the pieces are hash-checked. The key proves who ' +
            'published it, not that this is the newest version.')]
    case 'magnet':
      return [step('Address', 'none', 'Magnet link',
        'A magnet link is only a pointer to a torrent; nothing loads until ' +
        'it is added, and the torrent itself is verified against its infohash.')]
    case 'ar':
      return [step('Content', 'unverified',
        `Arweave transaction ${host}, fetched from a gateway over HTTPS`, ARWEAVE_CONTENT)]
    case 'gemini':
      // The Gemini client connects with certificate verification off and keeps
      // no record of the certificates it has seen, so there is no TOFU pin to
      // compare against. Encrypted, and that is all.
      return [step('Connection', 'unverified', 'Gemini over TLS, certificate not verified',
        'Encrypted in transit, but the server\'s certificate is neither ' +
        'checked against an authority nor remembered from a previous visit, ' +
        'so nothing establishes who answered.')]
    case 'nostr':
      // The mirror image of the `ens` case below. There the pointer is
      // unverified and the content is content-addressed; here the OBJECT is
      // proven — id recomputed and BIP-340 signature checked in this process
      // (src/protocols/nostr/event.js) — and what cannot be proven is the
      // ANSWER SET. A relay can withhold, and nothing signs "these are all the
      // events". So the lock never closes green.
      return [
        step('Authorship', 'verified', 'Schnorr signature (BIP-340) checked in this browser',
          'Every event on this page had its id recomputed from its own ' +
          'contents and its signature checked here. A relay cannot alter or ' +
          'forge one.'),
        step('Completeness', 'unverified', 'Whichever relays answered',
          'Relays can withhold events, and there is no way to prove you were ' +
          'shown all of them — or the newest one. The page lists which relays ' +
          'answered.')
      ]
    case 'did': {
      const did = String(url).replace(/^did:\/\//, 'did:')
      const method = /^did:([^:]+):/.exec(did)?.[1]
      if (['key', 'jwk', 'pkh'].includes(method)) {
        return [step('Identifier', 'unverified', 'Local DID derivation — no remote lookup',
          'This method derives its document from the identifier itself. ' +
          'The security panel has no recorded result for this page. ' +
          'Deriving a document does not prove anyone possesses the corresponding private key or controls the account.')]
      }
      if (method === 'plc' || method === 'web') {
        return [step('Identifier', 'unverified', method === 'plc' ? 'DID directory over HTTPS' : 'DID domain over HTTPS',
          'This method retrieves its document over HTTPS and checks its id. ' +
          'The security panel has no recorded result for this page. ' +
          (method === 'plc' ? 'The PLC operation log is not audited here.' : 'The domain and WebPKI remain trusted.'))]
      }
      return [step('Identifier', 'unverified', 'DID method not established', 'No successful resolution has been recorded for this identifier.')]
    }
    case 'ens':
      // The name mapping is RPC-trusted. Integrity varies by resolved
      // protocol and response, so no completed byte check follows from ens:.
      return [
        step('Name records', 'unverified', `Ethereum name ${host}, resolved through a public RPC`,
          'ENS lookups use an Ethereum RPC endpoint. ' +
          'This browser does not run an Ethereum light client, so that ' +
          'endpoint\'s answer is taken on its word — a wrong or hostile one ' +
          'could name different content.'),
        ensContentStep(evidence?.ens, url)
      ]
    case 'wildroot':
    case 'agregore':
    case 'browser':
    case 'about':
    case 'editor':
    case 'paste':
    case 'media':
    case 'docview':
      return [step('Page', 'verified', 'Built into this browser',
        'Served from the application itself; it never touched the network.')]
    case 'bluesky':
    case 'mastodon':
      // The APP is built in; what it shows is a social network's content,
      // fetched from that network's servers over ordinary HTTPS.
      return [
        step('Page', 'verified', 'Built into this browser',
          'The application itself is served from this browser.'),
        step('Content', 'unverified', `${protocol === 'bluesky' ? 'Bluesky' : 'Fediverse'} servers over HTTPS`,
          'What this app shows came from the network\'s own servers, vouched ' +
          'for by a certificate authority — the same standing as any https:// site.')
      ]
    case 'onion':
      // The onion address authenticates the SERVICE at the Tor layer, but the
      // page is plain HTTP inside the tunnel and is not otherwise verified —
      // so this is an OPEN lock ('unverified'), never a closed/verified one,
      // even though the scheme was made secure+standard so web apps can store.
      return [step('Connection', 'unverified', 'Tor onion service (HTTP inside Tor)',
        'Reached only through the Tor client on this device — never a hosted ' +
        'relay. The onion address authenticates the service at the Tor layer, ' +
        'but the page itself is plain HTTP inside the tunnel, so its contents ' +
        'are not otherwise verified.')]
    case 'search':
      return [step('Search', 'none', 'Private metasearch',
        'The query is sent to the configured search backend.')]
    case 'file':
      return [step('File', 'none', 'Local filesystem', 'Opened from this computer.')]
    default:
      return [step('Address', 'none', `${protocol}: scheme`,
        'This browser has no verification path for this scheme.')]
  }
}

/**
 * Exact-request evidence from trusted content handlers. This helper never
 * promotes a content-addressed identifier alone into a byte-integrity claim.
 * @param {{url:string, ok:boolean, protocol:string, verifiedBytes?:boolean}} evidence
 * @param {string} url
 */
// `evidence` is a main-process result for this exact request, never an
// assertion copied from arbitrary response headers. Callers without it must
// not infer byte integrity from the ens:// scheme or a contenthash alone.
function ensContentStep (evidence, url) {
  if (!evidence || evidence.url !== url || evidence.ok !== true || !['ipfs', 'ipns', 'arweave'].includes(evidence.protocol)) {
    return step('Content', 'unverified', 'Resolved content verification not recorded',
      'ENS may point to IPFS, IPNS or Arweave. The scheme alone does not establish that this page’s bytes were verified.')
  }
  if (evidence.verifiedBytes === true) {
    return step('Content', 'verified', `${evidence.protocol} bytes verified for this request`,
      'The content handler checked these bytes. The ENS name-to-content mapping remains RPC-trusted.')
  }
  return step('Content', 'unverified', `${evidence.protocol} content — bytes not verified`,
    evidence.protocol === 'arweave'
      ? 'An immutable transaction id does not by itself verify gateway bytes; this request has no successful byte verification result.'
      : 'No successful content-integrity result was recorded for this request.')
}

// Recent bridge traffic is narrower evidence than page-specific provenance.
// A configured Chromium/OS policy alone does not establish packets observed.
function icannNameStep (host, dns, bridge = null) {
  const servers = (dns && dns.servers) || []
  const mode = (dns && dns.mode) || 'automatic'
  if (bridge?.live && bridge.evidence === 'recent-lookup' && bridge.host === host && bridge.relay && bridge.target) {
    // The oblivious path, for an ordinary web address. Same property the
    // Handshake side has had all along, and worth stating in the same words.
    return step('Domain name', 'unverified',
      `Recent Oblivious DoH lookup — relay ${bridge.relay} → target ${bridge.target}`,
      `The bridge recently answered a lookup for ${host} through these endpoints. ` +
      'That is evidence of recent lookup activity, not proof that this page used that answer. ' +
      'The relay handles ciphertext and the target sees the relay; the answer remains the resolver’s word.')
  }
  if (dns && dns.oblivious) {
    // The bridge was configured, but no recent successful activity is
    // available. Cache reuse and configuration are not packet evidence.
    return step('Domain name', 'unverified',
      mode === 'secure'
        ? 'Oblivious bridge configured — no recent lookup evidence'
        : 'Resolver not determined — no recent oblivious lookup evidence',
      `There is no recent successful bridge lookup recorded for ${host}. ` +
      'The page may have reused a cached answer; this panel cannot establish the lookup path. ' +
      (mode === 'secure' ? 'Secure DNS is configured to refuse unencrypted fallback.' : 'Automatic DNS permits system fallback; this does not show that fallback occurred.'))
  }
  if (dns && dns.failClosed) {
    return step('Domain name', 'unverified', 'Secure DNS configured to refuse new lookups',
      'No secure resolver is configured. This is the configured policy, not an observed lookup failure; cached answers may still exist.')
  }
  if (!servers.length || mode === 'off') {
    return step('Domain name', 'unverified', 'DNS lookup path not observed',
      mode === 'off'
        ? 'Browser secure DNS is disabled. The operating system resolver and any encryption it provides are not observed here.'
        : 'The browser supplied no explicit resolver list. Chromium or operating system defaults and cached answers may apply; their transport was not observed here.')
  }
  let label = servers[0]
  try { label = new URL(servers[0]).host } catch {}
  const extra = servers.length > 1 ? ` (+${servers.length - 1} more)` : ''
  return step('Domain name', 'unverified',
    `Secure DNS configured: ${label}${extra} — NOT oblivious`,
    'This names the configured resolver list, not the endpoint observed serving this page. ' +
    'Direct DoH gives its resolver both the client address and question when used. ' +
    (mode === 'secure'
      ? 'Unencrypted DNS is refused.'
      : 'If those resolvers cannot be reached, this falls back to ' +
        'unencrypted system DNS (mode: automatic).'))
}

/**
 * One-line summary + overall state for the lock itself. The rule is the
 * weakest link: a page is only as verified as its least-verified step, which
 * is exactly what a padlock is claiming when it is closed. Five states:
 * `verified` (trustless), `partial` (trusted), `open` (the connection carries
 * no protection), `failed`, `unknown`.
 * @param {Step[]} steps
 */
export function summarize (steps) {
  // Only explicit non-applicability may be excluded. Missing required
  // protection with state "none" still weakens the verdict.
  steps = steps.filter((s) => s.applicable !== false)
  if (!steps.length) return { state: 'unknown', summary: 'Nothing is known about this page yet.' }
  if (steps.some((s) => s.state === 'failed')) {
    const bad = steps.find((s) => s.state === 'failed')
    return { state: 'failed', summary: `${bad.label} failed verification.` }
  }
  // OPEN: the connection itself carries no protection. This is the third
  // lock state, and it lives in the model rather than in a renderer: a plain
  // http:// page must never aggregate to the same verdict as an https:// one.
  const connection = steps.find((s) => s.label === 'Connection')
  if (connection && connection.state === 'none') {
    return { state: 'open', summary: 'This page is not encrypted or authenticated.' }
  }
  const weak = steps.filter((s) => s.state === 'unverified' || s.state === 'none')
  if (!weak.length) {
    return { state: 'verified', summary: 'Every step was verified on this computer.' }
  }
  return {
    state: 'partial',
    // The label leads and the verdict follows, so a plural label ("Name
    // records") and a singular one ("Connection") both read right.
    summary: weak.length === 1
      ? `Not verified: ${weak[0].label.toLowerCase()}.`
      : `${weak.length} steps are not verified: ${weak.map((s) => s.label.toLowerCase()).join(', ')}.`
  }
}
