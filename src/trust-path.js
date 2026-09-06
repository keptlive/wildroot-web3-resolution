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

/** @typedef {{label:string, state:'verified'|'unverified'|'failed'|'none', source:string, detail?:string}} Step */

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
 */
const CONTENT_ADDRESSED = new Set(['ipfs', 'ipns', 'bittorrent', 'hyper', 'arweave'])

function contentLabel (resolution, id) {
  switch (resolution.kind) {
    case 'ipfs': return `IPFS CID ${id}`
    case 'ipns': return `IPNS name ${id}`
    case 'bittorrent':
      return resolution.mutable
        ? `Torrent, signed by public key ${id}`
        : `Torrent infohash ${id}`
    case 'hyper': return `Hypercore key ${id}`
    default: return `Arweave tx ${id}`
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
  //     the same standing ens:// has, and the reason the lock stays open even
  //     when the records themselves carry a DANE pin.
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
    steps.push(step('Content', 'verified', contentLabel(resolution, id),
      'Content-addressed: the bytes are checked against the address they ' +
      'were requested by, so they cannot have been altered in transit.'))
    if (!chain) {
      steps.push(step('Pointer', 'unverified', 'DoH resolver',
        'The content is intact, but the record saying THIS name points at ' +
        'that content was not chain-verified.'))
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
export function schemeSteps (url, dns = null, bridge = null) {
  let protocol = ''
  let host = ''
  try {
    const u = new URL(url)
    protocol = u.protocol.replace(':', '')
    host = u.hostname
  } catch {
    return [step('Address', 'failed', 'Not a URL this browser could parse')]
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
      return [step('Content', 'verified', `IPFS ${protocol === 'ipfs' ? 'CID' : 'IPNS name'} ${host}`,
        protocol === 'ipfs'
          ? 'Content-addressed: the bytes are verified against the CID.'
          : 'An IPNS name is a signed pointer; the content it names is ' +
            'CID-verified once fetched.')]
    case 'hyper':
    case 'bt':
    case 'ssb':
      return [step('Content', 'verified', `${protocol} address ${host}`,
        'Content-addressed or key-addressed: integrity is checked against the ' +
        'address itself.')]
    case 'ar':
      return [step('Content', 'verified', `Arweave transaction ${host}`,
        'Content-addressed: the bytes are checked against the transaction id.')]
    case 'ens':
      // The bytes ARE content-addressed once fetched. What is not verified is
      // the mapping — which contenthash this name points at — read from a
      // public Ethereum RPC with no light client and no proof against a block
      // header. src/protocols/ens-protocol.js already marks its responses
      // `ens-rpc-unverified` and keeps the lock open for exactly this reason;
      // without a case here the panel fell through to "this browser has no
      // verification path for this scheme", which is both wrong and silent
      // about the one hop that actually needs saying. The `_op` route says the
      // same thing about the same shape of gap.
      return [
        step('Name records', 'unverified', `Ethereum name ${host}, read via a public RPC`,
          'What this name points at was read from an Ethereum RPC endpoint. ' +
          'This browser does not run an Ethereum light client, so that ' +
          'endpoint\'s answer is taken on its word — a wrong or hostile one ' +
          'could name different content.'),
        step('Content', 'verified', 'Content-addressed once resolved',
          'Whatever address the record named, the bytes fetched are checked ' +
          'against it — so the content cannot have been altered in transit, ' +
          'even though the pointer to it is unverified.')
      ]
    case 'wildroot':
    case 'agregore':
    case 'browser':
    case 'about':
    case 'editor':
    case 'paste':
      return [step('Page', 'verified', 'Built into this browser',
        'Served from the application itself; it never touched the network.')]
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
 * How an ordinary ICANN name was looked up. This is NOT our oblivious path
 * and the panel must not let anyone assume it is: Chromium resolves http(s)
 * hosts itself, through its own secure-DNS setting (`app.configureHostResolver`
 * in index.js), and Chromium speaks plain DoH only — it accepts https DoH
 * templates and has no ODoH support, so ICANN lookups are ENCRYPTED but not
 * OBLIVIOUS. In `automatic` mode it also falls back to unencrypted system DNS
 * when those resolvers cannot be reached, which is the weakest link left and
 * therefore the thing to say out loud.
 * @param {string} host
 * @param {{mode?:string, servers?:string[]}} [dns]
 */
function icannNameStep (host, dns, bridge = null) {
  const servers = (dns && dns.servers) || []
  const mode = (dns && dns.mode) || 'automatic'
  if (bridge && bridge.live) {
    // The oblivious path, for an ordinary web address. Same property the
    // Handshake side has had all along, and worth stating in the same words.
    return step('Domain name', 'unverified',
      `Oblivious DoH — relay ${bridge.relay || '(configured relay)'} → target ${bridge.target || 'odoh.hns.one'}`,
      `${host} was looked up obliviously: the relay saw your address and only ` +
      'ciphertext, the target saw the question and only the relay. Neither ' +
      'alone can link you to this site. The ANSWER is still the resolver\'s ' +
      'word — that is what "not verified" means here.')
  }
  if (!servers.length || mode === 'off') {
    return step('Domain name', 'unverified', 'System DNS, unencrypted',
      `${host} was looked up in the clear: your router, your ISP and anyone ` +
      'on the path saw the name.')
  }
  let label = servers[0]
  try { label = new URL(servers[0]).host } catch {}
  const extra = servers.length > 1 ? ` (+${servers.length - 1} more)` : ''
  return step('Domain name', 'unverified',
    `Encrypted DNS to ${label}${extra} — NOT oblivious`,
    `${host} was resolved by the browser's own secure DNS, so the lookup was ` +
    'encrypted in transit — but that resolver saw your address and the name ' +
    'together, which our oblivious path for Handshake names avoids. ' +
    (mode === 'secure'
      ? 'Unencrypted DNS is refused.'
      : 'If those resolvers cannot be reached, this falls back to ' +
        'unencrypted system DNS (mode: automatic).'))
}

/**
 * One-line summary + overall state for the lock itself. The rule is the
 * weakest link: a page is only as verified as its least-verified step, which
 * is exactly what a padlock is claiming when it is closed.
 * @param {Step[]} steps
 */
export function summarize (steps) {
  if (!steps.length) return { state: 'unknown', summary: 'Nothing is known about this page yet.' }
  if (steps.some((s) => s.state === 'failed')) {
    const bad = steps.find((s) => s.state === 'failed')
    return { state: 'failed', summary: `${bad.label} failed verification.` }
  }
  const weak = steps.filter((s) => s.state === 'unverified' || s.state === 'none')
  if (!weak.length) {
    return { state: 'verified', summary: 'Every step was verified on this computer.' }
  }
  return {
    state: 'partial',
    summary: weak.length === 1
      ? `${weak[0].label} is not verified.`
      : `${weak.length} steps are not verified: ${weak.map((s) => s.label.toLowerCase()).join(', ')}.`
  }
}
