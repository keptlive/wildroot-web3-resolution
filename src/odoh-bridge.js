// A loopback DoH endpoint that speaks ODoH upstream — so ordinary ICANN
// browsing gets the same privacy Handshake lookups already have.
//
// THE PROBLEM THIS SOLVES. Handshake names are resolved by our own protocol
// handler, which can use ODoH directly. Every ordinary http(s) host is
// resolved by CHROMIUM, which has no ODoH support at all: it accepts only
// https DoH templates. So the private half of the browser was Handshake, and
// the rest of the web still leaked "who asked what" to whichever DoH resolver
// was configured — the weakest remaining link, and the majority of lookups.
//
// THE SHAPE OF THE FIX. Chromium will talk plain RFC 8484 DoH to any https
// endpoint it trusts, including one on 127.0.0.1. So: run one here, and have
// it perform the ODoH exchange (relay + target) on Chromium's behalf. From
// Chromium's side it is a normal DoH server; from the network's side every
// query leaves sealed, through a relay that cannot read it, to a target that
// cannot see the asker.
//
//   Chromium ──https──▶ this bridge ──HPKE──▶ relay ──▶ target ──▶ resolver
//     (loopback only)      (in-process)     (someone else)   (us)
//
// WHAT IT COSTS, AND WHY IT IS OPTIONAL. A relay hop is real latency —
// measured around 200ms warm, more on a cold config fetch — on every cache
// miss for every site. That is a trade a user should get to make, so this is
// a setting (`odoh.icann`), and the resolution path is stated in the security
// panel rather than assumed.
//
// TRUST. The certificate is generated in memory at launch (self-cert.js) and
// pinned into Chromium with --ignore-certificate-errors-spki-list. That
// switch is why the key must never reach disk: it makes Chromium accept that
// public key for ANY host, so it is a MITM key for this browser, alive only
// for this process.
//
// FAILURE POLICY. If the oblivious path fails, this answers SERVFAIL rather
// than silently resolving some other way. Chromium's own secure-DNS mode
// decides what happens next (`automatic` falls back to system DNS,
// `secure` does not) — which keeps that decision in one place, visible in
// settings, instead of hidden in here.

import https from 'node:https'
import { randomBytes } from 'node:crypto'

import { OdohTransport } from './odoh.js'
import { generateLoopbackCert } from './self-cert.js'

const DNS_MEDIA = 'application/dns-message'
const MAX_QUERY = 4096

export class OdohBridge {
  /**
   * @param {object} opts
   * @param {Array<{host:string,path:string}>} opts.targets
   * @param {string[]} opts.relays
   * @param {number} [opts.port] 0 = pick a free one (the default; the port is
   *   read back after listen and handed to configureHostResolver)
   */
  constructor ({ targets, relays, port = 0, timeout = 10000, transport = null, tls = null } = {}) {
    this.port = port
    // A PER-LAUNCH SECRET PATH. The endpoint answers any caller that can
    // reach loopback, and an adversarial review showed a WEB PAGE could POST
    // its own hostname to it and thereby make the security panel report
    // "resolved obliviously" for a lookup that had actually gone out in the
    // clear. It cannot read the answer (no CORS), but it does not need to --
    // writing into `recent` is the whole attack. Only the template we hand
    // Chromium carries this segment.
    this.secretPath = '/' + randomBytes(16).toString('hex') + '/dns-query'
    this.server = null
    this.stats = { queries: 0, oblivious: 0, failed: 0 }
    // The names this bridge has actually answered, most recent last. The
    // security panel checks against this instead of inferring from settings:
    // with Chromium's secure-DNS mode set to `automatic` a lookup can still
    // fall back to system DNS, and a panel that said "oblivious" because the
    // FEATURE was on — rather than because THIS name went through it — would
    // be exactly the kind of claim this browser is supposed to stop making.
    // In-memory, capped, and nothing the page can read.
    this.recent = new Map()
    this.querySequence = 0
    this.transport = transport || new OdohTransport({ targets, relays, timeout })
    // The certificate is normally MINTED BEFORE THE APP IS READY (index.js) so
    // its pin can go on Chromium's command line, and handed in here. Minting
    // one locally is the standalone/test path; it would not be trusted by a
    // Chromium that never saw its pin.
    const { cert, key, spkiPin } = tls || generateLoopbackCert()
    this.spkiPin = spkiPin
    this._tls = { cert, key }
  }

  /** The https DoH template Chromium should be pointed at. */
  get template () {
    return `https://127.0.0.1:${this.port}${this.secretPath}`
  }

  async start () {
    this.server = https.createServer(this._tls, (req, res) => this._handle(req, res))
    // Loopback only. This endpoint answers anything that reaches it, so it
    // must not be reachable from the network.
    await new Promise((resolve, reject) => {
      this.server.once('error', reject)
      this.server.listen(this.port, '127.0.0.1', () => {
        this.port = this.server.address().port
        resolve()
      })
    })
    return this
  }

  async stop () {
    if (!this.server) return
    await new Promise((resolve) => this.server.close(resolve))
    this.server = null
  }

  async _handle (req, res) {
    let wire = null
    try {
      const url = new URL(req.url, 'https://127.0.0.1')
      if (url.pathname !== this.secretPath) return this._end(res, 404)
      // Belt to the braces: a fetch from page script always carries
      // Origin or Sec-Fetch-Site; Chromium's DoH client, which is not a
      // page, carries neither. Refuse anything that looks like a page.
      if (req.headers.origin || req.headers['sec-fetch-site']) return this._end(res, 403)
      if (req.method === 'GET') {
        const dns = url.searchParams.get('dns')
        if (!dns) return this._end(res, 400)
        wire = Buffer.from(dns, 'base64url')
      } else if (req.method === 'POST') {
        wire = await readBody(req, MAX_QUERY)
      } else {
        return this._end(res, 405)
      }
    } catch {
      return this._end(res, 400)
    }
    if (!wire || !wire.length || wire.length > MAX_QUERY) return this._end(res, 400)

    let question
    try {
      question = dnsEnvelope(wire)
      if (question.flags & 0xf800) throw new Error('not a standard DNS query')
    } catch {
      return this._end(res, 400)
    }
    this.stats.queries++
    const asked = question.name
    const queryType = question.type
    const sequence = ++this.querySequence
    try {
      const { answer, via, target } = await this.transport.query(wire)
      // HPKE authenticates the transport bytes, not their DNS meaning. An
      // empty, truncated or wrong-question response must not become evidence
      // that this host was answered, nor leave an earlier success current.
      const reply = dnsEnvelope(answer)
      if (!(reply.flags & 0x8000) || (reply.flags & 0x7a00) ||
          reply.id !== question.id || reply.questionKey !== question.questionKey ||
          reply.type !== question.type || reply.klass !== question.klass) {
        throw new Error('ODoH response does not answer this query')
      }
      this.stats.oblivious++
      if (asked) this._remember(asked, { queryType, sequence, via, target, rcode: reply.flags & 15 })
      res.writeHead(200, {
        'content-type': DNS_MEDIA,
        'content-length': answer.length,
        'cache-control': 'no-store'
      })
      res.end(Buffer.from(answer))
    } catch {
      // SERVFAIL, not a quiet fallback: what happens next is Chromium's
      // secure-DNS mode to decide, and the user can see that setting.
      this.stats.failed++
      if (asked) this._remember(asked, { queryType, sequence, rcode: 2 })
      const body = servfail(wire)
      res.writeHead(200, { 'content-type': DNS_MEDIA, 'content-length': body.length })
      res.end(body)
    }
  }

  /** Bounded exact-name activity, not proof of a navigation or cache hit. */
  _remember (name, { queryType = 1, sequence = ++this.querySequence, via = null, target = null, rcode = 0 } = {}) {
    const host = String(name || '').toLowerCase().replace(/\.$/, '')
    if (!host) return
    const key = host + ':' + queryType
    // An older request completing late cannot erase a newer failure/result.
    if ((this.recent.get(key)?.sequence || 0) > sequence) return
    this.recent.delete(key)
    this.recent.set(key, { host, queryType, sequence, relay: via, target, rcode, at: Date.now() })
    if (this.recent.size > 512) this.recent.delete(this.recent.keys().next().value)
  }

  recentEvidence (host, withinMs = 10 * 60 * 1000) {
    const wanted = String(host || '').toLowerCase().replace(/\.$/, '')
    if (!wanted) return null
    let latest = null
    for (const row of this.recent.values()) {
      if (row.host === wanted && (!latest || row.sequence > latest.sequence)) latest = row
    }
    if (!latest || latest.at < Date.now() - withinMs || ![0, 3].includes(latest.rcode)) return null
    const { sequence, ...evidence } = latest
    return { ...evidence, withinMs, evidence: 'recent-lookup' }
  }

  servedRecently (host, withinMs) { return !!this.recentEvidence(host, withinMs) }

  _end (res, code) {
    res.writeHead(code)
    res.end()
  }
}

function readBody (req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > limit) {
        reject(new Error('body too large'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

/** The QNAME of a wire query, lowercased, or null. A minimal parse: this
 * process forwards bytes it does not otherwise interpret. */
export function qnameOf (packet) {
  try {
    if (!packet || packet.length < 13) return null
    let i = 12
    const labels = []
    while (i < packet.length) {
      const length = packet[i]
      if (length === 0) break
      if (length & 0xC0) return null
      i += 1
      const label = packet.subarray(i, i + length)
      if (label.length !== length) return null
      labels.push(label.toString('ascii').toLowerCase())
      i += length
      if (labels.length > 128) return null
    }
    return labels.length ? labels.join('.') : null
  } catch {
    return null
  }
}

/** Validate the DNS envelope and question without imposing RR-type support
 * on Chromium's resolver. This is structural/question binding, not DNSSEC or
 * validation of the semantics inside each record's RDATA. */
function dnsEnvelope (input) {
  if (!(input instanceof Uint8Array) || input.byteLength < 12 || input.byteLength > 65535) throw new Error('invalid DNS packet size')
  const wire = Buffer.isBuffer(input) ? input : Buffer.from(input)
  if (wire.readUInt16BE(4) !== 1) throw new Error('expected one DNS question')
  function nameAt (start) {
    const labels = []
    const seen = new Set()
    let offset = start
    let next = null
    let length = 1
    while (true) {
      if (offset >= wire.length || seen.has(offset) || seen.size >= 128) throw new Error('invalid DNS name')
      seen.add(offset)
      const size = wire[offset]
      if ((size & 0xc0) === 0xc0) {
        if (offset + 2 > wire.length) throw new Error('truncated DNS pointer')
        if (next === null) next = offset + 2
        offset = wire.readUInt16BE(offset) & 0x3fff
        continue
      }
      if (size > 63 || offset + 1 + size > wire.length) throw new Error('invalid DNS label')
      offset++
      if (!size) return { labels, next: next === null ? offset : next }
      length += size + 1
      if (length > 255) throw new Error('DNS name exceeds limit')
      // DNS case folding is ASCII only. Comparing these bytes avoids ASCII
      // decoding accidentally equating distinct high-bit or dotted labels.
      const label = Buffer.from(wire.subarray(offset, offset + size))
      for (let i = 0; i < label.length; i++) if (label[i] >= 65 && label[i] <= 90) label[i] += 32
      labels.push(label)
      offset += size
    }
  }
  const question = nameAt(12)
  if (question.next + 4 > wire.length) throw new Error('truncated DNS question')
  let offset = question.next + 4
  const records = wire.readUInt16BE(6) + wire.readUInt16BE(8) + wire.readUInt16BE(10)
  for (let i = 0; i < records; i++) {
    offset = nameAt(offset).next
    if (offset + 10 > wire.length) throw new Error('truncated DNS record')
    const size = wire.readUInt16BE(offset + 8)
    offset += 10 + size
    if (offset > wire.length) throw new Error('truncated DNS record data')
  }
  if (offset !== wire.length) throw new Error('unframed DNS data')
  return {
    id: wire.readUInt16BE(0),
    flags: wire.readUInt16BE(2),
    name: question.labels.map(label => label.toString('latin1')).join('.'),
    questionKey: question.labels.map(label => label.toString('hex')).join('.'),
    type: wire.readUInt16BE(question.next),
    klass: wire.readUInt16BE(question.next + 2)
  }
}

/** A SERVFAIL response echoing the query's id and question section. */
export function servfail (query) {
  if (!query || query.length < 12) return Buffer.alloc(0)
  const out = Buffer.from(query)
  out[2] = (out[2] & 0x01) | 0x80 // QR=1, preserve RD
  out[3] = 0x02 // RCODE=SERVFAIL
  out.writeUInt16BE(0, 6) // ANCOUNT
  out.writeUInt16BE(0, 8) // NSCOUNT
  out.writeUInt16BE(0, 10) // ARCOUNT
  return out
}
