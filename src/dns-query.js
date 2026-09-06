/*
 * Minimal DNS wire-format client: one query to one nameserver.
 *
 * The browser resolves Handshake hosts in two hops: the SPV node answers
 * "which nameservers own this TLD" with an Urkel proof, then we ask that
 * authoritative server directly for the host's records. Node's dns module
 * cannot ask a *specific* server for TLSA records, and pulling in a full
 * DNS library for three record types is not worth the surface area — so
 * the ~worth-auditing-in-one-sitting encoder/decoder lives here.
 *
 * TCP only, deliberately: our own research (resolve.py) found UDP:53
 * unreliable across home ISPs and half the public Handshake resolvers,
 * while TCP behaved. An authoritative server that cannot do DNS-over-TCP
 * is broken per RFC 7766 anyway.
 */

import net from 'node:net'

export const TYPES = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  AAAA: 28,
  TXT: 16,
  DS: 43,
  RRSIG: 46,
  NSEC: 47,
  NSEC3: 50,
  NSEC3PARAM: 51,
  HTTPS: 65,
  DNSKEY: 48,
  TLSA: 52,
  // RFC 7929. A mail key in DNS; the browser looks one up before encrypting.
  OPENPGPKEY: 61
}

function encodeName (name) {
  const parts = name.replace(/\.$/, '').split('.')
  const chunks = []
  for (const part of parts) {
    const label = Buffer.from(part, 'ascii')
    if (label.length === 0 || label.length > 63) {
      throw new Error(`bad DNS label in ${name}`)
    }
    chunks.push(Buffer.from([label.length]), label)
  }
  chunks.push(Buffer.from([0]))
  return Buffer.concat(chunks)
}

export function buildQuery (name, type, id, { dnssec = false } = {}) {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(id, 0)
  header.writeUInt16BE(0x0100, 2) // RD (ignored by authoritative, harmless)
  header.writeUInt16BE(1, 4) // QDCOUNT
  if (dnssec) header.writeUInt16BE(1, 10) // ARCOUNT = 1 (the OPT record)
  const q = encodeName(name)
  const tail = Buffer.alloc(4)
  tail.writeUInt16BE(type, 0)
  tail.writeUInt16BE(1, 2) // IN
  if (!dnssec) return Buffer.concat([header, q, tail])
  // EDNS0 OPT record with the DO (DNSSEC OK) bit set, so the server returns
  // RRSIG/DNSKEY/NSEC alongside the answer.
  const opt = Buffer.alloc(11)
  opt.writeUInt8(0, 0) // root name
  opt.writeUInt16BE(41, 1) // TYPE OPT
  opt.writeUInt16BE(4096, 3) // UDP payload size (advisory; we use TCP)
  opt.writeUInt8(0, 5) // extended rcode
  opt.writeUInt8(0, 6) // version
  opt.writeUInt16BE(0x8000, 7) // flags: DO bit
  opt.writeUInt16BE(0, 9) // rdlen
  return Buffer.concat([header, q, tail, opt])
}

function readName (buf, offset) {
  const labels = []
  let jumped = false
  let next = offset
  let guard = 0
  while (guard++ < 128) {
    const len = buf[offset]
    if (len === undefined) throw new Error('truncated name')
    if ((len & 0xc0) === 0xc0) {
      const ptr = buf.readUInt16BE(offset) & 0x3fff
      if (!jumped) next = offset + 2
      offset = ptr
      jumped = true
      continue
    }
    if (len === 0) {
      if (!jumped) next = offset + 1
      return { name: labels.join('.'), next }
    }
    labels.push(buf.toString('ascii', offset + 1, offset + 1 + len))
    offset += 1 + len
  }
  throw new Error('name compression loop')
}

export function parseAnswers (buf) {
  const id = buf.readUInt16BE(0)
  const flags = buf.readUInt16BE(2)
  const rcode = flags & 0x0f
  const truncated = (flags & 0x0200) !== 0 // TC bit
  // AD: the answering RESOLVER says it validated DNSSEC. Worth nothing from
  // an authoritative server or an untrusted path, which is why the chain path
  // ignores it and validates signatures itself — but it is the only signal
  // available for an ICANN-anchored name, and callers must be able to tell
  // "authenticated" from "the resolver just says so".
  const authenticated = (flags & 0x0020) !== 0
  const qdcount = buf.readUInt16BE(4)
  const ancount = buf.readUInt16BE(6)
  const nscount = buf.readUInt16BE(8)
  const arcount = buf.readUInt16BE(10)
  let offset = 12
  // The question section is KEPT, not skipped: a reply is only a reply to
  // the question that was asked, and the caller checks (assertAnswersTo).
  const questions = []
  for (let i = 0; i < qdcount; i++) {
    const { name, next } = readName(buf, offset)
    questions.push({ name: name.toLowerCase().replace(/\.$/, ''), type: buf.readUInt16BE(next), klass: buf.readUInt16BE(next + 2) })
    offset = next + 4
  }

  /**
   * RFC 4034 §4.1.2 type bit maps: repeating (window, length, bitmap). Bit N
   * of the bitmap, counting from the high bit of byte 0, means rrtype
   * window*256 + N is present. Shared by NSEC and NSEC3, which encode this
   * field identically.
   * @param {Buffer} rdata the record's rdata
   * @param {number} at offset within rdata where the bitmaps begin
   */
  function readTypeBitmaps (rdata, at) {
    const types = new Set()
    let p = at
    while (p + 2 <= rdata.length) {
      const window = rdata[p]
      const len = rdata[p + 1]
      if (len < 1 || len > 32 || p + 2 + len > rdata.length) break
      for (let i = 0; i < len; i++) {
        const octet = rdata[p + 2 + i]
        for (let bit = 0; bit < 8; bit++) {
          if (octet & (0x80 >> bit)) types.add(window * 256 + i * 8 + bit)
        }
      }
      p += 2 + len
    }
    return types
  }

  function parseRecord () {
    const { name, next } = readName(buf, offset)
    offset = next
    const type = buf.readUInt16BE(offset)
    const ttl = buf.readUInt32BE(offset + 4)
    const rdlength = buf.readUInt16BE(offset + 8)
    const rdataStart = offset + 10
    const rdata = buf.subarray(rdataStart, rdataStart + rdlength)
    offset += 10 + rdlength
    const rec = { name, type, ttl }
    if (type === TYPES.A && rdata.length === 4) {
      rec.address = Array.from(rdata).join('.')
      rec.rdataRaw = Buffer.from(rdata) // canonical: no embedded names
    } else if (type === TYPES.AAAA && rdata.length === 16) {
      const parts = []
      for (let j = 0; j < 16; j += 2) parts.push(rdata.readUInt16BE(j).toString(16))
      rec.address = parts.join(':')
      rec.rdataRaw = Buffer.from(rdata)
    } else if (type === TYPES.TXT) {
      let p = 0
      const strings = []
      while (p < rdata.length) {
        const l = rdata[p]
        strings.push(rdata.toString('utf8', p + 1, p + 1 + l))
        p += 1 + l
      }
      rec.txt = strings
      rec.rdataRaw = Buffer.from(rdata)
    } else if (type === TYPES.TLSA && rdata.length > 3) {
      rec.usage = rdata[0]
      rec.selector = rdata[1]
      rec.matchingType = rdata[2]
      rec.certificate = rdata.subarray(3).toString('hex')
      rec.rdataRaw = Buffer.from(rdata)
    } else if (type === TYPES.DNSKEY && rdata.length > 4) {
      rec.flags = rdata.readUInt16BE(0)
      rec.protocol = rdata[2]
      rec.algorithm = rdata[3]
      rec.rawPubKey = Buffer.from(rdata.subarray(4))
      rec.rdataRaw = Buffer.from(rdata)
    } else if (type === TYPES.DS && rdata.length > 4) {
      rec.keyTag = rdata.readUInt16BE(0)
      rec.algorithm = rdata[2]
      rec.digestType = rdata[3]
      rec.digest = rdata.subarray(4).toString('hex')
      // Kept for the same reason as TXT's: a DS RRset at a delegation point
      // has to be verified against its RRSIG before the child zone may be
      // anchored to it, and RRSIG is computed over exactly these bytes. DS
      // rdata embeds no names, so the wire form IS the canonical form.
      rec.rdataRaw = Buffer.from(rdata)
    } else if (type === TYPES.RRSIG && rdata.length > 18) {
      rec.typeCovered = rdata.readUInt16BE(0)
      rec.algorithm = rdata[2]
      rec.labels = rdata[3]
      rec.originalTtl = rdata.readUInt32BE(4)
      rec.expiration = rdata.readUInt32BE(8)
      rec.inception = rdata.readUInt32BE(12)
      rec.keyTag = rdata.readUInt16BE(16)
      // Signer name (uncompressed per RFC 4034) starts at rdata offset 18.
      const { name: signer, next } = readName(buf, rdataStart + 18)
      rec.signer = signer
      rec.signature = Buffer.from(buf.subarray(next, rdataStart + rdlength))
    } else if (type === TYPES.OPENPGPKEY) {
      // The whole rdata IS the transferable public key (RFC 7929 §2.3) —
      // no sub-fields to parse, but it must be kept as raw bytes because the
      // RRSIG is computed over exactly these.
      rec.key = Buffer.from(rdata)
      rec.rdataRaw = Buffer.from(rdata)
    } else if (type === TYPES.NSEC) {
      // RFC 4034 §4.1: a next-owner name followed by type bit maps. The name
      // is uncompressed by the RFC, but readName handles a pointer anyway
      // rather than trusting a server to have obeyed.
      //
      // Parsed because AUTHENTICATED DENIAL is what turns "the zone said there
      // is no pin here" from an unsigned server's word into a proof — the gap
      // that let a forged NXDOMAIN at `_443._tcp.<host>` strip a real TLSA.
      const { name: next, next: afterName } = readName(buf, rdataStart)
      rec.nextName = next
      rec.types = readTypeBitmaps(rdata, afterName - rdataStart)
      rec.rdataRaw = Buffer.from(rdata)
    } else if (type === TYPES.NSEC3 && rdata.length > 5) {
      // RFC 5155 §3.2. Hashed denial: the owner name is base32hex(H(name)) and
      // the next-hashed field is RAW bytes, not text. Parsed so a zone using
      // NSEC3 — Namebase's `hns` among them — can prove a denial instead of
      // being refused for want of one (src/hns/nsec3.js).
      rec.hashAlgorithm = rdata[0]
      rec.flags = rdata[1]
      rec.optOut = !!(rdata[1] & 0x01)
      rec.iterations = rdata.readUInt16BE(2)
      const saltLen = rdata[4]
      rec.salt = Buffer.from(rdata.subarray(5, 5 + saltLen))
      const hashLenAt = 5 + saltLen
      const hashLen = rdata[hashLenAt]
      rec.nextHashed = Buffer.from(
        rdata.subarray(hashLenAt + 1, hashLenAt + 1 + hashLen))
      rec.types = readTypeBitmaps(rdata, hashLenAt + 1 + hashLen)
      rec.rdataRaw = Buffer.from(rdata)
    } else if (type === TYPES.HTTPS && rdata.length >= 2) {
      // RFC 9460 §2.2. SvcPriority, a target name, then a list of
      // (key, length, value) parameters in ascending key order.
      //
      // WHY WE PARSE IT: an ICANN domain can already say "reach me on this
      // port, with these protocols, and here is my ECH config" in one record,
      // and a Handshake zone had no way to say any of it because nothing here
      // could read type 65. It is also the record RFC 9848 requires a client
      // to resolve before the ClientHello, so ECH is unreachable without it.
      rec.priority = rdata.readUInt16BE(0)
      const { name: target, next: afterTarget } = readName(buf, rdataStart + 2)
      rec.target = target
      const params = {}
      let p = afterTarget - rdataStart
      while (p + 4 <= rdata.length) {
        const key = rdata.readUInt16BE(p)
        const len = rdata.readUInt16BE(p + 2)
        if (p + 4 + len > rdata.length) break
        const value = rdata.subarray(p + 4, p + 4 + len)
        if (key === 1) {
          // alpn: a list of length-prefixed protocol ids.
          const alpn = []
          let q = 0
          while (q < value.length) {
            const l = value[q]
            if (l === 0 || q + 1 + l > value.length) break
            alpn.push(value.toString('utf8', q + 1, q + 1 + l))
            q += 1 + l
          }
          params.alpn = alpn
        } else if (key === 2) {
          params.noDefaultAlpn = true
        } else if (key === 3 && len === 2) {
          params.port = value.readUInt16BE(0)
        } else if (key === 4) {
          const ips = []
          for (let q = 0; q + 4 <= value.length; q += 4) {
            ips.push(Array.from(value.subarray(q, q + 4)).join('.'))
          }
          params.ipv4hint = ips
        } else if (key === 5) {
          // The ECH config list, kept as bytes. Nothing consumes it yet — see
          // docs/STANDARDS.md on why the record is necessary and not
          // sufficient — but discarding it here would mean re-parsing later.
          params.ech = Buffer.from(value)
        } else {
          params[`key${key}`] = Buffer.from(value)
        }
        p += 4 + len
      }
      rec.params = params
      rec.rdataRaw = Buffer.from(rdata)
    } else if (type === TYPES.SOA) {
      // Only the fact of it is read: an SOA in AUTHORITY is what tells a
      // NODATA from a referral (src/hns/resolver.js referralIn).
      rec.rdataRaw = Buffer.from(rdata)
    } else if (type === TYPES.CNAME || type === TYPES.NS) {
      rec.target = readName(buf, rdataStart).name
    } else {
      rec.rdata = rdata.toString('hex')
    }
    return rec
  }

  // All three sections use the same record encoding. authority/additional
  // matter for root-server referrals: an hsd SPV node answers TLD queries
  // with the delegation (NS/DS) in AUTHORITY and glue A records in
  // ADDITIONAL — nothing in the answer section at all.
  const readSection = (count) => {
    const out = []
    for (let i = 0; i < count; i++) {
      const rec = parseRecord()
      if (rec.type !== 41) out.push(rec) // drop the EDNS OPT pseudo-record
    }
    return out
  }
  const answers = readSection(ancount)
  const authority = readSection(nscount)
  const additional = readSection(arcount)
  return { id, rcode, truncated, authenticated, questions, answers, authority, additional }
}

/**
 * A reply is a reply to the question that was asked. The message id is
 * 16 bits and, over DoH, fixed at zero — so the question section is the only
 * thing that binds an answer to a query, and a resolver or an on-path party
 * that returns the answer for a different name or type is caught here, not
 * believed. Owner names compare case-insensitively (RFC 4343).
 * @param {{questions?: Array<{name:string,type:number}>}} parsed
 * @param {string} name the name queried
 * @param {number} type the RR type queried
 * @returns the same parsed reply, for chaining
 */
export function assertAnswersTo (parsed, name, type) {
  const want = String(name || '').toLowerCase().replace(/\.$/, '')
  const q = parsed && parsed.questions && parsed.questions[0]
  if (!q || q.name !== want || q.type !== type) {
    throw new Error(`DNS reply answers a different question: asked ${want}/${type}, got ${q ? `${q.name}/${q.type}` : 'no question section'}`)
  }
  return parsed
}

/**
 * Ask one server one question over TCP. Resolves to parsed answers;
 * rejects on transport failure, timeout, or a mismatched reply id.
 *
 * `dial(host, port)` is the socket factory: the default is a direct
 * `net.connect`; with IP Protection on the resolver passes a SOCKS5 dialer
 * to the device-local Tor (src/hns/socks-dial.js), so the authoritative hop
 * keeps its chain proof and its DNSSEC validation and hides only the asker.
 */
export function query (server, port, name, type, { timeout = 5000, dnssec = false, dial = null } = {}) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 0xffff)
    const msg = buildQuery(name, type, id, { dnssec })
    const framed = Buffer.concat([Buffer.alloc(2), msg])
    framed.writeUInt16BE(msg.length, 0)

    const chunks = []
    let expected = null
    let socket = null
    const timer = setTimeout(() => {
      if (socket) socket.destroy()
      reject(new Error(`DNS timeout asking ${server} for ${name}`))
    }, timeout)

    const attach = (s) => {
      socket = s
      wire(s)
    }
    if (dial) {
      dial(server, port).then((s) => { attach(s); s.write(framed) }, (err) => {
        clearTimeout(timer)
        reject(err)
      })
    } else {
      attach(net.connect({ host: server, port }))
      socket.on('connect', () => socket.write(framed))
    }

    function wire (socket) {
      socket.on('data', (chunk) => {
        chunks.push(chunk)
        const buf = Buffer.concat(chunks)
        if (expected === null && buf.length >= 2) expected = buf.readUInt16BE(0)
        if (expected !== null && buf.length >= expected + 2) {
          clearTimeout(timer)
          socket.destroy()
          try {
            const parsed = parseAnswers(buf.subarray(2, expected + 2))
            if (parsed.id !== id) throw new Error('DNS reply id mismatch')
            resolve(assertAnswersTo(parsed, name, type))
          } catch (err) {
            reject(err)
          }
        }
      })
      socket.on('error', (err) => {
        clearTimeout(timer)
        reject(err)
      })
      // A server that accepts the connection and hangs up without a complete
      // reply used to cost the FULL timeout — the promise only settled on data
      // or on the timer. Settle it when the socket goes away instead; a reply
      // that already arrived has resolved above and this is a no-op.
      socket.on('close', () => {
        clearTimeout(timer)
        reject(new Error(`DNS connection to ${server} closed before a reply for ${name}`))
      })
    }
  })
}
