#!/usr/bin/env python3
"""
Authoritative DNS server for Handshake TLDs -- the HNS.one nameserver.

A Handshake TLD owner delegates to us by putting NS or GLUE records on-chain:

    python3 records.py delegate dir ns1.hns.one ns2.hns.one

From then on every query for  dir/  and everything under it  (www.dir,
alice.dir, ...)  arrives here, and this server answers it. That is what
"being a DNS server" means: those names resolve if and only if we are up.

Zones live in zones.json. Reloaded on every query, so edits take effect
immediately without a restart.

Usage:
    python3 nsd.py                       # 127.0.0.1:5300 (testing)
    python3 nsd.py --host 0.0.0.0 --port 53
    python3 nsd.py --zones /path/zones.json

Test it:
    python3 dnstest.py www.dir A --server 127.0.0.1 --port 5300

Running this on port 53 on a public IP is a 24/7 commitment. If it goes down,
every delegated name stops resolving, and the owners cannot fix it themselves
without an on-chain update that takes ~36 blocks to propagate. Run at least
two, on different providers, before accepting anyone else's delegation.
"""

import argparse
import base64
import json
import os
import socket
import socketserver
import struct
import sys
import threading
import time

# Names we hold and do not use. Consulted ONLY after find_zone has already
# failed, and never merged into the zones dict -- see parked.py.
try:
    import parked
except ImportError:                                          # pragma: no cover
    parked = None

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16,
         "AAAA": 28, "SRV": 33, "DS": 43, "RRSIG": 46, "NSEC": 47,
         "DNSKEY": 48, "TLSA": 52, "SMIMEA": 53,
         "OPENPGPKEY": 61, "CAA": 257}
BY_NUM = {v: k for k, v in TYPES.items()}

# Used only for a zone that carries no SOA of its own. It is a TEMPLATE, not
# an answer: nothing here names a host.
DEFAULT_SOA = {"mname": "ns1.hns.one.", "rname": "hostmaster.hns.one.",
               "serial": 1, "refresh": 7200, "retry": 3600,
               "expire": 1209600, "minimum": 300}

# DELIBERATELY EMPTY. This used to hold a demo `dir` zone -- apex, www, alice,
# bob -- pointing into RFC 5737 DOCUMENTATION space, and main() wrote it into
# zones.json whenever the file was missing. `dir` is a Handshake name we really
# own, so those addresses did not stay a demo: they were exported into the
# operator database and served to the public internet by ns1.hns.one, and
# zones-audit.py could not see them because it only ever checked zone NAMES.
#
# An authoritative server with no data must answer REFUSED, not invent one. A
# fabricated fallback is worse than an outage: an outage is visible, and this
# was not.
DEFAULT_ZONES = {}

try:
    import zonemerge
except ImportError:                                          # pragma: no cover
    zonemerge = None

DEFAULT_TTL = 300
_zone_cache = {"mtime": 0, "data": None}
_tenant_cache = {"mtime": 0, "data": {}}

# The tenant plane publishes into ITS OWN zone file, never this one.
#
# On 2026-08-18 a tenant-side write rebuilt the authoritative zones.json from a
# database holding only a shopfront copy of the registry, and took 14898.hns.one
# and the pastebin offline. The lesson was not "be careful with that file" --
# it was that one file with two writers of unequal knowledge will eventually be
# flattened by whichever one knows less.
#
# So they get separate files, and the split is enforced by the kernel rather
# than by discipline: hns-tenant.service runs ProtectSystem=strict with
# ReadWritePaths=/var/lib/hns-tenant, so the tenant process CANNOT open the
# operator's file for writing even if its code tries. The operator wins every
# conflict here, so a tenant entry can never shadow a real zone either.
TENANT_ZONES = os.environ.get("HNS_TENANT_ZONES",
                              "/var/lib/hns-tenant/zones-tenant.json")


def _read_json(path, cache, label):
    """Load `path` if its mtime moved. Returns None if it cannot be read.

    Never raises and never empties a good cache: this runs on the query path of
    the authoritative nameserver, so a transient read error must degrade to
    "serve what we last knew" rather than "serve nothing".
    """
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None
    if mtime != cache["mtime"] or cache["data"] is None:
        try:
            with open(path) as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                raise ValueError("top level is not an object")
            cache["data"] = data
            cache["mtime"] = mtime
        except (OSError, ValueError) as exc:
            print(f"!! {label} unreadable ({exc}); keeping previous",
                  file=sys.stderr)
            return cache["data"]
    return cache["data"]


def load_zones(path):
    """Operator zones merged with tenant-published records. See zonemerge."""
    if zonemerge is not None:
        return zonemerge.load(path, default=DEFAULT_ZONES)
    data = _read_json(path, _zone_cache, os.path.basename(path))
    if data is None:
        if _zone_cache["data"] is None:
            _zone_cache["data"] = DEFAULT_ZONES
        data = _zone_cache["data"]
    return data


# ---------------------------------------------------------------- wire format

def enc_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("idna" if any(
                ord(c) > 127 for c in label) else "ascii")
    return out + b"\x00"


def dec_name(buf, off):
    labels, jumped, ret, hops = [], False, off, 0
    while off < len(buf):
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", buf[off:off + 2])[0] & 0x3FFF
            if not jumped:
                ret = off + 2
            off, jumped = ptr, True
            hops += 1
            if hops > 20:
                break
            continue
        labels.append(buf[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    return ".".join(labels).lower(), (ret if jumped else off)


def enc_rdata(rtype, value):
    if rtype == 1:                                            # A
        return bytes(int(p) for p in value.split("."))
    if rtype == 28:                                           # AAAA
        return socket.inet_pton(socket.AF_INET6, value)
    if rtype in (2, 5):                                       # NS, CNAME
        return enc_name(value)
    if rtype == 15:                                           # MX
        pref, host = value.split(None, 1)
        return struct.pack("!H", int(pref)) + enc_name(host)
    if rtype == 16:                                           # TXT
        out = b""
        raw = value.encode()
        for i in range(0, len(raw), 255):
            chunk = raw[i:i + 255]
            out += bytes([len(chunk)]) + chunk
        return out
    if rtype == 33:                                           # SRV
        pri, wt, port, tgt = value.split()
        return struct.pack("!HHH", int(pri), int(wt), int(port)) + enc_name(tgt)
    if rtype == 52:                                           # TLSA
        # usage selector matching-type <hex>. Needed on the plain path too:
        # a client that asks for TLSA without the DO bit must still get the
        # record, not SERVFAIL.
        usage, sel, mtype, data = value.split()
        return (struct.pack("!BBB", int(usage), int(sel), int(mtype))
                + bytes.fromhex(data))
    if rtype == 53:                                           # SMIMEA
        # Identical wire shape to TLSA (RFC 8162 §2): usage selector matching
        # then the cert association data.
        usage, sel, mtype, data = value.split()
        return (struct.pack("!BBB", int(usage), int(sel), int(mtype))
                + bytes.fromhex(data))
    if rtype == 61:                                           # OPENPGPKEY
        # RFC 7929 §2.3: the RDATA is the raw OpenPGP Transferable Public Key,
        # opaque to DNS. We carry it base64 in the zone (the presentation
        # format), so decode rather than hex.
        import base64 as _b64
        return _b64.b64decode("".join(value.split()))
    if rtype == 43:                                           # DS
        keytag, alg, dtype, digest = value.split()
        return (struct.pack("!HBB", int(keytag), int(alg), int(dtype))
                + bytes.fromhex(digest))
    if rtype == 257:                                          # CAA
        # RFC 8659: flags(1) tag-length(1) tag value. This type sat in TYPES
        # without an encoder, so a zone carrying a CAA record answered
        # SERVFAIL to the exact query a certificate authority sends.
        flags_, tag, val = value.split(None, 2)
        val = val.strip()
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1]
        tag_b = tag.encode("ascii")
        return bytes([int(flags_), len(tag_b)]) + tag_b + val.encode("ascii")
    raise ValueError(f"unsupported type {rtype}")


def enc_soa(soa):
    return (enc_name(soa["mname"]) + enc_name(soa["rname"]) +
            struct.pack("!IIIII", soa.get("serial", 1), soa.get("refresh", 7200),
                        soa.get("retry", 3600), soa.get("expire", 1209600),
                        soa.get("minimum", 300)))


def rr(name, rtype, rdata, ttl=DEFAULT_TTL):
    return (enc_name(name) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata))
            + rdata)


# ---------------------------------------------------------------- resolution

def find_zone(qname, zones):
    """Longest-suffix zone match. 'www.alice.dir' -> zone 'dir'."""
    labels = qname.rstrip(".").split(".")
    for i in range(len(labels)):
        cand = ".".join(labels[i:])
        if cand in zones:
            return cand, ".".join(labels[:i]) or "@"
    return None, None


def find_delegation(z, sub):
    """The in-zone delegation cut governing `sub`, or (None, None).

    A non-apex owner holding NS records is a zone cut (RFC 4035 s2): the
    child zone is authoritative at and below it, and we answer with a
    referral rather than data or NXDOMAIN. The cut CLOSEST TO THE APEX
    governs -- an NS set deeper inside a delegated subtree is occluded, so
    suffixes of `sub` are tried shortest-first.
    """
    if sub in ("@", ""):
        return None, None
    recs = z.get("records", [])
    labels = sub.split(".")
    for i in range(len(labels) - 1, -1, -1):
        cand = ".".join(labels[i:]).lower()
        ns = [r for r in recs
              if str(r.get("name", "@")).lower() == cand
              and str(r.get("type", "")).upper() == "NS"]
        if ns:
            return cand, ns
    return None, None


def glue_records(z, zone, ns_records, ttl):
    """A/AAAA glue for NS targets that live inside this zone.

    A resolver following a referral to `ns1.alice.<zone>` cannot look that
    host up without re-entering the very delegation it is trying to leave;
    the glue in ADDITIONAL is what breaks the cycle. Targets outside the
    zone need no glue -- the resolver reaches them on its own.
    """
    out, n = b"", 0
    suffix = "." + zone.lower()
    for nsr in ns_records:
        host = str(nsr.get("value", "")).rstrip(".").lower()
        if not host.endswith(suffix):
            continue
        rel = host[: -len(suffix)]
        for r in z.get("records", []):
            if (str(r.get("name", "@")).lower() == rel
                    and str(r.get("type", "")).upper() in ("A", "AAAA")):
                rt = TYPES[r["type"].upper()]
                try:
                    out += rr(host, rt, enc_rdata(rt, r["value"]),
                              r.get("ttl", ttl))
                    n += 1
                except (ValueError, OSError, KeyError, struct.error):
                    # struct.error: oversize glue rdata is not a ValueError, so
                    # it would otherwise escape `answer()` (REVIEW-SERVING §2).
                    continue
    return out, n


def service_parent(sub):
    """For a service-discovery owner like '_443._tcp.hello' or '_443._tcp'
    (a TLSA/SRV name that hangs beneath a host), return the host label(s) it
    sits under -- 'hello', or '@' when it sits directly beneath the apex.
    Returns None when `sub` is not of that underscore-prefixed shape.

    Used to answer NODATA rather than NXDOMAIN for a missing TLSA (or other
    `_service._proto` record) beneath a host we really serve. NXDOMAIN there is
    literally defensible -- the `_443._tcp.<host>` node owns no records -- but on
    the wire it reads as "this host is unknown", which a DANE client cannot tell
    apart from "no pin published", so it fails closed and the host will not load
    over plain HTTP even though its zone never asked for DANE. NODATA is the
    truthful "we are authoritative for this host and there is no record of this
    type here". Only the UNSIGNED path uses this: under DO a genuinely absent
    name is denied with the covering NSEC (a provable NXDOMAIN) built above --
    a signed NODATA would need an NSEC at the underscore owner itself, which the
    signer (dnssec.py) does not emit, so we must not fabricate one.
    """
    labels = sub.split(".")
    if len(labels) >= 2 and labels[0][:1] == "_" and labels[1][:1] == "_":
        rest = labels[2:]
        return ".".join(rest) if rest else "@"
    return None


def answer(query, zones):
    """Build a response packet for a raw query. Returns bytes or None.

    A hardening net around `_answer`: neither a malformed query nor a
    pathological zone record may cost more than THIS query (REVIEW-SERVING §2).
    `_answer`'s own per-record guards skip a single bad record and serve the
    rest; this outer catch handles anything they miss -- a `struct.error` from
    oversize (>64KB) TXT/CAA rdata that reaches `rr()` (it is NOT a ValueError,
    so the record loop's `except (ValueError, OSError)` never caught it and it
    killed the handler thread), a `KeyError` from a record with no `value`, a
    truncated compression pointer in the QUERY itself. It becomes a SERVFAIL
    for this one query when the header + question can still be read, or a drop
    when they cannot. The Threading{UDP,TCP}Server thread always survives.
    """
    if len(query) < 12:
        return None
    try:
        return _answer(query, zones)
    except Exception:                                       # noqa: BLE001
        try:
            tid = struct.unpack("!H", query[:2])[0]
            _qname, off = dec_name(query, 12)
            if off + 4 > len(query):
                return None
            question = query[12:off + 4]
            return struct.pack("!HHHHHH", tid, 0x8402, 1, 0, 0, 0) + question
        except Exception:                                   # noqa: BLE001
            return None


def _answer(query, zones):
    """Build a response packet for a raw query. Returns bytes or None."""
    if len(query) < 12:
        return None
    tid, flags, qd = struct.unpack("!HHH", query[:6])
    if qd < 1:
        return None
    qname, off = dec_name(query, 12)
    if off + 4 > len(query):
        return None
    qtype, qclass = struct.unpack("!HH", query[off:off + 4])
    qend = off + 4

    zone, sub = find_zone(qname, zones)
    question = query[12:qend]

    def pack(rflags, ans=b"", auth=b"", add=b"", na=0, nn=0, nx=0):
        head = struct.pack("!HHHHHH", tid, rflags, 1, na, nn, nx)
        return head + question + ans + auth + add

    if zone is None:
        # Same rule as the gateway: parked names are consulted only after the
        # real zone lookup has failed, so a synthesized for-sale zone can never
        # shadow a published one. parked.find_zone answers for the apex and
        # `www` and nothing else -- everything deeper is genuinely NXDOMAIN.
        pname, psub = parked.find_zone(qname) if parked else (None, None)
        pz = parked.dns_zone(pname) if pname else None
        if pz is None:
            return pack(0x8183)                                # REFUSED-ish
        zone, sub, z = pname, psub, pz
    else:
        z = zones[zone]
    soa = z.get("soa") or DEFAULT_SOA
    aa = 0x8400                                                # QR + AA
    ttl = z.get("ttl", DEFAULT_TTL)

    # DNSSEC path: only when the client sets DO and we have signed data.
    do, _udp = wants_dnssec(query, qend)
    signed = load_signed(zone) if do else None

    # In-zone delegation ("use your own nameservers"): a query at or below a
    # cut gets a REFERRAL -- NOERROR, no AA, the NS set in AUTHORITY, in-zone
    # glue in ADDITIONAL. Exception: a DS query AT the cut stays ours, because
    # the PARENT is authoritative for DS (RFC 4035 s2.4) -- that record is the
    # secure handoff itself.
    cut, cut_ns = find_delegation(z, sub)
    if cut and not (sub.lower() == cut and qtype == TYPES["DS"]):
        cut_fqdn = f"{cut}.{zone}"
        glue, gn = glue_records(z, zone, cut_ns, ttl)
        if signed:
            # Signed referral: the NS set is deliberately UNSIGNED (the child
            # signs its own apex); the DS RRset, when present, is signed --
            # and when absent the cut's NSEC is the signed proof of that
            # absence, which is what lets a validator treat the delegation as
            # insecure rather than bogus.
            auth, nn = unsigned_rrs(signed, cut_fqdn, "NS")
            proof, pn = signed_rrs(signed, cut_fqdn, "DS", cut_fqdn)
            if not pn:
                proof, pn = signed_rrs(signed, cut_fqdn, "NSEC", cut_fqdn)
            if nn:
                return pack(0x8000, auth=auth + proof,
                            add=glue + opt_record(), nn=nn + pn, nx=gn + 1)
            # The signed file predates this delegation (tenant-plane write
            # not yet re-signed at home). Fall through to the unsigned
            # referral rather than answering a stale signed NXDOMAIN.
        auth, nn = b"", 0
        for r in cut_ns:
            # `.get`, not `r["value"]`: an NS record with no `value` used to
            # raise KeyError straight out of `answer()` and drop every query
            # below the cut (REVIEW-SERVING §2). Skip it like glue_records does.
            host = str(r.get("value") or "").strip()
            if not host:
                continue
            try:
                auth += rr(cut_fqdn, 2, enc_name(host), r.get("ttl", ttl))
                nn += 1
            except (ValueError, OSError, KeyError, struct.error):
                continue
        if nn:
            return pack(0x8000, auth=auth, add=glue, nn=nn, nx=gn)

    if signed:
        wanted_name = BY_NUM.get(qtype)
        if wanted_name:
            body, n = signed_rrs(signed, qname, wanted_name, qname)
            if n:
                return pack(aa, body, add=opt_record(), na=n, nx=1)
        # No matching type. Two distinct cases, both needing signed proof:
        #   NODATA   -- the name exists, this type does not: its own NSEC
        #   NXDOMAIN -- the name does not exist: the NSEC that covers it
        sb, sn = signed_rrs(signed, zone, "SOA", zone)
        exists = qname.lower() in signed.get("rrsets", {})
        if exists:
            nsec, nn = signed_rrs(signed, qname, "NSEC", qname)
            rcode = aa
        else:
            owner = covering_nsec(signed, qname)
            nsec, nn = (signed_rrs(signed, owner, "NSEC", owner)
                        if owner else (b"", 0))
            rcode = aa | 0x0003                       # NXDOMAIN
        if nn or sn:
            return pack(rcode, auth=nsec + sb, add=opt_record(),
                        nn=nn + sn, nx=1)

    # apex NS / SOA
    if sub == "@" and qtype == TYPES["NS"]:
        ans = b"".join(rr(zone, 2, enc_name(n), ttl) for n in z.get("ns", []))
        return pack(aa, ans, na=len(z.get("ns", [])))
    if sub == "@" and qtype == TYPES["SOA"]:
        return pack(aa, rr(zone, 6, enc_soa(soa), ttl), na=1)

    wanted = BY_NUM.get(qtype)
    recs = z.get("records", [])
    owned = [r for r in recs if r.get("name", "@").lower() == sub.lower()]

    if not owned:
        # A missing TLSA/SRV beneath a host we really serve is NODATA, not
        # NXDOMAIN (see service_parent): the host exists, it just publishes no
        # record of this type. Only when the underlying host itself exists --
        # otherwise a genuinely unknown name stays a real NXDOMAIN.
        parent = service_parent(sub)
        if parent is not None and (
                parent == "@" or
                any(str(r.get("name", "@")).lower() == parent.lower()
                    for r in recs)):
            return pack(aa, auth=rr(zone, 6, enc_soa(soa), ttl), nn=1)  # NODATA
        # NXDOMAIN, with SOA in authority so resolvers cache it correctly
        return pack(0x8403, auth=rr(zone, 6, enc_soa(soa), ttl), nn=1)

    matched = [r for r in owned if r["type"].upper() == wanted]

    # CNAME fallback: any type query follows a CNAME
    if not matched and wanted != "CNAME":
        cn = [r for r in owned if r["type"].upper() == "CNAME"]
        if cn:
            matched = cn

    if not matched:
        # name exists, type does not -> NOERROR with empty answer
        return pack(aa, auth=rr(zone, 6, enc_soa(soa), ttl), nn=1)

    body, count = b"", 0
    for r in matched:
        rt = TYPES.get(r["type"].upper())
        if rt is None:
            continue
        try:
            body += rr(qname, rt, enc_rdata(rt, r["value"]), r.get("ttl", ttl))
            count += 1
        except (ValueError, OSError, KeyError, struct.error):
            # struct.error: a TXT/CAA whose encoded rdata exceeds 65535 bytes
            # is NOT a ValueError (REVIEW-SERVING §2) -- catch it here so one
            # oversize record is skipped rather than killing the handler. If
            # every matched record is bad, count stays 0 -> SERVFAIL below.
            continue
    if not count:
        return pack(0x8402)                                    # SERVFAIL
    return pack(aa, body, na=count)


# ---------------------------------------------------------------- servers

ZONE_PATH = "zones.json"
VERBOSE = True
_signed_cache = {}


def load_signed(zone):
    """Load <zone>.dnssec.json if it exists. Reloaded when the file changes."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        f"{zone}.dnssec.json")
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None
    cached = _signed_cache.get(zone)
    if not cached or cached[0] != mtime:
        try:
            with open(path) as fh:
                _signed_cache[zone] = (mtime, json.load(fh))
        except (OSError, ValueError):
            return None
    return _signed_cache[zone][1]


def wants_dnssec(buf, qend):
    """Is the DO bit set? Look for an OPT record (type 41) in ADDITIONAL.

    Without DO we must not send RRSIGs -- they would bloat every response for
    clients that cannot use them.
    """
    try:
        _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", buf[:12])
        if ar < 1:
            return False, 512
        off = qend
        for _ in range(an + ns):
            _, off = dec_name(buf, off)
            rdlen = struct.unpack("!H", buf[off + 8:off + 10])[0]
            off += 10 + rdlen
        for _ in range(ar):
            start = off
            _, off = dec_name(buf, off)
            # OPT: type(2) class=udpsize(2) ttl(4) rdlen(2). The TTL field is
            # ext-rcode(1) version(1) flags(2), and DO is the top bit of flags
            # -- i.e. bit 15 of the 32-bit TTL, not of its first two bytes.
            rtype, udp, ttl = struct.unpack("!HHI", buf[off:off + 8])
            if rtype == 41:                      # OPT
                return bool(ttl & 0x8000), max(512, udp)
            rdlen = struct.unpack("!H", buf[off + 8:off + 10])[0]
            off += 10 + rdlen
            if off <= start:
                break
    except (struct.error, IndexError):
        pass
    return False, 512


def opt_record(udp=4096):
    """An EDNS0 OPT record for the additional section, DO bit set."""
    return (b"\x00" + struct.pack("!HHIH", 41, udp, 0x00008000, 0))


def canon_key(name):
    """Canonical DNS name order: compare labels right-to-left (RFC 4034 s6.1)."""
    return [l for l in reversed(name.rstrip(".").lower().split(".")) if l]


def covering_nsec(signed, qname):
    """The NSEC proving qname does not exist: the one whose owner immediately
    precedes it in canonical order. NSEC exists only for names that DO exist,
    so looking one up at the missing name itself always misses."""
    owners = sorted(signed.get("rrsets", {}), key=canon_key)
    if not owners:
        return None
    target = canon_key(qname)
    prev = owners[-1]                       # wrap around the zone apex
    for o in owners:
        if canon_key(o) < target:
            prev = o
        else:
            break
    return prev


def signed_rrs(signed, owner, rtype_name, qname):
    """Emit RRs plus their RRSIG straight from the pre-signed data."""
    rs = (signed.get("rrsets", {}).get(owner.lower(), {}) or {}).get(rtype_name)
    if not rs:
        return b"", 0
    rtype = TYPES.get(rtype_name)
    if rtype is None:
        return b"", 0
    out, n = b"", 0
    for b64 in rs["rdata"]:
        out += rr(qname, rtype, base64.b64decode(b64), rs["ttl"])
        n += 1
    s = rs.get("rrsig")
    if not s:
        # Deliberately unsigned RRset -- the NS at a delegation cut, which
        # the child signs, not us (RFC 4035 s2.2).
        return out, n
    sig_rdata = (struct.pack("!HBBIIIH", rtype, s["algorithm"], s["labels"],
                             s["original_ttl"], s["expiration"],
                             s["inception"], s["key_tag"])
                 + enc_name(s["signer"]) + base64.b64decode(s["signature"]))
    out += rr(qname, TYPES["RRSIG"], sig_rdata, rs["ttl"])
    return out, n + 1


def unsigned_rrs(signed, owner, rtype_name):
    """The RRset alone, no RRSIG -- the referral form of a delegation's NS."""
    rs = (signed.get("rrsets", {}).get(owner.lower(), {}) or {}).get(rtype_name)
    rtype = TYPES.get(rtype_name)
    if not rs or rtype is None:
        return b"", 0
    out, n = b"", 0
    for b64 in rs["rdata"]:
        out += rr(owner, rtype, base64.b64decode(b64), rs["ttl"])
        n += 1
    return out, n


def _log(proto, addr, query):
    if not VERBOSE:
        return
    try:
        qname, off = dec_name(query, 12)
        qtype = struct.unpack("!H", query[off:off + 2])[0]
        print(f"{time.strftime('%H:%M:%S')}  {proto}  {addr[0]:<15} "
              f"{qname}  {BY_NUM.get(qtype, qtype)}")
    except Exception:
        pass


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        _log("udp", self.client_address, data)
        resp = answer(data, load_zones(ZONE_PATH))
        if resp:
            sock.sendto(resp, self.client_address)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            hdr = self.request.recv(2)
            if len(hdr) < 2:
                return
            n = struct.unpack("!H", hdr)[0]
            data = self.request.recv(n)
            _log("tcp", self.client_address, data)
            resp = answer(data, load_zones(ZONE_PATH))
            if resp:
                self.request.sendall(struct.pack("!H", len(resp)) + resp)
        except OSError:
            pass


class UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def main():
    global ZONE_PATH, VERBOSE
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5300)
    ap.add_argument("--zones", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "zones.json"))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    ZONE_PATH, VERBOSE = args.zones, not args.quiet

    if not os.path.exists(ZONE_PATH):
        # An EMPTY starter file. Seeding it with example records is how
        # documentation addresses reached a live TLD; a nameserver with no
        # zones should say so and answer nothing.
        with open(ZONE_PATH, "w") as fh:
            json.dump({}, fh, indent=2)
        print(f"wrote empty starter zone file: {ZONE_PATH}")
        print("  no zone is served until one is added to it")

    zones = load_zones(ZONE_PATH)
    print(f"HNS.one nameserver on {args.host}:{args.port} (udp+tcp)")
    for zn, z in zones.items():
        print(f"  zone {zn}/  {len(z.get('records', []))} records, "
              f"ns={', '.join(z.get('ns', []))}")
    if args.port == 53:
        print("  serving on port 53 -- delegated names depend on this staying up")
    print("Ctrl+C to stop.\n")

    try:
        udp = UDPServer((args.host, args.port), UDPHandler)
        tcp = TCPServer((args.host, args.port), TCPHandler)
    except PermissionError:
        print(f"!! cannot bind port {args.port} (ports below 1024 need root)",
              file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"!! cannot bind {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 1

    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    try:
        udp.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
