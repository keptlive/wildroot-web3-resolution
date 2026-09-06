# The frozen resolver fixture

A complete authoritative nameserver plus one signed zone, vendored so the
resolver end-to-end tests run on **every** platform — including the Windows box
that builds the installers we ship.

| File | What it is |
|---|---|
| `nsd.py` | Verbatim copy of the HNS.one authoritative nameserver (`~/hns/nsd.py`). Python standard library only; its one optional import (`parked`) is guarded |
| `zones.json` | The **operator** view of zone `wrfixture` |
| `zones-tenant.json` | The **tenant** view — one label the operator file does not have |
| `wrfixture.dnssec.json` | The signer's output over the MERGED view: every RRset with its RRSIG, the DNSKEY, and the NSEC chain. `nsd.py` serves these when a query carries the DO bit |
| `zones-parent.json` | A second, signed zone `wrparent` with TWO delegations: `secure.wrparent` (a DS in the parent) and `open.wrparent` (no DS — an insecure delegation the parent's NSEC at the cut proves) |
| `zones-children.json` | The two child zones, served by a SECOND `nsd.py` instance: `secure.wrparent` signed, `open.wrparent` unsigned |
| `wrparent.dnssec.json`, `secure.wrparent.dnssec.json` | Their signed views. `dnssec-delegation-e2e.test.js` walks the referral from one instance to the other |

## Why it is frozen, and not read out of `~/hns`

The tests used to read the live operator `zones.json` and *search* it for a
host of a suitable shape. Two things were wrong with that:

- On any machine without `~/hns` — the Windows packaging box — every one of
  those tests skipped. 22 tests, including the DNSSEC chain and its
  fail-closed case, were silently unaudited on the platform we ship from.
- On the machine that *does* have it, what the tests asserted drifted with
  production. It had already gone stale once: an apex `A` record was removed
  from the real zone and the test began asserting something the data no longer
  claimed.

## What the zone is shaped to prove

`wrfixture` is synthetic and deliberately minimal. Every record earns its place:

| Name | Records | Exercises |
|---|---|---|
| `site.wrfixture` | `A` + `_443._tcp` `TLSA`, no TXT pointer | DNSSEC → TLSA validation up to the on-chain DS, and its fail-closed case |
| `plain.wrfixture` | `A` only | **NODATA** at `_443._tcp.plain.wrfixture` — NOERROR-and-empty, never NXDOMAIN |
| anything else | — | **NXDOMAIN**, which the NODATA rule must not weaken |
| `pointer.wrfixture` | `TXT ipfs=…` | the pointer path, signed |
| `tenant.wrfixture` | `TXT ipfs=…`, in `zones-tenant.json` **only** | the DO-bit regression pin: a tenant-published label must be IN the signed zone, or every validating resolver is told it does not exist |

`plain` is listed before `site` on purpose — the NODATA subject must be the
first `A` record without a TLSA.

### The delegation pair (added 2026-09-05)

`wrparent` exists to drive `_descend` through a live referral, which no other
fixture could: the DS link with real `hns` material is in
`tests/fixtures/hns-delegation.json`, but the rule RFC 4035 §5.2 adds to a walk
— a MISSING DS must be proven missing before the child is read unsigned — had
no test, and was not implemented. Generation: sign `secure.wrparent` first (its
own key), compute its DS with `dsDigest` + `keyTag` from `src/hns/dnssec.js`,
put that DS in the parent's `zones.json`, sign `wrparent`. The same `sed` for
the 20-year window applies to both.

## No private key is here, and the RRSIGs cannot rot

Everything in `wrfixture.dnssec.json` is public material: a DNSKEY, RRSIGs,
digests. The signing key was generated for this fixture, used once, and never
left the scratch directory it was made in.

The RRSIGs carry a **20-year** validity window rather than the signer's
production default of 30 days. That is not cosmetic. These tests drive the
resolver through `validateChain`, which — by design — takes no clock argument
and always reads the real one (see `tests/hns/dnssec-clock-guard.test.js`).
There is therefore nothing to pin: the window is the only lever, so it is set
long, and `dnssec-e2e.test.js` FAILS if it ever drops below three years' head
room. Re-generating this fixture with the default 30-day window turns the gate
red immediately rather than a month later.

Signature *expiry* itself is tested where a clock can be injected, against real
production-signer output: `tests/hns/dnssec.test.js` with
`tests/fixtures/dir.dnssec.json`.

## Regenerating it

Only on a machine with the HNS.one toolchain (`~/hns`) and `openssl`. Nothing
in the repo depends on being able to do this — the fixture is the artifact.

```sh
S=$(mktemp -d)
cp ~/hns/dnssec.py ~/hns/zonemerge.py "$S"/
sed -i 's/^VALIDITY_DAYS = 30$/VALIDITY_DAYS = 7300/' "$S"/dnssec.py
mkdir -p "$S"/certs
openssl ecparam -genkey -name prime256v1 -noout -out "$S"/certs/wrfixture.dnskey.pem
cp tests/fixtures/resolver/zones.json tests/fixtures/resolver/zones-tenant.json "$S"/
( cd "$S" && python3 dnssec.py sign wrfixture )
cp "$S"/wrfixture.dnssec.json tests/fixtures/resolver/
cp ~/hns/nsd.py tests/fixtures/resolver/nsd.py
rm -rf "$S"          # the private key dies with it
```

The `sed` is the step that matters. Leave it out and the fixture expires in 30
days.
