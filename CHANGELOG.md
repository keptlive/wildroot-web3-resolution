# Changelog

Package releases are listed below. These are historical release notes;
unresolved differences between the notes, specification, and source are
tracked in [REVIEW.md](REVIEW.md).

## 0.7.2

Synchronized selected modules with browser 2.78.28 (`93cdc62`).

- Rewrote the resolver's first-candidate selection as a `for await` loop,
  preserving candidate order and resolution results.
- Made `fileCid` yield every 4 MiB while hashing large files. CID output is
  unchanged.

## 0.7.1

- Limited Arweave byte verification to responses whose length equals the
  transaction header's `data_size`. Gateway-rendered bundle and manifest
  responses report `header` instead of being refused for a length mismatch.

## 0.7.0

- Added nameserver failover for transport failures, following the zone's
  nameserver order and preferring IPv4 glue. Validation failures do not
  trigger a retry against another server (HS-15).
- Added Arweave chunk-Merkle verification for responses within the 8 MiB
  verification limit, comparing against the header's `data_root` (AR-1).
- Added local derivation for `did:key`, `did:jwk`, and `did:pkh`, with
  `X-Resolution-Trust: derived`.
- Added ENSIP-5 text records to the page shown when an ENS name has no
  website. Text is displayed as text; `url` is linked only when it uses HTTPS.
- Made numeric Handshake names off by default, retaining the option and
  underscore URL form (`setNumericNames`, `buildWsPac({ numericNames })`).
- Added the `contentNode` delivery policy and recorded browser support for
  restarting Kubo with `--offline` in Private mode.

## 0.6.0

- Added route reports in `src/route-path.js`: `local`, `oblivious`, `tor`,
  `direct`, and `refused`, with the information disclosed by each hop.
- Documented the Arweave fetch requirement for manual redirects. The browser
  supplies a `net.request` wrapper because its `net.fetch` path rejects those
  responses.

## 0.5.0

- Added IPv6 handling for Handshake addresses, glue, DoH lookups, DANE
  connections, and SOCKS5. A and AAAA records use the same DNSSEC and address
  checks. `preferV4` chooses IPv4 when both families are available; it does
  not implement RFC 6724 or Happy Eyeballs selection (HS-2).
- Added decoding of hsd's `_synth` referrals from the target label or glue,
  allowing SPV resolution of SYNTH apex records.

## 0.4.0

- Published the shared resolution model, routing rules, and namespace
  chapters with their extracted implementation modules and tests.
- Added DNSLink handling alongside `ipfs=` records. Matching pointers merge;
  conflicting pointers are reported.
- Added Tor transport for authoritative DNS and SPV peer traffic while
  retaining chain-proof and DNSSEC checks.
- Added generated references and deviations indexes.
- Added the Fast/Private policy, including fail-closed Tor routing,
  oblivious DNS requirements, proxied Handshake and Nostr connections, and
  refusal of unsupported peer-discovery paths in Private mode.
- Added the privacy/transport inventory and browser-module comparison tool.
