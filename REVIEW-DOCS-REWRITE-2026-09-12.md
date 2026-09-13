# Review: the 2026-09-08 documentation rewrite — DO NOT MERGE AS IT STANDS

Reviewed 2026-09-12. Subject: `e90a1db` "Rewrite and reorganize resolution
documentation", on branch `docs/plain-language-rewrite` in the working copy at
`/home/matt/hns/hns-resolution-content-20260908/`, against `bd720c1` (current
`main`). Written by a ChatGPT agent.

`main` was NOT fast-forwarded and nothing from that branch was pushed. This
file is the record of that decision; the three things worth keeping from the
rewrite (§5) were taken separately, `REVIEW.md` among them.

To look at it yourself:

```sh
git -C ~/hns/hns-resolution fetch ~/hns/hns-resolution-content-20260908 docs/plain-language-rewrite
git -C ~/hns/hns-resolution diff bd720c1 FETCH_HEAD -- namespaces/icann/DEVIATIONS.md
```

## Summary

The rewrite is not a consolidation. **No deviation ID was lost — all 168, in
the same files, with the same numbers — but roughly 40% of the evidence under
them was deleted, and the deleted part is specifically the part that makes this
a standards-conformance record rather than an index.**

In `handshake`, `icann` and `nostr`, the `**The standard says.**` field — the
normative citation each deviation is measured against — was removed from
**every single entry**. That is the record.

Three things in the rewrite are genuine improvements and should be kept
(§4). The recommended action is to take those three and redo the prose pass
with the schema intact, not to merge this commit.

## What was verified

- `src/` and `namespaces/*/src/` are **byte-identical** across the two commits.
  The rewrite touches documentation, `scripts/build-docs.mjs`, `package.json`'s
  description, and one added test. Nothing it says can be wrong because the
  code moved.
- At `FETCH_HEAD`: `npm test` → **993 pass, 0 fail** (271 s). `npm run docs:check`
  → clean, so the generated files are in sync with the chapters.
- So this is purely a question of what the prose still says.

## 1. The deviation entries lost their normative citations

The entry schema **What / The standard says / Why / Consequence / Status** was
collapsed to **Behavior / Effect / Status** in six of thirteen namespaces.

| namespace | `### ` entries | `**The standard says.**` | distinct RFCs cited in the file |
|---|---|---|---|
| handshake | 23 → 23 | **12 → 0** | 19 → 14 |
| icann | 28 → 28 | **15 → 0** | **17 → 5** |
| nostr | 28 → 28 | **15 → 0** | 3 → 0 |
| router | — | 13 → 0 | 8 → 3 |
| tor | — | 6 → 0 | 3 → 2 |
| did | — | 7 → 0 | 0 → 0 |
| arweave | 10 → 10 | 3 → 2 | — |
| ipfs | 25 → 25 | 10 → 10 | — |
| ens, keys, apps, experimental | unchanged | ~unchanged | — |

Tree-wide: 70 of 168 entries lost `The standard says`, 66 lost `Why`, 30 lost
the italic source/SPEC citation line under the heading, and 48 per-entry spec
citations went missing. Section pointers (`§x.y`) across the namespace
DEVIATIONS files fell 289 → 167; source-file pointers (`src/foo.js:123`) fell
296 → 174. Body text under the IDs: 50,555 → 29,723 words.

Concrete losses:

- `IC-3` no longer cites RFC 6698 or RFC 7671.
- `IC-11` no longer cites RFC 7858, RFC 8484, RFC 9460 or RFC 9848.
- `RT-1` no longer cites RFC 3172, RFC 6761, RFC 6762 or RFC 8375.
- `HS-14` no longer cites RFC 5890, RFC 5891 or UTS-46.
- `NO-16` no longer cites BIP-340 or RFC 6455.

`IC-3: no DANE for ICANN names, DELIBERATE` without "RFC 6698 defines TLSA;
RFC 7671 §4 recommends applying them wherever published; `.se` and `.nl`
publish TLSA today" is a list item. The citation was the record.

The asymmetry — `ipfs`, `keys`, `apps`, `experimental` at ~0.9 of their
original length while `handshake` and `icann` are at 0.35 — reads as an
unfinished pass rather than a design decision.

## 2. Numbers, filenames and one recorded lesson deleted from CHANGELOG.md

The CHANGELOG is where the version and test counts are tracked. The rewrite
removed:

- **"931 deterministic tests in 11 suites, no network"** (0.4.0). No count
  replaces it.
- **"69 copied modules, 8 declared factored"** — the `scripts/parity.mjs`
  byte-identity figures — replaced by "browser-module comparison tool".
- Every test filename that evidenced a claim: `tests/nameserver-failover.test.js`,
  `tests/route-path.test.js`, `tests/ipv6.test.js`.
- Every implementing source file: `namespaces/arweave/src/ar-merkle.js`,
  `src/delivery-mode.js`, `src/dane-connect.js`, `src/socks-dial.js`,
  `src/spv.js`, `src/trust-path.js`, `namespaces/did/src/did-local.js`,
  `nostr/tor-websocket.js`.
- Every spec pointer: `SPEC.md §4.2`, Handshake `§6.5f/§6.4/§6.2`, Chapter 5
  `§5.6a`, `DIVERGENCE` row 8, the RFC 3596 citation for IPv6.
- **The 0.5.0 threat analysis**, in full: *"An attacker who forges an empty `A`
  can only steer a client to the zone's own signed `AAAA`; a tampered `AAAA`
  fails closed; an address family that could not be asked is `unreachable`,
  never `unregistered`."*
- **The `_synth` trap.** 0.5.0 said the SPV reader *"kept that name AS a
  nameserver and looked for the apex address in the answer section, where the
  root server never puts it, so no SYNTH apex resolved from an SPV node."*
  The rewrite says "Added decoding of hsd's `_synth` referrals". That is a
  lesson we paid for, and it is now unrecoverable from this repo.
- **"eighteen both-sides rows are built, and the five that survive are shipped"**
  → "Added the privacy/transport inventory". Both figures gone.
- A weakened behaviour claim in 0.7.0: *"a body under 8 MiB must hash to the
  proven header's `data_root` **or is refused**"* → "…comparing against the
  header's `data_root`". The fail-closed half of the sentence is what mattered.

## 3. README.md, the generated headers and the build script

- **README lost the Scope / Out-of-scope table**, which named for each excluded
  concern exactly which file in the browser tree owns it instead
  (`src/hns/ipfs.js`, `PUBLISHING-AND-DNS.md`, `src/ui/`, `src/protocols/index.js`).
  That table is how a reader finds the other half of the system.
- **README lost the Layout block** — the map from each `namespaces/<ns>/` to its
  chapter number and its implementing source file (`src/router.js`,
  `src/hip5-op.js`, `src/hns-url.cjs`, `src/ws-proxy.js`, …).
- README lost the reason the tests mean anything: *"several Handshake tests
  spawn a real authoritative nameserver, `tests/fixtures/resolver/nsd.py`, over
  frozen signed zones, so 'the signature validated' means a real server served
  real wire bytes"*, and *"RPCs, gateways, relays, directories and Tor are all
  scripted fakes that misbehave on purpose."*
- README no longer documents `npm run parity`. The script still exists.
- **`scripts/build-docs.mjs` no longer emits the per-deviation table of
  contents.** The old builder walked every `### <ID>. Title` heading and listed
  each one under its chapter; the new one links to the chapter only. A large
  share of the 4,762-line shrink in the generated `DEVIATIONS.md` is that
  index. The at-a-glance "every deviation by id" view is gone.
- **The policy statement at the head of `DEVIATIONS.md` was removed**, and it is
  the rule the whole document runs on: *"A deviation is recorded whether or not
  we think it is right — `DELIBERATE` says we would make the same choice again
  and why, `OPEN` says we would not and what we recommend. And nothing here is
  history: a departure that no longer exists is not described."* Its
  replacement drops both rules. The definition of the uncertainty ID scheme
  (`§2.n` within a chapter) went with it.
- `package.json`'s description was replaced with a generic sentence. It is what
  npm and GitHub show.

## 4. Normative strength softened, and two judgment changes

Paraphrases that dropped the conformance verb:

- `RT-2`: *"RFC 7686 §2 rule 1: applications **SHOULD NOT** resolve `.onion`
  names via DNS, and by the same argument must not resolve them on a chain
  either"* → "RFC 7686 supplies the onion requirement."
- `NO-3`: *"NIP-65 defines kind:10002 as the mechanism by which an author
  announces where their events can be found, and says clients **SHOULD**
  consult it"* → "NIP-65 defines author-published relay lists."
- `TO-7`: MUST → "requires". Acceptable.

Two entries changed position rather than wording, which is a decision for you,
not a copy edit:

- **`AR-3` flipped `DELIBERATE` → `OPEN`** and reversed the argument. Old: an
  Arweave identifier is immutable so a longer cache would be safe, and being
  conservative costs lookups and nothing else. New: the transaction id is
  immutable but the *name-to-id binding* is not, so the authoritative TTL still
  governs. The new position looks right, but it is a new position.
- **`NT-3` lost its `OPEN` status keyword entirely** — the only one of 168 with
  no greppable status — and lost the fact that it is "not fixable inside this
  codebase".

## 5. The three things worth keeping

1. **`AR-1` downgraded `RESOLVED` → `PARTIALLY IMPLEMENTED`, and it is right.**
   The rewrite found a real bug the old text papered over. `namespaces/arweave/src/ar.js:38`
   `headerMatchesId()` hashes the signature bytes and compares to the txid —
   and does nothing else. It never checks that the signature covers the header
   fields, so `owner`, `data_root`, `data_size` and `tags` can all be changed
   while keeping `signature` and the check still passes. Confirmed by reading
   the function. This deserves its own fix and its own entry regardless of what
   happens to the rewrite.
2. **`EN-1` corrected a stale entry.** Old said only `contenthash` is read and
   `text` is not. Since 2026-09-06 the no-website page reads seven ENSIP-5 text
   keys, capped at 512 characters — `namespaces/ens/src/ens-protocol.js:125`
   (`TEXT_KEYS`) and `:348` (`.slice(0, 512)`) confirm exactly that.
3. **`REVIEW.md` (new, 280 lines)** — the contradictions the rewrite found
   between the notes, the spec and the source. Worth having whatever else is
   decided.

Also genuinely additive: two new standards cited tree-wide (132 → 134, RFC 9849
added) and 23 net new `REFERENCES.md` rows.

## Recommendation

Do not `git merge --ff-only FETCH_HEAD`.

Cherry-pick the substance of §5 — the `AR-1` correction, the `EN-1` correction,
`REVIEW.md` — as their own commits against the existing schema. If the plain-
language pass is still wanted, redo it under a rule the next agent is given up
front: **prose may be rewritten; `The standard says`, `Why`, the per-entry spec
citations, the `§` and `src/file.js:line` pointers, the counts, and the
DEVIATIONS policy header may not be removed.** Restoring them for the six
gutted namespaces from `bd720c1` is mechanical if the rest of the pass is kept.

The `AR-1` `headerMatchesId()` gap is a live finding and should not wait on the
documentation question.

## What was done

All three of §5 were taken, as their own work rather than as this commit. The
`headerMatchesId()` gap was fixed in the browser and in this repository — the
transaction signature is verified over the header's fields
(`namespaces/arweave/src/ar-tx.js`) — and `AR-1` and `EN-1` were corrected in
their chapters. `REVIEW.md` is in the repository, re-checked against the
current code and reduced to what is still open. The plain-language pass was
not taken, and the rule it would have to be redone under stands as written
above.
