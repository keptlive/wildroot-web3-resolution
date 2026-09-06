/*
 * The authoritative-nameserver fixture: one interpreter rule, one copy of
 * nsd.py, one frozen zone.
 *
 * TWO FAILURES MOTIVATE THIS FILE, both of which made the release gate report
 * green on the machine that builds the installers we ship.
 *
 * 1. THE INTERPRETER. Four test files spawned the literal string 'python3'.
 *    On Windows the interpreter is `python`; `python3` is a Microsoft Store
 *    alias that exits without running anything. So every test that needed a
 *    nameserver could only ever have failed there — which nobody saw, because
 *    they were already skipping for reason 2.
 *
 * 2. THE TOOLCHAIN. They resolved nsd.py and zones.json out of ~/hns, a
 *    directory that exists on exactly one machine, and SKIPPED when it was
 *    absent. 22 resolver tests — the DNSSEC chain, fail-closed validation,
 *    the DO-bit regression pin, TLSA NODATA — silently did not run on the
 *    Windows packaging box. The same shape as the dnssec.test.js gap that
 *    tests/fixtures/dir.dnssec.json was vendored to close.
 *
 *    Reading ~/hns/zones.json was also a correctness problem on the machine
 *    that HAS it: that file is LIVE OPERATOR DATA. The tests searched it for a
 *    host of a suitable shape, so what they asserted drifted with production —
 *    and had already gone stale once (see the header of dnssec-e2e.test.js).
 *
 * So the zone is FROZEN in tests/fixtures/resolver/ and the tests assert
 * against it by name. See that directory's README.md for provenance and the
 * regeneration recipe.
 *
 * NOT vendored, and deliberately still a skip: the regtest hsd node that
 * resolver.test.js and handler.test.js need for real SPV proofs. That is a
 * running daemon with chain state, not a file.
 */

import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { query, TYPES } from '../src/dns-query.js'

const HERE = path.dirname(fileURLToPath(import.meta.url))

/** Where the frozen nameserver + zone live. */
export const FIXTURE_DIR = path.join(HERE, 'fixtures', 'resolver')
export const NSD_PY = path.join(FIXTURE_DIR, 'nsd.py')
export const ZONES = path.join(FIXTURE_DIR, 'zones.json')
export const TENANT_ZONES = path.join(FIXTURE_DIR, 'zones-tenant.json')

/** The zone the frozen fixture publishes, and the hosts that give it teeth. */
export const FIXTURE = {
  zone: 'wrfixture',
  signed: path.join(FIXTURE_DIR, 'wrfixture.dnssec.json'),
  // A record + TLSA, no TXT pointer: the only shape that reaches the
  // DNSSEC -> TLSA validation path.
  siteHost: 'site.wrfixture',
  // A record, no TLSA at its _443._tcp owner: the NODATA case.
  noTlsaHost: 'plain.wrfixture',
  tlsaOwner: '_443._tcp.site.wrfixture',
  noTlsaOwner: '_443._tcp.plain.wrfixture',
  // An operator-published ipfs= TXT: the pointer path.
  pointerHost: 'pointer.wrfixture',
  // Published ONLY in zones-tenant.json, so it exists in the signed file and
  // NOT in the operator zones.json. The DO-bit regression pin.
  tenantHost: 'tenant.wrfixture'
}

/**
 * Which Python to spawn on this platform. Pure, so the rule is testable
 * without a Windows box.
 *
 * `python3` does not exist on Windows: what is on PATH there is `python`, and
 * a bare `python3` hits the Microsoft Store app-execution alias, which prints
 * an advert and exits 9009 without ever running the script. PYTHON overrides
 * both, for a machine with the interpreter somewhere unusual.
 *
 * @param {string} [platform] defaults to process.platform
 * @param {Record<string, string|undefined>} [env] defaults to process.env
 * @returns {string}
 */
export function pythonInterpreter (platform = process.platform, env = process.env) {
  const override = env && env.PYTHON
  if (typeof override === 'string' && override.trim()) return override.trim()
  return platform === 'win32' ? 'python' : 'python3'
}

export const PYTHON = pythonInterpreter()

/**
 * Run `fn` against a live nsd.py on `port`, serving `zones`.
 *
 * Deliberately has NO skip path. A missing interpreter throws, because a test
 * that quietly does not run is what this file exists to stop; if Python is
 * genuinely somewhere else, set PYTHON.
 *
 * @param {{port: number, zones?: string, nsd?: string}} options
 * @param {() => Promise<void>|void} fn
 */
export async function withNsd ({ port, zones = ZONES, nsd = NSD_PY }, fn) {
  if (!existsSync(nsd)) throw new Error(`nameserver fixture missing: ${nsd}`)
  const child = spawn(PYTHON, [nsd, '--port', String(port),
    '--zones', zones, '--quiet'], { stdio: 'ignore' })
  let spawnError = null
  child.once('error', (err) => { spawnError = err })
  try {
    let up = false
    for (let i = 0; i < 24 && !up; i++) {
      await new Promise((resolve) => setTimeout(resolve, 250))
      if (spawnError) break
      try {
        await query('127.0.0.1', port, 'example', TYPES.TXT, { timeout: 500 })
        up = true
      } catch {}
    }
    if (!up) {
      throw new Error(
        `nsd.py did not start with '${PYTHON}'` +
        (spawnError ? ` (${spawnError.message})` : '') +
        '. On Windows the interpreter is `python`, not `python3`; set PYTHON ' +
        'to override.')
    }
    await fn()
  } finally {
    child.kill('SIGTERM')
  }
}
