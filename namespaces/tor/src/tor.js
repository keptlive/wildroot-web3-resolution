/*
 * The browser's own Tor client — "IP Protection".
 *
 * What this buys the user, honestly: when it is on, every request rides a
 * SOCKS proxy into the Tor network, so the site (and any search engine we
 * fan out to) sees a Tor exit node's IP, not the user's. That hides the
 * user's IP. It is NOT full anonymity: this browser does not yet resist
 * fingerprinting the way Tor Browser does, so a determined site can still
 * tell one visitor from another by other means. The UI says both things.
 *
 * Why a bundled client: a user who has never installed Tor should still get
 * IP protection. So this class ships and supervises its OWN tor binary,
 * modelled on SPVNode — spawned as a killable process group, reaped across
 * runs via a pid file, api-free (no ControlPort), fail-fast on early death,
 * and gated on a real "Bootstrapped 100%" readiness signal rather than a
 * bare socket open.
 *
 * Where the client comes from, in order:
 *   1. the BUNDLED tor binary under vendor/tor/<platform>-<arch>/ (placed by
 *      the packaging step; on a dev box without one, this is simply absent)
 *   2. an EXTERNAL tor the user already runs on 127.0.0.1:9050 (fallback)
 *   3. nothing -> unavailable, and the caller stays on a direct connection
 *      with an honest note. The browser degrades; it never pretends.
 *
 * Bootstrapping Tor is slow (10-60s on a first connection), so start() does
 * NOT block on it: it decides availability quickly and returns 'connecting'
 * while the bootstrap finishes in the background. The controller routes
 * traffic to the chosen SOCKS port immediately, so nothing leaks around the
 * tunnel during those seconds — requests simply wait for the circuit.
 */

import { spawn } from 'node:child_process'
import { EventEmitter } from 'node:events'
import { fileURLToPath } from 'node:url'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'

import { spawnGroupOpts, killTree, killPid } from '../../../src/proc.js'
import { anyFreePort } from './free-port.js'

const EXTERNAL_HOST = '127.0.0.1'
const EXTERNAL_PORT = 9050 // where a user's OWN tor listens by default

// Locate the bundled tor binary as an ABSOLUTE path (never trusted to PATH).
// Placed by the packaging step at vendor/tor/<platform>-<arch>/tor(.exe); the
// .asar -> .asar.unpacked swap mirrors resolveHsdBin, because an executable
// cannot run from inside the asar archive. Returns null when nothing is
// vendored for this platform (the normal case on a Linux dev box).
function resolveTorBin () {
  const bin = process.platform === 'win32' ? 'tor.exe' : 'tor'
  const dir = `${process.platform}-${process.arch}`
  const p = fileURLToPath(new URL(`../../vendor/tor/${dir}/${bin}`, import.meta.url))
    .replace(`.asar${path.sep}`, `.asar.unpacked${path.sep}`)
  return fs.existsSync(p) ? p : null
}

/**
 * The environment the bundled tor needs to find its OWN libraries.
 *
 * The Windows Expert Bundle's tor.exe is static, but the Linux one is
 * dynamically linked against libevent/libssl/libcrypto shipped BESIDE it —
 * with no RUNPATH, so the loader will not look there (verified 2026-08-29,
 * readelf -d). scripts/fetch-tor.mjs places those libraries next to the
 * binary; this points the loader at that directory, exactly as
 * src/media/transcoder.js mediaSpawnEnv() does for the vendored ffmpeg.
 * Windows needs nothing. Exported so a test can assert it without spawning.
 * @param {string} bin absolute path to the vendored tor
 */
export function torSpawnEnv (bin) {
  if (process.platform === 'win32' || !bin) return { ...process.env }
  const dir = path.dirname(bin)
  // darwin: DYLD_LIBRARY_PATH is the analogue; untested until a mac build
  // is pinned (vendor/tor/manifest.json). Setting it is harmless on Linux.
  const out = { ...process.env }
  for (const key of ['LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH']) {
    out[key] = process.env[key] ? `${dir}${path.delimiter}${process.env[key]}` : dir
  }
  return out
}

// A tor "Bootstrapped" log line, e.g.
//   Aug 24 12:00:00.000 [notice] Bootstrapped 45% (requesting_descriptors): Asking for relay descriptors
// (older tor omits the (tag): "Bootstrapped 50%: Loading relay descriptors").
// Returns the LATEST (highest) bootstrap point in a buffer that may carry
// several lines, or null when the buffer names no bootstrap progress at all.
const BOOTSTRAP_RE = /Bootstrapped (\d+)%(?:\s*\(([^)]*)\))?(?::\s*([^\r\n]*))?/g

export function parseBootstrap (chunk) {
  const s = String(chunk)
  let best = null
  let m
  BOOTSTRAP_RE.lastIndex = 0
  while ((m = BOOTSTRAP_RE.exec(s))) {
    const percent = Number(m[1])
    // The phase word is the human-readable message when present, else the tag.
    const message = (m[3] || '').trim()
    const tag = (m[2] || '').trim()
    const cand = { percent, tag, message: message || tag }
    if (!best || cand.percent >= best.percent) best = cand
  }
  return best
}

export class TorNode extends EventEmitter {
  /**
   * @param {object} [opts]
   * @param {string} [opts.dataDir]  torrc + DataDirectory live here
   * @param {string} [opts.binPath]  override the bundled binary (tests)
   * @param {number} [opts.socksPort] override the chosen SOCKS port (tests)
   * @param {number} [opts.bootstrapTimeout] ms to wait for "Bootstrapped 100%"
   * @param {Function} [opts.spawnImpl] injected child spawner (tests)
   * @param {Function} [opts.detectExternal] async () => boolean (tests)
   */
  constructor ({ dataDir, binPath, socksPort, bootstrapTimeout = 90_000, spawnImpl, detectExternal } = {}) {
    super()
    this.dataDir = dataDir || path.join(os.homedir(), '.hnsone-browser', 'tor')
    this._binPath = binPath // undefined => resolve the bundled one
    this._socksPort = socksPort || null
    this._bootstrapTimeout = bootstrapTimeout
    this._spawn = spawnImpl || spawn
    this._detectExternal = detectExternal ||
      (() => detectConnect(EXTERNAL_HOST, EXTERNAL_PORT, 1500).then(() => true, () => false))

    this.child = null
    this._external = false
    this._available = false // do we have a SOCKS port to route to?
    this._ready = false // has tor Bootstrapped 100%?
    // Live bootstrap progress, parsed from tor's stdout, so the UI can show a
    // real "Connecting to Tor… 45%" instead of a static "up to a minute" note.
    this.bootstrapPercent = 0
    this.bootstrapPhase = ''
    this._socks = null
    this._stopped = false
    this._readyWaiters = []
    this._superviseTimer = null
    this._superviseFails = 0
    this._recovering = false
  }

  /**
   * Decide availability and, for the bundled binary, kick off the bootstrap.
   * Resolves quickly (does NOT wait out the full bootstrap) with one of:
   *   'ready'       — a SOCKS proxy is up and usable right now
   *   'connecting'  — bundled tor spawned, still bootstrapping in background
   *   'unavailable' — no bundled binary and no external tor; stay direct
   */
  async start () {
    this._stopped = false
    if (this._ready) return 'ready'

    const bin = this._binPath !== undefined ? this._binPath : resolveTorBin()
    if (bin) {
      try {
        await this._spawnTor(bin)
        this._supervise()
        return this._ready ? 'ready' : 'connecting'
      } catch (err) {
        console.error('IP protection: bundled Tor failed to start —', err.message)
        await this.stopChild()
        this._available = false
      }
    }

    // Fallback: a tor the user runs themselves. NEVER "recover" toward this
    // one later unless the user configured it — it is theirs, not ours.
    if (await this._detectExternal()) {
      this._external = true
      this._available = true
      this._ready = true
      this._socks = `socks5://${EXTERNAL_HOST}:${EXTERNAL_PORT}`
      // An external tor is already bootstrapped from our point of view.
      this._setBootstrap(100, 'Done')
      this._flushReady(true)
      return 'ready'
    }

    this._available = false
    return 'unavailable'
  }

  async _spawnTor (bin) {
    // A fresh process bootstraps from zero (matters on the recovery respawn).
    this.bootstrapPercent = 0
    this.bootstrapPhase = ''
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 })
    const dataSub = path.join(this.dataDir, 'data')
    fs.mkdirSync(dataSub, { recursive: true, mode: 0o700 })

    // A non-default loopback SOCKS port, chosen once per session, so we coexist
    // with any system Tor on 9050 instead of fighting it for the port.
    if (!this._socksPort) this._socksPort = await anyFreePort('127.0.0.1')
    const port = this._socksPort
    this._socks = `socks5://127.0.0.1:${port}`

    // No ControlPort: readiness comes from the log line, not a control API, so
    // there is no local control socket to authenticate or leak.
    const torrc = [
      // IPv6Traffic: a Handshake site that has only an AAAA is dialled by
      // that address (ATYP 0x04); without the flag Tor refuses the request.
      `SocksPort 127.0.0.1:${port} IPv6Traffic`,
      `DataDirectory ${dataSub}`,
      'ClientOnly 1',
      'AvoidDiskWrites 1',
      'Log notice stdout',
      ''
    ].join('\n')
    const torrcPath = path.join(this.dataDir, 'torrc')
    fs.writeFileSync(torrcPath, torrc, { mode: 0o600 })

    const pidFile = path.join(this.dataDir, '.tor-pid')
    // Reap an orphan from a previous run (a SIGKILL skips our clean shutdown)
    // so its held SOCKS port frees up before we spawn a fresh one.
    const orphan = Number(this._read(pidFile))
    if (orphan) { try { killPid(orphan) } catch {} }

    this.child = this._spawn(bin, ['-f', torrcPath], spawnGroupOpts({
      stdio: ['ignore', 'pipe', 'pipe'],
      env: torSpawnEnv(bin)
    }))
    if (this.child.unref) this.child.unref()
    try { fs.writeFileSync(pidFile, String(this.child.pid), { mode: 0o600 }) } catch {}

    let died = null
    this.child.on('error', (err) => { died = err; this.child = null })
    this.child.on('exit', (code) => {
      died = died || new Error(`tor exited ${code}`)
      this._ready = false
    })
    const onLine = (buf) => {
      const s = String(buf)
      const progress = parseBootstrap(s)
      if (progress) this._setBootstrap(progress.percent, progress.message)
      if (/Bootstrapped 100%/.test(s)) {
        this._ready = true
        this._flushReady(true)
      }
    }
    if (this.child.stdout) this.child.stdout.on('data', onLine)
    if (this.child.stderr) this.child.stderr.on('data', onLine)

    // Short grace window: catch a binary that dies on launch (so start() can
    // fall back to external tor) without waiting out the whole bootstrap.
    for (let i = 0; i < 20; i++) {
      await sleep(100)
      if (died) throw died
      if (this._ready) break
    }
    this._available = true

    // Keep resolving whenReady() in the background until Bootstrapped 100% or
    // the bootstrap timeout — whichever comes first.
    if (!this._ready) {
      this._bootDeadline = setTimeout(() => {
        if (!this._ready) this._flushReady(false)
      }, this._bootstrapTimeout)
      if (this._bootDeadline.unref) this._bootDeadline.unref()
    }
  }

  /**
   * Record and announce a bootstrap tick. Monotonic — a later log line can
   * never drag the displayed percent backwards (tor occasionally re-emits an
   * earlier phase). Emits 'bootstrap' so the controller can surface live
   * progress; display-only, it never changes the leak-safe routing.
   */
  _setBootstrap (percent, phase) {
    if (!Number.isFinite(percent)) return
    if (percent < this.bootstrapPercent) return
    this.bootstrapPercent = percent
    if (phase) this.bootstrapPhase = phase
    this.emit('bootstrap', { percent: this.bootstrapPercent, phase: this.bootstrapPhase })
  }

  /** Latest bootstrap progress for the UI. */
  bootstrapProgress () {
    return { percent: this.bootstrapPercent, phase: this.bootstrapPhase }
  }

  /** True once tor has bootstrapped (external tor: immediately). */
  isReady () { return this._ready }

  /** True when there is a SOCKS port to route to — bootstrapped or not. */
  isAvailable () { return this._available }

  /** True when we are using the user's own tor, not our bundled one. */
  isExternal () { return this._external }

  /** The SOCKS URL to route through, or null when unavailable. */
  socksUrl () { return this._available ? this._socks : null }

  /**
   * Resolves true when tor finishes bootstrapping, false if it never does
   * (early exit or bootstrap timeout). Callers use this to flip the UI from
   * "connecting…" to "routing" without blocking the mode switch.
   */
  whenReady () {
    if (this._ready) return Promise.resolve(true)
    if (!this._available) return Promise.resolve(false)
    return new Promise((resolve) => { this._readyWaiters.push(resolve) })
  }

  _flushReady (ok) {
    const waiters = this._readyWaiters
    this._readyWaiters = []
    for (const r of waiters) { try { r(ok) } catch {} }
  }

  /**
   * A bundled tor can die under us. Probe the SOCKS port every 30s; after 3
   * consecutive failures, respawn our own — but only ours. An external tor the
   * user runs is theirs to restart; we only re-probe it, never adopt/replace.
   */
  _supervise () {
    if (this._superviseTimer || this._stopped || this._external) return
    this._superviseFails = 0
    this._superviseTimer = setInterval(async () => {
      if (this._recovering || this._stopped || !this._available) return
      if (await detectConnect('127.0.0.1', this._socksPort, 1500).then(() => true, () => false)) {
        this._superviseFails = 0
        return
      }
      this._superviseFails++
      if (this._superviseFails < 3) return
      console.error('IP protection: bundled Tor stopped answering — recovering')
      this._recovering = true
      try {
        await this.stopChild()
        this._ready = false
        this._available = false
        const bin = this._binPath !== undefined ? this._binPath : resolveTorBin()
        if (bin) {
          await this._spawnTor(bin)
          console.log('IP protection: bundled Tor recovered')
        }
        this._superviseFails = 0
      } catch (err) {
        console.error('IP protection: Tor recovery failed:', err.message)
      } finally {
        this._recovering = false
      }
    }, 30_000)
    if (this._superviseTimer.unref) this._superviseTimer.unref()
  }

  _read (file) {
    try { return fs.readFileSync(file, 'utf8').trim() } catch { return null }
  }

  /**
   * Kill only our own child (recovery path). No-op for external tor. An
   * orphan from a previous run is reaped by pid file on the next start(),
   * never adopted — unlike spv.js, which adopts and reaps its orphan here.
   */
  async stopChild () {
    if (this.child) killTree(this.child)
    this.child = null
  }

  async stop () {
    this._stopped = true
    if (this._superviseTimer) { clearInterval(this._superviseTimer); this._superviseTimer = null }
    if (this._bootDeadline) { clearTimeout(this._bootDeadline); this._bootDeadline = null }
    this._flushReady(false)
    this._ready = false
    this._available = false
    if (!this._external) await this.stopChild()
  }
}

function sleep (ms) { return new Promise((resolve) => setTimeout(resolve, ms)) }

/** Resolve if a TCP connection to host:port succeeds within timeout, else reject. */
function detectConnect (host, port, timeout) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port })
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('timeout')) }, timeout)
    socket.once('connect', () => { clearTimeout(timer); socket.destroy(); resolve() })
    socket.once('error', (err) => { clearTimeout(timer); reject(err) })
  })
}
