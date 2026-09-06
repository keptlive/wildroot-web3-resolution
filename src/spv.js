/*
 * The browser's connection to the Handshake chain: an hsd SPV node.
 *
 * Trust model, in one paragraph: every name lookup goes through
 * getnameresource on an SPV node, which validates an Urkel tree proof
 * against block headers it has verified itself. The browser therefore
 * never trusts a resolver's word for what a name's records are — a lying
 * server can at worst withhold an answer, not forge one. This is the part
 * DoH-based Handshake browsers skip, and the reason this module exists.
 *
 * Where the node comes from, in order:
 *   1. HNSONE_SPV_URL + HNSONE_SPV_KEY env (tests point this at regtest)
 *   2. an hsd already running on this machine (~/.hsd-spv, port 13037)
 *   3. a child hsd --spv spawned from the BUNDLED hsd dependency, under the
 *      browser's own profile dir
 *
 * The child node is the bundled hsd (a dependency, resolved to an absolute
 * path — not assumed on PATH) — no wallet is created and no wallet API is ever
 * exposed; the browser reads names, it cannot spend.
 *
 * NETWORK, declared (hsd is an npm dependency with no vendor manifest, so
 * this header is its `network` field; capture-verified 2026-08-29,
 * docs/BUNDLED-DEPENDENCIES.md): outbound TCP to Handshake peers on 12038
 * and whatever ports `getaddr` hands back, from every browser launch, for
 * headers and Urkel proofs — nothing inbound (--listen=false), no UDP, and
 * in practice no DNS: hsd dials its compiled-in seed IPs first. Dormant
 * fallback worth knowing: when it cannot hold two outbound peers it resolves
 * its two seed hostnames through a list hard-wired in hsd/lib/net/lookup.js
 * (1.1.1.1, 8.8.8.8/8.8.4.4, OpenDNS) over plaintext UDP 53 — not the OS
 * resolver, not the browser's ODoH. Not observed in the capture; recorded in
 * ~/hns/PRIVACY-COSTS.md §8. We never call getpeerinfo, which would
 * reverse-DNS every peer.
 */

import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'

import { spawnGroupOpts, killTree, killPid } from './proc.js'

// Resolve our own SPV launcher to an ABSOLUTE path (spawned with the
// Electron/node runtime directly — never via PATH or shell:true). We use our
// launcher rather than hsd/bin/hsd because upstream's script hard-exits unless
// bcrypto's NATIVE bindings are compiled; we run with NODE_BACKEND=js so users
// never need a C++ toolchain. Returns null only if hsd itself is missing.
function resolveHsdBin () {
  const req = createRequire(import.meta.url)
  try {
    req.resolve('hsd/lib/node/spvnode') // hsd installed?
  } catch {
    return null
  }
  return fileURLToPath(new URL('./hsd-spv-launcher.cjs', import.meta.url))
    .replace(`.asar${path.sep}`, `.asar.unpacked${path.sep}`)
}

const LOCAL_SPV = 'http://127.0.0.1:13037'
const LOCAL_KEY_FILE = path.join(os.homedir(), '.hsd-spv', '.node-api-key')

/**
 * The ports a spawned node PREFERS: dedicated numbers so two of our own
 * instances never share one by accident (http = the RPC, ns = the root
 * nameserver getResource() queries). Preferred, not assumed — see
 * _claimPorts. No recursive resolver: the browser never queries one, so
 * the node is started with --no-rs and binds nothing for it.
 */
export const DEFAULT_PORTS = Object.freeze({ http: 14539, ns: 14541 })

/** Beside the api key: the ports the spawned node was given. */
const PORTS_FILE = '.node-ports'

/** How much of hsd's stderr is kept to explain an exit. */
const STDERR_TAIL_BYTES = 4096

/**
 * The one line of a stderr tail worth putting in a log: the first `Error:`
 * line if there is one (hsd prints err.stack — the message, then frames),
 * else the last non-empty line. Empty stderr adds nothing.
 * @param {string} stderr
 */
export function explain (stderr) {
  const lines = String(stderr || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
  if (!lines.length) return ''
  const error = lines.find((l) => /^\w*Error\b/.test(l))
  return `: ${(error || lines[lines.length - 1]).slice(0, 300)}`
}

/**
 * Can this process bind `port` on loopback right now? A bind test, not a
 * connect: a connect answers "is someone there", which is the wrong question
 * (a node that is shutting down still accepts, a node with a different api
 * key answers 401 to the probe). EADDRINUSE from a real bind is what hsd
 * itself would get.
 * @param {number} port
 * @returns {Promise<boolean>}
 */
function portFree (port) {
  return new Promise((resolve) => {
    const server = net.createServer()
    server.unref()
    server.once('error', () => resolve(false))
    server.listen({ port, host: '127.0.0.1', exclusive: true }, () => {
      server.close(() => resolve(true))
    })
  })
}

/**
 * `count` distinct free loopback ports, held together while chosen so two
 * cannot be the same, then released for hsd to take.
 * @param {number} count
 * @returns {Promise<number[]>}
 */
async function freePorts (count) {
  const servers = []
  const ports = []
  try {
    for (let i = 0; i < count; i++) {
      const server = net.createServer()
      server.unref()
      await new Promise((resolve, reject) => {
        server.once('error', reject)
        server.listen({ port: 0, host: '127.0.0.1', exclusive: true }, resolve)
      })
      servers.push(server)
      ports.push(server.address().port)
    }
  } finally {
    await Promise.all(servers.map((s) => new Promise((resolve) => s.close(() => resolve()))))
  }
  return ports
}

// Is bdb's native LevelDB binding compiled? Loading bdb/lib/level.js throws
// when it is not (loady can't find leveldown.node). Cached: it cannot change
// within a run.
let _nativeLevel = null
function nativeLevelAvailable () {
  if (_nativeLevel === null) {
    try {
      createRequire(import.meta.url)('bdb/lib/level.js')
      _nativeLevel = true
    } catch {
      _nativeLevel = false
    }
  }
  return _nativeLevel
}

export class SPVNode {
  /**
   * @param {object} [opts]
   * @param {string} [opts.url] an external node to use instead of spawning
   * @param {string} [opts.apiKey]
   * @param {string} [opts.prefix] the spawned node's data directory
   * @param {string} [opts.bin] the launcher script to spawn (tests: a fake)
   * @param {{http: number, ns: number}} [opts.ports] the ports to PREFER for a
   *   spawned node; taken when free, replaced when not (see _claimPorts)
   * @param {number} [opts.pollMs] how often a spawned node is probed while it
   *   comes up (tests shorten it; the 30-probe budget is unchanged)
   */
  constructor ({ url, apiKey, prefix, bin, ports, pollMs = 1000 } = {}) {
    this.url = url || process.env.HNSONE_SPV_URL || null
    this.apiKey = apiKey || process.env.HNSONE_SPV_KEY || null
    // Remember what was EXPLICITLY configured: supervision must never
    // "recover" away from a node the user pointed us at.
    this._configuredUrl = this.url
    this.prefix = prefix || path.join(os.homedir(), '.hnsone-browser', 'hsd')
    this.bin = bin || null
    this.preferredPorts = ports || DEFAULT_PORTS
    this.pollMs = pollMs
    /** @type {{http: number, ns: number}?} the spawned/adopted node's ports */
    this.ports = null
    this.child = null
    this._superviseTimer = null
    this._superviseFails = 0
    this._recovering = false
    this._stopped = false
  }

  async start () {
    if (!this.url) {
      const localKey = this._readKey(LOCAL_KEY_FILE) || this._wslKey()
      if (await this._probe(LOCAL_SPV, localKey)) {
        this.url = LOCAL_SPV
        this.apiKey = localKey
      } else {
        await this._spawn()
      }
    }
    this._supervise()
    return this
  }

  /**
   * The node this session resolves through can die under us — an adopted
   * orphan reaped elsewhere, a WSL node killed by a Windows session change,
   * our own child crashing. Field failure 2026-08-17: the browser adopted a
   * node, the node died, and because startup success was latched the session
   * silently rode DoH forever — chain-proof resolution never came back.
   * Probe every 30s; after 3 consecutive failures, rebuild: prefer a healthy
   * local/WSL node again, else spawn our own. An explicitly configured URL
   * is only ever re-probed, never replaced.
   */
  _supervise () {
    if (this._superviseTimer || this._stopped) return
    this._superviseFails = 0
    this._superviseTimer = setInterval(async () => {
      if (this._recovering || this._stopped || !this.url) return
      if (await this._probe(this.url, this.apiKey)) {
        this._superviseFails = 0
        return
      }
      this._superviseFails++
      if (this._superviseFails < 3) return
      console.error(`HNS: SPV node at ${this.url} stopped answering — recovering`)
      this._recovering = true
      try {
        if (this._configuredUrl) return // external node: keep probing only
        // Reap our own dead child (if any) so ports free up, then rebuild.
        try { await this.stopChild() } catch {}
        this.url = null
        this.apiKey = null
        const localKey = this._readKey(LOCAL_KEY_FILE) || this._wslKey()
        if (await this._probe(LOCAL_SPV, localKey)) {
          this.url = LOCAL_SPV
          this.apiKey = localKey
        } else {
          await this._spawn()
        }
        console.log(`HNS: SPV node recovered at ${this.url}`)
        this._superviseFails = 0
      } catch (err) {
        // Leave url null-or-stale; next tick retries. Resolution rides DoH
        // meanwhile (isSynced() is false while the probe fails).
        console.error('HNS: SPV recovery failed:', err.message)
        this.url = this.url || null
      } finally {
        this._recovering = false
      }
    }, 30_000)
    if (this._superviseTimer.unref) this._superviseTimer.unref()
  }

  /**
   * Windows + WSL: an hsd running inside WSL answers on 127.0.0.1 (WSL2
   * localhost forwarding), but its api key lives on the WSL filesystem.
   * Windows can read it over the \\\\wsl.localhost UNC path — without this
   * the probe got a 401 and the browser pointlessly spawned a second node
   * that re-synced from genesis while a synced one sat next door.
   */
  _wslKey () { return this._wslRead('.node-api-key') }

  _wslRead (relname) {
    if (process.platform !== 'win32') return null
    for (const distro of ['Ubuntu', 'Ubuntu-24.04', 'Ubuntu-22.04', 'Debian']) {
      try {
        const home = `\\\\wsl.localhost\\${distro}\\home`
        for (const user of fs.readdirSync(home)) {
          const data = this._readKey(path.join(home, user, '.hsd-spv', relname))
          if (data) return data
        }
      } catch {}
    }
    return null
  }

  _readKey (file) {
    try {
      return fs.readFileSync(file, 'utf8').trim()
    } catch {
      return null
    }
  }

  async _probe (url, key) {
    try {
      const res = await this._rpc('getblockchaininfo', [], { url, key, timeout: 3000 })
      return res && typeof res.blocks === 'number'
    } catch {
      return false
    }
  }

  /**
   * Is the node at (or effectively at) the chain tip? A node that is still
   * syncing gives null proofs, so resolution must fall back to DoH until this
   * flips — and flip it can, mid-session, which is exactly the memory-mode
   * Windows story: DoH now, chain-proof in a few minutes. Cached briefly so a
   * burst of page loads costs one RPC, not one per subresource.
   */
  async isSynced () {
    const now = Date.now()
    if (this._syncedAt && now - this._syncedAt < 15000) return this._synced
    this._syncedAt = now
    try {
      const res = await this._rpc('getblockchaininfo', [],
        { url: this.url, key: this.apiKey, timeout: 2000 })
      // hsd's RPC reports bitcoin-style `verificationprogress` (the HTTP /
      // endpoint's field is `progress` — not this one). Progress ONLY: a
      // blocks>=headers heuristic is a lie on SPV nodes, where the chain IS
      // the headers so the two are always equal — it declared a node synced
      // at height 10k and made every name resolve as unregistered.
      const p = res && (res.verificationprogress ?? res.progress)
      this._synced = typeof p === 'number' && p > 0.999
    } catch {
      this._synced = false
    }
    return this._synced
  }

  /**
   * The ports to run on, decided BEFORE spawning rather than discovered by
   * the child failing.
   *
   * Field failure, diagnosed 2026-08-29 (docs/MVP-GAPS.md P1 #4): every cold
   * start on a fresh profile logged "hsd exited 1" and rode DoH for a minute.
   * With the child's stderr captured the reason was one line — `listen
   * EADDRINUSE 127.0.0.1:14539` — an hsd from an EARLIER run of a different
   * profile (a harness's, a crashed instance's) still holding our fixed port.
   * The adopt-the-orphan path could not see it: adoption needs the key file
   * in THIS prefix, and a foreign node's key is not here. So the fixed port
   * was assumed free, the child died on it, and the supervisor reported a
   * healthy machine as a broken node.
   *
   * Now: the preferred ports are bind-tested; when any is taken (a foreign
   * node, a predecessor still closing, anything else) fresh loopback ports
   * are allocated instead, and whichever set is used is persisted beside the
   * key so a later run can adopt this node wherever it landed. Nothing waits
   * on the port and nothing is logged as failed — a node on a different port
   * is exactly as good.
   * @returns {Promise<{http: number, ns: number}>}
   */
  async _claimPorts () {
    const preferred = this.preferredPorts
    const free = await Promise.all([portFree(preferred.http), portFree(preferred.ns)])
    if (free.every(Boolean)) return { http: preferred.http, ns: preferred.ns }
    const [http, ns] = await freePorts(2)
    const taken = free[0] ? preferred.ns : preferred.http
    console.log(`HNS: SPV port ${taken} is in use by another process; using ${http}/${ns} for this node`)
    return { http, ns }
  }

  /** The ports the last spawn in this prefix used, if the file is intact. */
  _savedPorts () {
    try {
      const saved = JSON.parse(fs.readFileSync(path.join(this.prefix, PORTS_FILE), 'utf8'))
      if (Number.isInteger(saved.http) && Number.isInteger(saved.ns)) return { http: saved.http, ns: saved.ns }
    } catch {}
    return null
  }

  async _spawn () {
    fs.mkdirSync(this.prefix, { recursive: true, mode: 0o700 })

    // An earlier run may have left an orphaned child (a SIGKILL does not run
    // our clean shutdown). Its api key and ports are persisted beside the
    // node, so adopt it instead of spawning a second node.
    const keyFile = path.join(this.prefix, '.node-api-key')
    const pidFile = path.join(this.prefix, '.node-pid')
    const existingKey = this._readKey(keyFile)
    const savedPorts = this._savedPorts()
    if (existingKey && savedPorts && await this._probe(`http://127.0.0.1:${savedPorts.http}`, existingKey)) {
      this.ports = savedPorts
      this.url = `http://127.0.0.1:${savedPorts.http}`
      this.apiKey = existingKey
      // Adopt the orphan's pid so stop() can reap it — otherwise a node we
      // spawned in a previous run outlives every browser session.
      this.adoptedPid = Number(this._readKey(pidFile)) || null
      return
    }

    const ports = await this._claimPorts()
    this.ports = ports
    this.url = `http://127.0.0.1:${ports.http}`
    const key = existingKey || randomBytes(20).toString('hex')
    this.apiKey = key
    // Key on disk (0600), not on argv where `ps` would expose it.
    fs.writeFileSync(keyFile, key, { mode: 0o600 })
    try { fs.writeFileSync(path.join(this.prefix, PORTS_FILE), JSON.stringify(ports), { mode: 0o600 }) } catch {}
    const args = [
      '--spv', '--no-wallet', '--no-rs',
      `--prefix=${this.prefix}`,
      '--http-host=127.0.0.1', `--http-port=${ports.http}`,
      `--ns-port=${ports.ns}`,
      '--listen=false'
    ]
    // Without the compiled LevelDB binding (Windows, no C++ toolchain) hsd
    // can still run entirely in memory: bdb's MemDB backend is pure JS. The
    // chain re-syncs each launch (headers only — minutes, in the background),
    // and resolution rides DoH until isSynced() flips. Detected once here so
    // machines WITH the native binding keep their persistent chain.
    if (!nativeLevelAvailable()) args.push('--memory')
    // Spawn the bundled hsd script with the current runtime (Electron runs it
    // as node via ELECTRON_RUN_AS_NODE). No shell, absolute paths, args as an
    // array — so a Windows profile path with spaces is passed intact. Detached
    // group (POSIX) / taskkill tree (Windows) reaps the worker tree on stop.
    const hsdBin = this.bin || resolveHsdBin()
    if (!hsdBin) throw new Error('bundled hsd not found')
    // NODE_BACKEND=js forces hsd's crypto (bcrypto/goosig) to its pure-JS
    // implementation, so the app never needs a C++ toolchain to build native
    // addons — critical on Windows, where users won't have Python + VS Build
    // Tools. Slightly slower crypto; fine for SPV header sync and lookups.
    //
    // stderr is PIPED, not ignored: it is the only place hsd says why it
    // exited, and an exit reported without it ("hsd exited 1") cost a day of
    // guessing. Its tail rides on the error; stdout (hsd's info log, which
    // also goes to debug.log in the prefix) stays ignored.
    this.child = spawn(process.execPath, [hsdBin, ...args], spawnGroupOpts({
      stdio: ['ignore', 'ignore', 'pipe'],
      env: { ...process.env, HSD_API_KEY: key, ELECTRON_RUN_AS_NODE: '1', NODE_BACKEND: 'js' }
    }))
    this.child.unref()
    let stderr = ''
    if (this.child.stderr) {
      this.child.stderr.unref()
      this.child.stderr.on('data', (chunk) => {
        stderr = (stderr + chunk).slice(-STDERR_TAIL_BYTES)
      })
    }
    // Persist the pid so a later run that adopts this node can also reap it.
    try { fs.writeFileSync(pidFile, String(this.child.pid), { mode: 0o600 }) } catch {}
    // Fail fast: if the child dies (hsd not installed, native build failure),
    // stop waiting immediately instead of burning the full 30s probe budget,
    // so the DoH fallback engages promptly — and say what it said.
    let died = null
    this.child.on('error', (err) => { died = err; this.child = null })
    this.child.on('exit', (code, signal) => {
      died = died || new Error(`hsd exited ${code === null ? signal : code}${explain(stderr)}`)
    })
    for (let i = 0; i < 30; i++) {
      await new Promise((resolve) => setTimeout(resolve, this.pollMs))
      if (died) throw new Error(`hsd SPV node failed to start: ${died.message}`)
      if (await this._probe(this.url, this.apiKey)) return
    }
    throw new Error('embedded hsd SPV node did not come up')
  }

  async _rpc (method, params, { url, key, timeout = 10000 } = {}) {
    const target = url || this.url
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeout)
    try {
      const headers = { 'Content-Type': 'application/json' }
      const k = key !== undefined ? key : this.apiKey
      if (k) {
        headers.Authorization =
          'Basic ' + Buffer.from(`x:${k}`).toString('base64')
      }
      const res = await fetch(target + '/', {
        method: 'POST',
        headers,
        body: JSON.stringify({ method, params }),
        signal: controller.signal
      })
      const body = await res.json()
      if (body.error) throw new Error(body.error.message || 'hsd error')
      return body.result
    } finally {
      clearTimeout(timer)
    }
  }

  /**
   * The chain's proof-verified records for a TLD, in getnameresource's JSON
   * shape.
   *
   * THREE ANSWERS, NOT TWO. `{records}` is a registered name; `null` means
   * the chain ANSWERED and has nothing for it; `{unreachable: true}` means we
   * could not ask at all. That last one used to be `null` as well, and the
   * difference matters a great deal: the sharing gate turns "unregistered"
   * into the sentence "There is no name alice.w3.", so a chain node that was
   * simply not running told the user, with complete confidence, that their
   * friend's name does not exist.
   *
   * On a FULL node the RPC works and is used directly. On an SPV node the RPC
   * always returns null ("Cannot prove in SPV mode" for proofs) — SPV nodes
   * serve chain data through their root NAMESERVER instead: query the TLD
   * there and the node fetches + verifies the Urkel proof from peers, then
   * answers as DNS — the delegation (NS/DS) in the AUTHORITY section, glue in
   * ADDITIONAL, apex records (TXT/A) as answers. Same local trust either way:
   * the node on this machine verified the proof against its own headers.
   */
  async getResource (tld) {
    let asked = false
    const viaRpc = await this._rpc('getnameresource', [tld])
      .then((r) => { asked = true; return r })
      .catch(() => null)
    if (viaRpc) return viaRpc
    const port = await this._nsPort()
    if (!port) return asked ? null : { unreachable: true }
    const { query, TYPES } = await import('./dns-query.js')
    const name = `${tld}.`
    const [ns, ds, txt, a] = await Promise.all(
      [TYPES.NS, TYPES.DS, TYPES.TXT, TYPES.A].map((t) =>
        query('127.0.0.1', port, name, t, { timeout: 5000, dnssec: true })
          .catch(() => null)))
    const records = []
    const seen = new Set()
    const push = (rec) => {
      const k = JSON.stringify([rec.type, rec.ns, rec.address, rec.txt, rec.digest])
      if (!seen.has(k)) { seen.add(k); records.push(rec) }
    }
    for (const r of [...((ns && ns.authority) || []), ...((ns && ns.answers) || [])]) {
      if (r.type === TYPES.NS && r.target) push({ type: 'NS', ns: `${r.target.replace(/\.$/, '')}.` })
    }
    for (const src of [ns, ds, txt, a]) {
      for (const r of (src && src.additional) || []) {
        if (r.type === TYPES.A && r.address) {
          push({ type: 'GLUE4', ns: `${String(r.name).replace(/\.$/, '')}.`, address: r.address })
        }
      }
      for (const r of [...((src && src.authority) || []), ...((src && src.answers) || [])]) {
        if (r.type === TYPES.DS && r.digest) {
          push({ type: 'DS', keyTag: r.keyTag, algorithm: r.algorithm, digestType: r.digestType, digest: r.digest })
        }
      }
    }
    for (const r of (txt && txt.answers) || []) {
      if (r.type === TYPES.TXT && r.txt) push({ type: 'TXT', txt: r.txt })
    }
    for (const r of (a && a.answers) || []) {
      // On-chain resources have no plain A at a TLD apex; the root server
      // synthesizes one from a SYNTH4/GLUE4-at-apex record.
      if (r.type === TYPES.A && r.address) push({ type: 'SYNTH4', address: r.address })
    }
    if (!records.length) {
      // Nothing came back. If EVERY query failed we never actually asked, and
      // saying "unregistered" would be a guess dressed as a fact.
      if (!asked && !ns && !ds && !txt && !a) return { unreachable: true }
      // NXDOMAIN (or nothing anywhere) — the name has no records / no state.
      return null
    }
    return { records }
  }

  /**
   * Port of the node's root nameserver — on 127.0.0.1 ONLY, always. Spawned
   * nodes use the ns port they were given (_claimPorts); a reused local node's port is read from its
   * hsd.conf next to the api key; HNSONE_SPV_NS_PORT overrides the PORT only.
   * The host is deliberately never configurable: a remote ns would mean raw
   * TCP to a remote host, which the anonymization design forbids. A remote
   * HNSONE_SPV_URL therefore gets NO ns-DNS lookups (returns null) — do not
   * "complete" this into remote-ns support.
   */
  async _nsPort () {
    if (process.env.HNSONE_SPV_NS_PORT) return Number(process.env.HNSONE_SPV_NS_PORT)
    if (this.ports && (this.child || this.adoptedPid)) return this.ports.ns
    if (this.url === LOCAL_SPV) {
      // The node's OWN config is the only trustworthy source for its ns port.
      // Guessing is dangerous: hsd's default 5349 can belong to a DIFFERENT
      // node on the same machine (seen live: a mid-resync full node answered
      // on 5349 with a STALE year-old tree, serving a name's previous owner's
      // dead nameservers). On Windows the conf lives on the WSL filesystem —
      // read it over the same UNC path as the api key.
      let conf = null
      try {
        conf = fs.readFileSync(
          path.join(os.homedir(), '.hsd-spv', 'hsd.conf'), 'utf8')
      } catch {}
      if (!conf) conf = this._wslRead('hsd.conf')
      if (conf) {
        const m = /^\s*ns-port:\s*(\d+)/m.exec(conf)
        if (m) return Number(m[1])
      }
      return conf ? 5349 : null // default only when the conf itself is silent
    }
    return null
  }

  async info () {
    return this._rpc('getblockchaininfo', [])
  }

  /** Kill only our own child/orphan process (recovery path). */
  async stopChild () {
    if (this.child) killTree(this.child)
    else if (this.adoptedPid) killPid(this.adoptedPid)
    this.child = null
    this.adoptedPid = null
  }

  async stop () {
    this._stopped = true
    if (this._superviseTimer) {
      clearInterval(this._superviseTimer)
      this._superviseTimer = null
    }
    await this.stopChild()
  }
}
