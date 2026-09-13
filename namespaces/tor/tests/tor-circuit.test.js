/*
 * TorNode — the device-local Tor client the whole onion path depends on.
 *
 * Every path is driven with an INJECTED spawner and external-detector, so no
 * real tor is required and nothing about the host machine can change the
 * result. That is deliberate and was learned the hard way: a version of the
 * last test here constructed a bare TorNode and relied on the machine having
 * no vendored binary and nothing on 9050, which made it an assertion about the
 * box rather than about the code — green on a Linux dev box, red on the
 * Windows packaging machine where a vendored tor.exe is present exactly as it
 * should be. Never reintroduce an ambient dependency in this file.
 *
 * NOTE ON THIS PACKAGE. `resolveTorBin()` looks for a vendored binary beside
 * the source tree. No binary is or ever will be vendored here, so it returns
 * null in this package and the bundled-tor branch is reachable only by
 * injecting `binPath`. See ../../../DEVIATIONS.md §4 (what the Tor chapter leaves out).
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { TorNode, parseBootstrap, torSpawnEnv } from '../src/tor.js'

function tmp () { return mkdtempSync(join(tmpdir(), 'tor-')) }

/** A fake `tor` child: an EventEmitter with stdout/stderr streams we drive. */
function fakeChild () {
  const ee = new EventEmitter()
  ee.pid = 4242
  ee.unref = () => {}
  ee.stdout = new EventEmitter()
  ee.stderr = new EventEmitter()
  return ee
}

// --- availability: the three states a caller must handle -------------------

test('no bundled binary AND no external tor -> unavailable (graceful)', async () => {
  const tor = new TorNode({ dataDir: tmp(), binPath: null, detectExternal: async () => false })
  assert.equal(await tor.start(), 'unavailable')
  assert.equal(tor.isReady(), false)
  assert.equal(tor.isAvailable(), false)
  assert.equal(tor.socksUrl(), null)
  assert.equal(await tor.whenReady(), false)
  await tor.stop()
})

test('no bundled binary but an external tor runs -> ready on 9050', async () => {
  const tor = new TorNode({ dataDir: tmp(), binPath: null, detectExternal: async () => true })
  assert.equal(await tor.start(), 'ready')
  assert.equal(tor.isReady(), true)
  assert.equal(tor.isExternal(), true)
  assert.equal(tor.socksUrl(), 'socks5://127.0.0.1:9050')
  assert.equal(tor.bootstrapProgress().percent, 100)
  await tor.stop()
})

test('a bundled tor that bootstraps -> ready on its chosen port', async () => {
  const child = fakeChild()
  const tor = new TorNode({
    dataDir: tmp(),
    binPath: 'fake-tor',
    socksPort: 40999,
    spawnImpl: () => child,
    detectExternal: async () => false
  })
  setTimeout(() => child.stdout.emit('data', Buffer.from('Bootstrapped 100% (done): Done\n')), 20)
  assert.equal(await tor.start(), 'ready')
  assert.equal(tor.isReady(), true)
  assert.equal(tor.isExternal(), false)
  assert.equal(tor.socksUrl(), 'socks5://127.0.0.1:40999')
  await tor.stop()
})

test('still bootstrapping -> connecting, with the SOCKS port ALREADY known', async () => {
  // This is the leak-safety property: the port is known before the circuit is
  // ready, so traffic can be pointed at it immediately and simply wait.
  const child = fakeChild()
  const tor = new TorNode({
    dataDir: tmp(),
    binPath: 'fake-tor',
    socksPort: 40998,
    spawnImpl: () => child,
    detectExternal: async () => false,
    bootstrapTimeout: 2000
  })
  assert.equal(await tor.start(), 'connecting')
  assert.equal(tor.isReady(), false)
  assert.equal(tor.socksUrl(), 'socks5://127.0.0.1:40998')
  const readyP = tor.whenReady()
  child.stdout.emit('data', 'Bootstrapped 100%')
  assert.equal(await readyP, true)
  assert.equal(tor.isReady(), true)
  await tor.stop()
})

test('a bundled binary that dies on launch falls back to the user own tor', async () => {
  const child = fakeChild()
  const tor = new TorNode({
    dataDir: tmp(),
    binPath: 'fake-tor',
    socksPort: 40997,
    spawnImpl: () => child,
    detectExternal: async () => true
  })
  setTimeout(() => child.emit('exit', 1), 10)
  assert.equal(await tor.start(), 'ready')
  assert.equal(tor.isExternal(), true)
  assert.equal(tor.socksUrl(), 'socks5://127.0.0.1:9050')
  await tor.stop()
})

test('a bundled binary that dies with no external tor -> unavailable', async () => {
  const child = fakeChild()
  const tor = new TorNode({
    dataDir: tmp(),
    binPath: 'fake-tor',
    socksPort: 40996,
    spawnImpl: () => child,
    detectExternal: async () => false
  })
  setTimeout(() => child.emit('exit', 1), 10)
  assert.equal(await tor.start(), 'unavailable')
  assert.equal(tor.socksUrl(), null)
  await tor.stop()
})

// --- a route that stops existing is revoked, synchronously -----------------

test('a tor that exits revokes the route it had offered, once', async () => {
  // Availability is not a slow-changing fact: between the process dying and
  // anybody noticing, socksUrl() would go on naming a port nothing listens
  // on, and a raw-socket caller would dial it.
  const child = fakeChild()
  const tor = new TorNode({
    dataDir: tmp(),
    binPath: 'fake-tor',
    socksPort: 40992,
    spawnImpl: () => child,
    detectExternal: async () => false
  })
  setTimeout(() => child.stdout.emit('data', Buffer.from('Bootstrapped 100% (done): Done\n')), 20)
  assert.equal(await tor.start(), 'ready')

  const events = []
  tor.on('route-unavailable', (e) => events.push(e))
  child.emit('exit', 1)
  assert.equal(events.length, 1, 'emitted synchronously with the exit')
  assert.equal(tor.isAvailable(), false)
  assert.equal(tor.isReady(), false)
  assert.equal(tor.socksUrl(), null)
  assert.equal(await tor.whenReady(), false, 'waiters are flushed false rather than left hanging')

  await tor.stop()
  assert.equal(events.length, 1, 'a route already revoked is not revoked again')
})

test('a tor that never offered a route emits nothing when it stops', async () => {
  // Startup is still free to choose its external fallback: revocation is about
  // taking back a route that was offered, not about announcing every failure.
  const tor = new TorNode({ dataDir: tmp(), binPath: null, detectExternal: async () => false })
  const events = []
  tor.on('route-unavailable', (e) => events.push(e))
  assert.equal(await tor.start(), 'unavailable')
  await tor.stop()
  assert.equal(events.length, 0)
})

test('stopping a running tor revokes its route', async () => {
  const child = fakeChild()
  const tor = new TorNode({
    dataDir: tmp(),
    binPath: 'fake-tor',
    socksPort: 40991,
    spawnImpl: () => child,
    detectExternal: async () => false
  })
  setTimeout(() => child.stdout.emit('data', Buffer.from('Bootstrapped 100% (done): Done\n')), 20)
  await tor.start()
  const events = []
  tor.on('route-unavailable', (e) => events.push(e))
  await tor.stop()
  assert.equal(events.length, 1)
  assert.equal(tor.socksUrl(), null)
})

// --- readiness comes from the log, not from a control port -----------------

test('parseBootstrap reads percent + phase from a real tor notice line', () => {
  const line = 'Aug 24 12:00:00.000 [notice] Bootstrapped 45% (requesting_descriptors): Asking for relay descriptors'
  const p = parseBootstrap(line)
  assert.equal(p.percent, 45)
  assert.equal(p.tag, 'requesting_descriptors')
  assert.equal(p.message, 'Asking for relay descriptors')
})

test('parseBootstrap handles the tagless older format and 0%/100%', () => {
  assert.equal(parseBootstrap('Bootstrapped 0% (starting): Starting').percent, 0)
  assert.equal(parseBootstrap('[notice] Bootstrapped 50%: Loading relay descriptors').percent, 50)
  const done = parseBootstrap('Bootstrapped 100% (done): Done')
  assert.equal(done.percent, 100)
  assert.equal(done.message, 'Done')
})

test('parseBootstrap: null when there is no progress, the HIGHEST in a chunk', () => {
  assert.equal(parseBootstrap('[notice] Opening Socks listener'), null)
  const chunk = 'Bootstrapped 10% (conn): a\nBootstrapped 30% (handshake): b\nBootstrapped 25% (x): c\n'
  assert.equal(parseBootstrap(chunk).percent, 30)
})

test('bootstrap ticks are emitted and are monotonic', async () => {
  const child = fakeChild()
  const tor = new TorNode({
    dataDir: tmp(),
    binPath: 'fake-tor',
    socksPort: 40995,
    spawnImpl: () => child,
    detectExternal: async () => false,
    bootstrapTimeout: 2000
  })
  const ticks = []
  tor.on('bootstrap', (p) => ticks.push(p))
  await tor.start()
  child.stdout.emit('data', Buffer.from('Bootstrapped 15% (conn): Connecting\n'))
  child.stdout.emit('data', Buffer.from('Bootstrapped 80% (loading_descriptors): Loading\n'))
  assert.equal(tor.bootstrapProgress().percent, 80)
  assert.equal(tor.bootstrapProgress().phase, 'Loading')
  assert.ok(ticks.some((t) => t.percent === 15))
  assert.ok(ticks.some((t) => t.percent === 80))
  child.stdout.emit('data', Buffer.from('Bootstrapped 40% (retry): x\n'))
  assert.equal(tor.bootstrapProgress().percent, 80, 'a stale lower tick never drags it back')
  await tor.stop()
})

// --- the torrc: no control port, loopback only -----------------------------

test('the generated torrc is client-only, loopback-only, and has NO ControlPort', async () => {
  const child = fakeChild()
  const dir = tmp()
  let args = null
  const tor = new TorNode({
    dataDir: dir,
    binPath: 'fake-tor',
    socksPort: 40994,
    spawnImpl: (_bin, a) => { args = a; return child },
    detectExternal: async () => false,
    bootstrapTimeout: 500
  })
  setTimeout(() => child.stdout.emit('data', Buffer.from('Bootstrapped 100% (done): Done\n')), 20)
  await tor.start()
  await tor.stop()
  const { readFileSync } = await import('node:fs')
  assert.deepEqual(args.slice(0, 1), ['-f'])
  const torrc = readFileSync(args[1], 'utf8')
  assert.match(torrc, /^SocksPort 127\.0\.0\.1:40994 IPv6Traffic$/m,
    'the SOCKS port is bound to loopback only; IPv6Traffic so an AAAA-only site can be dialled by address')
  assert.match(torrc, /^ClientOnly 1$/m)
  assert.match(torrc, /^Log notice stdout$/m)
  // Readiness is read from the log, so there is no local control socket to
  // authenticate, to leak, or to have a password stolen from.
  assert.doesNotMatch(torrc, /ControlPort/i)
  assert.doesNotMatch(torrc, /CookieAuthentication/i)
  assert.doesNotMatch(torrc, /HashedControlPassword/i)
  // A client, never a relay or a service: no onion service is published.
  assert.doesNotMatch(torrc, /HiddenService/i)
  assert.doesNotMatch(torrc, /ORPort|ExitRelay/i)
})

test('the bundled tor is spawned with its own directory on the library path', async () => {
  // The Linux Expert Bundle's tor is dynamically linked against libraries that
  // ship BESIDE it, with no RUNPATH, so the spawn must say where they are.
  const bin = '/app/vendor/tor/linux-x64/tor'
  if (process.platform !== 'win32') {
    assert.match(torSpawnEnv(bin).LD_LIBRARY_PATH, /^\/app\/vendor\/tor\/linux-x64/)
  }
  let seen = null
  const child = fakeChild()
  const tor = new TorNode({
    dataDir: tmp(),
    binPath: bin,
    socksPort: 40993,
    spawnImpl: (_bin, _args, opts) => { seen = opts; return child },
    detectExternal: async () => false
  })
  setTimeout(() => child.stdout.emit('data', Buffer.from('Bootstrapped 100% (done): Done\n')), 20)
  await tor.start()
  await tor.stop()
  assert.ok(seen && seen.env, 'spawn options carry an env')
  if (process.platform !== 'win32') {
    assert.match(seen.env.LD_LIBRARY_PATH, /^\/app\/vendor\/tor\/linux-x64/)
  }
})

test('in THIS package no binary is vendored, so the bundled branch needs an injected path', async () => {
  // Pins the extraction note above rather than an ambient machine property:
  // binPath:null is the only configuration this package can assert about.
  const tor = new TorNode({ dataDir: tmp(), binPath: null, detectExternal: async () => false })
  assert.equal(await tor.start(), 'unavailable')
  assert.equal(tor.socksUrl(), null)
  await tor.stop()
})
