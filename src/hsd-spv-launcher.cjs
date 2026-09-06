/*
 * hsd SPV launcher, minus upstream's native-bindings guard.
 *
 * hsd's own bin/spvnode refuses to start unless bcrypto's NATIVE bindings are
 * compiled (`blake2b.native === 2`) — a performance guard, not a functional
 * requirement. We deliberately run with NODE_BACKEND=js (pure-JS crypto) so
 * users never need Python + a C++ toolchain, so we boot the same SPVNode class
 * upstream does, with the same sequence, and skip only that guard.
 *
 * Spawned by spv.js with the same CLI args bin/hsd would get.
 */

'use strict'

// When the native LevelDB binding isn't compiled (Windows without a C++
// toolchain), bdb's module still requires it AT IMPORT TIME even though the
// in-memory backend never touches it. Pre-stub bdb/lib/level.js in the require
// cache so `--memory` mode loads cleanly; the stub only throws if something
// actually tries to open an on-disk database.
try {
  const levelPath = require.resolve('bdb/lib/level.js')
  try {
    require(levelPath) // native present? then leave everything alone
  } catch {
    const stub = class LevelDBUnavailable {
      constructor () {
        throw new Error(
          'LevelDB native binding unavailable — run hsd with --memory')
      }
    }
    require.cache[levelPath] = {
      id: levelPath,
      filename: levelPath,
      loaded: true,
      exports: stub
    }
  }
} catch {}

const SPVNode = require('hsd/lib/node/spvnode')

const node = new SPVNode({
  config: true,
  argv: true,
  env: true,
  logFile: true,
  logConsole: true,
  logLevel: 'info',
  memory: false,
  workers: true,
  listen: false,
  network: 'main',
  loader: require
})

// No wallet plugin, ever. spv.js passes --no-wallet and states the property
// ("the browser reads names, it cannot spend"); the upstream launcher loaded
// the wallet plugin when the flag was absent, which was the one line that
// could silently undo that if the flag ever moved (CODE-AUDIT §2 vestigial).

process.on('unhandledRejection', (err) => {
  throw err
})

process.on('SIGINT', async () => {
  await node.close()
})

node.on('abort', async (err) => {
  const timeout = setTimeout(() => {
    console.error('Shutdown is taking a long time. Exiting.')
    process.exit(3)
  }, 5000)
  timeout.unref()
  try {
    console.error('Shutting down...')
    await node.close()
    clearTimeout(timeout)
    console.error(err.stack)
    process.exit(2)
  } catch (e) {
    console.error(`Error occurred during shutdown: ${e.message}`)
    process.exit(3)
  }
})

;(async () => {
  await node.ensure()
  await node.open()
  await node.connect()
  node.startSync()
})().catch((err) => {
  console.error(err.stack)
  process.exit(1)
})
