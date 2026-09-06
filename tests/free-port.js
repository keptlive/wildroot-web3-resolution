// A port no other test process will also be given.
//
// WHY: resolver/handler/dnssec-e2e each spawned nsd.py on a HARDCODED port
// (5399, 5398, 5396). That is fine until the suite runs twice at once — two
// checkouts on one machine, or CI running a branch beside main — and then the
// second run's nameserver cannot bind, its queries reach the FIRST run's
// server, and tests fail in a shifting pattern that looks like a real
// regression in the resolver. It cost a release-day investigation to find that
// the flake was the gate colliding with itself.
//
// A gate that goes red for reasons unrelated to the code is a gate people
// learn to re-run instead of read, which is the beginning of not having one.
//
// ASKING THE OS FOR :0 DID NOT ACTUALLY FIX IT, which is what this rewrite is
// about. Binding :0, reading the port and closing the socket hands back a port
// that is free *now* and is bound by nsd.py a moment later — and in that gap
// the OS is free to give the identical port to another test process doing the
// same thing. Seven files now spawn a nameserver, `node --test` runs them in
// parallel processes, and the collision surfaced as whole unrelated files
// going red together (hip5-op's seven tests, 2026-09-04) while each passed
// alone. The old comment described the bug this file exists to prevent; the
// implementation still had a smaller version of it.
//
// So the port is not asked for — it is DERIVED from the process id, which the
// OS guarantees is unique among the processes running right now. Two test
// files therefore start their scans in different places by construction, and
// the scan itself skips anything already taken. UDP *and* TCP are checked,
// because nsd.py binds both and a port free on one is not free on the other.

import { createSocket } from 'node:dgram'
import { createServer } from 'node:net'

/** The scan window. Above the ephemeral range Linux hands out by default. */
const BASE = 20000
const SPAN = 30000

/** Sequential calls in one process must not repeat a port either. */
let cursor = 0

/** Knuth multiplicative hash — spreads adjacent pids across the window. */
function startFor (pid) {
  return BASE + Math.abs((pid * 2654435761) % SPAN)
}

const free = (make) => (port) => new Promise((resolve) => {
  const socket = make()
  socket.once('error', () => resolve(false))
  socket.bind
    ? socket.bind(port, '127.0.0.1', () => socket.close(() => resolve(true)))
    : resolve(false)
})

const udpFree = free(() => createSocket('udp4'))

function tcpFree (port) {
  return new Promise((resolve) => {
    const server = createServer()
    server.once('error', () => resolve(false))
    server.listen(port, '127.0.0.1', () => server.close(() => resolve(true)))
  })
}

/**
 * A port this process may bind, that no concurrently running test process
 * will have been given.
 */
/**
 * The scan STRIDES rather than walking. Windows reserves whole blocks of
 * ports for Hyper-V and WSL (`netsh interface ipv4 show excludedportrange`),
 * hundreds wide and many of them, and 500 consecutive probes from a start
 * that landed inside one found nothing — "no free port found in the scan
 * window", the Windows gate's one red test on 2026-09-05, in a different
 * nameserver file each run depending on the pid. Stepping by a prime visits
 * ports spread across the whole window instead, so a reserved block costs a
 * few probes, not the run.
 */
const STRIDE = 53

export async function freeUdpPort () {
  const start = startFor(process.pid)
  for (let i = 0; i < 1000; i++) {
    const port = BASE + ((start - BASE + cursor + i * STRIDE) % SPAN)
    // eslint-disable-next-line no-await-in-loop
    if (await udpFree(port) && await tcpFree(port)) {
      cursor += (i + 1) * STRIDE
      return port
    }
  }
  throw new Error('no free port found in the scan window')
}
