// Ports the app can actually bind, chosen at runtime.
//
// WHY THIS EXISTS. The embedded IPFS daemon used hardcoded ports — 2473/2474/
// 2475 for the ipfs:// handler, 15001/15080/14737 for the HNS content node.
// They were moved off IPFS's defaults on purpose, because a user running IPFS
// Desktop already holds 4001/5001/8080 and kubo REFUSES TO START when it
// cannot bind a configured address. But a private fixed port has the same
// failure mode, only rarer — and rarer is worse, because it turns into a
// support problem nobody can reproduce.
//
// It happened: on a Windows machine 2473, 2474, 2475 AND 14737 all returned
// WSAEADDRINUSE with nothing listening on them and no owning process visible
// to netstat, while the port one above (2476) bound fine. Every hns:// name
// whose content lives on IPFS then failed with "Unable to start the IPFS
// daemon", which reads as "the browser is broken".
//
// For a package other people install, that is not acceptable: we cannot know
// what is already running on someone else's machine. So the preferred port is
// a PREFERENCE. If it is free we use it — behaviour stays stable and
// predictable for everyone whose machine is uncontended — and if it is not, we
// ask the OS for one that works instead of refusing to start.

import { createServer } from 'node:net'

/** Can we actually bind this TCP port on this host right now? */
export function canBind (port, host = '0.0.0.0') {
  return new Promise((resolve) => {
    const server = createServer()
    server.once('error', () => resolve(false))
    server.listen({ port, host, exclusive: true }, () => {
      server.close(() => resolve(true))
    })
  })
}

/** A port the OS says is free right now. */
export function anyFreePort (host = '0.0.0.0') {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.once('error', reject)
    server.listen({ port: 0, host, exclusive: true }, () => {
      const { port } = server.address()
      server.close(() => resolve(port))
    })
  })
}

/**
 * The preferred port if it is bindable, otherwise one that is.
 *
 * There is an unavoidable race between releasing the probe socket and the
 * daemon claiming the port. It is tiny, and the alternative — holding the
 * socket open — would make the port unavailable to the very process we are
 * choosing it for.
 *
 * @param {number} preferred
 * @param {string} [host] the address the caller will actually bind
 */
export async function resolvePort (preferred, host = '0.0.0.0') {
  if (await canBind(preferred, host)) return preferred
  return anyFreePort(host)
}
