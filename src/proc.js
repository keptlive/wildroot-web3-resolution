/*
 * Cross-platform child-process termination.
 *
 * POSIX and Windows disagree on how to kill a process and its children:
 *   - POSIX: spawn detached (new process group), kill the whole group with
 *     process.kill(-pid). hsd and kubo both fork worker children, so killing
 *     only the leader would orphan them.
 *   - Windows: there are no process groups; process.kill(-pid) throws. Use
 *     `taskkill /pid <pid> /T /F` to take down the tree (/T = tree, /F = force).
 *
 * Getting this wrong is exactly the kind of thing that "works on my Linux box"
 * and leaves zombie daemons on a tester's Windows machine.
 */

import { spawn } from 'node:child_process'

export const isWindows = process.platform === 'win32'

/** Spawn options that make a child killable as a tree on this platform. */
export function spawnGroupOpts (base = {}) {
  // On POSIX, detached:true makes the child a group leader. On Windows we
  // rely on taskkill /T instead, so detaching is unnecessary (and detached
  // there just hides the window, which is fine).
  return { ...base, detached: !isWindows }
}

/** Kill a child (and its descendants) portably. */
export function killTree (child) {
  if (!child || !child.pid) return
  const pid = child.pid
  if (isWindows) {
    try {
      spawn('taskkill', ['/pid', String(pid), '/T', '/F'], { stdio: 'ignore' })
    } catch {
      try { child.kill() } catch {}
    }
    return
  }
  try {
    process.kill(-pid, 'SIGTERM') // whole process group
  } catch {
    try { child.kill('SIGTERM') } catch {}
  }
}

/** Kill by pid (an adopted orphan we hold no child handle for). */
export function killPid (pid) {
  if (!pid) return
  if (isWindows) {
    try {
      spawn('taskkill', ['/pid', String(pid), '/T', '/F'], { stdio: 'ignore' })
    } catch {}
    return
  }
  try { process.kill(-pid, 'SIGTERM') } catch {
    try { process.kill(pid, 'SIGTERM') } catch {}
  }
}
