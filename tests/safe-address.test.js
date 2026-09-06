import { test } from 'node:test'
import assert from 'node:assert/strict'

import { isPublicAddress } from '../src/safe-address.js'

test('rejects loopback, private, link-local, CGNAT, metadata', () => {
  for (const bad of [
    '127.0.0.1', '127.1.2.3', '10.0.0.1', '10.255.255.255',
    '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254',
    '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255',
    '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1',
    '::ffff:127.0.0.1', '::ffff:10.0.0.1',
    // non-canonical IPv4-mapped/compat forms that must not slip past
    '::ffff:7f00:1', '0:0:0:0:0:ffff:127.0.0.1', '::127.0.0.1',
    '::ffff:a9fe:a9fe', '64:ff9b::7f00:1', '64:ff9b::169.254.169.254'
  ]) {
    assert.equal(isPublicAddress(bad), false, `${bad} must be blocked`)
  }
})

test('allows real public addresses', () => {
  for (const ok of [
    '8.8.8.8', '1.1.1.1', '198.44.116.200', '203.0.113.10',
    '172.15.255.255', '172.32.0.1', '2606:4700:4700::1111',
    '::ffff:8.8.8.8'
  ]) {
    assert.equal(isPublicAddress(ok), true, `${ok} must be allowed`)
  }
})

test('rejects garbage and empties', () => {
  for (const bad of ['', null, undefined, 'not-an-ip', '999.1.1.1', '1.2.3']) {
    assert.equal(isPublicAddress(bad), false)
  }
})
