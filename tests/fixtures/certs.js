// Certificate fixtures for the DANE tests.
//
// WHY THESE ARE CHECKED IN RATHER THAN GENERATED. The tests used to build
// certificates by shelling out to the `openssl` CLI. That silently deleted
// this file's coverage on WINDOWS -- the platform we actually ship -- where
// openssl is not installed: all six DANE tests died with
// `spawnSync openssl ENOENT` and the release gate reported a "failure" nobody
// read as "DANE is untested here". A security feature whose tests only run on
// the maintainer's laptop is not tested.
//
// Static fixtures also make the expiry test HONEST. The old one admitted in a
// comment that it could not build an expired certificate portably, so it
// checked a *valid* one and trusted that the code had no date branch. The
// `expired` fixture below really is expired (notAfter 2020-01-02), so
// "DANE-EE ignores PKIX expiry" is now a fact the test proves.
//
// Regenerating (only if a fixture must change):
//   openssl ecparam -name prime256v1 -genkey -noout -out a.key
//   openssl req -new -x509 -key a.key -out a.crt -days 36500 -subj /CN=testzone \
//     -addext subjectAltName=DNS:testzone,DNS:*.testzone
//   # expired: openssl ca ... -startdate 20200101000000Z -enddate 20200102000000Z
// These carry no secret: the private keys were discarded and never leave a
// test. Do not point anything real at them.

/** A long-lived self-signed cert for `testzone`, and its SHA-256 SPKI hash. */
export const MATCHING = {
  pem: '-----BEGIN CERTIFICATE-----\nMIIBnzCCAUSgAwIBAgIUd+TiwZu6aHWSIZUzfLogLdIgq8gwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAwwIdGVzdHpvbmUwIBcNMjYwODIxMDA0ODM4WhgPMjEyNjA3Mjgw\nMDQ4MzhaMBMxETAPBgNVBAMMCHRlc3R6b25lMFkwEwYHKoZIzj0CAQYIKoZIzj0D\nAQcDQgAENJBdChZ/Zk0nRT6HW/Y1Ol/fSMiMfov8ytULqnNpwEE8eTgMoIzLD0Vp\n1cgqHnmxRwI+enVjodhNtfu0eiLd06N0MHIwHQYDVR0OBBYEFN2cslUT3OZlWXqr\nTeyKKqEkOZqXMB8GA1UdIwQYMBaAFN2cslUT3OZlWXqrTeyKKqEkOZqXMA8GA1Ud\nEwEB/wQFMAMBAf8wHwYDVR0RBBgwFoIIdGVzdHpvbmWCCioudGVzdHpvbmUwCgYI\nKoZIzj0EAwIDSQAwRgIhAKwnZmZy07+TDUrPUnGju+ItXm9uQ/8A6xYNEevw+NI6\nAiEA3Rfrw3u7fA9yBgD8yYlGz0ydjzY7LRC21wh6YLfs+xg=\n-----END CERTIFICATE-----\n',
  spki: '06b9e2a772e5f904fd22ee4c4ba485570feec77e5ade74099e0d65d2f299d6d9'
}

/** A DIFFERENT key, for the mismatch case. */
export const OTHER = {
  pem: '-----BEGIN CERTIFICATE-----\nMIIBfzCCASWgAwIBAgIUH0zZsZ+PG1kyNqnglq+Yje+hJtMwCgYIKoZIzj0EAwIw\nFDESMBAGA1UEAwwJb3RoZXJ6b25lMCAXDTI2MDgyMTAwNDgzOFoYDzIxMjYwNzI4\nMDA0ODM4WjAUMRIwEAYDVQQDDAlvdGhlcnpvbmUwWTATBgcqhkjOPQIBBggqhkjO\nPQMBBwNCAATYRI6rblMXt5OKCwhxcKcVpoeOYrFoRbq6a44t850/5BV4ro8oKAzp\nmK5hXtv4IDvaG16kbBbTX4lJ9Ub3TWqGo1MwUTAdBgNVHQ4EFgQU3A7/hILq7TFi\n3vCnPk+dwxTJefwwHwYDVR0jBBgwFoAU3A7/hILq7TFi3vCnPk+dwxTJefwwDwYD\nVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBW3tTxh5BCSjkgqxlqlYDa\nqBI6FAHthMIOUaO3NKk9twIhAM1kO8TJJ4p3C7lPcVMq80IQUU+I/JpinjKONIF5\n/U8A\n-----END CERTIFICATE-----\n',
  spki: 'f8baa9f720081e068f0fe96bc7f263c01e47a835fb4e985a1a8dacfa742512af'
}

/** Genuinely expired (notAfter Jan  2 00:00:00 2020 GMT) — same key as MATCHING, so its
 * pin still matches and only the DATE differs. */
export const EXPIRED = {
  pem: '-----BEGIN CERTIFICATE-----\nMIIBDDCBswIBATAKBggqhkjOPQQDAjATMREwDwYDVQQDDAh0ZXN0em9uZTAeFw0y\nMDAxMDEwMDAwMDBaFw0yMDAxMDIwMDAwMDBaMBIxEDAOBgNVBAMMB2V4cHpvbmUw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ0kF0KFn9mTSdFPodb9jU6X99IyIx+\ni/zK1Quqc2nAQTx5OAygjMsPRWnVyCoeebFHAj56dWOh2E21+7R6It3TMAoGCCqG\nSM49BAMCA0gAMEUCIDGX1+CD5yltdikST1XfxbhnaOKpupCphm/K6dyWHWrnAiEA\n/3XnnL1C1qdzQM5Fvoffhi5riL1S8xXBUog+hEiK8Tk=\n-----END CERTIFICATE-----\n',
  spki: '06b9e2a772e5f904fd22ee4c4ba485570feec77e5ade74099e0d65d2f299d6d9',
  validTo: 'Jan  2 00:00:00 2020 GMT'
}
