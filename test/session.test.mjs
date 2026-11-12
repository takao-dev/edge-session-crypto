import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto || !globalThis.crypto.subtle) {
  globalThis.crypto = webcrypto;
}

import {
  sealData,
  unsealData,
  parseCookies,
  serializeCookie,
  SessionManager,
} from '../dist/index.js';

const TEST_SECRET = 'super-secret-passphrase-at-least-32-chars';

test('sealData and unsealData round-trip preserves arbitrary JSON data', async () => {
  const payload = { userId: 'usr_123', roles: ['admin', 'billing'], verified: true };
  const sealed = await sealData(payload, TEST_SECRET);
  assert.ok(typeof sealed === 'string');
  assert.ok(sealed.startsWith('v1.'));

  const unsealed = await unsealData(sealed, TEST_SECRET);
  assert.deepEqual(unsealed, payload);
});

test('AAD (Additional Authenticated Data) binding prevents session hijacking', async () => {
  const payload = { userId: 'usr_sensitive' };
  const clientA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';
  const clientB = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)';

  // Seal with client A's User-Agent bound as AAD
  const sealed = await sealData(payload, TEST_SECRET, { additionalData: clientA });

  // Unseal with client A succeeds
  const unsealedA = await unsealData(sealed, TEST_SECRET, { additionalData: clientA });
  assert.deepEqual(unsealedA, payload);

  // Unseal with client B (hijack attempt) MUST fail closed
  await assert.rejects(
    () => unsealData(sealed, TEST_SECRET, { additionalData: clientB }),
    /failed to unseal session|authentication failed/i
  );

  // Unseal with omitted AAD MUST also fail closed
  await assert.rejects(
    () => unsealData(sealed, TEST_SECRET),
    /failed to unseal session|authentication failed/i
  );
});

test('Transparent payload compression reduces large session sizes', async () => {
  const largePayload = {
    items: Array.from({ length: 100 }, (_, i) => ({ id: i, text: `Item description number ${i} with repetitive text` })),
  };

  const uncompressed = await sealData(largePayload, TEST_SECRET, { compress: false });
  const compressed = await sealData(largePayload, TEST_SECRET, { compress: true });

  // Compressed payload should be substantially smaller
  assert.ok(compressed.length < uncompressed.length);

  const restored = await unsealData(compressed, TEST_SECRET);
  assert.deepEqual(restored, largePayload);
});

test('Prefix Guard enforces strict invariants for __Host- and __Secure- cookies', () => {
  // Valid __Host-
  assert.doesNotThrow(() => {
    serializeCookie('__Host-session', 'val', { path: '/', secure: true });
  });

  // Invalid: __Host- with secure: false
  assert.throws(
    () => serializeCookie('__Host-session', 'val', { secure: false }),
    /__Host- cookies must have Secure=true/
  );

  // Invalid: __Host- with non-root path
  assert.throws(
    () => serializeCookie('__Host-session', 'val', { path: '/api', secure: true }),
    /__Host- cookies must have Path="\/"/
  );

  // Invalid: __Host- with domain
  assert.throws(
    () => serializeCookie('__Host-session', 'val', { domain: 'example.com', secure: true }),
    /__Host- cookies must not specify a Domain attribute/
  );

  // Invalid: __Secure- with secure: false
  assert.throws(
    () => serializeCookie('__Secure-session', 'val', { secure: false }),
    /__Secure- cookies must have Secure=true/
  );
});

test('Bit-flip fuzzing: any single-bit mutation anywhere in ciphertext or tag is rejected', async () => {
  const payload = { admin: true, balance: 1_000_000 };
  const sealed = await sealData(payload, TEST_SECRET);
  const parts = sealed.split('.');

  // Ciphertext part contains AES-GCM ciphertext + 128-bit authentication tag
  const cipherBytes = Buffer.from(parts[3], 'base64url');

  // Test bit flips across multiple byte offsets
  const offsets = [0, 1, 5, Math.floor(cipherBytes.length / 2), cipherBytes.length - 1];
  for (const offset of offsets) {
    const mutated = Buffer.from(cipherBytes);
    mutated[offset] ^= 0x01; // flip 1 bit
    const tampered = [parts[0], parts[1], parts[2], mutated.toString('base64url')].join('.');

    await assert.rejects(
      () => unsealData(tampered, TEST_SECRET),
      /failed to unseal session|authentication failed/i
    );
  }
});

test('Truncation attack: truncated ciphertext or missing components fail closed', async () => {
  const payload = { token: 'xyz' };
  const sealed = await sealData(payload, TEST_SECRET);
  const parts = sealed.split('.');

  // Truncate ciphertext in half
  const truncatedCipher = parts[3].slice(0, Math.floor(parts[3].length / 2));
  const truncated = [parts[0], parts[1], parts[2], truncatedCipher].join('.');

  await assert.rejects(
    () => unsealData(truncated, TEST_SECRET),
    /failed to unseal session|authentication failed|invalid cryptographic component lengths/i
  );

  // Missing parts
  await assert.rejects(
    () => unsealData(parts[0] + '.' + parts[1], TEST_SECRET),
    /invalid or unsupported sealed session format/i
  );
});

test('unsealData supports transparent key rotation and session re-encryption', async () => {
  const oldSecret = 'old-secret-passphrase-32-chars';
  const newSecret = 'new-secret-passphrase-32-chars';
  const payload = { accountId: 'acc_999' };

  // Sealed using old key
  const sealedWithOld = await sealData(payload, oldSecret);

  // Unseal using rotation array [newSecret, oldSecret]
  const unsealed = await unsealData(sealedWithOld, [newSecret, oldSecret]);
  assert.deepEqual(unsealed, payload);

  // Re-encrypt (rotate) with new key
  const manager = new SessionManager({ password: [newSecret, oldSecret] });
  const migratedCookie = await manager.rotateSession(unsealed);

  // Must now unseal with new key alone
  const unsealedWithNewOnly = await unsealData(
    parseCookies(migratedCookie).session,
    newSecret
  );
  assert.deepEqual(unsealedWithNewOnly, payload);
});

test('unsealData enforces expiration with TTL', async () => {
  const payload = { temp: 'token' };
  const sealed = await sealData(payload, TEST_SECRET, { ttl: 1 });
  await new Promise((resolve) => setTimeout(resolve, 1100));

  await assert.rejects(
    () => unsealData(sealed, TEST_SECRET, { clockTolerance: 0 }),
    /session has expired/i
  );
});

test('SessionManager handles full session lifecycle with AAD client binding', async () => {
  const sessionManager = new SessionManager({
    cookieName: '__Secure-session',
    password: ['key-rot-2', 'key-rot-1'],
    ttl: 3600,
    compress: true,
  });

  const clientIp = '203.0.113.1';

  // Set session bound to client IP
  const setCookie = await sessionManager.setSession(
    { user: 'alice', plan: 'enterprise' },
    3600,
    clientIp
  );
  assert.ok(setCookie.startsWith('__Secure-session=v1.'));

  // Get session with matching client IP
  const session = await sessionManager.getSession(setCookie, clientIp);
  assert.ok(session);
  assert.equal(session.user, 'alice');

  // Get session with mismatched client IP (attack) returns null
  const hijacked = await sessionManager.getSession(setCookie, '198.51.100.99');
  assert.equal(hijacked, null);

  // Clear session
  const clearCookie = sessionManager.clearSession();
  assert.ok(clearCookie.includes('Max-Age=0'));
});
