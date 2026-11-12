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
  getWebCrypto,
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

test('Cookie parser and serializer comprehensive edge cases', () => {
  // Empty or invalid headers
  assert.deepEqual(parseCookies(null), {});
  assert.deepEqual(parseCookies(undefined), {});
  assert.deepEqual(parseCookies(''), {});

  // Complex cookie string: no value, quoted value, malformed URI, empty segments
  const parsed = parseCookies('flag; session="my-secret-val"; bad=%E0%A4; ; normal=123');
  assert.equal(parsed.flag, '');
  assert.equal(parsed['session'], 'my-secret-val');
  assert.equal(parsed['bad'], '%E0%A4');
  assert.equal(parsed.normal, '123');

  // Serialization errors
  assert.throws(() => serializeCookie('', 'val'), /cookie name must be a non-empty string/i);
  assert.throws(() => serializeCookie(null, 'val'), /cookie name must be a non-empty string/i);

  // Prefix Guard violations
  assert.throws(() => serializeCookie('__Host-id', '1', { secure: false }), /__Host- cookies must have Secure=true/i);
  assert.throws(() => serializeCookie('__Host-id', '1', { path: '/sub' }), /__Host- cookies must have Path="\/"/i);
  assert.throws(() => serializeCookie('__Host-id', '1', { domain: 'example.com' }), /__Host- cookies must not specify a Domain/i);
  assert.throws(() => serializeCookie('__Secure-id', '1', { secure: false }), /__Secure- cookies must have Secure=true/i);

  // Full serialization with all options
  const expDate = new Date('2030-01-01T00:00:00Z');
  const serialized = serializeCookie('test_cookie', 'val 1', {
    maxAge: 7200,
    expires: expDate,
    domain: 'takao.me',
    path: '/api',
    secure: false,
    httpOnly: false,
    sameSite: 'none',
    partitioned: true,
  });
  assert.ok(serialized.includes('test_cookie=val%201'));
  assert.ok(serialized.includes('Max-Age=7200'));
  assert.ok(serialized.includes('Expires=Tue, 01 Jan 2030'));
  assert.ok(serialized.includes('Domain=takao.me'));
  assert.ok(serialized.includes('Path=/api'));
  assert.ok(!serialized.includes('Secure'));
  assert.ok(!serialized.includes('HttpOnly'));
  assert.ok(serialized.includes('SameSite=None'));
  assert.ok(serialized.includes('Partitioned'));

  // sameSite strict and lax
  assert.ok(serializeCookie('c', '1', { sameSite: 'strict' }).includes('SameSite=Strict'));
  assert.ok(serializeCookie('c', '1', { sameSite: true }).includes('SameSite=Strict'));
  assert.ok(serializeCookie('c', '1', { sameSite: 'lax' }).includes('SameSite=Lax'));
});

test('sealData and unsealData failure and validation edge cases', async () => {
  // Empty secret validation
  await assert.rejects(() => sealData({ a: 1 }, []), /at least one non-empty secret is required/i);
  await assert.rejects(() => sealData({ a: 1 }, ''), /at least one non-empty secret is required/i);

  // Unseal validation errors
  await assert.rejects(() => unsealData('', TEST_SECRET), /non-empty string/i);
  await assert.rejects(() => unsealData('v1.a.b.c', []), /at least one secret is required/i);
  await assert.rejects(() => unsealData('invalid.format', TEST_SECRET), /invalid or unsupported sealed session format/i);
  await assert.rejects(() => unsealData('v2.salt.iv.cipher', TEST_SECRET), /invalid or unsupported sealed session format/i);
  await assert.rejects(() => unsealData('v1.not_b64!.bad.bad', TEST_SECRET), /malformed base64url encoding/i);
  await assert.rejects(() => unsealData('v1.AQ.AQ.AQ', TEST_SECRET), /invalid cryptographic component lengths/i);

  // Decryption failure when no key matches
  const validSealed = await sealData({ foo: 'bar' }, 'correct-secret');
  await assert.rejects(
    () => unsealData(validSealed, 'completely-wrong-secret'),
    /failed to unseal session/i
  );

  // Payload that decrypts successfully but is not valid JSON
  const crypto = globalThis.crypto;
  const rawKey = new TextEncoder().encode('valid-secret-key-padding-to-32b!');
  const k = await crypto.subtle.importKey('raw', rawKey, { name: 'PBKDF2' }, false, ['deriveKey']);
  const salt = new Uint8Array(16);
  const derivedKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 1000, hash: 'SHA-256' },
    k,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const iv = new Uint8Array(12);
  const encryptedGarbage = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    derivedKey,
    new TextEncoder().encode('this is completely invalid json and not compressed!')
  );
  function toB64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  const garbageSealed = `v1.${toB64(salt)}.${toB64(iv)}.${toB64(new Uint8Array(encryptedGarbage))}`;
  await assert.rejects(
    () => unsealData(garbageSealed, 'valid-secret-key-padding-to-32b!', { iterations: 1000 }),
    /failed to parse or decompress session envelope/i
  );
});

test('SessionManager constructor errors and custom options', () => {
  // Missing or invalid password
  assert.throws(() => new SessionManager(null), /requires a non-empty password/i);
  assert.throws(() => new SessionManager({}), /requires a non-empty password/i);
  assert.throws(() => new SessionManager({ password: [] }), /at least one valid password/i);
  assert.throws(() => new SessionManager({ password: [''] }), /at least one valid password/i);

  // Custom iterations and custom cookie options
  const customSm = new SessionManager({
    password: 'secret-passphrase',
    iterations: 50_000,
    cookie: { path: '/app', secure: true },
  });
  assert.equal(customSm.iterations, 50_000);
  assert.equal(customSm.cookieOptions.path, '/app');
});

test('SessionManager headers extraction and rotation edge cases', async () => {
  const sm = new SessionManager({
    password: TEST_SECRET,
  });

  // Default cookieName and TTL
  assert.equal(sm.cookieName, 'session');
  assert.equal(sm.ttl, 86400);

  const sealed = await sm.setSession({ role: 'admin' });
  const cookieHeader = `session=${sealed.split(';')[0].split('=')[1]}`;

  // Extract from plain string
  const s1 = await sm.getSession(cookieHeader);
  assert.equal(s1?.role, 'admin');

  // Extract from Headers object
  const headers = new Headers();
  headers.set('cookie', cookieHeader);
  const s2 = await sm.getSession(headers);
  assert.equal(s2?.role, 'admin');

  // Extract from object with headers.get()
  const s3 = await sm.getSession({ headers });
  assert.equal(s3?.role, 'admin');

  // Extract from object with plain headers dict (lowercase cookie)
  const s4 = await sm.getSession({ headers: { cookie: cookieHeader } });
  assert.equal(s4?.role, 'admin');

  // Extract from object with plain headers dict (Capital Cookie)
  const s5 = await sm.getSession({ headers: { Cookie: cookieHeader } });
  assert.equal(s5?.role, 'admin');

  // Extract from null, undefined, empty object
  assert.equal(await sm.getSession(null), null);
  assert.equal(await sm.getSession(undefined), null);
  assert.equal(await sm.getSession({}), null);

  // Missing session cookie in request
  assert.equal(await sm.getSession('other_cookie=xyz'), null);

  // rotateSession helper
  const rotated = await sm.rotateSession({ role: 'admin', updated: true });
  assert.ok(rotated.startsWith('session=v1.'));
});

test('unsealData rejects invalid sealed session envelope versions and formats', async () => {
  await assert.rejects(
    () => unsealData('v2.salt.iv.cipher', TEST_SECRET),
    /Invalid or unsupported sealed session format/i
  );
  await assert.rejects(
    () => unsealData('not-enough-parts.two.three', TEST_SECRET),
    /Invalid or unsupported sealed session format/i
  );
  await assert.rejects(
    () => unsealData('v1.only.three', TEST_SECRET),
    /Invalid or unsupported sealed session format/i
  );
});

test('getWebCrypto returns subtle crypto or throws when unavailable', () => {
  // 1. Normal resolution returns subtle
  const cryptoInstance = getWebCrypto();
  assert.ok(cryptoInstance.subtle);

  // 2. Throws when crypto is unavailable
  const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });
    assert.throws(
      () => getWebCrypto(),
      /WebCrypto SubtleCrypto is not available in this environment/i
    );
  } finally {
    if (originalCrypto) {
      Object.defineProperty(globalThis, 'crypto', originalCrypto);
    }
  }
});
