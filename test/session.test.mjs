import test from 'node:test';
import assert from 'node:assert/strict';
import {
  sealData,
  unsealData,
  parseCookies,
  serializeCookie,
  SessionManager,
} from '../dist/index.js';

test('sealData and unsealData round-trip preserves arbitrary JSON data', async () => {
  const secret = 'super-secret-passphrase-at-least-32-chars';
  const payload = { userId: 'usr_123', roles: ['admin', 'billing'], verified: true };

  const sealed = await sealData(payload, secret);
  assert.ok(typeof sealed === 'string');
  assert.ok(sealed.startsWith('v1.'));

  const unsealed = await unsealData(sealed, secret);
  assert.deepEqual(unsealed, payload);
});

test('unsealData fails closed when payload is tampered', async () => {
  const secret = 'super-secret-passphrase-at-least-32-chars';
  const payload = { userId: 'usr_123' };

  const sealed = await sealData(payload, secret);
  const parts = sealed.split('.');
  // Flip characters in the ciphertext part
  const tamperedCipher = parts[3].slice(0, -2) + (parts[3].endsWith('a') ? 'b' : 'a');
  const tampered = [parts[0], parts[1], parts[2], tamperedCipher].join('.');

  await assert.rejects(
    () => unsealData(tampered, secret),
    /failed to unseal session|authentication failed/i
  );
});

test('unsealData rejects invalid passwords', async () => {
  const secret = 'correct-secret-passphrase-32-chars';
  const wrongSecret = 'wrong-secret-passphrase-32-chars';
  const payload = { hello: 'world' };

  const sealed = await sealData(payload, secret);
  await assert.rejects(
    () => unsealData(sealed, wrongSecret),
    /failed to unseal session|authentication failed/i
  );
});

test('unsealData enforces expiration with TTL', async () => {
  const secret = 'super-secret-passphrase-32-chars';
  const payload = { temp: 'token' };

  // TTL is 1 second, tolerance is 0 seconds
  const sealed = await sealData(payload, secret, { ttl: 1 });
  // Wait 1.1s
  await new Promise((resolve) => setTimeout(resolve, 1100));

  await assert.rejects(
    () => unsealData(sealed, secret, { clockTolerance: 0 }),
    /session has expired/i
  );
});

test('unsealData supports transparent key rotation', async () => {
  const oldSecret = 'old-secret-passphrase-32-chars';
  const newSecret = 'new-secret-passphrase-32-chars';
  const payload = { accountId: 'acc_999' };

  // Sealed using old key
  const sealedWithOld = await sealData(payload, oldSecret);

  // Unseal using rotation array [newSecret, oldSecret]
  const unsealed = await unsealData(sealedWithOld, [newSecret, oldSecret]);
  assert.deepEqual(unsealed, payload);

  // Data sealed with new key can also be unsealed
  const sealedWithNew = await sealData(payload, [newSecret, oldSecret]);
  const unsealedFromNew = await unsealData(sealedWithNew, [newSecret, oldSecret]);
  assert.deepEqual(unsealedFromNew, payload);
});

test('cookie helpers correctly parse and serialize with security attributes and CHIPS', () => {
  const serialized = serializeCookie('sid', 'sealed.token.value', {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/api',
    maxAge: 3600,
    partitioned: true,
  });

  assert.ok(serialized.includes('sid=sealed.token.value'));
  assert.ok(serialized.includes('HttpOnly'));
  assert.ok(serialized.includes('Secure'));
  assert.ok(serialized.includes('SameSite=Strict'));
  assert.ok(serialized.includes('Path=/api'));
  assert.ok(serialized.includes('Max-Age=3600'));
  assert.ok(serialized.includes('Partitioned'));

  const parsed = parseCookies(serialized);
  assert.equal(parsed.sid, 'sealed.token.value');
});

test('SessionManager handles full session lifecycle and clears expired sessions', async () => {
  const sessionManager = new SessionManager({
    cookieName: '__Secure-session',
    password: ['master-key-rot-2', 'master-key-rot-1'],
    ttl: 3600,
  });

  // Create session
  const setCookie = await sessionManager.setSession({ user: 'alice', plan: 'enterprise' });
  assert.ok(setCookie.startsWith('__Secure-session=v1.'));
  assert.ok(setCookie.includes('HttpOnly'));
  assert.ok(setCookie.includes('Secure'));

  // Extract from incoming cookie string
  const session = await sessionManager.getSession(setCookie);
  assert.ok(session);
  assert.equal(session.user, 'alice');
  assert.equal(session.plan, 'enterprise');

  // Extract from Headers object
  const headers = new Headers();
  headers.set('cookie', setCookie);
  const sessionFromHeaders = await sessionManager.getSession(headers);
  assert.deepEqual(sessionFromHeaders, session);

  // Invalid cookie returns null gracefully
  const invalidSession = await sessionManager.getSession('__Secure-session=invalid.gibberish.token');
  assert.equal(invalidSession, null);

  // Clear session produces expiration header
  const clearCookie = sessionManager.clearSession();
  assert.ok(clearCookie.includes('Max-Age=0'));
  assert.ok(clearCookie.includes('Expires=Thu, 01 Jan 1970 00:00:00 GMT'));
});
