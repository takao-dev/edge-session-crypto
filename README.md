# edge-session-crypto

Stateless, encrypted cookie session manager for Edge, Cloudflare Workers, Node.js, and modern runtimes. Powered by native WebCrypto (AES-256-GCM + PBKDF2-SHA256) with zero runtime dependencies.

[![npm version](https://img.shields.io/npm/v/edge-session-crypto.svg)](https://www.npmjs.com/package/edge-session-crypto)
[![CI](https://github.com/takao-dev/edge-session-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/takao-dev/edge-session-crypto/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/takao-dev/edge-session-crypto/branch/main/graph/badge.svg)](https://codecov.io/gh/takao-dev/edge-session-crypto)
[![CodeQL](https://github.com/takao-dev/edge-session-crypto/actions/workflows/codeql.yml/badge.svg)](https://github.com/takao-dev/edge-session-crypto/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)]()

---

## Features

- **Stateless & Database-Free**: Encrypts and authenticates session payloads directly inside client cookies (Sealed Cookie pattern). No Redis, KV, or database required.
- **Zero Runtime Dependencies**: Written purely against WebCrypto `SubtleCrypto` standards.
- **Transparent Key Rotation**: Pass an array of secret keys (`[newKey, oldKey]`) to automatically decrypt legacy sessions and re-encrypt with the active key.
- **Modern Security Defaults**: Enforces `HttpOnly`, `Secure`, `SameSite=Lax`, and CHIPS (`Partitioned`) cookie attributes.
- **Universal Multi-Runtime Compatibility**: Fully supports Cloudflare Workers, Pages Functions, Node.js 18+, Deno, Bun, and browser contexts.

---

## Installation

```bash
npm install edge-session-crypto
```

---

## Quick Start

### High-Level `SessionManager`

```typescript
import { SessionManager } from 'edge-session-crypto';

interface UserSession {
  userId: string;
  role: string;
}

const sessionManager = new SessionManager<UserSession>({
  cookieName: '__Secure-session',
  password: process.env.SESSION_SECRET!, // At least 32 characters
  ttl: 60 * 60 * 24, // 24 hours
});

// 1. Reading session from incoming request
export async function handleRequest(request: Request) {
  const session = await sessionManager.getSession(request);
  if (!session) {
    return new Response('Unauthorized', { status: 401 });
  }
  return new Response(`Hello, ${session.userId}!`);
}

// 2. Setting session on login
export async function handleLogin(user: UserSession) {
  const setCookieHeader = await sessionManager.setSession(user);
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': setCookieHeader,
    },
  });
}

// 3. Clearing session on logout
export async function handleLogout() {
  const clearCookieHeader = sessionManager.clearSession();
  return new Response(null, {
    status: 302,
    headers: {
      Location: '/login',
      'Set-Cookie': clearCookieHeader,
    },
  });
}
```

### Low-Level `sealData` and `unsealData`

```typescript
import { sealData, unsealData } from 'edge-session-crypto';

// Seal arbitrary JSON data
const sealed = await sealData({ account: 'acc_123' }, 'secret-passphrase', {
  ttl: 3600, // 1 hour
});

// Unseal and verify authenticity + expiration
const data = await unsealData(sealed, 'secret-passphrase');
console.log(data.account); // 'acc_123'
```

---

## License

MIT License.
