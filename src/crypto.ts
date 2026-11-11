/**
 * Cryptographic helpers for edge-session-crypto.
 * Native WebCrypto SubtleCrypto implementation with Zero Runtime Dependencies.
 * Features: AES-256-GCM, PBKDF2-SHA256, AAD client binding, Deflate compression.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(base64url: string): Uint8Array {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function getWebCrypto(): Crypto {
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    return globalThis.crypto;
  }
  throw new Error('WebCrypto SubtleCrypto is not available in this environment');
}

/**
 * Derive an AES-256-GCM CryptoKey from a secret string and salt via PBKDF2-SHA256.
 */
export async function deriveKey(secret: string, salt: Uint8Array, iterations = 100_000): Promise<CryptoKey> {
  const crypto = getWebCrypto();
  const rawKey = encoder.encode(secret);
  const baseKey = await crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as unknown as BufferSource,
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Compress bytes using native CompressionStream (deflate).
 */
export async function compressBytes(data: Uint8Array): Promise<Uint8Array> {
  if (typeof CompressionStream === 'undefined') return data;
  const cs = new CompressionStream('deflate');
  const writer = cs.writable.getWriter();
  await writer.write(data as unknown as BufferSource);
  await writer.close();
  const buffer = await new Response(cs.readable).arrayBuffer();
  return new Uint8Array(buffer);
}

/**
 * Decompress bytes using native DecompressionStream (deflate).
 */
export async function decompressBytes(data: Uint8Array): Promise<Uint8Array> {
  if (typeof DecompressionStream === 'undefined') return data;
  const ds = new DecompressionStream('deflate');
  const writer = ds.writable.getWriter();
  await writer.write(data as unknown as BufferSource);
  await writer.close();
  const buffer = await new Response(ds.readable).arrayBuffer();
  return new Uint8Array(buffer);
}

export interface SealOptions {
  /** Time to live in seconds. If unset, session does not expire automatically. */
  ttl?: number;
  /** PBKDF2 derivation iterations. Defaults to 100,000. */
  iterations?: number;
  /** Additional Authenticated Data (AAD) to cryptographically bind to the session (e.g. User-Agent or IP). */
  additionalData?: string;
  /** Enable transparent payload compression. Defaults to false. */
  compress?: boolean;
}

export interface UnsealOptions {
  /** Allowed clock drift in seconds when checking expiration. Defaults to 60s. */
  clockTolerance?: number;
  /** PBKDF2 derivation iterations. Defaults to 100,000. */
  iterations?: number;
  /** Additional Authenticated Data (AAD) that must match the value provided during sealData. */
  additionalData?: string;
}

interface Envelope<T> {
  data: T;
  iat: number;
  exp?: number;
  c?: boolean; // compressed flag
}

/**
 * Encrypt and authenticate arbitrary data into a tamper-proof URL-safe string.
 */
export async function sealData<T = any>(
  data: T,
  secretOrSecrets: string | string[],
  options: SealOptions = {}
): Promise<string> {
  const secrets = Array.isArray(secretOrSecrets) ? secretOrSecrets : [secretOrSecrets];
  if (secrets.length === 0 || !secrets[0]) {
    throw new Error('At least one non-empty secret is required to seal session data');
  }
  const activeSecret = secrets[0];
  const crypto = getWebCrypto();

  const now = Date.now();
  const envelope: Envelope<T> = {
    data,
    iat: now,
  };
  if (typeof options.ttl === 'number' && options.ttl > 0) {
    envelope.exp = now + options.ttl * 1000;
  }
  if (options.compress) {
    envelope.c = true;
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const iterations = options.iterations ?? 100_000;

  const key = await deriveKey(activeSecret, salt, iterations);
  let plaintextBytes: Uint8Array = encoder.encode(JSON.stringify(envelope));
  if (options.compress) {
    plaintextBytes = await compressBytes(plaintextBytes);
  }

  const gcmParams: AesGcmParams = {
    name: 'AES-GCM',
    iv: iv as unknown as BufferSource,
    tagLength: 128,
  };

  if (options.additionalData) {
    gcmParams.additionalData = encoder.encode(options.additionalData) as unknown as BufferSource;
  }

  const ciphertext = await crypto.subtle.encrypt(
    gcmParams,
    key,
    plaintextBytes as unknown as BufferSource
  );

  return [
    'v1',
    toBase64Url(salt),
    toBase64Url(iv),
    toBase64Url(new Uint8Array(ciphertext)),
  ].join('.');
}

/**
 * Decrypt, verify authenticity, and check expiration of a sealed session string.
 * Supports transparent key rotation: tests all supplied secrets in sequence.
 */
export async function unsealData<T = any>(
  sealed: string,
  secretOrSecrets: string | string[],
  options: UnsealOptions = {}
): Promise<T> {
  if (typeof sealed !== 'string' || !sealed) {
    throw new Error('Sealed session payload must be a non-empty string');
  }

  const secrets = Array.isArray(secretOrSecrets) ? secretOrSecrets : [secretOrSecrets];
  if (secrets.length === 0) {
    throw new Error('At least one secret is required to unseal session data');
  }

  const parts = sealed.split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') {
    throw new Error('Invalid or unsupported sealed session format');
  }

  const [, saltB64, ivB64, cipherB64] = parts;
  let salt: Uint8Array;
  let iv: Uint8Array;
  let ciphertext: Uint8Array;

  try {
    salt = fromBase64Url(saltB64);
    iv = fromBase64Url(ivB64);
    ciphertext = fromBase64Url(cipherB64);
  } catch {
    throw new Error('Malformed base64url encoding in sealed session');
  }

  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 16) {
    throw new Error('Invalid cryptographic component lengths');
  }

  const crypto = getWebCrypto();
  const iterations = options.iterations ?? 100_000;
  const toleranceMs = (options.clockTolerance ?? 60) * 1000;

  const gcmParams: AesGcmParams = {
    name: 'AES-GCM',
    iv: iv as unknown as BufferSource,
    tagLength: 128,
  };

  if (options.additionalData) {
    gcmParams.additionalData = encoder.encode(options.additionalData) as unknown as BufferSource;
  }

  let decryptedBuffer: ArrayBuffer | null = null;

  for (const secret of secrets) {
    if (!secret) continue;
    try {
      const key = await deriveKey(secret, salt, iterations);
      decryptedBuffer = await crypto.subtle.decrypt(
        gcmParams,
        key,
        ciphertext as unknown as BufferSource
      );
      break;
    } catch {
      // Key mismatch or tampered ciphertext / AAD mismatch; continue to next secret
    }
  }

  if (!decryptedBuffer) {
    throw new Error('Failed to unseal session: authentication failed or tampered data');
  }

  let decryptedBytes: Uint8Array = new Uint8Array(decryptedBuffer);

  let envelope: Envelope<T> | null = null;
  try {
    const rawString = decoder.decode(decryptedBytes);
    const parsed = JSON.parse(rawString);
    if (parsed && typeof parsed === 'object' && typeof parsed.iat === 'number') {
      envelope = parsed;
    }
  } catch {
    // Not raw JSON, try decompressing below
  }

  if (!envelope) {
    try {
      const decompressed = await decompressBytes(decryptedBytes);
      envelope = JSON.parse(decoder.decode(decompressed));
    } catch {
      throw new Error('Failed to parse or decompress session envelope');
    }
  }

  if (!envelope) {
    throw new Error('Failed to parse or decompress session envelope');
  }

  return checkEnvelope(envelope, toleranceMs);
}

function checkEnvelope<T>(envelope: Envelope<T>, toleranceMs: number): T {
  const now = Date.now();
  if (typeof envelope.exp === 'number' && now - toleranceMs > envelope.exp) {
    throw new Error('Session has expired');
  }
  return envelope.data;
}
