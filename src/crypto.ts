/**
 * Cryptographic helpers for edge-session-crypto.
 * Native WebCrypto SubtleCrypto implementation with Zero Runtime Dependencies.
 * Features: AES-256-GCM, PBKDF2-SHA256, AAD client binding, Deflate compression.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const MAX_SESSION_PAYLOAD_BYTES = 1_048_576;

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
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto?.subtle) {
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
  return transformBytes(data, new CompressionStream('deflate'), MAX_SESSION_PAYLOAD_BYTES + 65_536);
}

/**
 * Decompress bytes using native DecompressionStream (deflate).
 */
export async function decompressBytes(data: Uint8Array): Promise<Uint8Array> {
  if (typeof DecompressionStream === 'undefined') return data;
  return transformBytes(data, new DecompressionStream('deflate'), MAX_SESSION_PAYLOAD_BYTES);
}

async function transformBytes(data: Uint8Array, stream: CompressionStream | DecompressionStream, maxOutput: number): Promise<Uint8Array> {
  const reader = stream.readable.getReader();
  const writer = stream.writable.getWriter();
  const chunks: Uint8Array[] = [];
  let length = 0;
  const draining = (async () => {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maxOutput) {
        await reader.cancel('Session payload exceeds the configured limit');
        throw new RangeError('Session payload exceeds the configured limit');
      }
      chunks.push(value);
    }
  })();
  try {
    await Promise.all([writer.write(data as unknown as BufferSource).then(() => writer.close()), draining]);
  } catch (error) {
    await writer.abort(error).catch(() => undefined);
    throw error;
  }
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length; }
  return output;
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
  /** Allowed clock drift in seconds when checking expiration. Defaults to 0s. */
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
  if (options.ttl !== undefined && (!Number.isFinite(options.ttl) || options.ttl <= 0)) throw new Error('ttl must be a positive finite number');
  validateIterations(options.iterations ?? 100_000);
  const activeSecret = secrets[0];
  const crypto = getWebCrypto();

  const now = Date.now();
  const envelope: Envelope<T> = {
    data,
    iat: now,
  };
  if (typeof options.ttl === 'number') {
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
  if (plaintextBytes.byteLength > MAX_SESSION_PAYLOAD_BYTES) throw new RangeError('Session payload exceeds the 1 MiB limit');
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
  validateIterations(options.iterations ?? 100_000);
  if (options.clockTolerance !== undefined && (!Number.isFinite(options.clockTolerance) || options.clockTolerance < 0)) throw new Error('clockTolerance must be non-negative and finite');
  if (sealed.length > 1_500_000) throw new RangeError('Sealed session exceeds the maximum encoded size');

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

  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 16 || ciphertext.length > MAX_SESSION_PAYLOAD_BYTES + 65_536 + 16) {
    throw new Error('Invalid cryptographic component lengths');
  }

  const crypto = getWebCrypto();
  const iterations = options.iterations ?? 100_000;
  const toleranceMs = (options.clockTolerance ?? 0) * 1000;

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
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && typeof parsed.iat === 'number') {
      envelope = parsed;
    }
  } catch {
    // Not raw JSON, try decompressing below
  }

  if (!envelope && decryptedBytes.length <= MAX_SESSION_PAYLOAD_BYTES) {
    try {
      const decompressed = await decompressBytes(decryptedBytes);
      envelope = JSON.parse(decoder.decode(decompressed));
    } catch {
      throw new Error('Failed to parse or decompress session envelope');
    }
  }

  return checkEnvelope(envelope!, toleranceMs);
}

function checkEnvelope<T>(envelope: Envelope<T>, toleranceMs: number): T {
  if (!envelope || typeof envelope !== 'object' || !Number.isFinite(envelope.iat)) throw new Error('Invalid session envelope');
  if (envelope.exp !== undefined && !Number.isFinite(envelope.exp)) throw new Error('Invalid session expiry');
  const now = Date.now();
  if (typeof envelope.exp === 'number' && now - toleranceMs >= envelope.exp) {
    throw new Error('Session has expired');
  }
  return envelope.data;
}

function validateIterations(iterations: number): void {
  if (!Number.isInteger(iterations) || iterations < 1 || iterations > 1_000_000) throw new Error('PBKDF2 iterations must be an integer from 1 to 1000000');
}
