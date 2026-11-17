/**
 * edge-session-crypto: Stateless encrypted cookie session manager for Edge, Cloudflare Workers, and Node.js.
 * Built with native WebCrypto SubtleCrypto. Zero Runtime Dependencies.
 */

export * from './crypto.js';
export * from './cookie.js';

import { sealData, unsealData } from './crypto.js';
import { parseCookies, serializeCookie, CookieSerializeOptions } from './cookie.js';

export interface SessionConfig {
  /** Name of the session cookie. Defaults to 'session'. */
  cookieName?: string;
  /** Primary secret or array of secrets for transparent key rotation. Required. */
  password: string | string[];
  /** Session TTL in seconds. Defaults to 86400 (24 hours). */
  ttl?: number;
  /** Cookie serialization options. */
  cookie?: CookieSerializeOptions;
  /** Crypto PBKDF2 iterations. Defaults to 100,000. */
  iterations?: number;
  /** Enable automatic payload compression. Defaults to false. */
  compress?: boolean;
}

export class SessionManager<T = Record<string, any>> {
  readonly cookieName: string;
  private readonly passwords: string[];
  readonly ttl: number;
  readonly cookieOptions: CookieSerializeOptions;
  readonly iterations: number;
  readonly compress: boolean;

  constructor(config: SessionConfig) {
    if (!config || !config.password) {
      throw new Error('SessionManager requires a non-empty password configuration');
    }

    this.cookieName = config.cookieName ?? 'session';
    this.passwords = Array.isArray(config.password) ? config.password : [config.password];
    if (this.passwords.length === 0 || !this.passwords[0]) {
      throw new Error('At least one valid password must be provided');
    }

    this.ttl = config.ttl ?? 86400; // 24 hours
    if (!Number.isFinite(this.ttl) || this.ttl <= 0) throw new Error('Session TTL must be a positive finite number');
    this.iterations = config.iterations ?? 100_000;
    this.compress = Boolean(config.compress);
    this.cookieOptions = {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: this.ttl,
      ...config.cookie,
    };
  }

  /**
   * Retrieve and decrypt the session from an HTTP Cookie header string, Request object, or Headers instance.
   * Supports optional client AAD binding (e.g. user-agent).
   */
  async getSession(
    input: string | Request | Headers | { headers?: Headers | Record<string, string> } | null | undefined,
    additionalData?: string
  ): Promise<T | null> {
    const cookieHeader = this.extractCookieHeader(input);
    if (!cookieHeader) return null;

    const cookies = parseCookies(cookieHeader);
    const sealed = cookies[this.cookieName];
    if (!sealed) return null;

    try {
      return await unsealData<T>(sealed, this.passwords, {
        iterations: this.iterations,
        additionalData,
      });
    } catch {
      return null;
    }
  }

  /**
   * Encrypt session data and return a `Set-Cookie` header string ready to send to the client.
   */
  async setSession(data: T, customTtl?: number, additionalData?: string): Promise<string> {
    const ttl = typeof customTtl === 'number' ? customTtl : this.ttl;
    const sealed = await sealData<T>(data, this.passwords, {
      ttl,
      iterations: this.iterations,
      additionalData,
      compress: this.compress,
    });

    const cookieOpts: CookieSerializeOptions = {
      ...this.cookieOptions,
      maxAge: ttl,
    };

    return serializeCookie(this.cookieName, sealed, cookieOpts);
  }

  /**
   * Re-encrypt an existing session with the newest primary key (active key migration).
   */
  async rotateSession(existingData: T, additionalData?: string): Promise<string> {
    return this.setSession(existingData, this.ttl, additionalData);
  }

  /**
   * Return a `Set-Cookie` header string that immediately clears the session on the client.
   */
  clearSession(): string {
    const cookieOpts: CookieSerializeOptions = {
      ...this.cookieOptions,
      maxAge: 0,
      expires: new Date(0),
    };

    return serializeCookie(this.cookieName, '', cookieOpts);
  }

  private extractCookieHeader(
    input: string | Request | Headers | { headers?: Headers | Record<string, string> } | null | undefined
  ): string | null {
    if (!input) return null;
    if (typeof input === 'string') return input;

    // Fetch API Headers instance
    if (typeof (input as Headers).get === 'function') {
      return (input as Headers).get('cookie');
    }

    // Request or object with headers
    const obj = input as any;
    if (obj.headers) {
      if (typeof obj.headers.get === 'function') {
        return obj.headers.get('cookie');
      }
      if (typeof obj.headers === 'object') {
        return obj.headers.cookie || obj.headers.Cookie || null;
      }
    }

    return null;
  }
}
