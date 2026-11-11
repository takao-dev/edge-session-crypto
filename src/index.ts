/**
 * edge-session-crypto: Stateless encrypted cookie session manager for Edge, Cloudflare Workers, and Node.js.
 * Built with native WebCrypto SubtleCrypto. Zero Runtime Dependencies.
 */

export * from './crypto.js';
export * from './cookie.js';

import { sealData, unsealData, SealOptions, UnsealOptions } from './crypto.js';
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
}

export class SessionManager<T = Record<string, any>> {
  readonly cookieName: string;
  private readonly passwords: string[];
  readonly ttl: number;
  readonly cookieOptions: CookieSerializeOptions;
  readonly iterations: number;

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
    this.iterations = config.iterations ?? 100_000;
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
   * Returns null if the session cookie is missing, expired, or invalid.
   */
  async getSession(
    input: string | Request | Headers | { headers?: Headers | Record<string, string> } | null | undefined
  ): Promise<T | null> {
    const cookieHeader = this.extractCookieHeader(input);
    if (!cookieHeader) return null;

    const cookies = parseCookies(cookieHeader);
    const sealed = cookies[this.cookieName];
    if (!sealed) return null;

    try {
      return await unsealData<T>(sealed, this.passwords, {
        iterations: this.iterations,
      });
    } catch {
      return null;
    }
  }

  /**
   * Encrypt session data and return a `Set-Cookie` header string ready to send to the client.
   */
  async setSession(data: T, customTtl?: number): Promise<string> {
    const ttl = typeof customTtl === 'number' ? customTtl : this.ttl;
    const sealed = await sealData<T>(data, this.passwords, {
      ttl,
      iterations: this.iterations,
    });

    const cookieOpts: CookieSerializeOptions = {
      ...this.cookieOptions,
      maxAge: ttl,
    };

    return serializeCookie(this.cookieName, sealed, cookieOpts);
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
