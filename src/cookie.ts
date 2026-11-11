/**
 * High-performance, RFC 6265bis & CHIPS (Partitioned Cookies) compliant cookie helpers.
 * Includes Prefix Guard enforcement for __Host- and __Secure- cookies.
 * Zero Runtime Dependencies.
 */

export interface CookieSerializeOptions {
  /** Cookie path. Defaults to '/'. */
  path?: string;
  /** Cookie domain. Must be undefined for __Host- cookies. */
  domain?: string;
  /** Max age in seconds. */
  maxAge?: number;
  /** Specific expiration date. */
  expires?: Date;
  /** Restricts cookie access to HTTP requests only (mitigating XSS). Defaults to true. */
  httpOnly?: boolean;
  /** Requires HTTPS transmission. Defaults to true. */
  secure?: boolean;
  /** Controls cross-site cookie behavior. Defaults to 'lax'. */
  sameSite?: 'lax' | 'strict' | 'none' | boolean;
  /** Enables CHIPS (Cookies Having Independent Partitioned State). Defaults to false. */
  partitioned?: boolean;
}

/**
 * Validate security invariants for special cookie prefixes per RFC 6265bis.
 */
export function validateCookiePrefix(name: string, options: CookieSerializeOptions): void {
  if (name.startsWith('__Host-')) {
    if (options.secure === false) {
      throw new Error('__Host- cookies must have Secure=true');
    }
    if (options.path && options.path !== '/') {
      throw new Error('__Host- cookies must have Path="/"');
    }
    if (options.domain) {
      throw new Error('__Host- cookies must not specify a Domain attribute');
    }
  } else if (name.startsWith('__Secure-')) {
    if (options.secure === false) {
      throw new Error('__Secure- cookies must have Secure=true');
    }
  }
}

/**
 * Parse an incoming HTTP `Cookie` header string into key-value pairs.
 */
export function parseCookies(header: string | null | undefined): Record<string, string> {
  if (!header || typeof header !== 'string') {
    return {};
  }

  const cookies: Record<string, string> = {};
  const pairs = header.split(';');

  for (let i = 0; i < pairs.length; i++) {
    const pair = pairs[i].trim();
    if (!pair) continue;

    const eqIdx = pair.indexOf('=');
    if (eqIdx === -1) {
      cookies[pair] = '';
      continue;
    }

    const key = pair.slice(0, eqIdx).trim();
    let val = pair.slice(eqIdx + 1).trim();

    // Remove quotes if present
    if (val.startsWith('"') && val.endsWith('"') && val.length >= 2) {
      val = val.slice(1, -1);
    }

    try {
      cookies[key] = decodeURIComponent(val);
    } catch {
      cookies[key] = val;
    }
  }

  return cookies;
}

/**
 * Serialize a cookie name, value, and options into a `Set-Cookie` header string.
 */
export function serializeCookie(
  name: string,
  value: string,
  options: CookieSerializeOptions = {}
): string {
  if (!name || typeof name !== 'string') {
    throw new Error('Cookie name must be a non-empty string');
  }

  // Enforce Prefix Guard
  validateCookiePrefix(name, options);

  const encodedValue = encodeURIComponent(value);
  let str = `${name}=${encodedValue}`;

  const maxAge = options.maxAge;
  if (typeof maxAge === 'number' && !Number.isNaN(maxAge)) {
    str += `; Max-Age=${Math.floor(maxAge)}`;
  }

  if (options.expires instanceof Date && !Number.isNaN(options.expires.getTime())) {
    str += `; Expires=${options.expires.toUTCString()}`;
  }

  if (options.domain) {
    str += `; Domain=${options.domain}`;
  }

  const path = options.path ?? '/';
  if (path) {
    str += `; Path=${path}`;
  }

  const secure = options.secure ?? true;
  if (secure) {
    str += '; Secure';
  }

  const httpOnly = options.httpOnly ?? true;
  if (httpOnly) {
    str += '; HttpOnly';
  }

  const sameSite = options.sameSite ?? 'lax';
  if (sameSite === true || sameSite === 'strict') {
    str += '; SameSite=Strict';
  } else if (sameSite === 'lax') {
    str += '; SameSite=Lax';
  } else if (sameSite === 'none') {
    str += '; SameSite=None';
  }

  if (options.partitioned) {
    str += '; Partitioned';
  }

  return str;
}
