/**
 * Input Sanitization Utilities
 * Standard sanitization functions for security-sensitive input handling
 */

export interface SanitizeOptions {
  maxLength?: number;
  allowNewlines?: boolean;
  allowUnicode?: boolean;
  stripHtml?: boolean;
  escapeShell?: boolean;
  escapeSql?: boolean;
}

const DEFAULT_OPTIONS: SanitizeOptions = {
  maxLength: 10000,
  allowNewlines: true,
  allowUnicode: true,
  stripHtml: true,
  escapeShell: false,
  escapeSql: false,
};

/**
 * HTML entity encoding map
 */
const HTML_ENTITIES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
  '/': '&#x2F;',
  '`': '&#x60;',
  '=': '&#x3D;',
};

/**
 * Shell metacharacters that need escaping
 */
const SHELL_METACHARACTERS = /[;&|`$(){}[\]<>*?!#~^\\\n\r]/g;

/**
 * Escape HTML entities to prevent XSS
 */
export function escapeHtml(input: string): string {
  return input.replace(/[&<>"'`=/]/g, (char) => HTML_ENTITIES[char] || char);
}

/**
 * Strip all HTML tags from input
 */
export function stripHtml(input: string): string {
  return input
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .trim();
}

/**
 * Escape shell metacharacters to prevent command injection
 */
export function escapeShell(input: string): string {
  return input.replace(SHELL_METACHARACTERS, '\\$&');
}

/**
 * Escape SQL special characters (basic - use parameterized queries instead)
 */
export function escapeSql(input: string): string {
  return input
    .replace(/'/g, "''")
    .replace(/\\/g, '\\\\')
    .replace(/\x00/g, '\\0')
    .replace(/\x1a/g, '\\Z');
}

/**
 * Remove null bytes and other dangerous control characters
 */
export function stripControlChars(input: string, allowNewlines = true): string {
  if (allowNewlines) {
    // Keep \n \r \t, remove other control chars
    return input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  }
  // Remove all control characters including newlines
  return input.replace(/[\x00-\x1F\x7F]/g, '');
}

/**
 * Normalize unicode to prevent homograph attacks
 */
export function normalizeUnicode(input: string): string {
  return input.normalize('NFKC');
}

/**
 * Remove path traversal sequences
 */
export function sanitizePath(input: string): string {
  return input
    .replace(/\.\.[/\\]/g, '')
    .replace(/^[/\\]+/, '')
    .replace(/\x00/g, '');
}

/**
 * Validate and sanitize URL
 */
export function sanitizeUrl(input: string): string | null {
  try {
    const url = new URL(input);
    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(url.protocol)) {
      return null;
    }
    return url.toString();
  } catch {
    return null;
  }
}

/**
 * Sanitize email address
 */
export function sanitizeEmail(input: string): string | null {
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  const trimmed = input.trim().toLowerCase();
  return emailRegex.test(trimmed) ? trimmed : null;
}

/**
 * Main sanitization function with configurable options
 */
export function sanitize(input: string, options: SanitizeOptions = {}): string {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  let result = input;

  // Truncate to max length
  if (opts.maxLength && result.length > opts.maxLength) {
    result = result.slice(0, opts.maxLength);
  }

  // Normalize unicode if allowed, otherwise strip non-ASCII
  if (opts.allowUnicode) {
    result = normalizeUnicode(result);
  } else {
    result = result.replace(/[^\x00-\x7F]/g, '');
  }

  // Strip control characters
  result = stripControlChars(result, opts.allowNewlines);

  // Strip or escape HTML
  if (opts.stripHtml) {
    result = stripHtml(result);
  }

  // Escape shell if needed
  if (opts.escapeShell) {
    result = escapeShell(result);
  }

  // Escape SQL if needed (prefer parameterized queries)
  if (opts.escapeSql) {
    result = escapeSql(result);
  }

  return result.trim();
}

/**
 * Validate input against common injection patterns
 * Returns true if input appears safe, false if suspicious
 */
export function validateInput(input: string): { safe: boolean; warnings: string[] } {
  const warnings: string[] = [];

  // Check for null bytes
  if (input.includes('\x00')) {
    warnings.push('Contains null bytes');
  }

  // Check for SQL injection patterns
  if (/('|--|;|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b)/i.test(input)) {
    warnings.push('Potential SQL injection pattern');
  }

  // Check for command injection patterns
  if (/[;&|`$()]|\$\(|`.*`/.test(input)) {
    warnings.push('Potential command injection pattern');
  }

  // Check for path traversal
  if (/\.\.[\\/]/.test(input)) {
    warnings.push('Path traversal sequence detected');
  }

  // Check for script tags
  if (/<script|javascript:|on\w+\s*=/i.test(input)) {
    warnings.push('Potential XSS pattern');
  }

  // Check for LDAP injection
  if (/[()\\*\x00]/.test(input)) {
    warnings.push('Potential LDAP injection characters');
  }

  return {
    safe: warnings.length === 0,
    warnings,
  };
}

export default {
  sanitize,
  validateInput,
  escapeHtml,
  stripHtml,
  escapeShell,
  escapeSql,
  stripControlChars,
  normalizeUnicode,
  sanitizePath,
  sanitizeUrl,
  sanitizeEmail,
};
