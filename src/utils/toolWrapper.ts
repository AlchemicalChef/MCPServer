/**
 * Tool Wrapper with Automatic Input Sanitization
 * Wraps MCP tool handlers to sanitize all string inputs automatically
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { sanitize, validateInput, SanitizeOptions } from './sanitize.js';

export interface ToolWrapperOptions {
  /** Sanitization options applied to all string inputs */
  sanitizeOptions?: SanitizeOptions;
  /** Log sanitization warnings */
  logWarnings?: boolean;
  /** Reject inputs that fail validation */
  rejectSuspicious?: boolean;
  /** Custom rejection message */
  rejectionMessage?: string;
}

const DEFAULT_WRAPPER_OPTIONS: ToolWrapperOptions = {
  sanitizeOptions: {
    maxLength: 100000,
    allowNewlines: true,
    allowUnicode: true,
    stripHtml: true,
  },
  logWarnings: true,
  rejectSuspicious: false,
  rejectionMessage: 'Input validation failed: suspicious patterns detected',
};

/**
 * Recursively sanitize all string values in an object
 */
export function sanitizeObject<T>(obj: T, options: SanitizeOptions): T {
  if (typeof obj === 'string') {
    return sanitize(obj, options) as T;
  }

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item, options)) as T;
  }

  if (obj !== null && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = sanitizeObject(value, options);
    }
    return result as T;
  }

  return obj;
}

/**
 * Recursively validate all string values in an object
 */
export function validateObject(obj: unknown, path = ''): { safe: boolean; allWarnings: Array<{ path: string; warnings: string[] }> } {
  const allWarnings: Array<{ path: string; warnings: string[] }> = [];

  if (typeof obj === 'string') {
    const { safe, warnings } = validateInput(obj);
    if (!safe) {
      allWarnings.push({ path: path || 'input', warnings });
    }
  } else if (Array.isArray(obj)) {
    obj.forEach((item, index) => {
      const result = validateObject(item, `${path}[${index}]`);
      allWarnings.push(...result.allWarnings);
    });
  } else if (obj !== null && typeof obj === 'object') {
    for (const [key, value] of Object.entries(obj)) {
      const result = validateObject(value, path ? `${path}.${key}` : key);
      allWarnings.push(...result.allWarnings);
    }
  }

  return {
    safe: allWarnings.length === 0,
    allWarnings,
  };
}

// Store global options
let globalOptions: ToolWrapperOptions = DEFAULT_WRAPPER_OPTIONS;

/**
 * Wrap a tool handler function with sanitization
 */
export function wrapHandler<TArgs, TExtra, TResult>(
  handler: (args: TArgs, extra: TExtra) => TResult | Promise<TResult>,
  options: ToolWrapperOptions = globalOptions
): (args: TArgs, extra: TExtra) => Promise<TResult> {
  return async (args: TArgs, extra: TExtra): Promise<TResult> => {
    // Validate inputs first
    const validation = validateObject(args);

    if (!validation.safe) {
      if (options.logWarnings) {
        console.warn('[SANITIZE] Input validation warnings:', JSON.stringify(validation.allWarnings, null, 2));
      }

      if (options.rejectSuspicious) {
        return {
          content: [{
            type: 'text',
            text: `${options.rejectionMessage}\n\nWarnings:\n${validation.allWarnings
              .map(w => `- ${w.path}: ${w.warnings.join(', ')}`)
              .join('\n')}`,
          }],
          isError: true,
        } as TResult;
      }
    }

    // Sanitize all string inputs
    const sanitizedArgs = sanitizeObject(args, options.sanitizeOptions || {});

    // Call the original handler with sanitized inputs
    return handler(sanitizedArgs, extra);
  };
}

/**
 * Enable global input sanitization on an MCP server
 * This patches the server.tool method to wrap all handlers
 */
export function enableGlobalSanitization(
  server: McpServer,
  options: ToolWrapperOptions = {}
): void {
  globalOptions = { ...DEFAULT_WRAPPER_OPTIONS, ...options };

  // Store the original tool method
  const originalTool = server.tool.bind(server);

  // Create patched version that wraps handlers
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (server as any).tool = function patchedTool(...args: unknown[]) {
    // server.tool has multiple overloads, handler is always last argument
    const lastArg = args[args.length - 1];

    if (typeof lastArg === 'function') {
      // Replace handler with wrapped version
      args[args.length - 1] = wrapHandler(lastArg as (...a: unknown[]) => unknown, globalOptions);
    }

    // Call original with modified args
    return originalTool(...(args as Parameters<typeof originalTool>));
  };
}

export default {
  wrapHandler,
  enableGlobalSanitization,
  sanitizeObject,
  validateObject,
};
