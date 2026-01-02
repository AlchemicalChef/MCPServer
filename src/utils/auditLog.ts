/**
 * Audit Logging Utility
 * Logs all tool invocations with context and inputs for security review and audit
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

export interface AuditLogEntry {
  timestamp: string;
  toolName: string;
  inputs: Record<string, unknown>;
  context?: {
    clientId?: string;
    sessionId?: string;
    userAgent?: string;
    sourceIp?: string;
  };
  sanitizationWarnings?: string[];
  executionTimeMs?: number;
  result?: {
    success: boolean;
    error?: string;
    outputSummary?: string;
  };
}

export interface AuditLogConfig {
  /** Enable/disable logging */
  enabled: boolean;
  /** Log file path (default: ./audit.log) */
  logFile: string;
  /** Also log to console */
  consoleOutput: boolean;
  /** Log level: 'minimal' (tool + timestamp), 'standard' (+ inputs), 'verbose' (+ outputs) */
  level: 'minimal' | 'standard' | 'verbose';
  /** Max log file size in bytes before rotation (default: 10MB) */
  maxFileSize: number;
  /** Redact sensitive fields from logs */
  redactSensitive: boolean;
  /** Fields to redact */
  sensitiveFields: string[];
}

const DEFAULT_CONFIG: AuditLogConfig = {
  enabled: true,
  logFile: './mcp-audit.log',
  consoleOutput: false,
  level: 'standard',
  maxFileSize: 10 * 1024 * 1024, // 10MB
  redactSensitive: true,
  sensitiveFields: ['password', 'secret', 'token', 'key', 'apiKey', 'api_key', 'credential', 'auth'],
};

let config: AuditLogConfig = { ...DEFAULT_CONFIG };
let logStream: fs.WriteStream | null = null;

/**
 * Initialize the audit logger with custom configuration
 */
export function initAuditLog(customConfig: Partial<AuditLogConfig> = {}): void {
  config = { ...DEFAULT_CONFIG, ...customConfig };

  if (config.enabled && config.logFile) {
    const logDir = path.dirname(config.logFile);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }

    // Check for log rotation
    rotateLogIfNeeded();

    logStream = fs.createWriteStream(config.logFile, { flags: 'a' });

    // Write header on new log
    const stats = fs.statSync(config.logFile);
    if (stats.size === 0) {
      const header = `# MCP Server Audit Log\n# Started: ${new Date().toISOString()}\n# Format: JSON Lines\n\n`;
      logStream.write(header);
    }
  }
}

/**
 * Rotate log file if it exceeds max size
 */
function rotateLogIfNeeded(): void {
  if (!fs.existsSync(config.logFile)) return;

  const stats = fs.statSync(config.logFile);
  if (stats.size >= config.maxFileSize) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const rotatedName = config.logFile.replace(/\.log$/, `-${timestamp}.log`);
    fs.renameSync(config.logFile, rotatedName);
  }
}

/**
 * Redact sensitive values from an object
 */
function redactSensitive(obj: Record<string, unknown>, sensitiveFields: string[]): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    const isFieldSensitive = sensitiveFields.some(field =>
      key.toLowerCase().includes(field.toLowerCase())
    );

    if (isFieldSensitive && typeof value === 'string') {
      result[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      result[key] = redactSensitive(value as Record<string, unknown>, sensitiveFields);
    } else {
      result[key] = value;
    }
  }

  return result;
}

/**
 * Truncate long strings for log readability
 */
function truncateStrings(obj: Record<string, unknown>, maxLength = 500): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string' && value.length > maxLength) {
      result[key] = value.substring(0, maxLength) + `... [truncated, ${value.length} chars total]`;
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      result[key] = truncateStrings(value as Record<string, unknown>, maxLength);
    } else {
      result[key] = value;
    }
  }

  return result;
}

/**
 * Log an audit entry
 */
export function logAudit(entry: Omit<AuditLogEntry, 'timestamp'>): void {
  if (!config.enabled) return;

  const fullEntry: AuditLogEntry = {
    timestamp: new Date().toISOString(),
    ...entry,
  };

  // Process inputs based on config
  if (fullEntry.inputs && config.redactSensitive) {
    fullEntry.inputs = redactSensitive(fullEntry.inputs, config.sensitiveFields);
  }

  // Truncate long values
  if (fullEntry.inputs) {
    fullEntry.inputs = truncateStrings(fullEntry.inputs);
  }

  // Format based on log level
  let logLine: string;

  switch (config.level) {
    case 'minimal':
      logLine = JSON.stringify({
        timestamp: fullEntry.timestamp,
        toolName: fullEntry.toolName,
        success: fullEntry.result?.success ?? true,
      });
      break;

    case 'verbose':
      logLine = JSON.stringify(fullEntry);
      break;

    case 'standard':
    default:
      logLine = JSON.stringify({
        timestamp: fullEntry.timestamp,
        toolName: fullEntry.toolName,
        inputs: fullEntry.inputs,
        context: fullEntry.context,
        sanitizationWarnings: fullEntry.sanitizationWarnings,
        executionTimeMs: fullEntry.executionTimeMs,
        success: fullEntry.result?.success ?? true,
        error: fullEntry.result?.error,
      });
      break;
  }

  // Write to file
  if (logStream) {
    logStream.write(logLine + '\n');
  }

  // Write to console if enabled
  if (config.consoleOutput) {
    console.log('[AUDIT]', logLine);
  }
}

/**
 * Create a logging wrapper for tool handlers
 * Automatically logs inputs and outputs
 */
export function withAuditLog<TParams extends Record<string, unknown>, TResult>(
  toolName: string,
  handler: (params: TParams) => Promise<TResult>
): (params: TParams) => Promise<TResult> {
  return async (params: TParams): Promise<TResult> => {
    const startTime = Date.now();
    let result: TResult;
    let success = true;
    let error: string | undefined;

    try {
      result = await handler(params);
      return result;
    } catch (err) {
      success = false;
      error = err instanceof Error ? err.message : String(err);
      throw err;
    } finally {
      const executionTimeMs = Date.now() - startTime;

      logAudit({
        toolName,
        inputs: params as Record<string, unknown>,
        executionTimeMs,
        result: {
          success,
          error,
        },
      });
    }
  };
}

/**
 * Convenience function to log tool invocation at the start of a handler
 */
export function logToolInvocation(
  toolName: string,
  inputs: Record<string, unknown>,
  sanitizationWarnings?: string[]
): void {
  logAudit({
    toolName,
    inputs,
    sanitizationWarnings,
  });
}

/**
 * Close the audit log stream
 */
export function closeAuditLog(): void {
  if (logStream) {
    logStream.end();
    logStream = null;
  }
}

/**
 * Get current audit log configuration
 */
export function getAuditConfig(): AuditLogConfig {
  return { ...config };
}

/**
 * Update audit log configuration at runtime
 */
export function updateAuditConfig(updates: Partial<AuditLogConfig>): void {
  config = { ...config, ...updates };
}

export default {
  initAuditLog,
  logAudit,
  logToolInvocation,
  withAuditLog,
  closeAuditLog,
  getAuditConfig,
  updateAuditConfig,
};
