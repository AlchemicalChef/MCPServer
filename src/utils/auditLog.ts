/**
 * Audit Logging Utility
 * Logs all tool invocations with context and inputs for security review and audit
 * Includes formal model generation from audit trails
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

// ============================================================================
// Types for Formal Model Generation
// ============================================================================

type FormalModelType = 'state-machine' | 'tlaplus' | 'alloy' | 'petri-net' | 'sequence';

interface ToolState {
  name: string;
  type: 'initial' | 'tool' | 'error' | 'final';
  invocationCount: number;
  avgExecutionMs: number;
  successRate: number;
}

interface ToolTransition {
  from: string;
  to: string;
  count: number;
  avgDelayMs: number;
  conditions: string[];
}

interface AuditFormalModel {
  type: FormalModelType;
  generatedAt: string;
  entryCount: number;
  states: ToolState[];
  transitions: ToolTransition[];
  specification: string;
}

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
  const fullEntry: AuditLogEntry = {
    timestamp: new Date().toISOString(),
    ...entry,
  };

  // Always record to history for model generation (even if file logging disabled)
  recordToHistory(fullEntry);

  if (!config.enabled) return;

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
 * Returns a function to log the output when done
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

// Track active tool invocations for timing
const activeInvocations: Map<string, { toolName: string; startTime: number; inputs: Record<string, unknown> }> = new Map();

/**
 * Start tracking a tool invocation (call at start of handler)
 * Returns an invocation ID to pass to logToolOutput
 */
export function startToolInvocation(
  toolName: string,
  inputs: Record<string, unknown>,
  sanitizationWarnings?: string[]
): string {
  const invocationId = `${toolName}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

  activeInvocations.set(invocationId, {
    toolName,
    startTime: Date.now(),
    inputs,
  });

  // Log the input
  logAudit({
    toolName,
    inputs,
    sanitizationWarnings,
  });

  return invocationId;
}

/**
 * Log tool output/result (call at end of handler)
 */
export function logToolOutput(
  invocationId: string,
  output: {
    success: boolean;
    error?: string;
    /** Summary of the output (e.g., "Found 5 vulnerabilities") */
    summary?: string;
    /** Key metrics from the output */
    metrics?: Record<string, unknown>;
    /** The full output text (will be truncated) */
    fullOutput?: string;
  }
): void {
  if (!config.enabled) return;

  const invocation = activeInvocations.get(invocationId);
  const executionTimeMs = invocation ? Date.now() - invocation.startTime : undefined;
  const toolName = invocation?.toolName || 'unknown';

  // Clean up
  if (invocation) {
    activeInvocations.delete(invocationId);
  }

  // Build output entry
  const outputEntry: Record<string, unknown> = {
    timestamp: new Date().toISOString(),
    type: 'output',
    toolName,
    executionTimeMs,
    success: output.success,
  };

  if (output.error) {
    outputEntry.error = output.error;
  }

  if (output.summary) {
    outputEntry.summary = output.summary;
  }

  if (output.metrics) {
    outputEntry.metrics = output.metrics;
  }

  // Only include full output in verbose mode
  if (config.level === 'verbose' && output.fullOutput) {
    const truncated = output.fullOutput.length > 2000
      ? output.fullOutput.substring(0, 2000) + `... [truncated, ${output.fullOutput.length} chars total]`
      : output.fullOutput;
    outputEntry.output = truncated;
  }

  // Apply redaction if configured
  if (config.redactSensitive && outputEntry.output) {
    outputEntry.output = redactSensitiveString(outputEntry.output as string, config.sensitiveFields);
  }

  const logLine = JSON.stringify(outputEntry);

  // Write to file
  if (logStream) {
    logStream.write(logLine + '\n');
  }

  // Write to console if enabled
  if (config.consoleOutput) {
    console.log('[AUDIT:OUTPUT]', logLine);
  }
}

/**
 * Redact sensitive patterns from a string
 */
function redactSensitiveString(str: string, sensitiveFields: string[]): string {
  let result = str;

  // Redact common secret patterns
  const patterns = [
    // API keys and tokens
    /(?:api[_-]?key|token|secret|password|auth)['":\s]*[=:]\s*['"]?([A-Za-z0-9\-_\.]{16,})['"]?/gi,
    // AWS keys
    /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
    // Generic secrets
    /['"][A-Za-z0-9\-_\.]{32,}['"]/g,
  ];

  for (const pattern of patterns) {
    result = result.replace(pattern, '[REDACTED]');
  }

  return result;
}

/**
 * Simple output logger without invocation tracking
 * Use when you just want to log output without timing
 */
export function logOutput(
  toolName: string,
  output: {
    success: boolean;
    error?: string;
    summary?: string;
    metrics?: Record<string, unknown>;
    fullOutput?: string;
  }
): void {
  if (!config.enabled) return;

  const outputEntry: Record<string, unknown> = {
    timestamp: new Date().toISOString(),
    type: 'output',
    toolName,
    success: output.success,
  };

  if (output.error) {
    outputEntry.error = output.error;
  }

  if (output.summary) {
    outputEntry.summary = output.summary;
  }

  if (output.metrics) {
    outputEntry.metrics = output.metrics;
  }

  if (config.level === 'verbose' && output.fullOutput) {
    const truncated = output.fullOutput.length > 2000
      ? output.fullOutput.substring(0, 2000) + `... [truncated, ${output.fullOutput.length} chars total]`
      : output.fullOutput;
    outputEntry.output = config.redactSensitive
      ? redactSensitiveString(truncated, config.sensitiveFields)
      : truncated;
  }

  const logLine = JSON.stringify(outputEntry);

  if (logStream) {
    logStream.write(logLine + '\n');
  }

  if (config.consoleOutput) {
    console.log('[AUDIT:OUTPUT]', logLine);
  }
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

// ============================================================================
// In-Memory Audit History for Formal Model Generation
// ============================================================================

interface AuditHistoryEntry {
  timestamp: Date;
  toolName: string;
  success: boolean;
  executionTimeMs?: number;
  inputKeys: string[];
  error?: string;
}

const auditHistory: AuditHistoryEntry[] = [];
const MAX_HISTORY_SIZE = 10000;

/**
 * Record an entry to in-memory history for model generation
 */
function recordToHistory(entry: AuditLogEntry): void {
  auditHistory.push({
    timestamp: new Date(entry.timestamp),
    toolName: entry.toolName,
    success: entry.result?.success ?? true,
    executionTimeMs: entry.executionTimeMs,
    inputKeys: Object.keys(entry.inputs || {}),
    error: entry.result?.error,
  });

  // Trim history if too large
  if (auditHistory.length > MAX_HISTORY_SIZE) {
    auditHistory.splice(0, auditHistory.length - MAX_HISTORY_SIZE);
  }
}

/**
 * Get the current audit history
 */
export function getAuditHistory(): AuditHistoryEntry[] {
  return [...auditHistory];
}

/**
 * Clear the audit history
 */
export function clearAuditHistory(): void {
  auditHistory.length = 0;
}

// ============================================================================
// Formal Model Generation from Audit Logs
// ============================================================================

/**
 * Analyze audit history to extract states and transitions
 */
function analyzeAuditHistory(): { states: ToolState[]; transitions: ToolTransition[] } {
  const toolStats: Map<string, {
    count: number;
    totalMs: number;
    successes: number;
  }> = new Map();

  const transitionStats: Map<string, {
    count: number;
    totalDelayMs: number;
    conditions: Set<string>;
  }> = new Map();

  let prevTool: string | null = null;
  let prevTime: Date | null = null;

  for (const entry of auditHistory) {
    // Track tool stats
    const stats = toolStats.get(entry.toolName) || { count: 0, totalMs: 0, successes: 0 };
    stats.count++;
    stats.totalMs += entry.executionTimeMs || 0;
    if (entry.success) stats.successes++;
    toolStats.set(entry.toolName, stats);

    // Track transitions
    if (prevTool) {
      const transKey = `${prevTool}→${entry.toolName}`;
      const trans = transitionStats.get(transKey) || { count: 0, totalDelayMs: 0, conditions: new Set() };
      trans.count++;
      if (prevTime) {
        trans.totalDelayMs += entry.timestamp.getTime() - prevTime.getTime();
      }
      // Add input keys as conditions
      entry.inputKeys.forEach(k => trans.conditions.add(k));
      transitionStats.set(transKey, trans);
    }

    prevTool = entry.toolName;
    prevTime = entry.timestamp;
  }

  // Convert to states
  const states: ToolState[] = [
    { name: 'START', type: 'initial', invocationCount: 0, avgExecutionMs: 0, successRate: 1 },
  ];

  for (const [name, stats] of toolStats) {
    states.push({
      name,
      type: 'tool',
      invocationCount: stats.count,
      avgExecutionMs: stats.count > 0 ? Math.round(stats.totalMs / stats.count) : 0,
      successRate: stats.count > 0 ? stats.successes / stats.count : 0,
    });
  }

  states.push({ name: 'END', type: 'final', invocationCount: 0, avgExecutionMs: 0, successRate: 1 });

  // Convert to transitions
  const transitions: ToolTransition[] = [];

  // Add START transitions to first tools
  const firstTools = new Set<string>();
  if (auditHistory.length > 0) {
    firstTools.add(auditHistory[0].toolName);
  }
  for (const tool of firstTools) {
    transitions.push({
      from: 'START',
      to: tool,
      count: 1,
      avgDelayMs: 0,
      conditions: [],
    });
  }

  for (const [key, stats] of transitionStats) {
    const [from, to] = key.split('→');
    transitions.push({
      from,
      to,
      count: stats.count,
      avgDelayMs: stats.count > 0 ? Math.round(stats.totalDelayMs / stats.count) : 0,
      conditions: Array.from(stats.conditions),
    });
  }

  return { states, transitions };
}

/**
 * Generate state machine diagram from audit history
 */
function generateStateMachineFromAudit(states: ToolState[], transitions: ToolTransition[]): string {
  const lines: string[] = [];

  lines.push('# Audit Trail State Machine');
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push(`Total Entries: ${auditHistory.length}`);
  lines.push('');

  lines.push('## States (Tool Invocations)');
  lines.push('');
  lines.push('| State | Type | Invocations | Avg Execution (ms) | Success Rate |');
  lines.push('|-------|------|-------------|-------------------|--------------|');
  for (const state of states) {
    const icon = state.type === 'initial' ? '▶' : state.type === 'final' ? '◉' : '○';
    lines.push(`| ${icon} ${state.name} | ${state.type} | ${state.invocationCount} | ${state.avgExecutionMs} | ${(state.successRate * 100).toFixed(1)}% |`);
  }
  lines.push('');

  lines.push('## Transitions');
  lines.push('');
  lines.push('| From | To | Count | Avg Delay (ms) |');
  lines.push('|------|-----|-------|----------------|');
  for (const trans of transitions) {
    lines.push(`| ${trans.from} | ${trans.to} | ${trans.count} | ${trans.avgDelayMs} |`);
  }
  lines.push('');

  lines.push('## Mermaid Diagram');
  lines.push('');
  lines.push('```mermaid');
  lines.push('stateDiagram-v2');
  lines.push('  [*] --> START');

  for (const trans of transitions) {
    if (trans.from === 'START') {
      lines.push(`  [*] --> ${trans.to}`);
    } else if (trans.to === 'END') {
      lines.push(`  ${trans.from} --> [*]`);
    } else {
      lines.push(`  ${trans.from} --> ${trans.to}: ${trans.count}x`);
    }
  }

  lines.push('```');

  return lines.join('\n');
}

/**
 * Generate TLA+ specification from audit history
 */
function generateTLAPlusFromAudit(states: ToolState[], transitions: ToolTransition[]): string {
  const lines: string[] = [];
  const toolNames = states.filter(s => s.type === 'tool').map(s => s.name);

  lines.push('---- MODULE AuditTrailModel ----');
  lines.push('EXTENDS Integers, Sequences, TLC');
  lines.push('');
  lines.push('\\* Generated from MCP Server audit trail');
  lines.push(`\\* Generated: ${new Date().toISOString()}`);
  lines.push('');

  lines.push('CONSTANTS');
  lines.push('  \\* Tool names');
  toolNames.forEach(t => lines.push(`  ${t.replace(/-/g, '_')},`));
  lines.push('  NULL');
  lines.push('');

  lines.push('VARIABLES');
  lines.push('  currentTool,    \\* Currently executing tool');
  lines.push('  toolHistory,    \\* Sequence of executed tools');
  lines.push('  errorState      \\* Whether we are in an error state');
  lines.push('');

  lines.push('vars == <<currentTool, toolHistory, errorState>>');
  lines.push('');

  lines.push('Tools == {' + toolNames.map(t => t.replace(/-/g, '_')).join(', ') + '}');
  lines.push('');

  lines.push('TypeInvariant ==');
  lines.push('  /\\ currentTool \\in Tools \\cup {NULL}');
  lines.push('  /\\ toolHistory \\in Seq(Tools)');
  lines.push('  /\\ errorState \\in BOOLEAN');
  lines.push('');

  lines.push('Init ==');
  lines.push('  /\\ currentTool = NULL');
  lines.push('  /\\ toolHistory = <<>>');
  lines.push('  /\\ errorState = FALSE');
  lines.push('');

  // Generate transition actions
  const uniqueTransitions = new Map<string, Set<string>>();
  for (const trans of transitions) {
    if (trans.from !== 'START' && trans.to !== 'END') {
      const fromKey = trans.from.replace(/-/g, '_');
      if (!uniqueTransitions.has(fromKey)) {
        uniqueTransitions.set(fromKey, new Set());
      }
      uniqueTransitions.get(fromKey)!.add(trans.to.replace(/-/g, '_'));
    }
  }

  for (const [from, toSet] of uniqueTransitions) {
    const targets = Array.from(toSet);
    lines.push(`${from}_Next ==`);
    lines.push(`  /\\ currentTool = ${from}`);
    lines.push(`  /\\ currentTool' \\in {${targets.join(', ')}}`);
    lines.push(`  /\\ toolHistory' = Append(toolHistory, currentTool)`);
    lines.push(`  /\\ UNCHANGED errorState`);
    lines.push('');
  }

  lines.push('\\* Any tool can start from initial state');
  lines.push('StartTool ==');
  lines.push('  /\\ currentTool = NULL');
  lines.push('  /\\ currentTool\' \\in Tools');
  lines.push('  /\\ UNCHANGED <<toolHistory, errorState>>');
  lines.push('');

  lines.push('Next ==');
  lines.push('  \\/ StartTool');
  for (const from of uniqueTransitions.keys()) {
    lines.push(`  \\/ ${from}_Next`);
  }
  lines.push('');

  lines.push('\\* Safety: Never reach error state');
  lines.push('Safety == ~errorState');
  lines.push('');

  lines.push('\\* Fairness: Each tool eventually gets executed');
  lines.push('Fairness == \\A t \\in Tools : WF_vars(currentTool\' = t)');
  lines.push('');

  lines.push('Spec == Init /\\ [][Next]_vars /\\ Fairness');
  lines.push('');
  lines.push('====');

  return lines.join('\n');
}

/**
 * Generate Alloy model from audit history
 */
function generateAlloyFromAudit(states: ToolState[], transitions: ToolTransition[]): string {
  const lines: string[] = [];
  const toolNames = states.filter(s => s.type === 'tool').map(s => s.name.replace(/-/g, '_'));

  lines.push('// Alloy model generated from MCP Server audit trail');
  lines.push(`// Generated: ${new Date().toISOString()}`);
  lines.push('module AuditTrailModel');
  lines.push('');

  lines.push('// Tool signatures');
  lines.push('abstract sig Tool {');
  lines.push('  successRate: one Int,');
  lines.push('  avgExecutionMs: one Int');
  lines.push('}');
  lines.push('');

  for (const state of states.filter(s => s.type === 'tool')) {
    const name = state.name.replace(/-/g, '_');
    lines.push(`one sig ${name} extends Tool {} {`);
    lines.push(`  successRate = ${Math.round(state.successRate * 100)}`);
    lines.push(`  avgExecutionMs = ${state.avgExecutionMs}`);
    lines.push('}');
    lines.push('');
  }

  lines.push('// Execution trace');
  lines.push('sig Execution {');
  lines.push('  tool: one Tool,');
  lines.push('  next: lone Execution');
  lines.push('}');
  lines.push('');

  lines.push('// Valid transitions based on observed behavior');
  lines.push('pred validTransition[e1, e2: Execution] {');
  const transPredicates: string[] = [];
  for (const trans of transitions) {
    if (trans.from !== 'START' && trans.to !== 'END') {
      const from = trans.from.replace(/-/g, '_');
      const to = trans.to.replace(/-/g, '_');
      transPredicates.push(`(e1.tool = ${from} and e2.tool = ${to})`);
    }
  }
  if (transPredicates.length > 0) {
    lines.push('  ' + transPredicates.join(' or\n  '));
  } else {
    lines.push('  some e1.tool and some e2.tool');
  }
  lines.push('}');
  lines.push('');

  lines.push('// All transitions must be valid');
  lines.push('fact ValidExecutionTrace {');
  lines.push('  all e: Execution | some e.next implies validTransition[e, e.next]');
  lines.push('}');
  lines.push('');

  lines.push('// No cycles in execution');
  lines.push('fact NoCycles {');
  lines.push('  no e: Execution | e in e.^next');
  lines.push('}');
  lines.push('');

  lines.push('// Assert: high success rate tools are reachable');
  lines.push('assert HighSuccessToolsReachable {');
  lines.push('  all t: Tool | t.successRate > 90 implies some e: Execution | e.tool = t');
  lines.push('}');
  lines.push('');

  lines.push('run {} for 10 Execution');
  lines.push('check HighSuccessToolsReachable for 10 Execution');

  return lines.join('\n');
}

/**
 * Generate Petri net from audit history
 */
function generatePetriNetFromAudit(states: ToolState[], transitions: ToolTransition[]): string {
  const lines: string[] = [];

  lines.push('# Petri Net Model from Audit Trail');
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push('');

  lines.push('## Places (Tool Ready States)');
  lines.push('');
  lines.push('| Place | Initial Tokens | Description |');
  lines.push('|-------|----------------|-------------|');
  lines.push('| ready | 1 | System ready to execute |');

  for (const state of states.filter(s => s.type === 'tool')) {
    lines.push(`| ${state.name}_pending | 0 | ${state.name} queued |`);
    lines.push(`| ${state.name}_done | 0 | ${state.name} completed |`);
  }
  lines.push('');

  lines.push('## Transitions');
  lines.push('');
  lines.push('| Transition | Input Places | Output Places |');
  lines.push('|------------|--------------|---------------|');

  for (const state of states.filter(s => s.type === 'tool')) {
    lines.push(`| start_${state.name} | ready | ${state.name}_pending |`);
    lines.push(`| complete_${state.name} | ${state.name}_pending | ${state.name}_done, ready |`);
  }
  lines.push('');

  lines.push('## GraphViz DOT');
  lines.push('');
  lines.push('```dot');
  lines.push('digraph PetriNet {');
  lines.push('  rankdir=LR;');
  lines.push('  node [shape=circle];');
  lines.push('  ready [label="ready\\n(1)"];');

  for (const state of states.filter(s => s.type === 'tool')) {
    lines.push(`  ${state.name}_pending [label="${state.name}\\npending"];`);
    lines.push(`  ${state.name}_done [label="${state.name}\\ndone"];`);
  }

  lines.push('  node [shape=box];');

  for (const state of states.filter(s => s.type === 'tool')) {
    lines.push(`  start_${state.name} [label="start"];`);
    lines.push(`  complete_${state.name} [label="complete"];`);
    lines.push(`  ready -> start_${state.name};`);
    lines.push(`  start_${state.name} -> ${state.name}_pending;`);
    lines.push(`  ${state.name}_pending -> complete_${state.name};`);
    lines.push(`  complete_${state.name} -> ${state.name}_done;`);
    lines.push(`  complete_${state.name} -> ready;`);
  }

  lines.push('}');
  lines.push('```');

  return lines.join('\n');
}

/**
 * Generate sequence diagram from audit history
 */
function generateSequenceDiagram(states: ToolState[], transitions: ToolTransition[]): string {
  const lines: string[] = [];

  lines.push('# Sequence Diagram from Audit Trail');
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push(`Total Events: ${auditHistory.length}`);
  lines.push('');

  lines.push('## Mermaid Sequence Diagram');
  lines.push('');
  lines.push('```mermaid');
  lines.push('sequenceDiagram');
  lines.push('  participant Client');
  lines.push('  participant Server');

  // Get unique tools
  const tools = new Set(auditHistory.map(e => e.toolName));
  for (const tool of tools) {
    lines.push(`  participant ${tool.replace(/-/g, '_')}`);
  }

  // Show last 50 events
  const recentHistory = auditHistory.slice(-50);
  for (const entry of recentHistory) {
    const toolId = entry.toolName.replace(/-/g, '_');
    lines.push(`  Client->>Server: invoke ${entry.toolName}`);
    lines.push(`  Server->>${toolId}: execute`);
    if (entry.success) {
      lines.push(`  ${toolId}-->>Server: success (${entry.executionTimeMs || '?'}ms)`);
    } else {
      lines.push(`  ${toolId}--xServer: error: ${entry.error || 'unknown'}`);
    }
    lines.push(`  Server-->>Client: result`);
  }

  lines.push('```');
  lines.push('');

  lines.push('## Event Log');
  lines.push('');
  lines.push('| Timestamp | Tool | Success | Duration |');
  lines.push('|-----------|------|---------|----------|');

  for (const entry of recentHistory) {
    const icon = entry.success ? '✓' : '✗';
    lines.push(`| ${entry.timestamp.toISOString()} | ${entry.toolName} | ${icon} | ${entry.executionTimeMs || '-'}ms |`);
  }

  return lines.join('\n');
}

/**
 * Generate a formal model from the audit history
 */
export function generateAuditFormalModel(modelType: FormalModelType = 'state-machine'): AuditFormalModel {
  const { states, transitions } = analyzeAuditHistory();

  let specification: string;

  switch (modelType) {
    case 'tlaplus':
      specification = generateTLAPlusFromAudit(states, transitions);
      break;
    case 'alloy':
      specification = generateAlloyFromAudit(states, transitions);
      break;
    case 'petri-net':
      specification = generatePetriNetFromAudit(states, transitions);
      break;
    case 'sequence':
      specification = generateSequenceDiagram(states, transitions);
      break;
    case 'state-machine':
    default:
      specification = generateStateMachineFromAudit(states, transitions);
      break;
  }

  return {
    type: modelType,
    generatedAt: new Date().toISOString(),
    entryCount: auditHistory.length,
    states,
    transitions,
    specification,
  };
}

/**
 * Parse existing log file and load into history
 */
export function loadAuditHistoryFromFile(logFilePath?: string): number {
  const filePath = logFilePath || config.logFile;

  if (!fs.existsSync(filePath)) {
    return 0;
  }

  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n').filter(line => line.trim() && !line.startsWith('#'));

  let loaded = 0;

  for (const line of lines) {
    try {
      const entry = JSON.parse(line);
      if (entry.toolName) {
        auditHistory.push({
          timestamp: new Date(entry.timestamp),
          toolName: entry.toolName,
          success: entry.success ?? entry.result?.success ?? true,
          executionTimeMs: entry.executionTimeMs,
          inputKeys: entry.inputs ? Object.keys(entry.inputs) : [],
          error: entry.error || entry.result?.error,
        });
        loaded++;
      }
    } catch {
      // Skip invalid lines
    }
  }

  // Trim if too large
  if (auditHistory.length > MAX_HISTORY_SIZE) {
    auditHistory.splice(0, auditHistory.length - MAX_HISTORY_SIZE);
  }

  return loaded;
}

export default {
  initAuditLog,
  logAudit,
  logToolInvocation,
  startToolInvocation,
  logToolOutput,
  logOutput,
  withAuditLog,
  closeAuditLog,
  getAuditConfig,
  updateAuditConfig,
  // Formal model generation
  getAuditHistory,
  clearAuditHistory,
  generateAuditFormalModel,
  loadAuditHistoryFromFile,
};
